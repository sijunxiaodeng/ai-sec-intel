"""使用合成来源验证自动评估，不联网，不修改运行库。"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from enrichment.assessment import assess, enrich_view, vector_explanations
from enrichment.documents import digest
from enrichment.sample import load_sample
from rag.evidence import _connection
from rag.ingest import ingest


class AssessmentTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "assessment.sqlite3"
        self.record, _ = load_sample()
        self.cve = self.record["item"]["cve_id"]
        self.fix = "https://github.com/ollama/ollama/pull/4175"
        self.record["references"] = [self.fix]
        self.record["item"]["references"] = []
        self.record["item"]["raw_data"]["related_documents"] = []
        self.metric = {"source": "vendor@example.org", "type": "Secondary", "cvssData": {
            "version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}
        self.match = {"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*",
                      "versionEndExcluding": "0.1.34"}
        self.nvd = {"id": self.cve, "lastModified": "2026-01-01T00:00:00",
                    "descriptions": [{"lang": "en", "value": "Synthetic vulnerability fixture."}],
                    "metrics": {"cvssMetricV31": [self.metric]},
                    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [self.match]}]}],
                    "references": [{"url": self.fix, "tags": ["Patch"]},
                                   {"url": "https://example.org/exploit", "tags": ["Exploit"]}]}
        self.fail_nvd = False

    def fetch(self, url):
        if "services.nvd.nist.gov" in url:
            if self.fail_nvd:
                raise TimeoutError("test refresh failure")
            data = {"vulnerabilities": [{"cve": self.nvd}]}
        elif "api.github.com" in url:
            data = {"title": "validate model digest", "body": "Synthetic patch record.",
                    "merged": True, "merge_commit_sha": "fixture"}
        else:
            raise AssertionError("unexpected fetch: " + url)
        return {"body": json.dumps(data).encode(), "content_type": "application/json", "url": url}

    def prepare(self):
        return ingest(self.record, self.db, max_sources=2, fetcher=self.fetch)

    def test_report_preserves_provider_boundaries_and_citations(self):
        self.prepare()
        report = assess(self.cve, self.db)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["cvss"]["source"], "vendor@example.org")
        self.assertEqual(report["cvss"]["metric_type"], "Secondary")
        self.assertEqual(report["affected_ranges"][0]["display"], "ollama：版本 < 0.1.34")
        self.assertEqual(next(r for r in report["attack_conditions"] if r["metric"] == "PR")["text"], "低")
        self.assertEqual(report["asset_impact"]["status"], "unknown")
        ids = {r["citation_id"] for r in report["evidence"]}
        for key in ("cvss_candidates", "affected_ranges", "attack_conditions", "technical_impact", "poc_candidates", "fix_records"):
            for row in report[key]:
                self.assertTrue(row["evidence_ids"])
                self.assertTrue(set(row["evidence_ids"]) <= ids)
        self.assertEqual(report["poc_candidates"][0]["validation"], "not_run")
        self.assertEqual(report["fix_records"][0]["fixed_version"], None)
        self.assertEqual(report["fix_records"][0]["validation"], "not_tested")

    def test_conflicting_scores_keep_sources_and_primary_selection(self):
        primary = copy.deepcopy(self.metric)
        primary.update(source="nvd@nist.gov", type="Primary")
        primary["cvssData"]["baseScore"] = 9.1
        self.nvd["metrics"]["cvssMetricV31"].append(primary)
        self.prepare()
        report = assess(self.cve, self.db)
        self.assertEqual(report["cvss"]["score"], 9.1)
        self.assertEqual({r["score"] for r in report["cvss_candidates"]}, {8.8, 9.1})
        self.assertTrue(any("没有取平均分" in w for w in report["warnings"]))

    def test_newer_cvss_version_keeps_older_score(self):
        self.nvd["metrics"]["cvssMetricV40"] = [{"source": "v4@example.org", "type": "Secondary", "cvssData": {
            "version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]
        self.prepare()
        report = assess(self.cve, self.db)
        self.assertEqual(report["cvss"]["version"], "4.0")
        self.assertEqual(len(report["cvss_candidates"]), 2)
        self.assertEqual(len(report["technical_impact"]), 6)
        self.assertEqual(next(r for r in report["attack_conditions"] if r["metric"] == "UI")["text"], "被动交互")
        self.assertIn("v4.0", report["interpretation_standard"])

    def test_config_dependencies_are_not_vulnerable_assets(self):
        self.nvd["configurations"][0]["operator"] = "AND"
        dependency = copy.deepcopy(self.match)
        dependency.update(vulnerable=False, criteria="cpe:2.3:o:example:os:*:*:*:*:*:*:*:*")
        self.nvd["configurations"][0]["nodes"][0]["cpeMatch"].append(dependency)
        self.match["versionStartIncluding"] = "0.1.0"
        self.prepare()
        report = assess(self.cve, self.db)
        self.assertEqual(len(report["affected_ranges"]), 1)
        self.assertTrue(report["affected_ranges"][0]["requires_environment_review"])
        self.assertIn("版本 >= 0.1.0", report["affected_ranges"][0]["display"])
        self.assertIn("版本 < 0.1.34", report["affected_ranges"][0]["display"])

    def test_missing_score_stays_partial(self):
        self.nvd["metrics"] = {}
        self.prepare()
        report = assess(self.cve, self.db)
        self.assertEqual(report["status"], "partial")
        self.assertIsNone(report["cvss"])
        self.assertEqual(report["technical_impact"], [])

    def test_prerelease_and_platform_qualifiers_are_preserved(self):
        self.match.update(criteria="cpe:2.3:a:ollama:ollama:0.11.5:rc0:*:*:*:windows:*:*", versionEndExcluding="")
        self.prepare()
        row = assess(self.cve, self.db)["affected_ranges"][0]
        self.assertIn("版本 = 0.11.5", row["display"])
        self.assertIn("更新/预发布标识 = rc0", row["display"])
        self.assertIn("运行平台 = windows", row["display"])
        self.assertEqual(row["qualifiers"], {"update": "rc0", "target_sw": "windows"})

    def test_refresh_failure_retains_dated_snapshot(self):
        self.prepare()
        before = assess(self.cve, self.db)
        self.fail_nvd = True
        self.prepare()
        after = assess(self.cve, self.db)
        self.assertEqual(after["source"]["sha256"], before["source"]["sha256"])
        self.assertEqual(after["source"]["retrieved_at"], before["source"]["retrieved_at"])
        self.assertEqual(after["source"]["latest_fetch_status"], "error")
        self.assertTrue(any("上次成功快照" in w for w in after["warnings"]))

    def test_tampered_snapshot_is_not_reported(self):
        self.prepare()
        sid = digest("https://nvd.nist.gov/vuln/detail/" + self.cve)[:16]
        with _connection(self.db) as conn:
            conn.execute("UPDATE source_snapshots SET body=? WHERE source_id=?", (b"{}", sid))
        report = assess(self.cve, self.db)
        self.assertEqual(report["status"], "invalid_evidence")
        self.assertIsNone(report["cvss"])
        self.assertEqual(report["evidence"], [])

    def test_tampered_metric_chunk_is_excluded(self):
        self.prepare()
        with _connection(self.db) as conn:
            for eid, payload in conn.execute("SELECT evidence_id,payload FROM evidence").fetchall():
                chunk = json.loads(payload)
                if chunk["locator"].startswith("metrics/"):
                    chunk["text"] = "changed"
                    conn.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(chunk), eid))
        report = assess(self.cve, self.db)
        self.assertIsNone(report["cvss"])
        self.assertEqual(report["status"], "partial")

    def test_read_view_preserves_input_and_does_not_persist_report(self):
        self.prepare()
        self.record["cvss"]["score"] = 4.0
        original = copy.deepcopy(self.record)
        enriched = enrich_view([self.record], self.db)[0]
        self.assertEqual(enriched["cvss"]["score"], 8.8)
        self.assertEqual(self.record, original)
        ingest(enriched, self.db, max_sources=2, fetcher=self.fetch)
        with _connection(self.db) as conn:
            stored = json.loads(conn.execute("SELECT payload FROM records").fetchone()[0])
        self.assertNotIn("automatic_assessment", stored["item"]["raw_data"])

    def test_chinese_qa_quotes_structured_facts_and_unverified_poc(self):
        from rag.retrieve import search
        from agents.qa_agent import run
        from agents.verifier_agent import run as verify
        self.prepare()
        with patch("rag.retrieve.load_kb", return_value=[]):
            records = search("CVSS 评分、受影响版本和 PoC 状态是什么？", cve_id=self.cve, db_path=self.db)
        with patch("agents.qa_agent.search", return_value=records), patch("agents.qa_agent.configured", return_value=False):
            result = run("CVSS 评分、受影响版本和 PoC 状态是什么？", cve_id=self.cve)
        self.assertIn("CVSS 3.1 基础分为 8.8", result["answer"])
        self.assertIn("版本 < 0.1.34", result["answer"])
        self.assertIn("未运行复现", result["answer"])
        self.assertTrue(verify(result["answer"], records)["passed"])

    def test_api_includes_assessment_and_rejects_unknown_id(self):
        from fastapi.testclient import TestClient
        from api.app import app
        self.prepare()
        enriched = enrich_view([self.record], self.db)[0]
        client = TestClient(app)
        with patch("api.app.get_record", return_value=enriched), patch("rag.ingest.document_status", return_value=[]):
            report = client.get("/api/assessment/" + self.cve).json()
            detail = client.get("/api/items/" + self.cve).json()
        self.assertEqual(report["status"], "ok")
        self.assertEqual(detail["cvss_version"], "3.1")
        self.assertEqual(detail["assessment"]["cvss"]["score"], 8.8)
        with patch("api.app.get_record", return_value=None):
            self.assertEqual(client.get("/api/assessment/CVE-2099-99999").status_code, 404)

    def test_absent_db_is_not_created_and_invalid_vector_values_not_translated(self):
        self.assertEqual(assess(self.cve, self.db)["status"], "insufficient_evidence")
        self.assertFalse(self.db.exists())
        self.assertEqual(vector_explanations({"version": "2.0", "vector": "AV:N/AC:L"}), [])
        self.assertEqual(vector_explanations({"version": "4.0", "vector": "CVSS:4.0/SA:S/UI:R"}), [])
        self.assertEqual(vector_explanations({"version": "3.1", "vector": "CVSS:3.1/UI:P"}), [])


if __name__ == "__main__":
    unittest.main()
