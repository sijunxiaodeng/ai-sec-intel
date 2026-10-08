import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from enrichment.documents import associate, extract_document, public_url
from enrichment.sample import load_sample
from rag.evidence import _all_evidence, _connection, save
from rag.hybrid import config_path, MODEL_NAME, update_index
from rag.ingest import ingest, document_status


class DocumentsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "sources.sqlite3"
        self.record, self.manual = load_sample()
        self.cve = self.record["item"]["cve_id"]
        self.analysis = "https://research.example/" + self.cve
        self.fix = "https://github.com/ollama/ollama/pull/4175"
        self.record["references"] = [self.analysis, self.fix]
        self.record["item"]["references"] = []
        self.record["item"]["raw_data"]["related_documents"] = []
        self.body = (self.cve + " affects Ollama versions before 0.1.34. "
                     "The fix validates model digest format. Upgrade to the patched version. "
                     "The API attack may cause arbitrary file writes and remote code execution.")
        self.failed = set()

    def fetch(self, url):
        if any(value in url for value in self.failed):
            raise TimeoutError("source timed out")
        if "services.nvd.nist.gov" in url:
            data = {"vulnerabilities": [{"cve": {"id": self.cve,
                "descriptions": [{"lang": "en", "value": "Ollama before 0.1.34 has a vulnerability."}],
                "metrics": {"cvssMetricV31": [{"source": "vendor", "type": "Primary", "cvssData": {"baseScore": 8.8}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{"versionEndExcluding": "0.1.34"}]}]}],
                "references": [{"url": self.analysis}, {"url": self.fix, "tags": ["Patch"]}]}}]}
            return {"body": json.dumps(data).encode(), "content_type": "application/json", "url": url}
        if "api.github.com" in url:
            data = {"title": "validate digest model path", "body": "", "merged": True, "merge_commit_sha": "test"}
            return {"body": json.dumps(data).encode(), "content_type": "application/json", "url": url}
        return {"body": self.body.encode(), "content_type": "text/plain", "url": url}

    def run_ingest(self):
        return ingest(self.record, self.db, max_sources=4, fetcher=self.fetch)

    def test_real_extractors_and_association_exclude_background(self):
        html = "<html><head><title>Research</title></head><body><nav>UNRELATED NAVIGATION</nav><article><h1>Research</h1><p>" + self.body + "</p><p>" + self.body + "</p></article></body></html>"
        doc = extract_document({"body": html.encode(), "content_type": "text/html", "url": self.analysis}, self.analysis)
        text = doc["parts"][0][1]
        self.assertIn(self.cve, text)
        self.assertNotIn("UNRELATED NAVIGATION", text)
        candidate = {"url": self.analysis, "tags": [], "origin": "record_reference"}
        self.assertEqual(associate(self.cve, candidate, doc)[0], "direct_analysis")
        doc["parts"] = [("text", "An unrelated page about AI")]
        self.assertEqual(associate(self.cve, candidate, doc)[0], "background")
        candidate.update(tags=["Exploit"])
        doc["parts"] = [("text", self.body)]
        self.assertEqual(associate(self.cve, candidate, doc)[0], "poc_candidate")

    def test_empty_html_and_unsupported_json_are_not_evidence(self):
        for content_type, body in (("text/html", b"<html><body></body></html>"), ("application/json", b"{}")):
            with self.assertRaises(ValueError):
                extract_document({"body": body, "content_type": content_type}, self.analysis)

    def test_repeat_ingestion_has_stable_ids_and_verifiable_snapshot(self):
        first = self.run_ingest()
        rows = _all_evidence(self.db)
        self.assertEqual(first["ok"], 3)
        self.assertEqual(first["index"]["status"], "deferred")
        self.assertEqual({row["relation_type"] for row in rows}, {"vulnerability_record", "direct_analysis", "fix_record"})
        ids = {row["evidence_id"] for row in rows}
        self.run_ingest()
        self.assertEqual(ids, {row["evidence_id"] for row in _all_evidence(self.db)})
        with _connection(self.db) as conn:
            for sha, body in conn.execute("SELECT digest, body FROM source_snapshots"):
                self.assertEqual(sha, hashlib.sha256(body).hexdigest())

    def test_refresh_failure_preserves_last_success_and_other_sources(self):
        self.run_ingest()
        before = _all_evidence(self.db)
        self.failed.add("research.example")
        result = self.run_ingest()
        self.assertEqual(result["ok"], 2)
        self.assertEqual({row["evidence_id"] for row in before}, {row["evidence_id"] for row in _all_evidence(self.db)})
        failed = next(row for row in document_status(self.cve, self.db) if row["url"] == self.analysis)
        self.assertEqual(failed["status"], "error")
        self.assertTrue(failed["retained_previous"])
        self.assertTrue(failed["last_success_at"])

    def test_nvd_failure_uses_dated_previous_reference_for_fix(self):
        self.run_ingest()
        self.failed.add("services.nvd.nist.gov")
        self.run_ingest()
        rows = _all_evidence(self.db)
        fix = next(row for row in rows if row["url"] == self.fix)
        self.assertEqual(fix["relation_type"], "fix_record")
        self.assertIn("上次成功 NVD 快照", fix["association_reason"])

    def test_source_json_ids_support_osv_and_cve_records(self):
        payload = {"id": self.cve, "summary": "Model security", "details": self.body}
        response = {"content_type": "application/json", "body": json.dumps(payload).encode(), "url": "https://api.osv.dev/v1/vulns/" + self.cve}
        doc = extract_document(response, response["url"])
        candidate = {"url": "https://osv.dev/vulnerability/" + self.cve, "tags": [], "origin": "record_reference"}
        self.assertEqual(associate(self.cve, candidate, doc)[0], "vulnerability_record")
        payload = {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": self.cve}, "containers": {"cna": {"descriptions": [{"value": self.body}]}}}
        response["body"] = json.dumps(payload).encode()
        doc = extract_document(response, response["url"])
        self.assertIn(self.cve, doc["title"])
        self.assertIn("containers/cna/descriptions", [field for field, _ in doc["parts"]])

    def test_web_retrieval_prefers_auto_and_covers_three_sources(self):
        from rag.retrieve import search
        self.run_ingest()
        same_sources = copy.deepcopy(self.manual)
        same_sources[1]["url"] = self.analysis
        save(self.record, same_sources, self.db)
        with patch("rag.retrieve.load_kb", return_value=[]):
            records = search("受影响版本是什么，如何修复？有没有修复记录？", cve_id=self.cve, db_path=self.db)
        chunks = records[0]["evidence_chunks"]
        self.assertTrue(all(chunk["text_kind"] == "automatic_source_extract" for chunk in chunks))
        self.assertEqual({chunk["relation_type"] for chunk in chunks}, {"vulnerability_record", "direct_analysis", "fix_record"})

    def test_changed_body_replaces_only_its_chunks_and_sample_keeps_auto(self):
        self.run_ingest()
        before = _all_evidence(self.db)
        self.body += " Mitigation: require authentication at the reverse proxy."
        self.run_ingest()
        after = _all_evidence(self.db)
        self.assertNotEqual({r["evidence_id"] for r in before if r["url"] == self.analysis}, {r["evidence_id"] for r in after if r["url"] == self.analysis})
        self.assertEqual({r["evidence_id"] for r in before if r["url"] != self.analysis}, {r["evidence_id"] for r in after if r["url"] != self.analysis})
        save(self.record, self.manual, self.db)
        self.assertEqual(len(_all_evidence(self.db)), len(after) + 8)

    def test_incremental_vectors_embed_only_changed_text(self):
        self.run_ingest()
        config_path(self.db).write_text(json.dumps({"enabled": True, "model": MODEL_NAME, "cache_dir": "local"}), encoding="utf-8")
        model = Mock()
        model.passage_embed.side_effect = lambda texts: [[1.0, 0.0] for _ in texts]
        with patch("rag.hybrid._model", return_value=model) as loader:
            first = update_index(self.db)
            self.assertGreater(first["updated"], 0)
            second = update_index(self.db)
            self.assertEqual(second["updated"], 0)
            self.assertEqual(model.passage_embed.call_count, 1)
            self.assertTrue(loader.call_args.args[1])
            self.body += " Require authentication."
            result = self.run_ingest()
            self.assertEqual(result["index"]["updated"], 1)
            self.assertEqual(model.passage_embed.call_count, 2)
            with _connection(self.db) as conn:
                count = conn.execute("SELECT count(*) FROM embeddings").fetchone()[0]
            self.assertEqual(count, len(_all_evidence(self.db)))

    def test_raw_brackets_do_not_become_fake_citations(self):
        from agents.verifier_agent import run
        chunk = {"citation_id": self.cve + "/AUTO-X", "text": 'Affected versions: ["0.1.33", "0.1.32"]'}
        record = copy.deepcopy(self.record)
        record["evidence_chunks"] = [chunk]
        answer = chunk["text"] + " [" + chunk["citation_id"] + "]"
        self.assertTrue(run(answer, [record])["passed"])
        self.assertFalse(run(answer + " [不存在的证据]", [record])["passed"])

    def test_public_fetch_rejects_local_and_redirect_targets(self):
        for url in ("http://example.com", "file:///etc/passwd", "https://user:password@example.com", "https://example.com:8080"):
            with self.assertRaises(ValueError):
                public_url(url)
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                public_url("https://example.com")
            from enrichment.documents import PublicRedirect
            with self.assertRaises(ValueError):
                PublicRedirect().redirect_request(None, None, 302, "", {}, "https://localhost")

    def test_api_processes_known_cve_and_rejects_unknown(self):
        from fastapi.testclient import TestClient
        from api.app import app
        result = self.run_ingest()
        with patch("api.app.get_record", return_value=self.record), patch("api.app.run_documents", return_value=result):
            response = TestClient(app).post("/api/documents", json={"cve_id": self.cve})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["chunks"], len(_all_evidence(self.db)))
        with patch("api.app.get_record", return_value=None):
            self.assertEqual(TestClient(app).post("/api/documents", json={"cve_id": "CVE-2099-99999"}).status_code, 404)

    def test_collect_pipeline_processes_new_records_with_budget(self):
        from agents.orchestrator import run_collect
        records = [copy.deepcopy(self.record) for _ in range(4)]
        with patch("agents.orchestrator.monitor_run", return_value={"items": [], "steps": []}), patch("agents.orchestrator.enrich_run", return_value={"records": records, "steps": []}), patch("agents.orchestrator.upsert", return_value=records), patch("agents.orchestrator.append_run"), patch("agents.orchestrator.ingest", return_value={"ok": 2}) as ingest_mock:
            result = run_collect()
            self.assertEqual(ingest_mock.call_count, 3)
            self.assertEqual(len(result["records"]), 4)
            self.assertIn("证据索引", result["steps"][-1]["action"])


if __name__ == "__main__":
    unittest.main()
