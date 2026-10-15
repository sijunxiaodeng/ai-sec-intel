"""Complete CVSS fields remain source-bound even when chunked for retrieval."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.citation_guard import cited_cvss_metrics, claim_issues, matching_cvss_metrics
from agents.qa_agent import _assessment_lines, run
from agents.verifier_agent import run as verify
from enrichment.assessment import assess
from enrichment.documents import digest, nvd_document, finish
from enrichment.sample import load_sample
from rag.evidence import _connection
from rag.ingest import store_document


CVE = "CVE-2025-15514"
BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
OPTIONAL = "/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"


def fixture():
    metric = {"source": "disclosure@example.org", "type": "Secondary", "cvssData": {
        "version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH", "vectorString": BASE + OPTIONAL}}
    fields = ("exploitMaturity confidentialityRequirement integrityRequirement availabilityRequirement "
              "modifiedAttackVector modifiedAttackComplexity modifiedAttackRequirements modifiedPrivilegesRequired "
              "modifiedUserInteraction modifiedVulnConfidentialityImpact modifiedVulnIntegrityImpact "
              "modifiedVulnAvailabilityImpact modifiedSubConfidentialityImpact modifiedSubIntegrityImpact "
              "modifiedSubAvailabilityImpact Safety Automatable Recovery valueDensity vulnerabilityResponseEffort providerUrgency")
    metric["cvssData"].update({field: "NOT_DEFINED" for field in fields.split()})
    cve = {"id": CVE, "metrics": {"cvssMetricV40": [metric]}, "descriptions": [{"lang": "en", "value": "Synthetic fixture."}]}
    response = {"body": json.dumps({"vulnerabilities": [{"cve": cve}]}).encode(),
                "content_type": "application/json", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + CVE}
    doc = finish(nvd_document(CVE, response), CVE, "https://nvd.nist.gov/vuln/detail/" + CVE, response, "2026-01-01T00:00:00Z")
    metadata = {k: v for k, v in doc.items() if k not in ("chunks", "parts", "text", "references", "_response_body")}
    chunks = [dict(metadata, **chunk, citation_id=CVE + "/" + chunk["evidence_id"])
              for chunk in doc["chunks"] if chunk["locator"].startswith("metrics/")]
    return metric, doc, chunks


class CVSSFragmentTest(unittest.TestCase):
    def setUp(self):
        self.metric, self.doc, self.chunks = fixture()
        self.assertGreater(len(self.chunks), 1)
        self.text = "CVSS 4.0 基础分为 8.7，严重等级高；向量 " + BASE + OPTIONAL + "；评分来源 disclosure@example.org。"

    def test_all_fragments_and_original_optional_vector_are_accepted(self):
        self.assertEqual(cited_cvss_metrics(self.chunks), [self.metric])
        self.assertFalse(claim_issues(self.text, list(reversed(self.chunks))))
        self.assertFalse(claim_issues("按 CVSS 向量解释，附加攻击要求：无；所需权限：无。", self.chunks))

    def test_missing_or_repeated_fragment_cannot_authorize_even_a_version(self):
        for chunks in (self.chunks[:1], self.chunks[1:], self.chunks + self.chunks[:1]):
            with self.subTest(count=len(chunks)):
                self.assertTrue(claim_issues(self.text, chunks))
                self.assertTrue(claim_issues("CVSS 4.0。", chunks))

    def test_fragments_from_different_snapshot_source_cve_or_field_do_not_join(self):
        for key in ("cve_id", "source_id", "source_response_sha256", "url", "locator"):
            rows = copy.deepcopy(self.chunks)
            rows[-1][key] = rows[-1][key].replace("/0；", "/1；") if key == "locator" else "different-" + rows[-1][key]
            with self.subTest(key=key):
                self.assertTrue(claim_issues(self.text, rows))

    def test_corrupt_hash_and_conflicting_projection_fail_closed(self):
        rows = copy.deepcopy(self.chunks)
        rows[0]["text"] = rows[0]["text"].replace("8.7", "8.6")
        self.assertTrue(claim_issues(self.text.replace("8.7", "8.6"), rows))
        rows[0]["text_sha256"] = digest(rows[0]["text"])
        rows[0]["structured_value"] = self.metric
        self.assertTrue(claim_issues(self.text.replace("8.7", "8.6"), rows))
        for projection in ("not an object", {"cvssData": {"baseScore": 8.7}}):
            rows = copy.deepcopy(self.chunks)
            rows[-1]["structured_value"] = projection
            self.assertTrue(claim_issues(self.text, rows))

    def test_invalid_span_length_gap_and_overlap_fail(self):
        for locator in ("metrics/cvssMetricV40/0；字符 [1,9999)", "metrics/cvssMetricV40/0；字符 [0,1)", "metrics/cvssMetricV40/0"):
            rows = copy.deepcopy(self.chunks)
            rows[-1]["locator"] = locator
            self.assertTrue(claim_issues(self.text, rows))

    def test_only_optional_x_is_equivalent_to_omission(self):
        self.assertTrue(matching_cvss_metrics("CVSS 4.0 基础分为 8.7，向量 " + BASE, [self.metric]))
        for vector in (BASE + "/E:A", BASE + "/S:N", BASE.replace("PR:N", "PR:L"), BASE + "/E:X/E:X"):
            self.assertFalse(matching_cvss_metrics("CVSS 4.0 基础分为 8.7，向量 " + vector, [self.metric]))
        defined = copy.deepcopy(self.metric)
        defined["cvssData"]["vectorString"] = BASE + "/E:A"
        self.assertFalse(matching_cvss_metrics("CVSS 4.0 基础分为 8.7，向量 " + BASE, [defined]))
        # Standalone legacy-style component assertions still cannot borrow v4's S/AU.
        self.assertTrue(claim_issues("按 CVSS 向量解释，S:U。", self.chunks))
        self.assertTrue(claim_issues("按 CVSS 向量解释，AU:N。", self.chunks))


class ArchivedCVSSFragmentTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Path(directory.name) / "source.sqlite3"
        self.metric, self.doc, self.chunks = fixture()
        self.record, _ = load_sample()
        self.record["item"]["cve_id"] = CVE
        self.record["item"]["raw_data"] = {}
        store_document(self.record, self.doc, self.db)

    def test_archive_checked_projection_is_attached_and_rule_answer_verifies(self):
        report = assess(CVE, self.db)
        self.assertEqual(report["cvss"]["score"], 8.7)
        record = {"item": dict(self.record["item"], raw_data={"automatic_assessment": report}),
                  "cvss": report["cvss"], "evidence_chunks": copy.deepcopy(self.chunks[:1])}
        _assessment_lines(record, "CVSS 评分")
        self.assertEqual(len(record["evidence_chunks"]), len(self.chunks))
        self.assertTrue(all(c["structured_value"] == self.metric for c in record["evidence_chunks"]))
        with patch("agents.qa_agent.search", return_value=[record]), patch("agents.qa_agent.configured", return_value=False):
            result = run(CVE + " 的 CVSS 评分和评分来源是什么？", db_path=self.db)
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])

    def test_archive_rejects_self_consistent_text_and_digest_forgery(self):
        row = copy.deepcopy(self.chunks[0])
        row["text"] = row["text"].replace("8.7", "8.6")
        row["text_sha256"] = digest(row["text"])
        with _connection(self.db) as conn:
            conn.execute("UPDATE evidence SET payload=? WHERE cve_id=? AND evidence_id=?", (json.dumps(row), CVE, row["evidence_id"]))
        report = assess(CVE, self.db)
        self.assertIsNone(report["cvss"])
        self.assertFalse(report["cvss_candidates"])

    def test_archive_rejects_missing_tail_and_mutated_projection(self):
        with _connection(self.db) as conn:
            conn.execute("DELETE FROM evidence WHERE cve_id=? AND evidence_id=?", (CVE, self.chunks[-1]["evidence_id"]))
        self.assertIsNone(assess(CVE, self.db)["cvss"])
        store_document(self.record, self.doc, self.db)
        row = copy.deepcopy(self.chunks[0])
        row["structured_value"] = copy.deepcopy(self.metric)
        row["structured_value"]["cvssData"]["baseScore"] = 9.9
        with _connection(self.db) as conn:
            conn.execute("UPDATE evidence SET payload=? WHERE cve_id=? AND evidence_id=?", (json.dumps(row), CVE, row["evidence_id"]))
        self.assertIsNone(assess(CVE, self.db)["cvss"])


if __name__ == "__main__":
    unittest.main()
