import copy
import json
import unittest
from urllib.request import Request

from questions.acceptance_snapshot import NoRedirect, capture, closed_citations, validate_base


class AcceptanceSnapshotTest(unittest.TestCase):
    def fixture(self, base, route, body=None):
        if route == "/api/overview":
            return {"items": 1, "sources": ["Fixture"], "llm_ready": True, "latency_count": 0, "monitor": {"interval_hours": 6}, "private_debug": "secret"}
        if route == "/api/library":
            return {"overview": {"documents": 2, "chunks": 4, "types": {}, "source_categories": [], "scope_counts": {}, "failed_documents": []}}
        if route.startswith("/api/assessment/"):
            return {"status": "ok", "cvss": {}, "poc_candidates": [{"validation": "not_run"}], "fix_records": [{"validation": "not_tested"}]}
        if route == "/api/assets":
            return {"count": 1, "demo_count": 0, "items": [{"hostname": "private.company.internal", "owner": "Secret user"}]}
        if route.startswith("/api/library/search"):
            return {"mode": "bm25", "evidence": [{"text": "private raw response"}]}
        if route.startswith("/api/library/relations/graph"):
            return {"status": "ready", "facts": [{"text": "private raw response"}], "unavailable_facts": []}
        if route.startswith("/api/library/relations/candidates"):
            return {"items": [{"effective_state": "pending", "quote": "private raw response", "reviews": []}]}
        self.assertEqual(route, "/api/library/analyze")
        self.assertFalse(body["use_model"])
        return self.answer()

    @staticmethod
    def answer():
        return {"status": "answered", "answer": "private raw response", "model_attempted": False,
                "evidence": [{"document_id": "D1", "citation_id": "C1"}, {"document_id": "D2", "citation_id": "C2"}],
                "analyses": [{"evidence_ids": ["C1", "C2"]}], "graph": {"edges": [{"evidence_ids": ["C1"]}]}}

    def test_snapshot_exports_only_whitelisted_counts_and_no_competition_grade(self):
        report = capture(requester=self.fixture)
        text = json.dumps(report)
        for private in ("private.company.internal", "Secret user", "private raw response", "private_debug"):
            self.assertNotIn(private, text)
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertIsNone(report["summary"]["competition_passed"])
        self.assertIsNone(report["summary"]["independent_qa_accuracy"])
        self.assertEqual(report["inventory"]["assessment"]["poc_validation_states"], ["not_run"])

    def test_failed_endpoint_does_not_abort_other_checks_or_export_error_body(self):
        def broken(base, route, body=None):
            if route == "/api/library": raise OSError("sensitive upstream debug body")
            return self.fixture(base, route, body)
        report = capture(requester=broken)
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertIn("model_supply_chain_analysis", report["inventory"])
        self.assertNotIn("sensitive upstream", json.dumps(report))

    def test_missing_data_and_unreviewed_graph_are_explicit(self):
        def empty(base, route, body=None):
            result = self.fixture(base, route, body)
            if route == "/api/overview": result["items"] = 0
            if route.startswith("/api/library/relations/graph"): result["status"] = "partial"
            return result
        report = capture(requester=empty)
        self.assertEqual(report["summary"]["needs_data_or_review"], 3)

    def test_wrong_missing_or_single_document_citations_fail(self):
        original = self.answer()
        for mutate in (lambda p: p["graph"]["edges"][0].update(evidence_ids=["invented"]),
                       lambda p: p["analyses"][0].update(evidence_ids=[]),
                       lambda p: p["graph"].update(edges=[]),
                       lambda p: p["evidence"].pop()):
            result = copy.deepcopy(original); mutate(result)
            self.assertFalse(closed_citations(result))

    def test_unexpected_model_call_marks_analysis_for_review(self):
        def called(base, route, body=None):
            result = self.fixture(base, route, body)
            if route == "/api/library/analyze": result["model_attempted"] = True
            return result
        report = capture(requester=called)
        self.assertEqual(report["summary"]["needs_data_or_review"], 2)

    def test_only_loopback_roots_and_valid_cve_allowed(self):
        for url in ("https://example.com", "http://127.0.0.1.evil.test", "http://user:password@localhost", "http://localhost/path", "http://localhost?secret=x"):
            with self.assertRaises(ValueError): validate_base(url)
        self.assertEqual(validate_base("http://[::1]:8023/"), "http://[::1]:8023")
        with self.assertRaises(ValueError): capture(cve_id="not-cve", requester=self.fixture)

    def test_redirect_is_rejected_before_external_request(self):
        handler = NoRedirect()
        with self.assertRaises(ValueError): handler.redirect_request(Request("http://localhost:8023"), None, 302, "Found", {}, "https://example.com")


if __name__ == "__main__":
    unittest.main()
