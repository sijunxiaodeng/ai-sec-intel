"""Gap-driven execution regressions: all providers/model calls are offline fakes."""
import copy
import gc
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents import investigation as agent
from models import enriched_record


class InvestigationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Older evidence helpers return SQLite context managers whose handles
        # close on collection, rather than on transaction exit (Windows locks).
        self.addCleanup(gc.collect)
        self.db = Path(self.temp.name) / "evidence.sqlite3"
        self.record = enriched_record({"cve_id": "CVE-2026-34567", "title": "Synthetic AI model issue",
                                       "description": "Synthetic fixture, not a public vulnerability", "product": "fixture"})
        self.empty = {"status": "insufficient_evidence", "evidence": [], "cvss": None,
                      "cvss_candidates": [], "affected_ranges": []}
        self.full = {"status": "ok", "evidence": [{"citation_id": "fixture/verified"}],
                     "cvss": {"score": 8.1, "version": "3.1"},
                     "cvss_candidates": [{"score": 8.1, "version": "3.1"}],
                     "affected_ranges": [{"vendor": "fixture", "product": "fixture", "version": "1.0"}]}
        self.paper = {"title": "Synthetic research", "url": "https://example.org/paper"}
        self.current = copy.deepcopy(self.empty)
        self.order = []
        self.assess = self.enterContext(patch.object(agent, "assess", side_effect=lambda *_: copy.deepcopy(self.current)))
        self.documents = self.enterContext(patch.object(agent, "ingest", side_effect=self.ingest))
        self.feeds = self.enterContext(patch.object(agent, "apply_public_feeds", side_effect=self.public_feeds))
        self.papers = self.enterContext(patch.object(agent, "fetch_papers", side_effect=self.research))
        self.model = self.enterContext(patch.object(agent, "chat", side_effect=AssertionError("Unexpected model/network call")))
        self.enterContext(patch.object(agent, "configured", return_value=False))
        self.enterContext(patch.dict(os.environ, {"INVESTIGATION_USE_MODEL": "0"}))

    def ingest(self, record, **kwargs):
        self.order.append(agent.DOCUMENTS)
        self.current = copy.deepcopy(self.full)
        return {"attempted": 2, "ok": 2, "deferred_sources": 0}

    def public_feeds(self, records):
        self.order.append(agent.FEEDS)
        records[0].update(epss={"status": "ok", "score": "0.21"}, kev={"status": "not_listed"})
        return {"epss_error": None, "kev_error": None}

    def research(self, ids, **kwargs):
        self.order.append(agent.PAPERS)
        self.assertEqual(kwargs["cursor_path"], self.db.parent / "paper_queries.sqlite3")
        return {ids[0]: [copy.deepcopy(self.paper)]}, None

    def run_agent(self, **kwargs):
        return agent.run(self.record, db_path=self.db, **kwargs)

    def populated(self):
        self.current = copy.deepcopy(self.full)
        self.record.update(epss={"status": "empty"}, kev={"status": "not_listed"}, papers=[self.paper])

    def test_rules_execute_real_handlers_reassess_and_never_mutate_input(self):
        before = copy.deepcopy(self.record)
        result = self.run_agent()
        self.assertEqual(self.order, [agent.DOCUMENTS, agent.FEEDS, agent.PAPERS])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["stop_reason"], "evidence_sufficient")
        self.assertEqual(result["remaining_gaps"], [])
        self.assertEqual(result["record"]["epss"]["score"], "0.21")
        self.assertEqual(self.record, before)
        self.assertEqual(self.assess.call_count, 4)
        self.assertTrue(result["documents_changed"])
        self.assertFalse(result["retryable"])
        self.model.assert_not_called()

    def test_model_choice_changes_execution_then_observes_actual_result(self):
        requests = []
        def model(messages, **kwargs):
            payload = json.loads(messages[-1]["content"])
            requests.append(payload)
            self.assertLessEqual(kwargs["max_tokens"], 128)
            self.assertLessEqual(kwargs["timeout"], 8)
            return json.dumps({"tool": agent.PAPERS if not payload["observations"] else agent.FEEDS})
        with patch.object(agent, "configured", return_value=True), patch.object(agent, "chat", side_effect=model):
            result = self.run_agent(use_model=True)
        self.assertEqual(self.order, [agent.PAPERS, agent.FEEDS, agent.DOCUMENTS])
        self.assertEqual(result["model_calls"], 2)
        self.assertEqual(requests[1]["observations"][0]["tool"], agent.PAPERS)
        self.assertNotIn("research_evidence", requests[1]["gaps"])
        self.assertEqual(result["trace"]["decisions"][0]["selected_by"], "model")
        self.assertEqual(result["record"]["cvss"], self.record["cvss"])

    def test_forged_url_shell_or_fields_are_not_executed_or_stored(self):
        for raw in ('{"tool":"shell.run"}', '{"tool":"evidence.fetch","url":"http://127.0.0.1"}',
                    '{"tool":"evidence.fetch","cvss":10}', 'not json'):
            with self.subTest(raw=raw):
                self.current = copy.deepcopy(self.empty)
                self.order.clear()
                with patch.object(agent, "configured", return_value=True), patch.object(agent, "chat", return_value=raw):
                    result = self.run_agent(use_model=True, max_model_calls=1)
                self.assertEqual(self.order, [agent.DOCUMENTS, agent.FEEDS, agent.PAPERS])
                self.assertEqual(result["trace"]["decisions"][0]["selected_by"], "rules")
                self.assertEqual(result["record"]["cvss"], self.record["cvss"])
                self.assertNotIn("127.0.0.1", json.dumps(result))

    def test_existing_verified_dimensions_skip_all_tools_and_model(self):
        self.populated()
        with patch.object(agent, "configured", return_value=True):
            result = self.run_agent(use_model=True)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["trace"]["calls"], [])
        self.model.assert_not_called()

    def test_only_missing_dimension_executes_and_does_not_spend_model_budget(self):
        self.populated()
        self.record["kev"] = None
        with patch.object(agent, "configured", return_value=True):
            result = self.run_agent(use_model=True)
        self.assertEqual(self.order, [agent.FEEDS])
        self.assertEqual(result["remaining_gaps"], [])
        self.model.assert_not_called()

    def test_no_key_uses_rules_even_when_model_requested(self):
        result = self.run_agent(use_model=True)
        self.assertFalse(result["trace"]["model_enabled"])
        self.assertEqual(result["model_calls"], 0)
        self.model.assert_not_called()

    def test_failures_preserve_other_dimensions_and_do_not_leak_exception_secrets(self):
        self.feeds.side_effect = ConnectionError("private-token-must-not-leak")
        result = self.run_agent()
        self.assertEqual(result["record"]["papers"], [self.paper])
        self.assertTrue(result["retryable"])
        self.assertIn("public_feeds_error", result["errors"])
        self.assertEqual(result["stop_reason"], "available_tools_exhausted")
        self.assertNotIn("private-token", json.dumps(result))
        self.feeds.assert_called_once()

    def test_successful_empty_sources_remain_unknown_without_endless_retry(self):
        self.documents.side_effect = lambda *a, **k: {"attempted": 1, "ok": 1}
        self.papers.side_effect = lambda *a, **k: ({}, None)
        result = self.run_agent()
        self.assertEqual(len(result["trace"]["calls"]), 3)
        self.assertEqual(result["status"], "partial")
        self.assertIn("affected_versions", result["remaining_gaps"])
        self.assertIn("research_evidence", result["remaining_gaps"])
        self.assertEqual(result["trace"]["evidence_status"], "unknown")
        self.assertFalse(result["retryable"])
        self.documents.assert_called_once()
        self.papers.assert_called_once()

    def test_conflicting_scores_and_unbounded_versions_never_become_certain(self):
        self.populated()
        self.current["cvss_candidates"].append({"score": 9.8, "version": "3.1"})
        self.current["affected_ranges"][0]["version"] = "*"
        self.documents.side_effect = lambda *a, **k: {"attempted": 1, "ok": 1}
        result = self.run_agent()
        self.assertIn("source_conflict", result["remaining_gaps"])
        self.assertIn("affected_versions", result["remaining_gaps"])
        self.assertEqual(len(result["assessment"]["cvss_candidates"]), 2)
        self.assertEqual(result["trace"]["evidence_status"], "unknown")
        self.assertEqual(result["trace"]["asset_impact"], "unknown_until_inventory_evaluation")

    def test_tool_budget_and_zero_budget_stop_before_extra_work(self):
        result = self.run_agent(max_tool_calls=1)
        self.assertEqual(self.order, [agent.DOCUMENTS])
        self.assertEqual(result["stop_reason"], "tool_budget_exhausted")
        self.order.clear()
        result = self.run_agent(max_tool_calls=0)
        self.assertEqual(self.order, [])
        self.assertEqual(result["stop_reason"], "tool_budget_exhausted")

    def test_elapsed_budget_stops_after_inflight_tool_and_records_limitation(self):
        clock = [100.0]
        def slow(*args, **kwargs):
            clock[0] += 10
            return self.ingest(*args, **kwargs)
        self.documents.side_effect = slow
        with patch.object(agent.time, "monotonic", side_effect=lambda: clock[0]):
            result = self.run_agent(time_budget_seconds=5)
        self.assertEqual(self.order, [agent.DOCUMENTS])
        self.assertEqual(result["stop_reason"], "time_budget_exhausted")
        self.assertEqual(result["trace"]["elapsed_ms"], 10000)
        self.assertIn("in-flight", result["trace"]["budget_scope"])

    def test_guard_is_passed_and_stale_work_propagates(self):
        from automation.processing import StaleWork
        guard = lambda: None
        self.run_agent(commit_guard=guard, max_tool_calls=1)
        self.assertIs(self.documents.call_args.kwargs["commit_guard"], guard)
        self.current = copy.deepcopy(self.empty)
        self.documents.side_effect = StaleWork("stale")
        with self.assertRaises(StaleWork):
            self.run_agent()

    def test_invalid_budgets_and_identity_reject_before_execution(self):
        for options in ({"max_tool_calls": True}, {"max_model_calls": 3}, {"time_budget_seconds": float("nan")},
                        {"time_budget_seconds": 0}, {"use_model": "true"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.run_agent(**options)
        with self.assertRaises(ValueError):
            agent.run({"item": {"cve_id": "bad"}}, db_path=self.db)
        self.assertEqual(self.order, [])

    def test_real_archive_ingest_then_assessment_closes_version_gap(self):
        from enrichment.assessment import assess as real_assess
        from rag.ingest import ingest as real_ingest
        cve = self.record["item"]["cve_id"]
        nvd = {"id": cve, "descriptions": [{"lang": "en", "value": "Synthetic fixture only."}],
               "metrics": {"cvssMetricV31": [{"source": "synthetic@example.org", "type": "Primary",
                            "cvssData": {"version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH",
                                         "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
               "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                   "vulnerable": True, "criteria": "cpe:2.3:a:fixture:fixture:*:*:*:*:*:*:*:*",
                   "versionEndExcluding": "2.0"}]}]}], "references": []}
        def fetch(url):
            self.assertEqual(url, "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve)
            return {"url": url, "content_type": "application/json",
                    "body": json.dumps({"vulnerabilities": [{"cve": nvd}]}).encode()}
        def archive(record, **kwargs):
            return real_ingest(record, fetcher=fetch, **kwargs)
        with patch.object(agent, "assess", side_effect=real_assess), patch.object(agent, "ingest", side_effect=archive):
            result = self.run_agent()
        self.assertTrue(self.db.exists())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["assessment"]["affected_ranges"][0]["versionEndExcluding"], "2.0")
        self.assertEqual(result["assessment"]["cvss"]["source"], "synthetic@example.org")
        self.assertIn("affected_versions", result["trace"]["calls"][0]["resolved_gaps"])
        self.assertTrue(result["assessment"]["affected_ranges"][0]["evidence_ids"])


if __name__ == "__main__":
    unittest.main()
