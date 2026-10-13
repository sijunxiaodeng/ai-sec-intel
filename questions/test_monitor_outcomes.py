"""Source outages remain visible without clearing data or stopping library sync."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from agents import orchestrator
from api.app import app
from automation import schedule
from models import enriched_record, intelligence_item
from rag.library import sync_team as actual_sync_team, sync_team_drain as actual_sync_team_drain


def record(number):
    return enriched_record(intelligence_item({"cve_id": "CVE-2026-%04d" % number,
        "title": "Synthetic AI component issue", "description": "Known stored evidence", "source": "OSV", "product": "vllm"}))


def monitor_result(*, nvd="skipped", osv="failed", aggregate="failed", items=None):
    labels = {"nvd": "NVD", "osv": "OSV", "aggregate": "多源情报"}
    states = {"nvd": nvd, "osv": osv, "aggregate": aggregate}
    steps = [{"role": "监测", "action": "调用 " + labels[name] + (" 失败" if state == "failed" else ""),
              "detail": "Synthetic source result"} for name, state in states.items()]
    return {"items": items or [], "steps": steps, "collectors": {}, "stats": {
        "nvd_ok": nvd != "failed", "nvd_disabled_duplicate": nvd == "skipped",
        "osv_ok": osv != "failed", "aggregate_ok": aggregate != "failed",
        "hit": len(items or []), "kept": len(items or []), "nvd": {}, "osv": {}, "external_fetches": 0}}


EMPTY_LIBRARY = {"attempted": 0, "ok": 0, "sources": []}


class OutcomeFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(temp.name)
        self.stack.enter_context(patch.object(schedule, "STATE_PATH", root / "monitor.json"))
        self.stack.enter_context(patch.object(schedule, "LOG_PATH", root / "collect.log"))
        self.stack.enter_context(patch("api.b_monitor.b_monitor_on_refresh", return_value=False))
        self.team_sync = self.stack.enter_context(patch("rag.library.sync_team_drain", return_value={"status": "ok", **EMPTY_LIBRARY}))
        self.stack.enter_context(patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected live network")))
        self.stack.enter_context(patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected live network")))
        self.old = [record(6101)]
        self.stack.enter_context(patch("agents.orchestrator.load_kb", return_value=self.old))
        self.stack.enter_context(patch("agents.orchestrator.append_run"))
        self.stack.enter_context(patch("agents.orchestrator._documents_step", return_value=([], [])))
        self.client = TestClient(app)

    def source_patches(self, monitored):
        self.stack.enter_context(patch("agents.orchestrator.monitor_run", return_value=monitored))
        rows = [enriched_record(item) for item in monitored["items"]]
        enrich = self.stack.enter_context(patch("agents.orchestrator.enrich_run", return_value={"records": rows, "steps": []}))
        write = {"records": self.old + rows, "fetched": len(rows), "inserted": len(rows), "merged": 0, "total": len(self.old + rows)}
        upsert = self.stack.enter_context(patch("agents.orchestrator.upsert_stats", return_value=write))
        return enrich, upsert

    def api_patches(self, library=None):
        self.stack.enter_context(patch("api.app._team_reachable_probe", return_value={"reachable": True}))
        public = self.stack.enter_context(patch("rag.library.sync", return_value=library or EMPTY_LIBRARY))
        team = self.stack.enter_context(patch("rag.library.sync_team_drain", return_value={"status": "ok", **EMPTY_LIBRARY}))
        return public, team


class OrchestratorOutcomeTest(OutcomeFixture):
    def test_disabled_nvd_does_not_turn_all_remaining_failures_into_success(self):
        monitored = monitor_result()
        collector = Mock()
        monitored["collectors"] = {"osv": collector}
        enrich, upsert = self.source_patches(monitored)
        phases = []
        result = orchestrator.run_collect(on_phase=lambda stage, **fields: phases.append((stage, fields)))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["source_outcomes"]["nvd"], "skipped")
        self.assertTrue(result["error"])
        self.assertEqual(result["records"], self.old)
        self.assertEqual(result["round_stats"]["inserted"], 0)
        enrich.assert_not_called()
        upsert.assert_not_called()
        collector.commit_cursor.assert_not_called()
        self.assertTrue(any(s == "monitoring" and f["status"] == "error" for s, f in phases))
        self.assertTrue(any(s == "persist" and f["status"] == "skip" for s, f in phases))

    def test_valid_empty_poll_is_success_and_may_confirm_empty_source(self):
        monitored = monitor_result(osv="success", aggregate="success")
        collector = Mock()
        monitored["collectors"] = {"osv": collector}
        _, upsert = self.source_patches(monitored)
        result = orchestrator.run_collect()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["error"], "")
        self.assertEqual(result["records"], self.old)
        upsert.assert_called_once_with([])
        collector.commit_cursor.assert_called_once()

    def test_partial_sources_keep_successful_records_and_confirm_their_cursor(self):
        monitored = monitor_result(osv="success", items=[intelligence_item({"cve_id": "CVE-2026-6102", "source": "OSV"})])
        collector = Mock()
        monitored["collectors"] = {"osv": collector}
        self.source_patches(monitored)
        result = orchestrator.run_collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["round_stats"]["inserted"], 1)
        self.assertIn("多源情报", result["error"])
        collector.commit_cursor.assert_called_once()

    def test_partial_package_failure_and_cursor_write_failure_are_visible(self):
        monitored = monitor_result(osv="success", aggregate="success")
        monitored["stats"]["osv"] = {"packages_failed": 1}
        collector = Mock()
        collector.commit_cursor.side_effect = OSError("Synthetic state disk failure")
        monitored["collectors"] = {"osv": collector}
        self.source_patches(monitored)
        result = orchestrator.run_collect()
        self.assertEqual(result["status"], "partial")
        self.assertIn("部分包", result["error"])
        self.assertIn("位点未保存", result["error"])


class ManualOutcomeTest(OutcomeFixture):
    def test_failed_refresh_returns_explicit_failure_keeps_dashboard_and_syncs_library(self):
        self.source_patches(monitor_result())
        public, team = self.api_patches()
        response = self.client.post("/api/monitor/run", json={"sync_library": True})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "failed")
        self.assertTrue(data["error"])
        self.assertEqual(data["pipeline"]["status"], "error")
        self.assertEqual(data["source_diag"]["nvd"]["status"], "跳过")
        self.assertEqual([row["cve_id"] for row in data["items"]], ["CVE-2026-6101"])
        public.assert_not_called()
        team.assert_called_once()
        status = self.client.get("/api/monitor/status?light=1").json()
        self.assertEqual(status["last_status"], "failed")
        self.assertTrue(status["last_error"])
        self.assertFalse(status["running"])
        with patch("api.app.knowledge_records", return_value=self.old), \
                patch("api.app._team_intel_snapshot", return_value={"reachable": False}), \
                patch("rag.library.overview", return_value={"documents": 0, "chunks": 0, "source_categories": []}), \
                patch("api.app.configured", return_value=False), patch("api.app.last_steps", return_value=[]):
            self.assertEqual(self.client.get("/api/overview").status_code, 200)

    def test_empty_success_clears_previous_error_and_finishes_normally(self):
        schedule.mark_run(status="failed", error="Previous failure")
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        self.api_patches()
        response = self.client.post("/api/monitor/run", json={"sync_library": False})
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["pipeline"]["status"], "done")
        status = self.client.get("/api/monitor/status?light=1").json()
        self.assertEqual(status["last_status"], "success")
        self.assertEqual(status["last_error"], "")

    def test_partial_refresh_retains_visible_degradation(self):
        self.source_patches(monitor_result(osv="success"))
        self.api_patches()
        data = self.client.post("/api/monitor/run", json={"sync_library": True}).json()
        self.assertEqual(data["status"], "partial")
        self.assertTrue(data["warnings"])
        self.assertEqual(data["pipeline"]["status"], "partial")
        self.assertEqual(schedule.state()["last_status"], "partial")
        self.assertIn("多源情报", schedule.state()["last_error"])

    def test_collection_exception_still_runs_documents_and_returns_no_500(self):
        self.stack.enter_context(patch("api.app.run_collect", side_effect=TimeoutError("Synthetic outage")))
        self.stack.enter_context(patch("api.app.knowledge_records", return_value=self.old))
        public, team = self.api_patches()
        response = self.client.post("/api/monitor/run", json={"sync_library": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "failed")
        self.assertIn("TimeoutError", response.json()["error"])
        public.assert_not_called()
        team.assert_called_once()

    def test_document_failures_without_exception_do_not_look_like_empty_success(self):
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        library = {"status": "partial", "attempted": 1, "ok": 0, "sources": [{"source_id": "blog", "status": "error"}]}
        public, team = self.api_patches()
        team.return_value = library
        data = self.client.post("/api/monitor/run", json={"sync_library": True}).json()
        self.assertEqual(data["status"], "partial")
        self.assertIn("资料摘要同步", data["error"])
        public.assert_not_called()
        team.assert_called_once()
        self.assertEqual(data["library_sync"]["status"], "partial")

    def test_failed_b_and_osv_cannot_be_rescued_by_reading_cached_team_records(self):
        self.source_patches(monitor_result(aggregate="success"))
        self.api_patches()
        with patch("api.b_monitor.b_monitor_on_refresh", return_value=True), \
                patch("api.b_embed.embed_enabled", return_value=True), \
                patch("api.b_monitor.run_b_monitor_cycle", return_value={"status": "failed"}):
            data = self.client.post("/api/monitor/run", json={"sync_library": True}).json()
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["pipeline"]["status"], "error")
        self.assertTrue(any("读取缓存" in warning for warning in data["warnings"]))


class ScheduledOutcomeTest(OutcomeFixture):
    def test_all_failed_scheduled_run_keeps_error_and_still_syncs_documents(self):
        self.source_patches(monitor_result())
        with patch("rag.library.sync", return_value=EMPTY_LIBRARY) as library:
            state = schedule.run_once("llm")
        self.assertEqual(state["last_status"], "failed")
        self.assertTrue(state["last_error"])
        self.assertFalse(state["running"])
        self.assertEqual(state["pipeline"]["status"], "error")
        library.assert_not_called()
        self.team_sync.assert_called_once_with(max_documents=200)

    def test_scheduled_empty_success_clears_error_and_partial_is_separate(self):
        schedule.mark_run(status="failed", error="Old source outage")
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        with patch("rag.library.sync", return_value=EMPTY_LIBRARY):
            success = schedule.run_once()
        self.assertEqual(success["last_status"], "success")
        self.assertEqual(success["last_error"], "")
        self.team_sync.return_value = {"status": "partial", "attempted": 1, "ok": 0}
        with patch("rag.library.sync") as public:
            degraded = schedule.run_once()
        public.assert_not_called()
        self.assertEqual(degraded["last_status"], "partial")
        self.assertEqual(degraded["pipeline"]["status"], "partial")
        self.assertIn("资料摘要同步", degraded["last_error"])

    def test_scheduled_exception_records_failure_after_independent_sync(self):
        self.stack.enter_context(patch("agents.orchestrator.run_collect", side_effect=TimeoutError("Synthetic outage")))
        with patch("rag.library.sync", return_value=EMPTY_LIBRARY) as library:
            with self.assertRaises(TimeoutError):
                schedule.run_once()
        library.assert_not_called()
        self.team_sync.assert_called_once_with(max_documents=200)
        self.assertEqual(schedule.state()["last_status"], "failed")
        self.assertIn("TimeoutError", schedule.state()["last_error"])
        self.assertFalse(schedule._RUN_LOCK.locked())

    def test_b_refresh_failure_is_not_hidden_by_reading_cached_records(self):
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        with patch("api.b_monitor.b_monitor_on_refresh", return_value=True), \
                patch("api.b_embed.embed_enabled", return_value=True), \
                patch("api.b_monitor.run_b_monitor_cycle", return_value={"status": "failed"}), \
                patch("rag.library.sync", return_value=EMPTY_LIBRARY):
            state = schedule.run_once()
        self.assertEqual(state["last_status"], "partial")
        self.assertIn("来源刷新", state["last_error"])

    def test_scheduled_round_drains_latest_team_summaries_without_public_fetch(self):
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        self.team_sync.return_value = {"status": "ok", "attempted": 3, "ok": 3}
        with patch("rag.library.sync", return_value={"attempted": 2, "ok": 2, "sources": []}) as public:
            state = schedule.run_once()
        public.assert_not_called()
        self.team_sync.assert_called_once_with(max_documents=200)
        self.assertEqual(state["last_status"], "success")
        self.assertEqual(state["library_last_ok"], 3)
        self.assertNotIn("library_public_last_ok", state)
        self.assertEqual(state["library_team_last_ok"], 3)
        self.assertEqual(state["library_team_last_status"], "success")
        self.assertEqual(state["library_team_last_error"], "")
        self.assertTrue(state["library_team_last_run"])

    def test_independent_public_exception_does_not_stop_team_summary_sync(self):
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        self.team_sync.return_value = {"status": "ok", "attempted": 1, "ok": 1}
        with patch("rag.library.sync", side_effect=ConnectionError("Synthetic public source outage")) as public:
            public_state = schedule.run_public_once()
            state = schedule.run_once()
        public.assert_called_once_with(include_seeds=False)
        self.team_sync.assert_called_once_with(max_documents=200)
        self.assertEqual(public_state["library_public_last_status"], "failed")
        self.assertEqual(state["last_status"], "success")
        self.assertEqual(state["library_public_last_status"], "failed")
        self.assertEqual(state["library_team_last_status"], "success")
        self.assertEqual(state["library_last_ok"], 1)

    def test_team_exception_keeps_independent_public_results_and_visible_degradation(self):
        self.source_patches(monitor_result(osv="success", aggregate="success"))
        self.team_sync.side_effect = ConnectionError("Synthetic team outage")
        with patch("rag.library.sync", return_value={"attempted": 2, "ok": 2, "sources": []}) as public:
            schedule.run_public_once()
            state = schedule.run_once()
        public.assert_called_once_with(include_seeds=False)
        self.team_sync.assert_called_once_with(max_documents=200)
        self.assertEqual(state["last_status"], "partial")
        self.assertIn("资料摘要同步", state["last_error"])
        self.assertEqual(state["library_team_last_status"], "failed")
        self.assertTrue(state["library_team_last_error"])
        self.assertEqual(state["library_last_ok"], 0)
        self.assertEqual(state["library_public_last_ok"], 2)

    def test_cve_and_public_failures_still_attempt_team_without_clearing_failure(self):
        self.source_patches(monitor_result())
        self.team_sync.return_value = {"status": "ok", "attempted": 1, "ok": 1}
        with patch("rag.library.sync", side_effect=TimeoutError("Synthetic public timeout")) as public:
            schedule.run_public_once()
            state = schedule.run_once()
        public.assert_called_once_with(include_seeds=False)
        self.team_sync.assert_called_once_with(max_documents=200)
        self.assertEqual(state["last_status"], "failed")
        self.assertEqual(state["pipeline"]["status"], "error")
        self.assertEqual(state["library_team_last_status"], "success")

    def test_disabled_team_is_a_configuration_skip_with_no_b_request(self):
        monitored = monitor_result(osv="success", aggregate="skipped")
        monitored["stats"]["aggregate_disabled"] = True
        self.source_patches(monitored)
        with patch.dict("os.environ", {"TEAM_INTEL_MODE": "off"}), \
                patch("rag.library.sync", return_value=EMPTY_LIBRARY) as public, \
                patch("rag.library.sync_team_drain", wraps=actual_sync_team_drain) as team, \
                patch("rag.library.sync_team", wraps=actual_sync_team), \
                patch("collectors.team_documents.TeamDocumentCollector") as adapter:
            state = schedule.run_once()
        public.assert_not_called()
        team.assert_called_once_with(max_documents=200)
        adapter.assert_not_called()
        self.assertEqual(state["last_status"], "success")
        self.assertEqual(state["last_error"], "")
        self.assertEqual(state["library_team_last_status"], "skipped")
        self.assertEqual(state["library_team_last_ok"], 0)
        self.assertEqual(state["library_team_last_error"], "")
        self.assertNotIn("library_team_last_run", state)

    def test_independent_public_sync_reports_partial_source_results(self):
        library = {"attempted": 2, "ok": 1, "sources": [
            {"source_id": "healthy", "status": "ok"},
            {"source_id": "offline", "status": "failed"},
        ]}
        with patch("rag.library.sync", return_value=library):
            state = schedule.run_public_once()
        self.assertEqual(state["library_public_last_status"], "partial")
        self.assertEqual(state["library_public_last_ok"], 1)
        self.assertEqual(state["library_source_errors"], ["offline"])
        self.assertTrue(state["library_public_last_error"])
        self.team_sync.assert_not_called()


if __name__ == "__main__":
    unittest.main()
