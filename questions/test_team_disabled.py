"""Disabling B skips default adapters without querying or changing stored data."""
from contextlib import ExitStack
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from automation import schedule
from collectors.team_documents import TeamDocumentCollector
from database import store
from questions.test_team_documents import FixtureCollector, record
from rag.library import documents, sync_team


class TeamDisabledTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.db = self.root / "library.sqlite3"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {"TEAM_INTEL_MODE": "off"}))
        self.stack.enter_context(patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected live network")))
        self.stack.enter_context(patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected live network")))
        self.stack.enter_context(patch.object(schedule, "STATE_PATH", self.root / "monitor.json"))
        self.stack.enter_context(patch.object(schedule, "LOG_PATH", self.root / "collect.log"))
        for name, path in (("DATA", self.root), ("KB_PATH", self.root / "knowledge.json"),
                           ("CARDS_PATH", self.root / "cards.json"), ("CARDS_JS_PATH", self.root / "cards.js"),
                           ("RUNS_PATH", self.root / "runs.json")):
            self.stack.enter_context(patch.object(store, name, path))
        self.api = importlib.import_module("api.app")

    def test_disabled_health_snapshot_and_feed_do_not_query_b(self):
        with patch("api.b_embed.inprocess_health") as health, patch("api.b_embed.list_documents_page") as documents_page:
            for mode in ("off", "disabled", "0", "false", "no"):
                with self.subTest(mode=mode), patch.dict(os.environ, {"TEAM_INTEL_MODE": mode}):
                    views = [self.api._team_intel_snapshot(), self.api._team_reachable_probe()]
                    docs, meta = self.api._fetch_team_documents()
                    self.assertEqual(docs, [])
                    for value in views + [meta]:
                        self.assertEqual(value["mode"], "off")
                        self.assertEqual(value["status"], "skipped")
                        self.assertIs(value["enabled"], False)
                        self.assertFalse(value["reachable"])
                        self.assertNotIn("error", value)
            health.assert_not_called()
            documents_page.assert_not_called()

    def test_overview_visibility_labels_disabled_team_without_fault(self):
        with patch.object(self.api, "knowledge_records", return_value=[]), \
                patch.object(self.api, "configured", return_value=False), \
                patch.object(self.api, "last_steps", return_value=[]), \
                patch("rag.library.overview", return_value={"documents": 0, "chunks": 0, "source_categories": []}):
            result = TestClient(self.api.app).get("/api/overview")
        self.assertEqual(result.status_code, 200)
        data = result.json()
        self.assertIs(data["team_intel"]["enabled"], False)
        self.assertNotIn("error", data["team_intel"])
        peers = [peer for module in data["visibility"]["modules"]
                 for peer in module["integration"]["peers"] if peer["party"] == "B"]
        self.assertTrue(peers)
        self.assertTrue(all(peer["status"] != "不可达" for peer in peers))

    def test_light_or_running_status_preserves_known_disabled_mode(self):
        with patch("api.b_embed.inprocess_health") as health:
            for running in (False, True):
                for light in (0, 1):
                    with self.subTest(running=running, light=light), \
                            patch.object(self.api, "monitor_state", return_value={"running": running}):
                        response = TestClient(self.api.app).get("/api/monitor/status?light=%d" % light)
                    self.assertEqual(response.status_code, 200)
                    team = response.json()["team"]
                    self.assertEqual(team["mode"], "off")
                    self.assertEqual(team["status"], "skipped")
                    self.assertIs(team["enabled"], False)
                    self.assertFalse(team["reachable"])
                    self.assertNotIn("error", team)
            health.assert_not_called()

    def test_manual_cycle_keeps_configured_skip_separate_from_failure(self):
        collected = {"status": "success", "error": "", "warnings": [], "records": [],
                     "steps": [{"role": "监测", "action": "跳过 本机库", "detail": "Disabled by configuration"}],
                     "source_outcomes": {"nvd": "success", "osv": "success", "aggregate": "skipped"},
                     "round_stats": {"hit": 0, "kept": 0, "inserted": 0, "merged": 0}}
        with patch.object(self.api, "run_collect", return_value=collected), \
                patch("rag.library.sync", return_value={"attempted": 0, "ok": 0, "sources": []}) as public, \
                patch("rag.library.sync_team") as team, patch("api.b_monitor.run_b_monitor_cycle") as cycle:
            response = TestClient(self.api.app).post("/api/monitor/run", json={"sync_library": True})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["warnings"], [])
        self.assertEqual(data["library_sync"]["status"], "success")
        self.assertEqual(data["library_sync"]["team"], {"status": "skipped", "enabled": False})
        self.assertEqual(data["source_diag"]["b_team"]["status"], "跳过")
        self.assertEqual(schedule.state()["last_status"], "success")
        public.assert_called_once()
        team.assert_not_called()
        cycle.assert_not_called()

    def test_skipped_default_sync_keeps_existing_library_byte_for_byte(self):
        initial = sync_team(self.db, collector=FixtureCollector([record()]))
        self.assertEqual(initial["ok"], 1)
        before_docs, before = documents(self.db), self.db.read_bytes()
        with patch("collectors.team_documents.TeamDocumentCollector") as constructor, \
                patch("rag.library._record_source") as publish:
            result = sync_team(self.db)
        self.assertEqual(result["status"], "skipped")
        self.assertIs(result["enabled"], False)
        self.assertEqual((result["attempted"], result["ok"], result["changed"]), (0, 0, 0))
        self.assertNotIn("error", result)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(documents(self.db), before_docs)
        constructor.assert_not_called()
        publish.assert_not_called()

    def test_skip_does_not_create_library_or_accept_invalid_window(self):
        self.assertEqual(sync_team(self.db)["status"], "skipped")
        self.assertFalse(self.db.exists())
        with self.assertRaises(ValueError):
            sync_team(self.db, max_documents=201)

    def test_default_document_collector_skips_without_any_adapter(self):
        for mode in ("off", "disabled", "0", "false", "no"):
            with self.subTest(mode=mode), patch.dict(os.environ, {"TEAM_INTEL_MODE": mode}), \
                    patch.object(TeamDocumentCollector, "get") as get, \
                    patch.object(TeamDocumentCollector, "_collect_embed") as embed:
                value = TeamDocumentCollector().collect()
                self.assertEqual(value["status"], "skipped")
                self.assertIs(value["enabled"], False)
                self.assertIsNone(value["total"])
                get.assert_not_called()
                embed.assert_not_called()

    def test_explicit_base_and_injected_collector_remain_valid_overrides(self):
        collector = TeamDocumentCollector(base_url="http://127.0.0.1:8765")
        self.assertFalse(collector.disabled)
        self.assertFalse(collector.embed)
        with patch.object(collector, "get", return_value={"body": json.dumps({"total": 0, "items": []}).encode()}) as get:
            self.assertEqual(collector.collect()["selected"], 0)
            get.assert_called_once()
        batch = {"candidates": [], "errors": [], "total": 0, "selected": 0, "remaining": 0, "coverage": "Synthetic fixture"}
        with patch.object(TeamDocumentCollector, "collect", return_value=batch) as collect:
            result = sync_team(self.db, base_url="http://127.0.0.1:8765")
            self.assertEqual(result["status"], "ok")
            collect.assert_called_once()
        injected = Mock()
        injected.base_url = "http://127.0.0.1:8765"
        injected.collect.return_value = batch
        result = sync_team(self.db, collector=injected)
        self.assertEqual(result["status"], "ok")
        injected.collect.assert_called_once()

    def test_configured_library_skip_is_neither_successful_source_nor_degradation(self):
        skipped = sync_team(self.db)
        self.assertEqual(schedule.library_outcome(skipped), "skipped")
        result = {"status": "success", "warnings": [], "source_outcomes": {"nvd": "success", "aggregate": "skipped"}}
        outcome = schedule.combine_monitor_outcome(result, libraries=(("本机库资料同步", skipped),))
        self.assertEqual(outcome["status"], "success")
        self.assertEqual(outcome["warnings"], [])
        failed = schedule.combine_monitor_outcome(dict(result, status="failed", error="External source failed"),
                                                  libraries=(("本机库资料同步", skipped),))
        self.assertEqual(failed["status"], "failed")


if __name__ == "__main__":
    unittest.main()
