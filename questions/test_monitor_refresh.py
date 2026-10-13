"""Monitor/UI contracts stay aligned with durable B synchronization."""
import importlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from automation import pipeline, schedule


class MonitorRefreshTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {
            "AUTO_MONITOR_ENABLED": "0", "B_MONITOR_ENABLED": "0",
            "ACTIONS_SYNC_ON_START": "0", "AUTO_INGEST_ON_COLLECT": "0",
        }))
        self.enterContext(patch.object(schedule, "STATE_PATH", self.root / "monitor.json"))
        self.api = importlib.import_module("api.app")
        self.enterContext(patch.object(self.api, "start_schedule"))
        self.enterContext(patch("api.actions_ingest.maybe_pull_on_startup", return_value=None))
        self.enterContext(patch.object(self.api, "_team_reachable_probe", return_value={"reachable": True}))
        self.result = {
            "records": [], "fetched": 10, "steps": [], "status": "success",
            "source_results": [{"source": "B", "status": "success", "fetched": 10}],
            "round_stats": {"hit": 10, "kept": 10, "inserted": 2, "merged": 3,
                            "external_fetches": 0},
        }

        def collect(keyword, *, on_phase=None):
            on_phase("monitoring", status="ok")
            on_phase("persist", status="ok")
            return self.result

        self.collect = self.enterContext(patch.object(self.api, "run_collect", side_effect=collect))
        self.sync = self.enterContext(patch("rag.library.sync_team_drain", return_value={
            "status": "ok", "attempted": 7, "ok": 7,
        }))
        self.public = self.enterContext(patch("rag.library.sync"))
        self.client = self.enterContext(TestClient(self.api.app))

    def test_inserted_count_is_distinct_from_received_and_total(self):
        response = self.client.post("/api/monitor/run", json={})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["count"], body["fetched"], body["kb_total"]), (2, 10, 0))
        self.assertEqual(body["pipeline"]["status"], "done")
        self.assertEqual(self.client.get("/api/monitor/status?light=1").json()["last_count"], 2)
        self.sync.assert_called_once()
        self.public.assert_not_called()

    def test_manual_refresh_respects_scheduler_cycle_lock(self):
        before = schedule.state()
        with schedule._RUN_LOCK:
            response = self.client.post("/api/monitor/run", json={})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(schedule.state(), before)
        self.collect.assert_not_called()

    def test_partial_document_sync_remains_visible_as_partial(self):
        self.sync.return_value = {"status": "partial", "attempted": 7, "ok": 3}
        body = self.client.post("/api/monitor/run", json={}).json()
        self.assertEqual(body["status"], "partial")
        self.assertEqual(body["pipeline"]["status"], "error")
        library_stage = next(stage for stage in body["pipeline"]["stages"]
                             if stage["id"] == "library_sync")
        self.assertEqual(library_stage["status"], "error")
        self.assertEqual(schedule.state()["last_status"], "partial")

    def test_failed_sync_finishes_progress_and_releases_cycle_lock(self):
        self.collect.side_effect = ConnectionError("B unavailable")
        response = self.client.post("/api/monitor/run", json={})
        self.assertEqual(response.status_code, 502)
        self.assertFalse(schedule.state()["running"])
        self.assertEqual(schedule.state()["last_status"], "failed")
        self.assertEqual(pipeline.get_pipeline()["status"], "error")
        self.assertFalse(any(stage["status"] in {"pending", "running"}
                             for stage in pipeline.get_pipeline()["stages"]))
        self.assertTrue(schedule._RUN_LOCK.acquire(blocking=False))
        schedule._RUN_LOCK.release()

    def test_legacy_collect_uses_same_statistics_without_public_fetch(self):
        response = self.client.post("/api/collect", json={"keyword": "llm"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["count"], 2)
        self.sync.assert_not_called()
        self.public.assert_not_called()

    def test_offline_status_never_advertises_scheduled_network_collection(self):
        with patch.dict(os.environ, {"OFFLINE_DEMO": "1", "AUTO_MONITOR_ENABLED": "1"}):
            schedule.mark_run(count=0)
            response = self.client.get("/api/monitor/status?light=1").json()
        self.assertTrue(response["offline_demo"])
        self.assertFalse(response["automatic_enabled"])
        self.assertEqual(response["next_run"], "")

    def test_diverse_document_feed_respects_sidecar_page_size_contract(self):
        def open_page(url, timeout):
            limit = int(parse_qs(urlsplit(url).query)["limit"][0])
            self.assertLessEqual(limit, 100)
            return io.BytesIO(json.dumps({"items": [{"title": "A document"}], "total": 1}).encode())

        with patch("api.b_embed.embed_enabled", return_value=False), \
             patch("collectors.intelligence.team_base_url", return_value="http://127.0.0.1:8765"), \
             patch("urllib.request.urlopen", side_effect=open_page):
            rows, metadata = self.api._fetch_team_documents(limit=48)
        self.assertTrue(metadata["reachable"], metadata)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
