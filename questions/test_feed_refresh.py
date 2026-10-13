"""Public-feed refresh regressions; no network, model or production data access."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents import orchestrator
from database import store
from enrichment.service import apply_public_feeds, merge_feed
from models import enriched_record


class FeedRefreshTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.cve = "CVE-2024-37032"
        for key, path in {"DATA": self.root, "DB_PATH": self.root / "knowledge.sqlite3", "KB_PATH": self.root / "knowledge.json",
                          "CARDS_PATH": self.root / "cards.json", "CARDS_JS_PATH": self.root / "cards.js",
                          "RUNS_PATH": self.root / "runs.json"}.items():
            patcher = patch.object(store, key, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        environment = patch.dict(os.environ, {"MAIN_KB_DB_PATH": str(store.DB_PATH), "MAIN_IMPORT_DEMO_CARDS": "0"})
        environment.start()
        self.addCleanup(environment.stop)
        self.time = "2026-10-12T01:00:00+00:00"
        self.epss_payload = {"data": [{"cve": self.cve, "epss": "0.77", "percentile": "0.99", "date": "2026-10-11"}]}
        self.kev_payload = {"dateReleased": "2026-10-10T12:00:00Z", "vulnerabilities": [
            {"cveID": self.cve, "dateAdded": "2026-10-09", "vulnerabilityName": "Offline fixture"}]}

    def record(self, epss=None, kev=None):
        return enriched_record({"item": {"cve_id": self.cve, "title": "Offline fixture", "published_at": "2024-01-01"},
                                "epss": epss, "kev": kev})

    def refresh(self, *, failure=False):
        responses = RuntimeError("offline failed query") if failure else [copy.deepcopy(self.epss_payload), copy.deepcopy(self.kev_payload)]
        with patch("enrichment.service._get_json", side_effect=responses), patch("enrichment.service._now", return_value=self.time), \
                patch("agents.orchestrator.fetch_papers", return_value=({}, None)), \
                patch("agents.orchestrator._documents_step", return_value=([], [])):
            return orchestrator.run_enrich()["records"][0]

    def test_real_enrich_upsert_path_replaces_old_errors_and_old_successes(self):
        for number, old_epss in enumerate(({"status": "error"}, {"status": "empty"}, {"status": "ok", "score": "0.10"})):
            with self.subTest(old_epss=old_epss), patch.dict(os.environ, {"MAIN_KB_DB_PATH": str(self.root / ("case-%d.sqlite3" % number))}):
                original = self.record(old_epss, {"status": "not_listed"})
                expected_original = copy.deepcopy(original)
                store.save_kb([original])
                result = self.refresh()
                self.assertEqual(result["epss"]["score"], "0.77")
                self.assertEqual(result["kev"]["status"], "listed")
                self.assertEqual(result["epss"]["source_date"], "2026-10-11")
                self.assertEqual(result["kev"]["source_date"], self.kev_payload["dateReleased"])
                self.assertEqual(result["kev"]["date_added"], "2026-10-09")
                self.assertEqual(result["epss"]["queried_at"], self.time)
                self.assertEqual(result["item"]["published_at"], "2024-01-01")
                self.assertEqual(original, expected_original)
                self.assertEqual(store.load_kb()[0]["epss"], result["epss"])

    def test_failure_preserves_last_success_and_records_separate_attempt(self):
        store.save_kb([self.record()])
        good = self.refresh()
        self.time = "2026-10-12T02:00:00+00:00"
        failed = self.refresh(failure=True)
        for key in ("epss", "kev"):
            self.assertEqual(failed[key]["status"], good[key]["status"])
            self.assertEqual(failed[key]["queried_at"], good[key]["queried_at"])
            self.assertEqual(failed[key]["source_date"], good[key]["source_date"])
            self.assertEqual(failed[key]["last_success_at"], good[key]["last_success_at"])
            self.assertEqual(failed[key]["latest_attempt"]["status"], "error")
            self.assertEqual(failed[key]["latest_attempt"]["queried_at"], self.time)
            self.assertTrue(failed[key]["retained_previous"])
        self.time = "2026-10-12T03:00:00+00:00"
        recovered = self.refresh()
        self.assertFalse(recovered["epss"]["retained_previous"])
        self.assertEqual(recovered["epss"]["latest_attempt"]["status"], "ok")

    def test_first_failure_has_no_invented_last_success_or_source_date(self):
        records = [self.record()]
        with patch("enrichment.service._get_json", side_effect=RuntimeError("offline")):
            apply_public_feeds(records)
        self.assertEqual(records[0]["epss"]["status"], "error")
        self.assertNotIn("last_success_at", records[0]["epss"])
        self.assertNotIn("source_date", records[0]["epss"])

    def test_successful_empty_query_replaces_previous_observation(self):
        store.save_kb([self.record({"status": "ok", "score": "0.10"}, {"status": "listed"})])
        self.epss_payload["data"] = []
        self.kev_payload["vulnerabilities"] = []
        result = self.refresh()
        self.assertEqual(result["epss"]["status"], "empty")
        self.assertNotIn("score", result["epss"])
        self.assertEqual(result["kev"]["status"], "not_listed")
        self.assertEqual(result["kev"]["source_date"], self.kev_payload["dateReleased"])
        self.assertEqual(result["epss"]["latest_attempt"]["status"], "ok")

    def test_older_query_does_not_replace_newer_result_and_inputs_are_immutable(self):
        old = {"status": "ok", "score": "0.77", "queried_at": "2026-10-12T03:00:00+00:00"}
        new = {"status": "ok", "score": "0.10", "queried_at": "2026-10-12T01:00:00+00:00"}
        snapshots = copy.deepcopy((old, new))
        self.assertEqual(merge_feed(old, new), old)
        self.assertEqual((old, new), snapshots)
        self.assertEqual(merge_feed(old, None), old)

    def test_stale_snapshot_failure_keeps_newer_committed_observations(self):
        first_time = "2026-10-12T01:00:00+00:00"
        fresh_time = "2026-10-12T02:00:00+00:00"
        failed_time = "2026-10-12T03:00:00+00:00"
        store.save_kb([self.record(
            {"status": "ok", "score": "0.10", "queried_at": first_time, "last_success_at": first_time},
            {"status": "listed", "queried_at": first_time, "last_success_at": first_time})])
        stale = store.load_kb()[0]
        store.upsert([self.record(
            {"status": "ok", "score": "0.77", "queried_at": fresh_time, "last_success_at": fresh_time},
            {"status": "not_listed", "queried_at": fresh_time, "last_success_at": fresh_time})])
        for field in ("epss", "kev"):
            stale[field] = merge_feed(stale[field], {"status": "error", "queried_at": failed_time})
        store.upsert([stale])
        current = store.load_kb()[0]
        self.assertEqual(current["epss"]["score"], "0.77")
        self.assertEqual(current["kev"]["status"], "not_listed")
        for field in ("epss", "kev"):
            self.assertEqual(current[field]["queried_at"], fresh_time)
            self.assertEqual(current[field]["last_success_at"], fresh_time)
            self.assertEqual(current[field]["latest_attempt"], {"status": "error", "queried_at": failed_time})
            self.assertTrue(current[field]["retained_previous"])

    def test_stale_success_cannot_replace_a_newer_committed_feed_result(self):
        newest = {"status": "ok", "score": "0.77", "queried_at": "2026-10-12T03:00:00+00:00"}
        store.save_kb([self.record(newest, {"status": "not_listed", "queried_at": newest["queried_at"]})])
        store.upsert([self.record(
            {"status": "ok", "score": "0.10", "queried_at": "2026-10-12T01:00:00+00:00"},
            {"status": "listed", "queried_at": "2026-10-12T01:00:00+00:00"})])
        current = store.load_kb()[0]
        self.assertEqual(current["epss"], newest)
        self.assertEqual(current["kev"]["status"], "not_listed")


if __name__ == "__main__":
    unittest.main()
