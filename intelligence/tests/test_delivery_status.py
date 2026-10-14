"""Deployment facts bind the API's actual database to a sanitized generation."""
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from ai_pipeline.documents import DocumentClassificationStore
from ai_pipeline.store import ClassificationStore
from api_v6.app import create_app
from deployment.actions_state import save_state
from deployment.delivery_status import deployment_delivery
from deployment.snapshot_contract import runtime_classifier_version
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class DeliveryStatusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        database = self.source / "intelligence.db"
        SQLiteIntelligenceStore(database)
        SQLiteDocumentStore(database)
        ClassificationStore(database)
        DocumentClassificationStore(database)
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("CREATE TABLE source_observation_baselines(source TEXT PRIMARY KEY,started_at TEXT)")
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": "2026-10-04T00:00:00Z"}))
        self.mirror = self.root / "mirror"
        self.generation = self.mirror / "snapshots/42"
        save_state(self.source, self.generation, repository="team/public-repo", branch="main", run_id=42,
                   workflow="intelligence-collect.yml", collector_commit="a" * 40, run_number=7)
        self.database = self.generation / "intelligence.db"

    def publish_current(self):
        try:
            (self.mirror / "current").symlink_to("snapshots/42", target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and exc.winerror == 1314:
                self.skipTest("Windows directory symlink privilege is not available")
            raise
        self.database = self.mirror / "current/intelligence.db"

    def facts(self):
        return deployment_delivery(self.database, classifier_version=runtime_classifier_version(), now=NOW)

    def test_api_serves_actual_current_generation_and_both_feed_contracts(self):
        self.publish_current()
        self.assert_api_generation()

    def test_api_serves_standalone_generation_and_both_feed_contracts(self):
        self.assert_api_generation()

    def assert_api_generation(self):
        facts = self.facts()
        self.assertEqual(facts["status"], "serving_verified_generation")
        self.assertEqual(facts["generation"]["run_id"], 42)
        self.assertTrue(facts["database_available"])
        self.assertTrue(facts["compatibility"]["ready"])
        self.assertEqual(facts["changefeed"]["through"], 0)
        self.assertEqual(facts["consumer_status"], "unverified")
        self.assertEqual(facts["poller_observation"], "not_observed")
        app = create_app(root=ROOT, db_path=self.database)
        with closing(TestClient(app)) as client:
            response = client.get("/api/intelligence/delivery")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["generation"], facts["generation"])

    def test_old_classifier_or_missing_feed_is_incompatible_even_with_ready_manifest(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DROP TABLE team_changes")
        facts = self.facts()
        self.assertEqual(facts["status"], "incompatible")
        self.assertFalse(facts["compatibility"]["ready"])
        self.assertIn("missing_schema:team_changes", facts["compatibility"]["problems"])

    def test_poll_ready_must_match_current_generation_and_recent_time(self):
        # This tests status/manifest binding. Atomic symlink publication is covered
        # separately; an ordinary directory exercises the same status inputs.
        shutil.copytree(self.generation, self.mirror / "current")
        self.database = self.mirror / "current/intelligence.db"
        path = self.mirror / "mirror_status.json"
        poll = {"status": "ready", "run_id": 42, "collector_commit": "a" * 40,
                "checked_at": NOW.isoformat(), "poll_interval_seconds": 60,
                "secret": "fixture-secret-do-not-export"}
        path.write_text(json.dumps(poll))
        self.assertEqual(self.facts()["poller_observation"], "ready")
        poll["run_id"] = 41
        path.write_text(json.dumps(poll))
        self.assertEqual(self.facts()["poller_observation"], "generation_mismatch")
        poll["checked_at"] = (NOW - timedelta(minutes=10)).isoformat()
        path.write_text(json.dumps(poll))
        self.assertEqual(self.facts()["poller_observation"], "stale")
        self.assertNotIn("fixture-secret", json.dumps(self.facts()))

    def test_missing_generation_stays_unverified_and_never_creates_database(self):
        absent = self.root / "absent/intelligence.db"
        facts = deployment_delivery(absent, classifier_version=runtime_classifier_version())
        self.assertEqual(facts["status"], "unverified")
        self.assertFalse(absent.exists())

    def test_forged_generation_manifest_stays_unverified_and_sanitized(self):
        manifest = self.generation / "manifest.json"
        old = json.loads(manifest.read_text())
        old["collector_commit"] = "fixture-secret-do-not-export"
        manifest.write_text(json.dumps(old))
        self.assertEqual(self.facts()["status"], "unverified")
        self.assertNotIn("fixture-secret", json.dumps(self.facts()))


if __name__ == "__main__":
    unittest.main()
