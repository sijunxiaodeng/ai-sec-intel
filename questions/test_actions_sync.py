"""Offline Actions delivery contracts; all databases are isolated fixtures."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
INTEL = ROOT / "intelligence"
REPOSITORY = "sijunxiaodeng/ai-sec-intel"
BASELINE = "2026-10-07T00:00:00+00:00"
FIRST_SEEN = "2026-10-08T01:02:03+00:00"
TOKEN = "synthetic-fixture-token-only"


def _load_sync():
    # Keep the main application's collectors.* ahead of intelligence/.
    if str(INTEL) not in sys.path:
        sys.path.append(str(INTEL))
    from deployment.actions_state import save_state
    from deployment import actions_sync
    return save_state, actions_sync


class ActionsSyncInstallTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "mirror"
        self.archive_counter = 0
        with sqlite3.connect(self.source / "intelligence.db") as db:
            db.executescript("""
                CREATE TABLE source_items(source TEXT, source_id TEXT, first_seen_at TEXT);
                CREATE TABLE unified_vulnerabilities(cve_id TEXT, first_seen_at TEXT);
                CREATE TABLE source_observation_baselines(source TEXT, started_at TEXT);
                CREATE TABLE knowledge_documents(document_id TEXT, first_seen_at TEXT);
            """)
            db.execute("INSERT INTO source_items VALUES (?,?,?)", ("NVD", "CVE-2026-10001", FIRST_SEEN))
            db.execute("INSERT INTO unified_vulnerabilities VALUES (?,?)", ("CVE-2026-10001", FIRST_SEEN))
            db.execute("INSERT INTO source_observation_baselines VALUES (?,?)", ("NVD", BASELINE))
            db.execute("INSERT INTO knowledge_documents VALUES (?,?)", ("blog-1", FIRST_SEEN))
        (self.source / "monitoring_baseline.json").write_text(
            json.dumps({"started_at": BASELINE}), encoding="utf-8")
        self.save_state, self.sync = _load_sync()

    def tearDown(self):
        # Published generations intentionally have read-only directory modes.
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.temporary.cleanup()

    def archive(self, run_id=9001, number=1, repository=REPOSITORY):
        self.archive_counter += 1
        snapshot = self.root / ("snapshot-%d" % self.archive_counter)
        self.save_state(self.source, snapshot, repository=repository, branch="main", run_id=run_id,
                        workflow="intelligence-collect.yml", collector_commit="a" * 40, run_number=number)
        return self.sync.zip_directory(snapshot)

    def install(self, payload, run_id=9001):
        return self.sync.install_archive(payload, self.destination, repository=REPOSITORY,
                                         branch="main", run_id=run_id, source="unittest")

    def client(self):
        # Mount only the ingest router; no real application startup/collector.
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from api.actions_ingest import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def environment(self):
        return patch.dict(os.environ, {"ACTIONS_INGEST_TOKEN": TOKEN,
                                       "ACTIONS_SYNC_REPOSITORY": REPOSITORY,
                                       "ACTIONS_SYNC_DIRECTORY": str(self.destination),
                                       "INTELLIGENCE_DB_PATH": str(self.destination / "current/intelligence.db")})

    def headers(self, run_id=9001, repository=REPOSITORY):
        return {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/zip",
                "X-Actions-Repository": repository, "X-Actions-Branch": "main",
                "X-Actions-Run-Id": str(run_id)}

    def test_install_publishes_isolated_generation_and_preserves_unrelated_files(self):
        self.destination.mkdir()
        (self.destination / "keep-me.log").write_text("unrelated", encoding="utf-8")
        marker = self.install(self.archive())
        self.assertTrue(marker["changed"])
        self.assertEqual(marker["run_id"], 9001)
        self.assertTrue((self.destination / "current").is_symlink())
        self.assertEqual((self.destination / "current").resolve(), self.destination / "snapshots/9001")
        self.assertFalse((self.destination / "intelligence.db").exists())
        self.assertTrue((self.destination / "current/intelligence.db").is_file())
        baseline = json.loads((self.destination / "current/monitoring_baseline.json").read_text())
        self.assertEqual(baseline["started_at"], BASELINE)
        self.assertEqual((self.destination / "keep-me.log").read_text(), "unrelated")
        manifest = self.sync.read_sync_marker(self.destination)
        self.assertEqual(manifest["collector_commit"], "a" * 40)
        self.assertEqual(manifest["workflow"], "intelligence-collect.yml")
        self.assertEqual(manifest["run_number"], 1)

    def test_same_archive_is_idempotent_and_old_run_cannot_roll_back_current(self):
        older = self.archive()
        latest = self.archive(run_id=9002, number=2)
        self.assertTrue(self.install(latest, 9002)["changed"])
        current = (self.destination / "current").resolve()
        self.assertFalse(self.install(latest, 9002)["changed"])
        from deployment.actions_state import StateError
        with self.assertRaisesRegex(StateError, "roll back"):
            self.install(older)
        self.assertEqual((self.destination / "current").resolve(), current)
        self.assertEqual(self.sync.read_sync_marker(self.destination)["run_id"], 9002)

    def test_existing_collector_database_is_never_overwritten(self):
        self.destination.mkdir()
        target = self.destination / "intelligence.db"
        original = (self.source / "intelligence.db").read_bytes()
        target.write_bytes(original)
        with self.assertRaisesRegex(RuntimeError, "cannot be overwritten"):
            self.install(self.archive())
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse((self.destination / "current").exists())

    def test_bad_run_id_is_rejected_and_previous_generation_retained(self):
        self.install(self.archive())
        from deployment.actions_state import StateError
        with self.assertRaises(StateError):
            self.install(self.archive(run_id=9002, number=2), run_id=9999)
        self.assertEqual(self.sync.read_sync_marker(self.destination)["run_id"], 9001)

    def test_api_requires_authorization_before_reading_or_installing_body(self):
        with self.environment(), self.client() as client:
            with patch("api.actions_ingest._sync_module") as load:
                response = client.post("/api/admin/actions-sync", content=b"not a zip",
                                       headers={"X-Actions-Repository": REPOSITORY, "X-Actions-Run-Id": "9001"})
                self.assertEqual(response.status_code, 401)
                wrong = dict(self.headers(), Authorization="Bearer incorrect-fixture-token")
                self.assertEqual(client.post("/api/admin/actions-sync", content=b"not a zip",
                                             headers=wrong).status_code, 403)
                load.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_api_rejects_different_repository_before_parsing_authorized_body(self):
        with self.environment(), self.client() as client:
            with patch("api.actions_ingest._sync_module") as load:
                response = client.post("/api/admin/actions-sync", content=b"not a zip",
                                       headers=self.headers(repository="another/team"))
                self.assertEqual(response.status_code, 403)
                load.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_api_rejects_foreign_manifest_even_when_request_headers_match(self):
        self.install(self.archive())
        payload = self.archive(run_id=9002, number=2, repository="another/team")
        with self.environment(), self.client() as client:
            response = client.post("/api/admin/actions-sync", content=payload, headers=self.headers(9002))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.sync.read_sync_marker(self.destination)["run_id"], 9001)

    def test_api_publishes_current_and_existing_repository_sees_new_data_next_query(self):
        from api_v6.repository import IntelligenceRepository
        repository = IntelligenceRepository(self.destination / "current/intelligence.db", self.root)
        with self.environment(), self.client() as client:
            response = client.post("/api/admin/actions-sync", content=self.archive(), headers=self.headers())
            self.assertEqual(response.status_code, 200, response.text)
            self.assertFalse(response.json()["restart_recommended"])
            with repository.read() as old_reader:
                self.assertEqual(old_reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 1)
                with sqlite3.connect(self.source / "intelligence.db") as db:
                    db.execute("INSERT INTO source_items VALUES (?,?,?)", ("NVD", "CVE-2026-10002", FIRST_SEEN))
                response = client.post("/api/admin/actions-sync", content=self.archive(9002, 2),
                                       headers=self.headers(9002))
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(old_reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 1)
            with repository.read() as next_reader:
                self.assertEqual(next_reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 2)
                with self.assertRaises(sqlite3.OperationalError):
                    next_reader.execute("DELETE FROM source_items")
            status = client.get("/api/admin/actions-sync").json()
            self.assertEqual(status["last_sync"]["run_id"], 9002)
            self.assertTrue(status["synced"])

    def test_ingest_disabled_without_token_does_not_modify_global_environment(self):
        from api.actions_ingest import ingest_enabled
        with patch.dict(os.environ, {"ACTIONS_INGEST_TOKEN": ""}):
            self.assertFalse(ingest_enabled())


if __name__ == "__main__":
    unittest.main()
