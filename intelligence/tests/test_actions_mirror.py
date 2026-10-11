"""A deployment mirror must deliver authentic, monotonic, immutable history."""
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from api_v6.repository import IntelligenceRepository
from deployment.actions_mirror import deliver_latest
from deployment.actions_state import StateError, save_state
from deployment.state_role import claim_role

REPOSITORY = "team/public-repo"
WORKFLOW = "intelligence-collect.yml"
FIRST_SEEN = "2026-10-08T01:02:03.123456+00:00"
BASELINE = "2026-10-07T00:00:00+00:00"


class SnapshotClient:
    repository = REPOSITORY

    def __init__(self, payload, number=1, run_id=42):
        self.payload = payload
        self.metadata = {"id": run_id, "run_number": number, "workflow_id": 101,
                         "head_branch": "main", "head_sha": "a" * 40,
                         "head_repository": {"full_name": REPOSITORY},
                         "event": "schedule", "status": "completed"}
        self.artifact = {"id": 90 + number, "name": f"intelligence-state-{run_id}",
                         "expired": False, "workflow_run": {"id": run_id}}

    def workflow_id(self, workflow):
        return 101

    def runs(self, workflow, branch):
        return iter([self.metadata])

    def run(self, run_id):
        return self.metadata

    def artifacts(self, run_id):
        return [self.artifact] if self.artifact is not None else []

    def collection_started(self, run_id):
        return True

    def download(self, artifact_id):
        return self.payload


class ActionsMirrorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        with sqlite3.connect(self.source / "intelligence.db") as db:
            db.executescript("""
                CREATE TABLE source_items(source TEXT,source_id TEXT,first_seen_at TEXT);
                CREATE TABLE unified_vulnerabilities(cve_id TEXT,first_seen_at TEXT);
                CREATE TABLE source_observation_baselines(source TEXT,started_at TEXT);
                CREATE TABLE knowledge_documents(document_id TEXT,first_seen_at TEXT);
            """)
            db.execute("INSERT INTO source_items VALUES (?,?,?)", ("NVD", "CVE-2026-10001", FIRST_SEEN))
            db.execute("INSERT INTO unified_vulnerabilities VALUES (?,?)", ("CVE-2026-10001", FIRST_SEEN))
            db.execute("INSERT INTO source_observation_baselines VALUES (?,?)", ("NVD", BASELINE))
            db.execute("INSERT INTO knowledge_documents VALUES (?,?)", ("blog-1", FIRST_SEEN))
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": BASELINE}))
        self.mirror = self.root / "mirror"

    def tearDown(self):
        # The production generations are immutable even to their owning API UID.
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.temporary.cleanup()

    def client(self, number=1, run_id=42, *, commit="a" * 40):
        snapshot = self.root / f"snapshot-{number}-{run_id}"
        save_state(self.source, snapshot, repository=REPOSITORY, branch="main", run_id=run_id,
                   workflow=WORKFLOW, collector_commit=commit, run_number=number)
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w") as archive:
            for path in snapshot.iterdir():
                archive.write(path, path.name)
        return SnapshotClient(memory.getvalue(), number=number, run_id=run_id)

    def deliver(self, client):
        return deliver_latest(client, self.mirror)

    def test_new_requests_follow_atomic_generation_switch_and_old_reader_can_finish(self):
        self.deliver(self.client())
        repo = IntelligenceRepository(self.mirror / "current/intelligence.db", self.root)
        with repo.read() as old_reader:
            self.assertEqual(old_reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 1)
            with sqlite3.connect(self.source / "intelligence.db") as db:
                db.execute("INSERT INTO source_items VALUES (?,?,?)", ("NVD", "CVE-2026-10002", FIRST_SEEN))
            self.deliver(self.client(2, 43))
            self.assertEqual(old_reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 1)
        with repo.read() as reader:
            self.assertEqual(reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 2)
            with self.assertRaises(sqlite3.OperationalError):
                reader.execute("DELETE FROM source_items")
        manifest = json.loads((self.mirror / "current/manifest.json").read_text())
        self.assertEqual(manifest["run_id"], 43)
        self.assertEqual(json.loads((self.mirror / "current/monitoring_baseline.json").read_text())["started_at"], BASELINE)

    def test_corrupt_download_retains_current_generation(self):
        self.deliver(self.client())
        incoming = self.client(2, 43)
        memory = io.BytesIO(incoming.payload)
        with zipfile.ZipFile(memory) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        contents["monitoring_baseline.json"] = b'{"started_at":"2026-10-09T00:00:00Z"}'
        rewritten = io.BytesIO()
        with zipfile.ZipFile(rewritten, "w") as archive:
            for name, payload in contents.items():
                archive.writestr(name, payload)
        incoming.payload = rewritten.getvalue()
        with self.assertRaisesRegex(StateError, "checksum"):
            self.deliver(incoming)
        self.assertEqual((self.mirror / "current").resolve().name, "42")

    def test_missing_latest_writer_artifact_does_not_fall_back(self):
        self.deliver(self.client())
        incoming = self.client(2, 43)
        incoming.artifact = None
        with self.assertRaisesRegex(StateError, "missing"):
            self.deliver(incoming)
        self.assertEqual((self.mirror / "current").resolve().name, "42")

    def test_wrong_repository_artifact_identity_or_code_revision_is_rejected(self):
        for case in ("repository", "artifact", "code"):
            with self.subTest(case=case):
                incoming = self.client(run_id=42 + ("repository", "artifact", "code").index(case))
                if case == "repository":
                    incoming.metadata["head_repository"]["full_name"] = "other/repo"
                elif case == "artifact":
                    incoming.artifact["workflow_run"]["id"] = 999
                else:
                    incoming.metadata["head_sha"] = "b" * 40
                with self.assertRaises(StateError):
                    self.deliver(incoming)
                self.assertFalse((self.mirror / "current").exists())

    def test_later_first_seen_or_deleted_record_cannot_reset_history(self):
        self.deliver(self.client())
        with sqlite3.connect(self.source / "intelligence.db") as db:
            db.execute("UPDATE source_items SET first_seen_at='2026-10-09T00:00:00+00:00'")
        with self.assertRaisesRegex(StateError, "history"):
            self.deliver(self.client(2, 43))
        with sqlite3.connect(self.source / "intelligence.db") as db:
            db.execute("DELETE FROM source_items")
        with self.assertRaisesRegex(StateError, "history"):
            self.deliver(self.client(3, 44))
        self.assertEqual((self.mirror / "current").resolve().name, "42")

    def test_monitoring_baseline_cannot_be_restarted(self):
        self.deliver(self.client())
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": FIRST_SEEN}))
        with self.assertRaisesRegex(StateError, "baseline"):
            self.deliver(self.client(2, 43))

    def test_older_run_is_rejected_and_same_run_is_idempotent(self):
        current = self.client(2, 43)
        self.deliver(current)
        self.assertFalse(self.deliver(current)["changed"])
        with self.assertRaisesRegex(StateError, "roll back"):
            self.deliver(self.client())

    def test_restart_after_unpublished_staging_retries_and_bounds_local_snapshots(self):
        self.deliver(self.client())
        orphan = self.mirror / "snapshots/43"
        orphan.mkdir()
        (orphan / "marker").write_text("interrupted publication")
        self.deliver(self.client(2, 43))
        self.assertFalse((self.mirror / "current/marker").exists())
        for number in range(3, 10):
            self.deliver(self.client(number, 41 + number))
        self.assertEqual(len(list((self.mirror / "snapshots").iterdir())), 8)
        self.assertEqual((self.mirror / "current").resolve().name, "50")

    def test_collector_and_mirror_cannot_claim_the_same_volume(self):
        claim_role(self.mirror, "collector")
        with self.assertRaisesRegex(RuntimeError, "different writer"):
            self.deliver(self.client())
        other = self.root / "other-volume"
        claim_role(other, "actions-mirror")
        with self.assertRaisesRegex(RuntimeError, "different writer"):
            claim_role(other, "collector")


if __name__ == "__main__":
    unittest.main()
