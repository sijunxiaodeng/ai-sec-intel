"""A deployment mirror must deliver authentic, monotonic, immutable history."""
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path

from api_v6.repository import IntelligenceRepository
from deployment.actions_mirror import deliver_latest, verify_history
from deployment.actions_state import StateError, save_state
from deployment.state_role import claim_role
from deployment.snapshot_contract import runtime_classifier_version
from storage.changefeed import ensure_changefeed

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
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.executescript("""
                CREATE TABLE source_items(source TEXT,source_id TEXT,first_seen_at TEXT);
                CREATE TABLE unified_vulnerabilities(cve_id TEXT,first_seen_at TEXT,content_sha256 TEXT);
                CREATE TABLE source_observation_baselines(source TEXT,started_at TEXT);
                CREATE TABLE knowledge_documents(document_id TEXT,first_seen_at TEXT,content_sha256 TEXT);
                CREATE TABLE ai_classifications(cve_id TEXT,content_sha256 TEXT,classifier_version TEXT,state TEXT,ai_related INTEGER);
                CREATE TABLE document_ai_classifications(document_id TEXT,content_sha256 TEXT,classifier_version TEXT,state TEXT,ai_related INTEGER);
            """)
            db.execute("INSERT INTO source_items VALUES (?,?,?)", ("NVD", "CVE-2026-10001", FIRST_SEEN))
            db.execute("INSERT INTO unified_vulnerabilities VALUES (?,?,?)", ("CVE-2026-10001", FIRST_SEEN, "hash-1"))
            db.execute("INSERT INTO source_observation_baselines VALUES (?,?)", ("NVD", BASELINE))
            db.execute("INSERT INTO knowledge_documents VALUES (?,?,?)", ("blog-1", FIRST_SEEN, "doc-hash-1"))
            db.execute("INSERT INTO ai_classifications VALUES (?,?,?,?,?)",
                       ("CVE-2026-10001", "hash-1", runtime_classifier_version(), "classified", 1))
            db.execute("INSERT INTO document_ai_classifications VALUES (?,?,?,?,?)",
                       ("blog-1", "doc-hash-1", runtime_classifier_version(), "classified", 1))
            ensure_changefeed(db)
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": BASELINE}))
        self.mirror = self.root / "mirror"

    def tearDown(self):
        # The production generations are immutable even to their owning API UID.
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)
        self.temporary.cleanup()

    def require_directory_symlink(self):
        probe = self.root / "symlink-probe"
        try:
            probe.symlink_to(self.source, target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and exc.winerror == 1314:
                self.skipTest("Windows directory symlink privilege is not available")
            raise
        else:
            probe.unlink()

    @staticmethod
    def rewrite_archive(incoming, transform):
        with zipfile.ZipFile(io.BytesIO(incoming.payload)) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        transform(contents)
        rewritten = io.BytesIO()
        with zipfile.ZipFile(rewritten, "w") as archive:
            for name, payload in contents.items():
                archive.writestr(name, payload)
        incoming.payload = rewritten.getvalue()
        return incoming

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
        self.require_directory_symlink()
        self.deliver(self.client())
        repo = IntelligenceRepository(self.mirror / "current/intelligence.db", self.root)
        with repo.read() as old_reader:
            self.assertEqual(old_reader.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 1)
            with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
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
        self.require_directory_symlink()
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
        self.require_directory_symlink()
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
                expected = "lineage" if case == "code" else "provenance"
                with self.assertRaisesRegex(StateError, expected):
                    self.deliver(incoming)
                self.assertFalse((self.mirror / "current").exists())

    def test_later_first_seen_or_deleted_record_cannot_reset_history(self):
        self.require_directory_symlink()
        self.deliver(self.client())
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE source_items SET first_seen_at='2026-10-09T00:00:00+00:00'")
        with self.assertRaisesRegex(StateError, "history"):
            self.deliver(self.client(2, 43))
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("DELETE FROM source_items")
        with self.assertRaisesRegex(StateError, "history"):
            self.deliver(self.client(3, 44))
        self.assertEqual((self.mirror / "current").resolve().name, "42")

    def test_monitoring_baseline_cannot_be_restarted(self):
        self.require_directory_symlink()
        self.deliver(self.client())
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": FIRST_SEEN}))
        with self.assertRaisesRegex(StateError, "baseline"):
            self.deliver(self.client(2, 43))

    def test_older_run_is_rejected_and_same_run_is_idempotent(self):
        self.require_directory_symlink()
        current = self.client(2, 43)
        self.deliver(current)
        self.assertFalse(self.deliver(current)["changed"])
        with self.assertRaisesRegex(StateError, "roll back"):
            self.deliver(self.client())

    def test_restart_after_unpublished_staging_retries_and_bounds_local_snapshots(self):
        self.require_directory_symlink()
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

    def test_incompatible_old_classifier_or_missing_feed_keeps_previous_generation(self):
        self.require_directory_symlink()
        self.deliver(self.client())
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE ai_classifications SET classifier_version='old-classifier'")
        with self.assertRaisesRegex(StateError, "classifier_version_stale"):
            self.deliver(self.client(2, 43))
        self.assertEqual((self.mirror / "current").resolve().name, "42")
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE ai_classifications SET classifier_version=?", (runtime_classifier_version(),))
            db.execute("DROP TRIGGER team_feed_knowledge_documents_update")
        with self.assertRaisesRegex(StateError, "missing_changefeed_triggers"):
            self.deliver(self.client(3, 44))
        self.assertEqual((self.mirror / "current").resolve().name, "42")

    def test_normal_new_content_classification_backlog_can_be_delivered(self):
        self.require_directory_symlink()
        self.deliver(self.client())
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE unified_vulnerabilities SET content_sha256='updated-content'")
            db.execute("INSERT INTO knowledge_documents VALUES (?,?,?)", ("blog-2", FIRST_SEEN, "new-document"))
        self.assertTrue(self.deliver(self.client(2, 43))["changed"])
        contract = json.loads((self.mirror / "current/manifest.json").read_text())["compatibility"]
        self.assertTrue(contract["ready"])
        self.assertEqual(contract["classification"]["cve"]["content_stale"], 1)
        self.assertEqual(contract["classification"]["document"]["missing"], 1)

    def test_missing_or_forged_manifest_contract_cannot_be_published(self):
        self.require_directory_symlink()
        self.deliver(self.client())
        for run_id, contract in ((43, None), (44, {"ready": True})):
            incoming = self.client(run_id - 41, run_id)
            with zipfile.ZipFile(io.BytesIO(incoming.payload)) as archive:
                contents = {name: archive.read(name) for name in archive.namelist()}
            manifest = json.loads(contents["manifest.json"])
            if contract is None:
                manifest.pop("compatibility")
            else:
                manifest["compatibility"] = contract
            contents["manifest.json"] = json.dumps(manifest).encode()
            rewritten = io.BytesIO()
            with zipfile.ZipFile(rewritten, "w") as archive:
                for name, payload in contents.items():
                    archive.writestr(name, payload)
            incoming.payload = rewritten.getvalue()
            with self.assertRaisesRegex(StateError, "contract"):
                self.deliver(incoming)
            self.assertEqual((self.mirror / "current").resolve().name, "42")

    def test_corrupt_initial_download_is_rejected_before_publication(self):
        incoming = self.rewrite_archive(self.client(), lambda contents: contents.update(
            {"monitoring_baseline.json": b'{"started_at":"2026-10-09T00:00:00Z"}'}))
        with self.assertRaisesRegex(StateError, "checksum"):
            self.deliver(incoming)
        self.assertFalse((self.mirror / "current").exists())

    def test_missing_initial_artifact_is_rejected_before_publication(self):
        incoming = self.client()
        incoming.artifact = None
        with self.assertRaisesRegex(StateError, "missing"):
            self.deliver(incoming)
        self.assertFalse((self.mirror / "current").exists())

    def test_incompatible_initial_classifier_or_feed_is_rejected_before_publication(self):
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE ai_classifications SET classifier_version='old-classifier'")
        with self.assertRaisesRegex(StateError, "classifier_version_stale"):
            self.deliver(self.client())
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE ai_classifications SET classifier_version=?", (runtime_classifier_version(),))
            db.execute("DROP TRIGGER team_feed_knowledge_documents_update")
        with self.assertRaisesRegex(StateError, "missing_changefeed_triggers"):
            self.deliver(self.client(2, 43))
        self.assertFalse((self.mirror / "current").exists())

    def test_initial_missing_or_forged_manifest_contract_is_rejected_before_publication(self):
        for run_id, contract in ((42, None), (43, {"ready": True})):
            with self.subTest(contract=contract):
                def change_contract(contents):
                    manifest = json.loads(contents["manifest.json"])
                    if contract is None:
                        manifest.pop("compatibility")
                    else:
                        manifest["compatibility"] = contract
                    contents["manifest.json"] = json.dumps(manifest).encode()

                incoming = self.rewrite_archive(self.client(run_id=run_id), change_contract)
                with self.assertRaisesRegex(StateError, "contract"):
                    self.deliver(incoming)
                self.assertFalse((self.mirror / "current").exists())

    def test_history_validation_rejects_later_first_seen_and_deleted_records_without_publication(self):
        previous = self.root / "previous"
        shutil.copytree(self.source, previous)
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("UPDATE source_items SET first_seen_at='2026-10-09T00:00:00+00:00'")
        with self.assertRaisesRegex(StateError, "history"):
            verify_history(previous, self.source)
        with closing(sqlite3.connect(self.source / "intelligence.db")) as db, db:
            db.execute("DELETE FROM source_items")
        with self.assertRaisesRegex(StateError, "history"):
            verify_history(previous, self.source)

    def test_history_validation_rejects_restarted_baseline_without_publication(self):
        previous = self.root / "previous"
        shutil.copytree(self.source, previous)
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": FIRST_SEEN}))
        with self.assertRaisesRegex(StateError, "baseline"):
            verify_history(previous, self.source)


if __name__ == "__main__":
    unittest.main()
