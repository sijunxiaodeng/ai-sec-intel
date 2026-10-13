"""Old-version writer upgrade preserves real history and serves fresh decisions."""
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ai_pipeline.documents import DocumentClassificationStore
from ai_pipeline.store import ClassificationStore
from api_v6.change_repository import ChangeRepository
from api_v6.repository import IntelligenceRepository
from collectors.base import IntelligenceItem
from collectors.documents import KnowledgeDocument
from deployment.actions_mirror import install_snapshot
from deployment.actions_state import StateError, restore_archive, save_state, validate_deployment_state
from deployment.snapshot_contract import database_contract, runtime_classifier_version
from run_migrate_state import _history_digests, migrate_state
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

BASELINE = "2026-10-04T00:00:00+00:00"


class StateMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.db = self.source / "intelligence.db"
        cves = SQLiteIntelligenceStore(self.db)
        for number, description in enumerate(("Ollama vulnerability", "Ordinary image editor vulnerability",
                                             "AI assistant affected, precise product unknown")):
            cve = f"CVE-2026-{10001 + number}"
            cves.ingest_batch("NVD", [IntelligenceItem("NVD", cve, cve, description, description,
                f"https://nvd.nist.gov/vuln/detail/{cve}", BASELINE, None, None,
                raw_data={"original_evidence": description})])
        documents = SQLiteDocumentStore(self.db)
        documents.ingest("BLOG", "security_blog", [KnowledgeDocument(
            "blog-1", "BLOG", "security_blog", "blog", "Artificial Intelligence privacy standard",
            "Original AI privacy safeguards", "https://example.org/source", BASELINE, None,
            raw_data={"source_text": "Original source evidence"})])
        verdict = SimpleNamespace(is_ai_related=True, category="ai_infrastructure", confidence=.95,
            reason="Historical verdict retained for audit", evidence=["Historical source evidence"],
            decision_source="historical_model", needs_review=False, rule_score=.95)
        classification = ClassificationStore(self.db)
        for row in classification.fresh("old-version", 10):
            classification.record(row, "old-version", "classified", result=verdict)
        doc_classification = DocumentClassificationStore(self.db)
        doc_classification.record(doc_classification.fresh("old-version", 10)[0], "old-version", verdict)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("CREATE TABLE source_observation_baselines(source TEXT PRIMARY KEY,started_at TEXT)")
            db.execute("INSERT INTO source_observation_baselines VALUES ('NVD',?)", (BASELINE,))
            db.execute("CREATE TABLE incremental_cursors(source TEXT,cursor TEXT)")
            db.execute("INSERT INTO incremental_cursors VALUES ('NVD',?)", (BASELINE,))
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
                db.execute(f"DROP TRIGGER {row[0]}")
            db.execute("DROP TABLE team_feed_meta")
            db.execute("DROP TABLE team_changes")
        (self.source / "monitoring_baseline.json").write_text(json.dumps({"started_at": BASELINE}))
        self.before = _history_digests(self.db)

    def tearDown(self):
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.temporary.cleanup()

    def archive(self, directory):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in directory.iterdir():
                archive.write(path, path.name)
        return buffer.getvalue()

    def test_legacy_restores_for_writer_but_cannot_be_deployed_until_migrated(self):
        snapshot = self.root / "legacy-snapshot"
        manifest = save_state(self.source, snapshot, repository="team/repo", branch="main", run_id=1,
                              workflow="intelligence-collect.yml", collector_commit="a" * 40, run_number=1)
        self.assertFalse(manifest["compatibility"]["ready"])
        restored = self.root / "restored"
        restore_archive(self.archive(snapshot), restored, repository="team/repo", branch="main", run_id=1)
        with self.assertRaisesRegex(StateError, "incompatible"):
            install_snapshot(self.archive(snapshot), self.root / "mirror", repository="team/repo",
                             branch="main", run_id=1)
        report = migrate_state(restored)
        self.assertTrue(report["compatibility"]["ready"])
        self.assertEqual(report["cves"]["before"]["classified_ai_positive"], 0)
        self.assertEqual(report["cves"]["after"]["classified_ai_positive"], 1)
        self.assertEqual(_history_digests(restored / "intelligence.db"), self.before)

    def test_complete_reclassification_keeps_unknown_unknown_and_preserves_old_evidence(self):
        with patch("classification.semantic_judge.SemanticJudge.judge", side_effect=AssertionError("No model calls")):
            report = migrate_state(self.source)
        self.assertTrue(report["history_preserved"])
        self.assertEqual(report["archived_verdicts"], 4)
        self.assertEqual(report["cves"]["after"]["need_initial_or_refresh"], 0)
        self.assertEqual(report["cves"]["after"]["states"]["pending_llm"], 1)
        self.assertEqual(report["documents"]["after"]["classified_ai_positive"], 1)
        self.assertEqual(_history_digests(self.db), self.before)
        with closing(sqlite3.connect(self.db)) as db:
            records = [json.loads(row[0]) for row in db.execute("SELECT record_json FROM classification_migration_history")]
            self.assertEqual(len(records), 4)
            self.assertTrue(all(json.loads(row["evidence_json"]) == ["Historical source evidence"] for row in records))
            self.assertTrue(all(row["classifier_version"] == "old-version" for row in records))
        current = IntelligenceRepository(self.db, Path(__file__).resolve().parents[1])
        self.assertEqual(current.stats()["classified_ai_positive"], 1)
        feed = ChangeRepository(current)
        cves = feed.page(kind="cve", limit=100)
        docs = feed.page(kind="document", limit=100)
        self.assertEqual(len(cves["changes"]), 3)
        self.assertEqual([row["operation"] for row in cves["changes"]].count("upsert"), 1)
        self.assertEqual(docs["changes"][0]["operation"], "upsert")

    def test_restart_is_idempotent_and_current_classifications_are_not_rewritten(self):
        migrate_state(self.source)
        with closing(sqlite3.connect(self.db)) as db:
            original_verdicts = db.execute("SELECT * FROM ai_classifications ORDER BY cve_id").fetchall()
            cursor = db.execute("SELECT MAX(seq) FROM team_changes").fetchone()[0]
            epoch = db.execute("SELECT value FROM team_feed_meta WHERE key='epoch'").fetchone()[0]
        second = migrate_state(self.source)
        self.assertEqual(second["archived_verdicts"], 0)
        self.assertEqual(second["cves"]["batch"], {})
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("SELECT * FROM ai_classifications ORDER BY cve_id").fetchall(), original_verdicts)
            self.assertEqual(db.execute("SELECT MAX(seq) FROM team_changes").fetchone()[0], cursor)
            self.assertEqual(db.execute("SELECT value FROM team_feed_meta WHERE key='epoch'").fetchone()[0], epoch)

    def test_saved_contract_is_checked_against_database_and_actual_runtime(self):
        migrate_state(self.source)
        snapshot = self.root / "snapshot"
        save_state(self.source, snapshot, repository="team/repo", branch="main", run_id=2)
        self.assertTrue(validate_deployment_state(snapshot)["ready"])
        incompatible = database_contract(snapshot / "intelligence.db", classifier_version="new-runtime")
        self.assertFalse(incompatible["ready"])
        self.assertEqual(incompatible["classification"]["cve"]["version_stale"], 3)
        self.assertEqual(runtime_classifier_version(), validate_deployment_state(snapshot)["classifier_version"])
        manifest = json.loads((snapshot / "manifest.json").read_text())
        manifest["compatibility"]["classifier_version"] = "manufactured-version"
        (snapshot / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(StateError, "contract"):
            validate_deployment_state(snapshot)

    def test_genuine_new_state_requires_explicit_first_deployment_and_empty_directory(self):
        empty = self.root / "new-state"
        empty.mkdir()
        with self.assertRaises(sqlite3.OperationalError):
            migrate_state(empty)
        result = migrate_state(empty, allow_new=True)
        self.assertEqual(result["status"], "new_deployment")
        self.assertTrue(result["initial_collection_required"])
        self.assertEqual(list(empty.iterdir()), [])
        (empty / "monitoring_baseline.json").write_text(json.dumps({"started_at": BASELINE}))
        with self.assertRaisesRegex(StateError, "incomplete history"):
            migrate_state(empty, allow_new=True)
        self.assertEqual(json.loads((empty / "monitoring_baseline.json").read_text())["started_at"], BASELINE)


if __name__ == "__main__":
    unittest.main()
