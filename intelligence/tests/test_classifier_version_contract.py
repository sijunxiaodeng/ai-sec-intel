"""Real worker -> API -> changefeed contract, with only the provider mocked."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ai_pipeline.worker_v5 import run_priority_batch
from api_v6.change_repository import ChangeRepository
from api_v6.repository import IntelligenceRepository, current_classifier_version
from classification.semantic_judge import SemanticJudge
from classification.version import classifier_version, CLASSIFIER_FILES
from collectors.base import IntelligenceItem
from deployment.deepseek_review import _worker
from deployment.snapshot_contract import runtime_classifier_version
from run_ai_classification_v4 import classifier_version as worker_version
from storage.sqlite_store import SQLiteIntelligenceStore

ROOT = Path(__file__).resolve().parents[1]


class ClassifierVersionContractTests(unittest.TestCase):
    def test_scope_policy_invalidates_all_readers_and_missing_source_fails_closed(self):
        self.assertEqual(classifier_version(), worker_version())
        self.assertEqual(classifier_version(), runtime_classifier_version())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in CLASSIFIER_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            before = current_classifier_version(root)
            (root / "classification/scope_policy.py").write_text("updated scope", encoding="utf-8")
            self.assertNotEqual(before, current_classifier_version(root))
            (root / "classification/scope_policy.py").unlink()
            self.assertIsNone(current_classifier_version(root))

    def test_semantic_review_stays_visible_and_upserts_after_normal_worker_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "intelligence.db"
            store = SQLiteIntelligenceStore(db)
            records = []
            for number, description in ((10001, "Ollama remote code execution vulnerability"), (10002, "A novel LLM gateway vulnerability")):
                cve = f"CVE-2026-{number}"
                records.append(IntelligenceItem(source="NVD", source_id=cve, cve_id=cve, title=cve,
                    description=description, url="https://nvd.nist.gov/vuln/detail/" + cve,
                    published_at="2026-10-10T00:00:00Z", modified_at=None, severity=None,
                    raw_data={"id": cve, "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                        "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*"}]}]}]} if number == 10001 else {"id": cve}))
            store.ingest_batch("NVD", records)
            version = classifier_version()
            repository = IntelligenceRepository(db, ROOT)
            semantic = SimpleNamespace(is_ai_related=True, category="ai_application_agent", confidence=.99,
                                       reason="Offline controlled result", evidence=["LLM gateway"])
            with patch("requests.sessions.Session.request", side_effect=AssertionError("No network")):
                run_priority_batch(db, version, 300, 0, verbose=False)
                self.assertEqual(repository.list_items(ai_related=True)["total"], 1)
                with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "OFFLINE_DUMMY"}), patch.object(SemanticJudge, "judge", return_value=semantic) as judge:
                    self.assertEqual(_worker(db, Path(directory) / "progress.json", "deepseek-chat", 2), 0)
                    judge.assert_called_once()
                self.assertEqual(repository.list_items(ai_related=True)["total"], 2)
                page = ChangeRepository(repository).page(kind="cve")
                self.assertEqual({r["operation"] for r in page["changes"]}, {"upsert"})
                self.assertEqual(len(page["changes"]), 2)
                run_priority_batch(db, version, 300, 0, verbose=False)
                self.assertEqual(repository.list_items(ai_related=True)["total"], 2)
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute("SELECT DISTINCT classifier_version FROM ai_classifications").fetchall(), [(version,)])
