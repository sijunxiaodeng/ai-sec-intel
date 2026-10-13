"""Offline regressions for uniform admission, unknowns and changed source text."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_pipeline.documents import DocumentClassificationStore, run_document_batch
from api_v6.change_repository import ChangeRepository
from api_v6.repository import IntelligenceRepository, current_classifier_version
from classification.scope_policy import classify_scope
from collectors.documents import KnowledgeDocument
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore


class UniformScopeTests(unittest.TestCase):
    def test_source_independent_vulnerability_policy_and_ambiguous_no_verdict(self):
        fields_by_source = {
            "NVD": {"product": "ollama"},
            "GITHUB_ADVISORY": {"package_names": ["pip:ollama"]},
            "CISA_KEV": {"title": "Ollama server vulnerability"},
            "OSV": {"package_names": ["PyPI:ollama"]},
        }
        for source, fields in fields_by_source.items():
            with self.subTest(source=source):
                positive = classify_scope(**fields)
                self.assertTrue(positive.is_ai_related)
                self.assertEqual(positive.category, "ai_infrastructure")
        unknown = classify_scope(description="A novel LLM gateway contains a flaw")
        self.assertIsNone(unknown.is_ai_related)
        self.assertTrue(unknown.needs_review)
        self.assertEqual(unknown.category, "unknown")

    def test_document_topic_needs_security_and_plain_substrings_are_not_evidence(self):
        cases = (
            ("Artificial Intelligence Research Grants", "Funding research", False),
            ("Artificial Intelligence Privacy Standard", "Privacy safeguards", True),
            ("基于人工智能的隐私风险评估", "", True),
            ("LLM 应用中间接提示注入", "", True),
            ("Power transformers management", "Firmware security", None),
            ("Ordinary router", "Firmware security", False),
            ("AI image generator", "A colorful image", False),
            ("Novel inference software", "Potential security risk", None),
        )
        for title, description, expected in cases:
            with self.subTest(title=title):
                result = classify_scope(title=title, description=description, record_kind="document")
                self.assertIs(result.is_ai_related, expected)
                self.assertEqual(result.needs_review, expected is None)


class DocumentScopePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = Path(self.temporary.name) / "intelligence.db"
        SQLiteIntelligenceStore(self.db)
        self.documents = SQLiteDocumentStore(self.db)

    def document(self, source, category, title, description, identifier="doc-1"):
        return KnowledgeDocument(identifier, source, category, category, title, description,
                                 "https://example.test/published", "2026-10-01T00:00:00Z", None,
                                 raw_data={"source_text": description, "query_scoped": True})

    def test_every_document_category_is_classified_with_no_model_calls(self):
        categories = ("security_community", "vendor_advisory", "security_blog", "academic_paper",
                      "technical_standard", "policy_regulation", "government_alert")
        for index, category in enumerate(categories):
            source = f"source-{index}"
            self.documents.ingest(source, category, [self.document(
                source, category, "Artificial Intelligence Privacy Standard", "Privacy safeguards",
                f"doc-{index}")])
        with patch("classification.semantic_judge.requests.post") as request:
            result = run_document_batch(self.db, "version-1", 100)
        request.assert_not_called()
        self.assertEqual((result["selected"], result["positive"], result["model_calls"]), (7, 7, 0))
        self.assertEqual(run_document_batch(self.db, "version-1", 100)["selected"], 0)

    def test_query_scoped_ambiguous_item_is_review_and_keeps_raw_text(self):
        document = self.document("BLOG", "security_blog", "A novel inference gateway", "Security risk")
        self.documents.ingest("BLOG", "security_blog", [document])
        before = self.documents.get_document(document.document_id)
        result = run_document_batch(self.db, "version-1")
        after = self.documents.get_document(document.document_id)
        self.assertEqual(result["needs_review"], 1)
        self.assertEqual(result["positive"], 0)
        self.assertEqual(before, after)
        with DocumentClassificationStore(self.db).connect() as con:
            row = con.execute("SELECT * FROM document_ai_classifications").fetchone()
            self.assertEqual(row["state"], "review")
            self.assertIsNone(row["ai_related"])

    def test_content_change_withdraws_old_verdict_preserves_first_seen_and_appends_feed(self):
        document = self.document("BLOG", "security_blog", "Artificial Intelligence Privacy Standard", "Privacy safeguards")
        self.documents.ingest("BLOG", "security_blog", [document])
        run_document_batch(self.db, "version-1")
        before = self.documents.get_document(document.document_id)
        classifier = DocumentClassificationStore(self.db)
        with classifier.connect() as con:
            old_sequence = con.execute("SELECT MAX(seq) FROM team_changes").fetchone()[0]
        document.title, document.description = "Ordinary router firmware", "Security patch"
        document.raw_data["source_text"] = document.description
        self.documents.ingest("BLOG", "security_blog", [document])
        result = run_document_batch(self.db, "version-1")
        after = self.documents.get_document(document.document_id)
        self.assertEqual(after["first_seen_at"], before["first_seen_at"])
        self.assertEqual(after["raw_data"], document.raw_data)
        self.assertEqual(result["positive"], 0)
        with classifier.connect() as con:
            verdict = con.execute("SELECT state,ai_related FROM document_ai_classifications").fetchone()
            changes = con.execute("SELECT * FROM team_changes WHERE seq>?", (old_sequence,)).fetchall()
        self.assertEqual(tuple(verdict), ("classified", 0))
        self.assertGreaterEqual(len(changes), 2)  # source edit and changed admission verdict

    def test_optimistic_guard_rejects_stale_document_verdict(self):
        document = self.document("BLOG", "security_blog", "AI security", "Privacy safeguards")
        self.documents.ingest("BLOG", "security_blog", [document])
        classifier = DocumentClassificationStore(self.db)
        old = classifier.fresh("version-1", 1)[0]
        document.description = "Different source content"
        self.documents.ingest("BLOG", "security_blog", [document])
        verdict = classify_scope(title="AI security", record_kind="document")
        self.assertFalse(classifier.record(old, "version-1", verdict))
        self.assertEqual(classifier.stats("version-1")["need_initial_or_refresh"], 1)


class DemoScopeIntegrationTests(unittest.TestCase):
    def test_seed_uses_real_policy_and_delivers_both_demo_kinds(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "demo.db"
            seeded = subprocess.run([sys.executable, str(root / "seed_demo_db.py"), "--db", str(db)],
                                    cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(seeded.returncode, 0, seeded.stderr)
            self.assertEqual(json.loads(seeded.stdout)["label"], "demo_synthetic_offline_fixture")
            feed = ChangeRepository(IntelligenceRepository(db, root))
            for kind, count in (("cve", 5), ("document", 7)):
                page = feed.page(kind=kind)
                self.assertEqual(len(page["changes"]), count)
                self.assertEqual({change["operation"] for change in page["changes"]}, {"upsert"})
            self.assertEqual(DocumentClassificationStore(db).stats(
                current_classifier_version(root))["classified_ai_positive"], 7)


if __name__ == "__main__":
    unittest.main()
