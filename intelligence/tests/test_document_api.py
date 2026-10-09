"""Offline regression checks for document API read-side queries."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_v6.document_repository import DocumentRepository
from collectors.documents import KnowledgeDocument
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

T1 = "2026-10-08T01:00:00+00:00"


def document(document_id="one", **changes):
    values = dict(
        document_id=document_id, source="ARXIV", source_category="academic_paper",
        content_type="paper", title="AI security research", description="Model safety findings",
        url=f"https://example.org/{document_id}", published_at="2026-10-08T00:00:00Z",
        modified_at=None, cve_ids=[], raw_data={"source_text": "Original unmodified evidence"},
    )
    values.update(changes)
    return KnowledgeDocument(**values)


class DocumentRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.db = self.root / "intelligence.db"
        self.store = SQLiteDocumentStore(self.db)
        self.repo = DocumentRepository(self.db, self.root)

    def add(self, *documents):
        for item in documents:
            with patch("storage.document_store.utc_now", return_value=T1):
                self.store.ingest(item.source, item.source_category, [item])

    def schema(self):
        with sqlite3.connect(self.db) as connection:
            return connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()

    def test_read_payload_metadata_default_raw_omission_and_explicit_evidence(self):
        self.add(document())
        self.assertTrue(self.repo.available())
        record = self.repo.one("one")
        self.assertEqual(record["document_id"], "one")
        self.assertEqual(record["first_seen_at"], T1)
        self.assertEqual(record["last_seen_at"], T1)
        self.assertEqual(record["content_updated_at"], T1)
        self.assertNotIn("raw_data", record)
        evidence = self.repo.one("one", include_raw=True)
        self.assertEqual(evidence["raw_data"], {"source_text": "Original unmodified evidence"})
        evidence["raw_data"]["source_text"] = "Caller changed its copy"
        self.assertEqual(self.repo.one("one", include_raw=True)["raw_data"]["source_text"],
                         "Original unmodified evidence")
        self.assertNotIn("raw_data", self.repo.list_items()["items"][0])
        self.assertIn("raw_data", self.repo.list_items(include_raw=True)["items"][0])

    def test_literal_percent_underscore_and_backslash_search(self):
        self.add(document("literal", title=r"Threat_100% \ model"),
                 document("ordinary", title="ThreatX1000 model"))
        for term in ("_100%", "%", "\\"):
            records = self.repo.list_items(q=term)
            self.assertEqual(records["total"], 1)
            self.assertEqual(records["items"][0]["document_id"], "literal")

    def test_sql_injection_strings_remain_parameters(self):
        self.add(document())
        before = self.schema()
        injection = "' OR 1=1 --"
        self.assertEqual(self.repo.list_items(q=injection)["total"], 0)
        self.assertEqual(self.repo.list_items(source=injection)["total"], 0)
        self.assertEqual(self.repo.list_items(category=injection)["total"], 0)
        self.assertEqual(self.repo.list_items(content_type=injection)["total"], 0)
        self.assertEqual(self.repo.list_items(cve_id=injection)["total"], 0)
        self.assertIsNone(self.repo.one(injection))
        self.assertEqual(self.schema(), before)

    def test_related_cve_filter_matches_complete_array_member(self):
        self.add(document("short", cve_ids=["CVE-2026-1234"]),
                 document("long", cve_ids=["CVE-2026-12345"]), document("unlinked"))
        result = self.repo.list_items(cve_id=" cve-2026-1234 ")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["document_id"], "short")
        self.assertEqual(self.repo.list_items(cve_id="CVE-2026-123")["total"], 0)
        self.assertEqual(self.repo.list_items(q="cve-2026-12345")["total"], 1)
        self.assertEqual(self.repo.list_items(q="findings")["total"], 3)

    def test_category_source_content_filters_and_deterministic_pagination(self):
        self.add(document("a"), document("b"),
                 document("c", source="OFFICIAL", source_category="policy_regulation",
                          content_type="policy"))
        self.assertEqual(self.repo.list_items(source="ARXIV")["total"], 2)
        self.assertEqual(self.repo.list_items(category="policy_regulation")["total"], 1)
        self.assertEqual(self.repo.list_items(content_type="policy")["total"], 1)
        page = self.repo.list_items(source="ARXIV", category="academic_paper", limit=1, offset=1)
        self.assertEqual((page["total"], page["limit"], page["offset"]), (2, 1, 1))
        self.assertEqual(page["items"][0]["document_id"], "b")
        self.assertEqual(self.repo.list_items(offset=20)["items"], [])
        for values in ({"limit": 0}, {"limit": True}, {"offset": -1}, {"offset": 0.5}):
            with self.assertRaises(ValueError):
                self.repo.list_items(**values)

    def test_date_precision_and_absent_publication_survive_api(self):
        self.add(document("day", published_at="2026-10-08"),
                 document("missing", published_at=None),
                 document("naive", published_at="2026-10-08T09:00:00"))
        self.assertEqual(self.repo.one("day")["published_at"], "2026-10-08")
        self.assertIsNone(self.repo.one("missing")["published_at"])
        self.assertEqual(self.repo.one("naive")["published_at"], "2026-10-08T09:00:00")

    def test_stats_use_retained_documents_and_latest_run_including_failure(self):
        self.add(document("a"), document("b"),
                 document("c", source="OFFICIAL", source_category="technical_standard",
                          content_type="standard"))
        self.store.ingest("EMPTY", "security_blog", [])
        self.store.record_failure("ARXIV", "academic_paper", "Offline fixture failure")
        stats = self.repo.stats()
        self.assertEqual(stats["total_documents"], 3)
        self.assertEqual(stats["source_record_counts"], {"ARXIV": 2, "OFFICIAL": 1})
        self.assertEqual(stats["source_category_counts"], {"academic_paper": 2, "technical_standard": 1})
        self.assertEqual(stats["content_type_counts"], {"paper": 2, "standard": 1})
        self.assertEqual(len(stats["latest_runs"]), 3)
        run = next(row for row in stats["latest_runs"] if row["source"] == "ARXIV")
        self.assertEqual(run["status"], "failed")

    def test_cve_only_database_returns_empty_without_creating_document_schema(self):
        legacy = self.root / "legacy.db"
        SQLiteIntelligenceStore(legacy)
        repository = DocumentRepository(legacy, self.root)
        with sqlite3.connect(legacy) as connection:
            before = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
        self.assertFalse(repository.available())
        self.assertEqual(repository.list_items(), {"total": 0, "limit": 20, "offset": 0, "items": []})
        self.assertIsNone(repository.one("missing"))
        self.assertEqual(repository.stats(), {
            "total_documents": 0, "source_record_counts": {}, "source_category_counts": {},
            "content_type_counts": {}, "latest_runs": [],
        })
        with sqlite3.connect(legacy) as connection:
            after = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
        self.assertEqual(before, after)

    def test_missing_database_raises_without_creating_a_file(self):
        missing = self.root / "never-created.db"
        repository = DocumentRepository(missing, self.root)
        for operation in (repository.available, repository.list_items, repository.stats,
                          lambda: repository.one("missing")):
            with self.assertRaises(FileNotFoundError):
                operation()
        self.assertFalse(missing.exists())

    def test_partial_schema_reports_unavailable_without_repair_or_mutation(self):
        partial = self.root / "partial.db"
        with sqlite3.connect(partial) as connection:
            connection.execute("CREATE TABLE knowledge_documents(document_id TEXT PRIMARY KEY)")
        repository = DocumentRepository(partial, self.root)
        self.assertFalse(repository.available())
        self.assertEqual(repository.list_items()["total"], 0)
        with sqlite3.connect(partial) as connection:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(knowledge_documents)")]
        self.assertEqual(columns, ["document_id"])

    def test_read_connection_enforces_read_only_and_queries_leave_state_unchanged(self):
        self.add(document())
        before_schema = self.schema()
        before_stats = self.store.stats()
        before_record = self.store.get_document("one")
        with self.repo.read() as connection:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("DELETE FROM knowledge_documents")
        self.repo.available()
        self.repo.list_items(q="model")
        self.repo.one("one", include_raw=True)
        self.repo.stats()
        self.assertEqual(self.schema(), before_schema)
        self.assertEqual(self.store.stats(), before_stats)
        self.assertEqual(self.store.get_document("one"), before_record)


if __name__ == "__main__":
    unittest.main()
