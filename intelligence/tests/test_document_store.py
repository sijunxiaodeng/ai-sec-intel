"""Offline checks for non-CVE persistence, precision and HTTP checkpoint safety."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from collectors.documents import KnowledgeDocument
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

CATEGORY = "academic_paper"
SOURCE = "ARXIV"
T1 = "2026-10-08T01:00:00+00:00"
T2 = "2026-10-08T02:00:00+00:00"
T3 = "2026-10-08T03:00:00+00:00"


def document(**changes):
    values = dict(
        document_id="document-1", source=SOURCE, source_category=CATEGORY,
        content_type="paper", title="AI model security", description="A research abstract",
        url="https://example.org/papers/1", published_at="2026-10-08T08:00:00+08:00",
        modified_at=None, cve_ids=[], raw_data={"abstract": "original source content"},
    )
    values.update(changes)
    return KnowledgeDocument(**values)


class DocumentStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "intelligence.db"
        self.store = SQLiteDocumentStore(self.db)

    def rows(self, sql, params=()):
        with sqlite3.connect(self.db) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql, params)]

    def ingest_at(self, timestamp, records):
        with patch("storage.document_store.utc_now", return_value=timestamp):
            return self.store.ingest(SOURCE, CATEGORY, records)

    def test_document_without_cve_persists_with_evidence_and_normalized_aware_time(self):
        original = document(cve_ids=[" cve-2026-1234 ", "CVE-2026-1234"], raw_data={
            "published": "2026-10-08T08:00:00+08:00", "observed_at": "source-provided fact"})
        snapshot = asdict(original)
        result = self.ingest_at(T1, [original, document(document_id="document-2", cve_ids=[])])
        self.assertEqual(result, {"fetched": 2, "inserted": 2, "updated": 0, "unchanged": 0})
        saved = self.store.get_document("document-1")
        self.assertEqual(saved["published_at"], "2026-10-08T00:00:00+00:00")
        self.assertEqual(saved["cve_ids"], ["CVE-2026-1234"])
        self.assertEqual(saved["raw_data"], snapshot["raw_data"])
        self.assertEqual(asdict(original), snapshot)
        self.assertEqual(self.store.get_document("document-2")["cve_ids"], [])
        columns = self.rows("SELECT published_at,source_category,cve_ids_json FROM knowledge_documents WHERE document_id='document-1'")[0]
        self.assertEqual(json.loads(columns["cve_ids_json"]), ["CVE-2026-1234"])
        self.assertEqual(columns["source_category"], CATEGORY)

    def test_date_only_naive_and_missing_publication_do_not_gain_a_timezone_or_time(self):
        records = [document(document_id="day", published_at="2026-10-08"),
                   document(document_id="naive", published_at="2026-10-08T09:00:00"),
                   document(document_id="missing", published_at=None)]
        self.ingest_at(T1, records)
        self.assertEqual(self.store.get_document("day")["published_at"], "2026-10-08")
        self.assertEqual(self.store.get_document("naive")["published_at"], "2026-10-08T09:00:00")
        self.assertIsNone(self.store.get_document("missing")["published_at"])

    def test_rfc_feed_timestamp_normalizes_known_timezone(self):
        self.ingest_at(T1, [document(published_at="Thu, 08 Oct 2026 08:00:00 +0800")])
        self.assertEqual(self.store.get_document("document-1")["published_at"],
                         "2026-10-08T00:00:00+00:00")

    def test_insert_update_and_unchanged_metadata_and_counts(self):
        record = document()
        self.ingest_at(T1, [record])
        first = self.store.get_document("document-1")
        counts = self.ingest_at(T2, [record])
        unchanged = self.store.get_document("document-1")
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(unchanged["content_sha256"], first["content_sha256"])
        self.assertEqual(unchanged["first_seen_at"], T1)
        self.assertEqual(unchanged["content_updated_at"], T1)
        self.assertEqual(unchanged["last_seen_at"], T2)
        counts = self.ingest_at(T3, [document(description="Updated analysis")])
        updated = self.store.get_document("document-1")
        self.assertEqual(counts["updated"], 1)
        self.assertEqual(updated["first_seen_at"], T1)
        self.assertEqual(updated["content_updated_at"], T3)
        self.assertNotEqual(updated["content_sha256"], first["content_sha256"])

    def test_source_provided_observed_at_is_content_and_is_never_discarded(self):
        self.ingest_at(T1, [document(raw_data={"observed_at": "fact one"})])
        counts = self.ingest_at(T2, [document(raw_data={"observed_at": "fact two"})])
        self.assertEqual(counts["updated"], 1)
        self.assertEqual(self.store.get_document("document-1")["raw_data"], {"observed_at": "fact two"})

    def test_first_seen_is_stamped_after_lock_and_batch_processing(self):
        with patch("storage.document_store.utc_now", side_effect=[T1, T2, T3]):
            self.store.ingest(SOURCE, CATEGORY, [document()])
        self.assertEqual(self.store.get_document("document-1")["first_seen_at"], T3)
        run = self.rows("SELECT started_at,finished_at FROM document_source_runs")[0]
        self.assertEqual(run, {"started_at": T1, "finished_at": T3})

    def test_batch_validation_failure_rolls_back_partial_documents_and_success_run(self):
        self.ingest_at(T1, [document()])
        before = self.store.stats()
        with self.assertRaises(ValueError):
            self.store.ingest(SOURCE, CATEGORY, [document(document_id="new"),
                                                document(document_id="bad", published_at="2026-02-30")])
        self.assertEqual(self.store.stats(), before)
        self.assertIsNone(self.store.get_document("new"))
        self.assertIsNone(self.store.get_document("bad"))

    def test_misattributed_source_or_category_cannot_be_ingested(self):
        for record in (document(source="OTHER"), document(source_category="security_blog")):
            with self.assertRaises(ValueError):
                self.store.ingest(SOURCE, CATEGORY, [record])
        self.assertEqual(self.store.stats()["documents"], 0)
        self.assertEqual(self.store.stats()["latest_runs"], [])

    def test_document_id_cannot_be_overwritten_by_a_different_source(self):
        self.ingest_at(T1, [document()])
        with self.assertRaisesRegex(ValueError, "different source"):
            self.store.ingest("OTHER", CATEGORY, [document(source="OTHER")])
        self.assertEqual(self.store.get_document("document-1")["source"], SOURCE)
        self.assertEqual(len(self.rows("SELECT * FROM document_source_runs")), 1)

    def test_empty_and_failed_runs_retain_documents_and_prior_http_checkpoint(self):
        self.ingest_at(T1, [document()])
        self.store.save_http_state(SOURCE, '"version-1"', "Thu, 08 Oct 2026 00:00:00 GMT")
        original_state = self.store.get_http_state(SOURCE)
        self.store.record_failure(SOURCE, CATEGORY, "fixture network failure", T2)
        with self.assertRaisesRegex(ValueError, "successful"):
            self.store.save_http_state(SOURCE, '"incorrect-advance"')
        self.assertEqual(self.store.get_http_state(SOURCE), original_state)
        self.assertIsNotNone(self.store.get_document("document-1"))
        counts = self.ingest_at(T3, [])
        self.assertEqual(counts, {"fetched": 0, "inserted": 0, "updated": 0, "unchanged": 0})
        self.store.save_http_state(SOURCE, original_state["etag"], original_state["last_modified"])
        self.assertEqual(self.store.get_http_state(SOURCE)["etag"], original_state["etag"])
        self.assertEqual(self.store.get_http_state(SOURCE)["last_success_at"], T3)
        self.assertEqual(self.store.stats()["documents"], 1)
        self.assertEqual(self.store.stats()["latest_runs"][0]["status"], "success")

    def test_http_checkpoint_requires_success_and_retained_source_documents(self):
        with self.assertRaises(ValueError):
            self.store.save_http_state(SOURCE, '"premature"')
        self.ingest_at(T1, [])
        self.store.save_http_state(SOURCE, '"empty"')
        self.assertIsNone(self.store.get_http_state(SOURCE))
        self.ingest_at(T2, [document()])
        self.store.save_http_state(SOURCE, '"retained"')
        self.assertIsNotNone(self.store.get_http_state(SOURCE))
        with sqlite3.connect(self.db) as connection:
            connection.execute("DELETE FROM knowledge_documents")
        self.assertIsNone(self.store.get_http_state(SOURCE))

    def test_query_filters_cve_links_pagination_and_parameter_binding(self):
        self.ingest_at(T1, [document(document_id="one", cve_ids=["CVE-2026-1234"]),
                           document(document_id="two", content_type="standard")])
        self.assertEqual(len(self.store.list_documents(category=CATEGORY)), 2)
        self.assertEqual(self.store.list_documents(cve_id="cve-2026-1234")[0]["document_id"], "one")
        self.assertEqual(self.store.list_documents(content_type="standard")[0]["document_id"], "two")
        self.assertEqual(self.store.list_documents(source="' OR 1=1 --"), [])
        self.assertEqual(len(self.store.list_documents(limit=1, offset=1)), 1)
        for kwargs in ({"limit": 0}, {"offset": -1}, {"limit": True}):
            with self.assertRaises(ValueError):
                self.store.list_documents(**kwargs)

    def test_document_schema_is_additive_and_does_not_mutate_cve_tables(self):
        SQLiteIntelligenceStore(self.db)
        before = self.rows("SELECT name,sql FROM sqlite_master WHERE name IN ('source_items','unified_vulnerabilities','collector_runs','collector_state') ORDER BY name")
        SQLiteDocumentStore(self.db)
        self.ingest_at(T1, [document()])
        after = self.rows("SELECT name,sql FROM sqlite_master WHERE name IN ('source_items','unified_vulnerabilities','collector_runs','collector_state') ORDER BY name")
        self.assertEqual(before, after)
        self.assertEqual(self.rows("SELECT COUNT(*) n FROM source_items")[0]["n"], 0)
        self.assertEqual(self.rows("SELECT COUNT(*) n FROM collector_runs")[0]["n"], 0)

    def test_stats_count_real_categories_without_inventing_empty_coverage(self):
        self.ingest_at(T1, [document()])
        self.store.ingest("BLOG", "security_blog", [])
        stats = self.store.stats()
        self.assertEqual(stats["source_categories"], {CATEGORY: 1})
        self.assertEqual(stats["sources"], {SOURCE: 1})
        self.assertEqual(len(stats["latest_runs"]), 2)


if __name__ == "__main__":
    unittest.main()
