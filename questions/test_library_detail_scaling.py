"""Single-document checks stay bounded while raw-snapshot integrity remains live."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rag import library
from rag.evidence import _connection
from questions.test_reference_text import response


class LibraryDetailScalingTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / "library.sqlite3"
        candidate = {"url": "https://research.example/detail-fixture", "document_type": "research_article",
                     "source_name": "Synthetic research", "source_id": "fixture"}
        source = "A synthetic AI security boundary retains original evidence for source verification. " * 8
        item = library.ingest_document(candidate, self.db, lambda url: response(url, source, "text/plain"))
        self.identifier = item["document_id"]
        self.assertEqual(item["status"], "ok")

    def test_unrelated_library_size_does_not_multiply_metadata_decoding(self):
        original_loads = json.loads
        with patch.object(library.json, "loads", wraps=original_loads) as decode:
            before = library.detail(self.identifier, self.db)
            baseline_calls = decode.call_count
        with _connection(self.db) as conn:
            for index in range(400):
                identifier = "DOC-" + hashlib.sha256(str(index).encode()).hexdigest()[:16]
                data = {"document_id": identifier, "document_type": "research_article", "title": "Unrelated fixture",
                        "published_at": "2026-01-01", "text": "large metadata fixture " * 100}
                conn.execute("INSERT INTO library_documents VALUES (?,?)", (identifier, json.dumps(data)))
                conn.execute("INSERT INTO library_attempts VALUES (?,?)",
                             (identifier, json.dumps({"document_id": identifier, "status": "ok"})))
        with patch.object(library.json, "loads", wraps=original_loads) as decode:
            after = library.detail(self.identifier, self.db)
            expanded_calls = decode.call_count
        self.assertEqual(after, before)
        self.assertLessEqual(expanded_calls, baseline_calls + 2,
                             "unrelated metadata must not be decoded on each document recheck")

    def test_failed_attempt_and_child_links_preserve_metadata_and_order(self):
        with _connection(self.db) as conn:
            conn.execute("INSERT OR REPLACE INTO library_attempts VALUES (?,?)",
                         (self.identifier, json.dumps({"document_id": self.identifier, "status": "error"})))
            for index, date in enumerate(("2026-01-01", "2026-02-01")):
                identifier = "DOC-" + str(index + 1) * 16
                child = {"document_id": identifier, "parent_document_id": self.identifier,
                         "published_at": date, "content_scope": "full_text_html"}
                conn.execute("INSERT INTO library_documents VALUES (?,?)", (identifier, json.dumps(child)))
                conn.execute("INSERT INTO library_attempts VALUES (?,?)",
                             (identifier, json.dumps({"document_id": identifier, "status": "error" if index else "ok"})))
        result = library.detail(self.identifier, self.db)
        self.assertEqual(result["integrity_status"], "ok")
        self.assertEqual(result["latest_attempt_status"], "error")
        self.assertTrue(result["retained_previous"])
        children = result["full_text_documents"]
        self.assertEqual([row["published_at"] for row in children], ["2026-02-01", "2026-01-01"])
        self.assertTrue(children[0]["retained_previous"])
        self.assertFalse(children[1]["retained_previous"])

    def test_repeat_detail_detects_raw_snapshot_corruption_without_a_cached_verdict(self):
        good = library.detail(self.identifier, self.db)
        self.assertEqual(good["integrity_status"], "ok")
        self.assertTrue(good["evidence"])
        with _connection(self.db) as conn:
            conn.execute("UPDATE library_snapshots SET body=? WHERE document_id=?",
                         (b"changed without changing the digest", self.identifier))
        bad = library.detail(self.identifier, self.db)
        self.assertEqual(bad["integrity_status"], "incomplete_or_invalid")
        self.assertEqual(bad["evidence"], [])


if __name__ == "__main__":
    unittest.main()
