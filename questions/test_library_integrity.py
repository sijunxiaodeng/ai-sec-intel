"""Real archived bytes outrank mutable index text, hashes, IDs and metadata."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collectors.reference import REFERENCE_SOURCES
from enrichment.documents import digest
from rag.evidence import _connection
from rag.library import detail, ingest_document, search
from questions.test_reference_text import policy_body, response


TEXT = "AI security research describes prompt injection through untrusted retrieved documents. " * 5
FORGED = "AI security FORGED_INDEX_FACT claims every audit record is deleted by Zephyr erasure."


class LibraryIntegrityTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.url = "https://research.example/archive"
        for target in ("urllib.request.urlopen", "requests.sessions.Session.request", "rag.library._dense"):
            patcher = patch(target, side_effect=AssertionError("Unexpected live IO"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def ingest(self, kind="research_article", *, url=None, body=None, media="text/plain", encoding=None, **extra):
        candidate = {"url": url or self.url, "document_type": kind, "source_name": "Offline fixture", "source_id": "offline", **extra}
        def fetcher(fetch_url):
            result = response(fetch_url, body if body is not None else TEXT, media)
            if encoding:
                result["encoding"] = encoding
            return result
        result = ingest_document(candidate, self.db, fetcher)
        self.assertEqual(result["status"], "ok", result)
        doc = detail(result["document_id"], self.db)
        self.assertEqual(doc["integrity_status"], "ok", doc)
        return doc

    def alter_chunk(self, doc, **changes):
        row = dict(doc["evidence"][0], **changes)
        with _connection(self.db) as con:
            before = con.execute("SELECT digest,body FROM library_snapshots WHERE document_id=?", (doc["document_id"],)).fetchone()
            con.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(row), doc["evidence"][0]["evidence_id"]))
            after = con.execute("SELECT digest,body FROM library_snapshots WHERE document_id=?", (doc["document_id"],)).fetchone()
        self.assertEqual(before, after)
        return row

    def test_all_six_document_kinds_reject_rehashed_index_text(self):
        advisory_url = "https://github.com/fixture/fixture/security/advisories/GHSA-abcd-efgh-ijkl"
        advisory = json.dumps({"ghsa_id": "GHSA-abcd-efgh-ijkl", "html_url": advisory_url,
                               "summary": "AI security advisory", "description": TEXT, "published_at": "2026-10-01T00:00:00Z"})
        abstract = '<html><head><meta name="citation_title" content="AI security research"></head><body><blockquote class="abstract">' + TEXT + '</blockquote></body></html>'
        policy = REFERENCE_SOURCES[0]
        standard = REFERENCE_SOURCES[-1]
        catalog = "中文标准名称：\n网络安全技术 生成式人工智能服务安全基本要求\n标准状态：\n现行\n发布日期\n2025-04-25\n实施日期\n2025-11-01\n发布单位\n国家市场监督管理总局、国家标准化管理委员会"
        cases = [
            ("research_article", self.url, TEXT, "text/plain"),
            ("vendor_guidance", self.url + "-guidance", TEXT, "text/plain"),
            ("vendor_advisory", advisory_url, advisory, "application/json"),
            ("academic_paper", "https://arxiv.org/abs/2302.12173", abstract, "text/html"),
            ("policy", policy["url"], json.dumps({"title": policy["expected_title"], "description": policy_body(policy)}), "application/json"),
            ("standard", standard["url"], json.dumps({"title": standard["expected_title"], "description": catalog}), "application/json"),
        ]
        for kind, url, body, media in cases:
            with self.subTest(kind=kind):
                doc = self.ingest(kind, url=url, body=body, media=media)
                changed = self.alter_chunk(doc, text=FORGED, text_sha256=digest(FORGED))
                self.assertEqual(changed["source_response_sha256"], doc["source_response_sha256"])
                invalid = detail(doc["document_id"], self.db)
                self.assertEqual(invalid["integrity_status"], "incomplete_or_invalid")
                self.assertNotIn(changed["evidence_id"], {row["evidence_id"] for row in invalid["evidence"]})
                self.assertFalse(any(row["text"] == FORGED for row in search("FORGED_INDEX_FACT", db_path=self.db)["evidence"]))

    def test_locator_and_citation_cannot_be_rebound_while_text_hash_stays_valid(self):
        doc = self.ingest()
        for changes in ({"locator": "forged page 999"}, {"citation_id": doc["evidence"][0]["citation_id"] + "-fake"}):
            with self.subTest(changes=changes):
                self.alter_chunk(doc, **changes)
                current = detail(doc["document_id"], self.db)
                self.assertEqual(current["integrity_status"], "incomplete_or_invalid")
                self.assertEqual(current["evidence"], [])

    def test_title_changed_in_both_document_and_index_does_not_match_raw_bytes(self):
        doc = self.ingest()
        with _connection(self.db) as con:
            stored = json.loads(con.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc["document_id"],)).fetchone()[0])
            stored["title"] = "Forged source title"
            con.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(stored), doc["document_id"]))
        self.alter_chunk(doc, title="Forged source title")
        current = detail(doc["document_id"], self.db)
        self.assertEqual(current["integrity_status"], "incomplete_or_invalid")
        self.assertEqual(current["evidence"], [])

    def test_forged_chunk_id_in_sql_and_payload_cannot_impersonate_original_chunk(self):
        doc = self.ingest()
        row = dict(doc["evidence"][0])
        old_id = row["evidence_id"]
        row.update(evidence_id="LIB-fake-id", citation_id=doc["document_id"] + "/LIB-fake-id")
        with _connection(self.db) as con:
            con.execute("UPDATE evidence SET evidence_id=?,payload=? WHERE evidence_id=?", (row["evidence_id"], json.dumps(row), old_id))
        current = detail(doc["document_id"], self.db)
        self.assertEqual(current["integrity_status"], "incomplete_or_invalid")
        self.assertEqual(current["evidence"], [])

    def test_subscription_date_keeps_its_provenance_when_raw_has_no_date(self):
        doc = self.ingest(published_at="2026-10-10T00:00:00Z")
        self.assertEqual(doc["published_at_basis"], "subscription_metadata")
        self.assertEqual(doc["published_at"], "2026-10-10T00:00:00Z")
        self.assertTrue(doc["evidence"])

    def test_stored_source_encoding_reparses_non_utf8_bytes(self):
        text = "AI security 提示注入研究：外部文档可能含有恶意指令。" * 20
        doc = self.ingest(body=text.encode("gb18030"), encoding="gb18030")
        self.assertEqual(doc["source_encoding"], "gb18030")
        self.assertEqual(doc["text_sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertIn("提示注入研究", doc["evidence"][0]["text"])

    def test_legacy_utf8_rows_without_encoding_still_reparse(self):
        doc = self.ingest()
        with _connection(self.db) as con:
            stored = json.loads(con.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc["document_id"],)).fetchone()[0])
            stored.pop("source_encoding")
            con.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(stored), doc["document_id"]))
            row = dict(doc["evidence"][0])
            row.pop("source_encoding")
            con.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(row), row["evidence_id"]))
        self.assertEqual(detail(doc["document_id"], self.db)["integrity_status"], "ok")


if __name__ == "__main__":
    unittest.main()
