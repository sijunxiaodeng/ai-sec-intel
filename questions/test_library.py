import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collectors.library import SOURCES, parse_feed
from enrichment.documents import fetch_url
from rag.evidence import _connection
from rag.library import detail, documents, ingest_document, overview, search, sync


class LibraryTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.candidate = {"url": "https://research.example/ai-security", "source_id": "research",
                          "source_name": "Research", "document_type": "research_article"}
        self.text = "LLM prompt injection security research. This article mentions CVE-2024-37032 in related work. " * 3
        self.body = self.text.encode()

    def fetch(self, url):
        return {"body": self.body, "url": url, "content_type": "text/plain"}

    def ingest(self):
        return ingest_document(self.candidate, self.db, self.fetch)

    def test_general_document_does_not_create_cve_record(self):
        result = self.ingest()
        doc = detail(result["document_id"], self.db)
        self.assertEqual(doc["document_type"], "research_article")
        self.assertEqual(doc["associations"][0]["relation"], "identifier_mention")
        self.assertIn("不代表", doc["associations"][0]["reason"])
        self.assertTrue(all(row["cve_id"] == "" for row in doc["evidence"]))
        self.assertTrue(all(row["citation_id"].startswith(result["document_id"] + "/LIB-") for row in doc["evidence"]))
        with _connection(self.db) as conn:
            self.assertFalse(conn.execute("SELECT name FROM sqlite_master WHERE name='records'").fetchone())

    def test_repeat_is_idempotent_and_raw_snapshot_has_checksum(self):
        first = self.ingest()
        ids = {r["evidence_id"] for r in detail(first["document_id"], self.db)["evidence"]}
        again = self.ingest()
        self.assertFalse(again["changed"])
        self.assertEqual(len(documents(self.db)), 1)
        self.assertEqual(ids, {r["evidence_id"] for r in detail(first["document_id"], self.db)["evidence"]})
        with _connection(self.db) as conn:
            sha, body = conn.execute("SELECT digest,body FROM library_snapshots").fetchone()
        self.assertEqual(sha, hashlib.sha256(body).hexdigest())

    def test_changed_source_replaces_chunks_and_preserves_first_seen(self):
        first = self.ingest()
        before = detail(first["document_id"], self.db)
        self.body = b"LLM security: malicious pickle model deserialization supply chain attacks." * 4
        self.assertTrue(self.ingest()["changed"])
        after = detail(first["document_id"], self.db)
        self.assertEqual(before["first_seen_at"], after["first_seen_at"])
        self.assertNotEqual(before["text_sha256"], after["text_sha256"])
        self.assertEqual(after["associations"], [])
        self.assertNotIn("prompt injection", " ".join(r["text"] for r in after["evidence"]))

    def test_refresh_error_retains_last_good_document_and_evidence(self):
        first = self.ingest()
        before = detail(first["document_id"], self.db)
        def fail(url):
            raise TimeoutError("timed out")
        error = ingest_document(self.candidate, self.db, fail)
        self.assertEqual(error["status"], "error")
        self.assertTrue(error["retained_previous"])
        after = detail(first["document_id"], self.db)
        self.assertEqual(after["text_sha256"], before["text_sha256"])
        self.assertTrue(after["retained_previous"])
        self.assertEqual(after["latest_attempt_status"], "error")

    def test_changed_chunk_cannot_be_returned_as_original_evidence(self):
        result = self.ingest()
        with _connection(self.db) as conn:
            eid, payload = conn.execute("SELECT evidence_id,payload FROM evidence LIMIT 1").fetchone()
            row = json.loads(payload)
            row["text"] = "Invented LLM prompt injection conclusion"
            conn.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(row), eid))
        doc = detail(result["document_id"], self.db)
        self.assertEqual(doc["integrity_status"], "incomplete_or_invalid")
        self.assertFalse(any(r["evidence_id"] == eid for r in doc["evidence"]))

    def test_changed_snapshot_cannot_be_used_for_retrieval(self):
        self.ingest()
        with _connection(self.db) as conn:
            conn.execute("UPDATE library_snapshots SET body=?", (b"modified original",))
        self.assertEqual(search("prompt injection", db_path=self.db)["evidence"], [])

    def test_irrelevant_body_rejected_not_just_source_title(self):
        self.body = b"This is an article about new staff and office events. " * 5
        self.candidate["title"] = "AI security"
        self.assertEqual(self.ingest()["status"], "error")
        self.assertEqual(documents(self.db), [])

    def test_keyword_and_cve_filters_do_not_expand_topic_into_vulnerability(self):
        self.ingest()
        with patch("rag.library._dense", side_effect=RuntimeError()):
            self.assertTrue(search("提示注入", db_path=self.db)["evidence"])
            self.assertTrue(search("CVE-2024-37032", db_path=self.db)["evidence"])
            self.assertFalse(search("CVE-2025-0312 提示注入", db_path=self.db)["evidence"])
            self.assertFalse(search("提示注入", document_type="academic_paper", db_path=self.db)["evidence"])

    def test_specific_security_topic_does_not_return_generic_ai_risk_paragraph(self):
        self.body = b"LLM security risk management framework describes general governance risks. " * 4
        self.ingest()
        with patch("rag.library._dense", return_value=[]):
            self.assertFalse(search("间接提示注入", db_path=self.db)["evidence"])
        self.body = b"LLM security framework describes indirect prompt\ninjection in retrieved content. " * 4
        self.ingest()
        with patch("rag.library._dense", return_value=[]):
            self.assertTrue(search("间接提示注入", db_path=self.db)["evidence"])

    def test_hybrid_uses_same_candidate_filters_and_ids(self):
        self.ingest()
        row = detail(documents(self.db)[0]["document_id"], self.db)["evidence"][0]
        with patch("rag.library._dense", return_value=[dict(row, cosine_score=0.8)]):
            result = search("prompt injection", db_path=self.db)
        self.assertEqual(result["mode"], "hybrid")
        self.assertEqual(set(result["evidence"][0]["channels"]), {"bm25", "dense"})

    def test_paper_without_cve_is_abstract_and_retains_authors(self):
        candidate = dict(self.candidate, url="https://arxiv.org/abs/2302.12173", document_type="academic_paper")
        self.body = ('<html><head><meta name="citation_title" content="Indirect prompt injection attacks">'
                     '<meta name="citation_author" content="Author A"><meta name="citation_date" content="2023/02/23">'
                     '<meta name="citation_pdf_url" content="https://arxiv.org/pdf/2302.12173"></head><body>'
                     '<blockquote class="abstract mathjax">Abstract: ' + "LLM applications are vulnerable to indirect prompt injection attacks through retrieved documents. " * 3 + '</blockquote></body></html>').encode()
        result = ingest_document(candidate, self.db, self.fetch)
        self.assertEqual(result["status"], "ok")
        doc = detail(result["document_id"], self.db)
        self.assertEqual(doc["content_scope"], "abstract")
        self.assertEqual(doc["authors"], ["Author A"])
        self.assertEqual(doc["associations"], [])
        self.assertTrue(any(row["locator"].startswith("abstract；") for row in doc["evidence"]))

    def test_vendor_declared_cve_and_ghsa_only_are_both_supported(self):
        candidate = dict(self.candidate, url="https://github.com/vllm-project/vllm/security/advisories/GHSA-test-test-test", document_type="vendor_advisory")
        payload = {"html_url": candidate["url"], "ghsa_id": "GHSA-test-test-test", "state": "published",
                   "summary": "vLLM security", "description": "Denial of service", "cve_id": "CVE-2025-10000",
                   "vulnerabilities": [{"package": {"name": "vllm"}, "vulnerable_version_range": "<1.0", "patched_versions": ">=1.0"}]}
        def fetch_json(url):
            return {"body": json.dumps(payload).encode(), "url": url, "content_type": "application/json"}
        result = ingest_document(candidate, self.db, fetch_json)
        doc = detail(result["document_id"], self.db)
        self.assertEqual(doc["associations"][0]["relation"], "publisher_declared_identifier")
        self.assertTrue(any(r["locator"].startswith("vulnerabilities；") for r in doc["evidence"]))
        payload["cve_id"] = None
        ingest_document(candidate, self.db, fetch_json)
        self.assertEqual(detail(result["document_id"], self.db)["associations"], [])
        payload["html_url"] = "https://github.com/other/repo/security/advisories/GHSA-wrong"
        self.assertEqual(ingest_document(candidate, self.db, fetch_json)["status"], "error")

    def test_rss_topic_filter_and_host_allowlist(self):
        source = SOURCES[2]
        body = b'<rss><channel><item><title>LLM prompt injection security</title><link>https://blog.trailofbits.com/good/</link></item><item><title>LLM security</title><link>https://evil.example/article</link></item><item><title>Office news</title><link>https://blog.trailofbits.com/news/</link></item></channel></rss>'
        rows = parse_feed(source, {"body": body})
        self.assertEqual([r["url"] for r in rows], ["https://blog.trailofbits.com/good/"])

    def test_atom_has_no_cve_requirement_and_rejects_unrelated(self):
        body = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>http://arxiv.org/abs/2601.00001v1</id><title>LLM prompt injection</title><summary>security attacks</summary></entry><entry><id>http://arxiv.org/abs/2601.00002</id><title>Astronomy</title><summary>Stars</summary></entry></feed>'
        rows = parse_feed(SOURCES[3], {"body": body})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["url"], "https://arxiv.org/abs/2601.00001v1")

    def test_dtd_or_invalid_json_not_treated_as_empty_success(self):
        with self.assertRaises(ValueError):
            parse_feed(SOURCES[2], {"body": b'<!DOCTYPE rss [<!ENTITY x "hi">]><rss/>'})
        with self.assertRaises(ValueError):
            parse_feed(SOURCES[0], {"body": b'{"message":"rate limited"}'})
        with self.assertRaises(ValueError):
            parse_feed(SOURCES[2], {"body": b'<html><body>Access denied</body></html>'})

    def test_sync_source_failure_is_visible_and_other_source_continues(self):
        source = SOURCES[2]
        feed = b'<rss><channel><item><title>LLM prompt injection</title><link>https://blog.trailofbits.com/good/</link></item></channel></rss>'
        def fetcher(url):
            if url == SOURCES[0]["url"]:
                raise TimeoutError("source unavailable")
            return {"body": feed if url == source["url"] else self.body, "url": url, "content_type": "text/plain"}
        with patch("rag.library.update_index", return_value={"status": "deferred"}):
            result = sync(self.db, sources=(SOURCES[0], source), seeds=(), fetcher=fetcher)
        self.assertEqual(result["ok"], 1)
        self.assertEqual(result["sources"][0]["status"], "error")
        self.assertEqual(overview(self.db)["source_categories"], ["research"])
        with _connection(self.db) as conn:
            sha, body = conn.execute("SELECT digest,body FROM library_feeds").fetchone()
        self.assertEqual(hashlib.sha256(body).hexdigest(), sha)

    def test_api_type_validation_and_detail_not_found(self):
        from fastapi.testclient import TestClient
        from api.app import app
        client = TestClient(app)
        with patch("rag.library.LIBRARY_DB", self.db), patch("rag.library.documents", return_value=[]), patch("rag.library.overview", return_value={}):
            self.assertEqual(client.get("/api/library").status_code, 200)
            self.assertEqual(client.get("/api/library?document_type=wrong").status_code, 422)
        self.assertEqual(client.get("/api/library/search?q=hello&top_k=0").status_code, 422)
        self.assertEqual(client.post("/api/library/sync", json={"per_source": 9}).status_code, 422)
        self.assertEqual(client.get("/api/library/unknown").status_code, 404)
        with patch("rag.library.sync", side_effect=ValueError("busy")):
            self.assertEqual(client.post("/api/library/sync", json={}).status_code, 409)

    def test_repository_advisory_fetch_url_uses_official_endpoint(self):
        self.assertEqual(fetch_url("https://github.com/vllm-project/vllm/security/advisories/GHSA-abcd-efgh-ijkl"),
                         "https://api.github.com/repos/vllm-project/vllm/security-advisories/GHSA-abcd-efgh-ijkl")


class LibraryScheduleTest(unittest.TestCase):
    def run_with(self, error=False):
        from automation.schedule import run_once
        with patch("agents.orchestrator.run_collect", side_effect=TimeoutError("NVD unavailable") if error else None, return_value={"records": []}), \
             patch("rag.library.sync", return_value={"ok": 2, "attempted": 3, "sources": []}) as library, \
             patch("automation.schedule.ensure_state", return_value={}), patch("automation.schedule._write_state"), patch("automation.schedule.log_line"):
            if error:
                with self.assertRaises(TimeoutError):
                    run_once()
            else:
                run_once()
            library.assert_called_once_with(include_seeds=False)

    def test_schedule_syncs_library_after_success(self):
        self.run_with()

    def test_schedule_syncs_library_even_if_vulnerability_collect_fails(self):
        self.run_with(error=True)
