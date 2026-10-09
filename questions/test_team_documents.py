"""Cross-service summary boundaries, real storage and citation behavior."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from agents.library_qa import run
from collectors.team_documents import TEAM_MEDIA, TeamDocumentCollector, parse_record, team_id
from enrichment.documents import digest
from enrichment.relation_candidates import source_documents
from rag.evidence import _connection
from rag.library import detail, documents, full_text, ingest_document, search, sync_team, verified_sources
from questions.test_reference_text import html_paper, response


def record(category="security_blog", number=1):
    return {"document_id": "doc-" + hashlib.sha256(str(number).encode()).hexdigest(),
        "source": "SYNTHETIC_" + category.upper(), "source_category": category, "content_type": category,
        "title": "Synthetic LLM security " + str(number),
        "description": "Synthetic LLM prompt injection research summary. Retrieved documents may contain untrusted instructions.",
        "url": "https://research.example/" + str(number), "published_at": "2026-10-08",
        "modified_at": None, "first_seen_at": "2026-10-09T01:00:00Z",
        "content_updated_at": "2026-10-09T01:00:00Z", "cve_ids": ["CVE-2099-99999"]}


class FixtureCollector(TeamDocumentCollector):
    def __init__(self, rows, max_documents=30):
        super().__init__(max_documents=max_documents)
        self.rows, self.failed, self.paths = rows, set(), []

    def get(self, path):
        self.paths.append(path)
        if path in self.failed:
            raise TimeoutError("Synthetic fixture failure")
        query = parse_qs(urlsplit(path).query)
        if query:
            offset, limit = int(query["offset"][0]), int(query["limit"][0])
            obj = {"total": len(self.rows), "items": self.rows[offset:offset + limit]}
        else:
            obj = next(r for r in self.rows if path.endswith(r["document_id"]))
        return {"body": json.dumps(obj).encode(), "url": self.base_url + path,
                "content_type": TEAM_MEDIA, "retrieved_at": "2026-10-09T02:00:00Z"}


class TeamDocumentsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.rows = [record(c, i) for i, c in enumerate(("security_blog", "academic_paper", "technical_standard", "policy_regulation"), 1)]
        self.collector = FixtureCollector(self.rows)

    def sync(self):
        return sync_team(self.db, collector=self.collector)

    def test_four_types_store_api_snapshots_and_valid_citations(self):
        result = self.sync()
        self.assertEqual(result["ok"], 4)
        self.assertEqual({r["document_type"] for r in documents(self.db)}, {"research_article", "academic_paper", "standard", "policy"})
        for row in self.rows:
            doc = detail(team_id(row["document_id"]), self.db)
            self.assertEqual(doc["integrity_status"], "ok")
            self.assertEqual(doc["content_scope"], "team_summary")
            self.assertEqual(doc["published_at"], row["published_at"])
            self.assertEqual(doc["team_content_updated_at"], row["content_updated_at"])
            self.assertEqual(doc["associations"], [])  # API CVE tags alone are not source statements.
        with _connection(self.db) as conn:
            for sha, body in conn.execute("SELECT digest,body FROM library_snapshots"):
                self.assertEqual(sha, hashlib.sha256(body).hexdigest())
                self.assertIn("document_id", json.loads(body))

    def test_repeat_import_is_idempotent(self):
        self.sync()
        before = detail(team_id(self.rows[0]["document_id"]), self.db)
        result = self.sync()
        after = detail(before["document_id"], self.db)
        self.assertEqual(result["changed"], 0)
        self.assertEqual(len(documents(self.db)), 4)
        self.assertEqual(before["first_seen_at"], after["first_seen_at"])
        self.assertEqual([(r["citation_id"], r["text_sha256"], r["source_response_sha256"]) for r in before["evidence"]],
                         [(r["citation_id"], r["text_sha256"], r["source_response_sha256"]) for r in after["evidence"]])

    def test_changed_summary_replaces_old_evidence_and_preserves_first_seen(self):
        self.sync()
        before = detail(team_id(self.rows[0]["document_id"]), self.db)
        self.rows[0]["description"] = "Synthetic LLM security model supply chain pickle risk."
        self.rows[0]["content_updated_at"] = "2026-10-09T03:00:00Z"
        result = self.sync()
        after = detail(before["document_id"], self.db)
        self.assertEqual(result["changed"], 1)
        self.assertEqual(before["first_seen_at"], after["first_seen_at"])
        self.assertNotEqual(before["text_sha256"], after["text_sha256"])
        self.assertEqual(after["integrity_status"], "ok")

    def test_same_url_does_not_overwrite_original_article(self):
        row = self.rows[0]
        stored = ingest_document({"url": row["url"], "document_type": "research_article", "source_name": "Synthetic original", "source_id": "fixture"},
            self.db, lambda url: response(url, "Original LLM security prompt injection research. " * 5, "text/plain"))
        before = detail(stored["document_id"], self.db)
        self.sync()
        after = detail(stored["document_id"], self.db)
        self.assertEqual(after["text_sha256"], before["text_sha256"])
        self.assertEqual(after["content_scope"], "article_body")
        self.assertNotEqual(stored["document_id"], team_id(row["document_id"]))

    def test_api_outage_retains_existing_sources(self):
        self.sync()
        before = documents(self.db)
        with patch.object(self.collector, "collect", side_effect=ConnectionError("Synthetic outage")):
            result = self.sync()
        self.assertEqual(result["status"], "error")
        self.assertEqual(documents(self.db), before)
        self.assertTrue(search("prompt injection", db_path=self.db)["evidence"])

    def test_one_detail_failure_is_partial_and_retains_last_snapshot(self):
        self.sync()
        row = self.rows[0]
        before = detail(team_id(row["document_id"]), self.db)
        self.collector.failed.add("/api/documents/" + row["document_id"])
        result = self.sync()
        after = detail(before["document_id"], self.db)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["ok"], 3)
        self.assertEqual(after["text_sha256"], before["text_sha256"])
        self.assertTrue(after["retained_previous"])

    def test_invalid_record_does_not_stop_valid_details(self):
        self.rows[0]["source_category"] = "unknown"
        result = self.sync()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["ok"], 3)

    def test_bounded_window_reports_remaining_records(self):
        result = sync_team(self.db, collector=FixtureCollector(self.rows, max_documents=2))
        self.assertEqual(result["ok"], 2)
        self.assertEqual(result["source"]["remaining"], 2)

    def test_pagination_reads_second_page(self):
        fixture = FixtureCollector([record(number=i) for i in range(101)], max_documents=150)
        result = fixture.collect()
        self.assertEqual(len(result["candidates"]), 101)
        self.assertIn("offset=100", fixture.paths[1])

    def test_bad_pagination_cannot_be_imported_as_partial_success(self):
        for page in ({"total": True, "items": []}, {"total": 1, "items": []}, {"total": 1, "items": self.rows[:2]}):
            with self.subTest(page=page):
                with patch.object(self.collector, "get", return_value={"body": json.dumps(page).encode()}):
                    result = self.sync()
                self.assertEqual(result["status"], "error")
                self.assertEqual(documents(self.db), [])

    def test_duplicate_or_changed_pagination_rejected(self):
        duplicate = FixtureCollector([self.rows[0], self.rows[0]])
        with self.assertRaises(ValueError):
            duplicate.collect()
        fixture = FixtureCollector([record(number=i) for i in range(101)], max_documents=150)
        first = {"total": 101, "items": fixture.rows[:100]}
        second = {"total": 102, "items": fixture.rows[100:]}
        with patch.object(fixture, "get", side_effect=[{"body": json.dumps(p).encode()} for p in (first, second)]):
            with self.assertRaises(ValueError):
                fixture.collect()

    def test_invalid_record_urls_and_field_types_rejected(self):
        for update in ({"url": "https://127.0.0.1/private"}, {"url": "javascript:alert(1)"},
                       {"url": "https://user:password@example.org/a"}, {"published_at": 123},
                       {"description": ""}, {"document_id": "../unsafe"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                parse_record(json.dumps(dict(self.rows[0], **update)).encode())
        for base in ("https://example.org", "http://localhost", "http://127.0.0.1/other"):
            with self.assertRaises(ValueError):
                TeamDocumentCollector(base_url=base)

    def test_team_summary_qa_keeps_scope_and_never_attempts_model(self):
        self.sync()
        ids = [team_id(r["document_id"]) for r in self.rows]
        with patch("agents.library_qa.configured", return_value=True), patch("agents.library_qa.chat") as model:
            result = run("prompt injection", document_ids=ids, db_path=self.db)
        model.assert_not_called()
        self.assertFalse(result["model_attempted"])
        self.assertIn("接口字段摘录", result["answer"])
        self.assertIn("非原始全文", result["answer"])
        self.assertEqual({r["document_id"] for r in result["evidence"]}, set(ids))

    def test_forged_excerpt_even_with_matching_text_hash_is_rejected(self):
        self.sync()
        with _connection(self.db) as conn:
            eid, payload = conn.execute("SELECT evidence_id,payload FROM evidence LIMIT 1").fetchone()
            row = json.loads(payload)
            row["text"] = "Forged LLM prompt injection finding."
            row["text_sha256"] = digest(row["text"])
            conn.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(row), eid))
        self.assertFalse(any(r["evidence_id"] == eid for r in search("prompt injection", db_path=self.db)["evidence"]))

    def test_scope_or_format_tampering_cannot_promote_summary_to_fulltext(self):
        self.sync()
        doc_id = team_id(self.rows[0]["document_id"])
        with _connection(self.db) as conn:
            (payload,) = conn.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc_id,)).fetchone()
            doc = json.loads(payload)
            doc.update(content_type="text/html", content_scope="full_text_html")
            conn.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(doc), doc_id))
        self.assertEqual(detail(doc_id, self.db)["evidence"], [])

    def test_summaries_do_not_become_article_relation_or_vulnerability_facts(self):
        self.sync()
        self.assertEqual(source_documents("article_relations", [team_id(self.rows[0]["document_id"])], self.db), [])
        self.assertEqual(verified_sources(self.db), [])

    def test_paper_fulltext_is_explicit_and_separate_from_team_summary(self):
        row = self.rows[1]
        row["url"] = "https://arxiv.org/abs/2302.12173v2"
        self.sync()
        summary_id = team_id(row["document_id"])
        result = full_text(summary_id, self.db, lambda url: response(url, html_paper()))
        self.assertEqual(result["status"], "ok")
        self.assertNotEqual(result["document_id"], summary_id)
        self.assertEqual(detail(summary_id, self.db)["content_scope"], "team_summary")
        self.assertEqual(detail(result["document_id"], self.db)["content_scope"], "full_text_html")

    def test_api_route_validates_window_and_dispatches_without_client_base_url(self):
        from fastapi.testclient import TestClient
        from api.app import app
        with patch("rag.library.sync_team", return_value={"status": "ok", "ok": 4}) as imported:
            client = TestClient(app)
            self.assertEqual(client.post("/api/library/team-sync", json={"max_documents": 30}).status_code, 200)
            imported.assert_called_once_with(max_documents=30)
            self.assertEqual(client.post("/api/library/team-sync", json={"max_documents": 201}).status_code, 422)
            client.close()

    def test_explicit_article_fetch_stores_original_separately_and_makes_it_eligible(self):
        self.sync()
        summary_id = team_id(self.rows[0]["document_id"])
        result = full_text(summary_id, self.db, lambda url: response(url, "Original LLM security prompt injection discussion. " * 6, "text/plain"))
        original = detail(result["document_id"], self.db)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(original["content_scope"], "article_body")
        self.assertEqual(original["parent_document_id"], summary_id)
        self.assertEqual(detail(summary_id, self.db)["content_scope"], "team_summary")
        self.assertEqual([d["document_id"] for d in source_documents("article_relations", [original["document_id"]], self.db)], [original["document_id"]])

    def test_original_fetch_failure_keeps_team_summary_searchable(self):
        self.sync()
        summary_id = team_id(self.rows[0]["document_id"])
        before = detail(summary_id, self.db)
        with patch("rag.library.fetch", side_effect=TimeoutError("Synthetic source timeout")) as fetcher:
            result = full_text(summary_id, self.db, fetcher)
        self.assertEqual(result["status"], "error")
        self.assertEqual(detail(summary_id, self.db)["text_sha256"], before["text_sha256"])
        self.assertTrue(search("prompt injection", document_ids=[summary_id], db_path=self.db)["evidence"])


if __name__ == "__main__":
    unittest.main()
