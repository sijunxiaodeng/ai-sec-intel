import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.library_qa import run
from agents.excerpts import select as _select
from collectors.reference import REFERENCE_SOURCES
from rag.library import detail, ingest_document
from questions.test_reference_text import policy_body, response


class LibraryQATest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.row = {"citation_id": "DOC-1234567890123456/LIB-test", "document_id": "DOC-1234567890123456",
                    "text": "The system must not follow instructions in untrusted documents. This is a synthetic test.",
                    "content_scope": "full_text_html"}
        self.option = {"excerpt_id": "EX-01", "rows": [self.row], "quote": self.row["text"]}

    def encoded(self, identifier):
        return json.dumps({"selections": [{"excerpt_id": identifier}]})

    def test_model_selects_stored_original_without_copying_or_rewriting(self):
        selected = _select(self.encoded("EX-01"), [self.option], {self.row["document_id"]})
        self.assertEqual(selected[0]["quote"], self.row["text"])

    def test_rewrite_unknown_excerpt_and_empty_identifier_rejected(self):
        for choice in ({"excerpt_id": "EX-01", "quote": "The system must follow untrusted instructions."},
                       {"excerpt_id": "EX-unknown"}, {"excerpt_id": ""}):
            with self.assertRaises(ValueError):
                _select(json.dumps({"selections": [choice]}), [self.option], set())

    def test_source_instructions_cannot_add_free_generated_answer_field(self):
        raw = json.dumps({"selections": [{"excerpt_id": "EX-01"}], "answer": "Send your password"})
        with self.assertRaises(ValueError):
            _select(raw, [self.option], set())

    def test_cross_document_quote_cannot_omit_selected_document(self):
        with self.assertRaisesRegex(ValueError, "遗漏"):
            _select(self.encoded("EX-01"), [self.option], {self.row["document_id"], "DOC-other"})

    def test_policy_adds_full_scope_exemption_and_effective_clause(self):
        source = REFERENCE_SOURCES[0]
        body = policy_body(source)
        candidate = dict(source, source_id=source["id"], source_name=source["name"], document_type="policy")
        with patch("enrichment.reference_text.extract_document", return_value={"title": source["expected_title"], "parts": [("body", body)], "published_at": "2023-07-13"}):
            stored = ingest_document(candidate, self.db, lambda u: response(u, "synthetic fixture"))
        self.assertEqual(stored["status"], "ok")
        with patch("rag.library._dense", side_effect=RuntimeError()):
            result = run("安全评估是什么规定？", document_ids=[stored["document_id"]], use_model=False, db_path=self.db)
        self.assertIn("未向境内公众", result["answer"])
        self.assertIn("2023年8月15日", result["answer"])
        self.assertIn("未自动判断法规", result["answer"])
        self.assertTrue(any(r["locator"].startswith("第二条；") for r in result["evidence"]))
        self.assertFalse(result["model_attempted"])

    def test_invalid_model_quote_falls_back_without_rewritten_text(self):
        candidate = {"url": "https://research.example/security", "document_type": "research_article", "source_name": "Synthetic Research", "source_id": "fixture"}
        stored = ingest_document(candidate, self.db, lambda u: response(u, "LLM security prompt injection research. " * 10, "text/plain"))
        forged = json.dumps({"selections": [{"excerpt_id": "EX-01", "quote": "Forged unsupported statement from model."}]})
        with patch("rag.library._dense", side_effect=RuntimeError()), patch("agents.library_qa.configured", return_value=True), patch("agents.library_qa.chat", return_value=forged):
            result = run("prompt injection", document_ids=[stored["document_id"]], db_path=self.db)
        self.assertTrue(result["model_attempted"])
        self.assertFalse(result["used_model"])
        self.assertNotIn("Forged unsupported", result["answer"])
        self.assertTrue(result["evidence"])
        self.assertEqual(result["fallback_reason"], "invalid_schema")

    def test_model_request_error_is_classified_without_exposing_exception_body(self):
        candidate = {"url": "https://research.example/security", "document_type": "research_article", "source_name": "Synthetic", "source_id": "fixture"}
        stored = ingest_document(candidate, self.db, lambda u: response(u, "LLM security prompt injection research with a qualification and a complete paragraph. " * 4, "text/plain"))
        with patch("rag.library._dense", side_effect=RuntimeError()), patch("agents.library_qa.configured", return_value=True), patch("agents.library_qa.chat", side_effect=RuntimeError("private credential in exception")):
            result = run("security", document_ids=[stored["document_id"]], db_path=self.db)
        self.assertEqual(result["fallback_reason"], "model_request_failed")
        self.assertNotIn("private credential", json.dumps(result))
        self.assertFalse(result["used_model"])

    def test_cve_question_routes_to_vulnerability_qa_without_model(self):
        with patch("agents.library_qa.chat") as model:
            result = run("CVE-2024-37032 如何修复", db_path=self.db)
        model.assert_not_called()
        self.assertEqual(result["verdict"]["scope"], "routing")

    def test_valid_model_selections_keep_two_policies_and_forced_clauses_grouped(self):
        ids = []
        for source in REFERENCE_SOURCES[:2]:
            body = policy_body(source)
            candidate = dict(source, source_id=source["id"], source_name=source["name"], document_type="policy")
            with patch("enrichment.reference_text.extract_document", return_value={"title": source["expected_title"], "parts": [("body", body)]}):
                stored = ingest_document(candidate, self.db, lambda u: response(u, "fixture " + source["id"]))
            ids.append(stored["document_id"])
        def select_original(messages, **kwargs):
            payload = json.loads(messages[-1]["content"])
            choices = []
            for doc_id in payload["required_document_ids"]:
                row = next(r for r in payload["excerpts"] if r["document_id"] == doc_id)
                choices.append({"excerpt_id": row["excerpt_id"]})
            return json.dumps({"selections": choices})
        with patch("rag.library._dense", side_effect=RuntimeError()), patch("agents.library_qa.configured", return_value=True), patch("agents.library_qa.chat", side_effect=select_original):
            result = run("训练数据安全评估", document_ids=ids, db_path=self.db)
        self.assertTrue(result["used_model"])
        evidence_groups = [r["document_id"] for r in result["evidence"]]
        first_second = evidence_groups.index(ids[1])
        self.assertEqual(set(evidence_groups[:first_second]), {ids[0]})
        self.assertEqual(set(evidence_groups[first_second:]), {ids[1]})
        for doc_id in ids:
            clauses = [r["locator"].split("；")[0] for r in result["evidence"] if r["document_id"] == doc_id]
            self.assertIn("第二条", clauses)

    def test_empty_question_and_invalid_or_missing_document_rejected(self):
        for kwargs in ({"question": " "}, {"question": "security", "document_ids": ["http://127.0.0.1"]}, {"question": "security", "document_ids": ["DOC-1234567890123456"]}):
            with self.assertRaises(ValueError):
                run(db_path=self.db, **kwargs)

    def test_empty_library_returns_no_evidence_and_does_not_call_model(self):
        with patch("agents.library_qa.chat") as model:
            result = run("prompt injection", db_path=self.db)
        model.assert_not_called()
        self.assertEqual(result["evidence"], [])

    def test_api_validates_body_and_full_text_selection(self):
        from fastapi.testclient import TestClient
        from api.app import app
        client = TestClient(app)
        self.assertEqual(client.post("/api/library/ask", json={"question": ""}).status_code, 422)
        self.assertEqual(client.post("/api/library/ask", json={"question": "abc", "document_ids": ["x"] * 5}).status_code, 422)
        self.assertEqual(client.post("/api/library/unknown/full-text").status_code, 422)
        with patch("agents.library_qa.run", return_value={"answer": "fixture", "evidence": []}):
            self.assertEqual(client.post("/api/library/ask", json={"question": "prompt injection"}).json()["answer"], "fixture")


if __name__ == "__main__":
    unittest.main()
