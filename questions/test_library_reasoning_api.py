"""Actual ASGI contracts for optional reasoning; all documents and models are offline."""
import importlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from agents.library_qa import run as actual_run
from rag.library import ingest_document
from questions.test_reference_text import response


class LibraryReasoningApiTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / "library.sqlite3"
        self.ids = []
        for n in range(4):
            candidate = {"url":"https://research.example/api-fixture-%d" % n,
                         "document_type":"research_article", "source_name":"Synthetic API fixture",
                         "source_id":"fixture-%d" % n}
            text = "Zephyr cache follows Orion protocol. This synthetic AI security document describes cache protection controls for a hypothetical service. "
            item = ingest_document(candidate, self.db, lambda url: response(url, text * 4, "text/plain"))
            self.assertEqual(item["status"], "ok")
            self.ids.append(item["document_id"])
        def dispatch(question, **kwargs):
            kwargs.setdefault("db_path", self.db)
            return actual_run(question, **kwargs)
        self.patches = [patch("agents.library_qa.run", side_effect=dispatch),
                        patch("agents.library_qa.configured", return_value=False),
                        patch("agents.general_reasoning.configured", return_value=False),
                        patch("agents.library_qa.chat"), patch("agents.general_reasoning.chat"),
                        patch("rag.library._dense", side_effect=RuntimeError()),
                        patch("urllib.request.urlopen", side_effect=AssertionError("network disabled"))]
        self.mocks = [item.start() for item in self.patches]
        for item in self.patches:
            self.addCleanup(item.stop)
        self.client = TestClient(importlib.import_module("api.app").app, raise_server_exceptions=True)

    def ask(self, **kwargs):
        body = {"question":"Zephyr cache protection", "document_ids":[self.ids[0]], "use_model":False}
        body.update(kwargs)
        return self.client.post("/api/library/ask", json=body)

    def assert_no_models(self):
        self.mocks[3].assert_not_called()
        self.mocks[4].assert_not_called()

    def test_default_mode_keeps_the_existing_exact_excerpt_contract(self):
        response = self.ask()
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["answer_scope"], "retrieved_excerpts")
        self.assertIn("原文摘录", result["answer"])
        self.assertNotIn("reasoning_mode", result)
        self.assertNotIn("mode", self.mocks[0].call_args.kwargs)
        self.assert_no_models()

    def test_invalid_mode_is_422_before_any_backend_call(self):
        for mode in ["execute_shell", "excerpt", "", None]:
            with self.subTest(mode=mode):
                self.assertEqual(self.ask(mode=mode).status_code, 422)
        self.mocks[0].assert_not_called()
        self.assert_no_models()

    def test_reasoning_with_model_disabled_preserves_excerpts_and_declares_fallback(self):
        result = self.ask(mode="reasoning").json()
        self.assertEqual(result["reasoning_mode"], "reasoning")
        self.assertEqual(result["reasoning_status"], "fallback")
        self.assertEqual(result["fallback_reason"], "model_disabled")
        self.assertFalse(result["model_attempted"])
        self.assertFalse(result["used_model"])
        self.assertEqual(result["model_calls"], 0)
        self.assertIn("原文摘录", result["answer"])
        self.assert_no_models()

    def test_unconfigured_model_returns_current_excerpt_fallback(self):
        response = self.ask(mode="reasoning", use_model=True)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["fallback_reason"], "model_not_configured")
        self.assertFalse(result["model_attempted"])
        self.assertIn("原文摘录", result["answer"])
        self.assert_no_models()

    def test_cve_question_uses_the_existing_routing_guard_even_in_reasoning_mode(self):
        with patch("agents.general_reasoning.run") as reasoner:
            response = self.ask(question="CVE-2024-37032 的修复版本是什么？", mode="reasoning", use_model=True)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["verdict"]["scope"], "routing")
        self.assertIn("情报问答", result["answer"])
        self.assertEqual(result["evidence"], [])
        reasoner.assert_not_called()
        self.assert_no_models()

    def test_four_selected_documents_are_supported_and_five_are_rejected(self):
        response = self.ask(mode="reasoning", document_ids=self.ids)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({row["document_id"] for row in response.json()["evidence"]}, set(self.ids))
        self.assertEqual(self.ask(mode="reasoning", document_ids=self.ids + [self.ids[0]]).status_code, 422)
        self.assert_no_models()

    def test_missing_document_and_unknown_type_are_422_not_silent_success(self):
        self.assertEqual(self.ask(mode="reasoning", document_ids=["DOC-ffffffffffffffff"]).status_code, 422)
        self.assertEqual(self.ask(mode="reasoning", document_type="made_up_type").status_code, 422)
        self.assert_no_models()

    def test_fixed_relation_analysis_does_not_receive_reasoning_mode(self):
        with patch("agents.relations_qa.run", return_value={"answer":"fixed relation fixture"}) as relations:
            response = self.client.post("/api/library/analyze", json={"question":"Zephyr comparison", "mode":"excerpts"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("mode", relations.call_args.kwargs)
        self.assert_no_models()


if __name__ == '__main__':
    unittest.main()
