"""Compact model outputs still require exact quotes and independent verification."""
import copy
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from agents import general_reasoning as reasoning
from agents.library_qa import run
from questions import test_general_reasoning as fixtures


class ReasoningOutputBudgetTest(unittest.TestCase):
    def setUp(self):
        fixtures.GeneralReasoningTest.setUp(self)

    model = fixtures.GeneralReasoningTest.model
    ask = fixtures.GeneralReasoningTest.ask

    def test_stage_budgets_allow_short_multi_document_claims_without_repeating_them_in_verification(self):
        captured = []
        original = self.model
        def model(messages, **kwargs):
            captured.append((messages[0]["content"], kwargs["max_tokens"]))
            return original(messages, **kwargs)
        self.model = model
        result = self.ask()
        self.assertTrue(result["used_model"])
        self.assertEqual([tokens for prompt, tokens in captured], [640, 2400, 1200])
        self.assertIn("12 至 240", captured[1][0])
        self.assertIn("不重复其 text 或 supports", captured[2][0])
        stages = [row for row in result["reasoning_trace"] if row.get("status") == "received"]
        self.assertEqual(len(stages), 3)
        self.assertTrue(all(row["request_ms"] >= 0 and row["archive_check_ms"] >= 0 for row in stages))
        self.assertEqual(result["reasoning_claims"][0]["supports"], self.supports)

    def test_synthesis_truncation_is_distinct_and_does_not_publish_partial_claims(self):
        original = self.model
        def model(messages, **kwargs):
            payload = json.loads(messages[-1]["content"])
            if "evidence" in payload and "draft" not in payload:
                raise RuntimeError("大模型输出达到长度限制，回答可能不完整")
            return original(messages, **kwargs)
        self.model = model
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "reasoning_output_truncated")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])
        self.assertEqual(result["model_calls"], 2)
        failure = result["reasoning_trace"][-1]
        self.assertEqual((failure["stage"], failure["status"], failure["output_token_limit"]),
                         ("synthesize", "failed", 2400))

    def test_known_transport_categories_never_expose_provider_content(self):
        cases = [
            (TimeoutError("private-provider-message"), "reasoning_model_timeout"),
            (urllib.error.HTTPError("https://private-provider-message", 401, "private-provider-message", {},
                                    io.BytesIO(b"private-provider-message")), "reasoning_model_http_error"),
            (urllib.error.URLError("private-provider-message"), "reasoning_model_connection_error"),
            (RuntimeError("private-provider-message"), "reasoning_request_failed"),
        ]
        for error, category in cases:
            with self.subTest(category=category), patch("rag.library._dense", side_effect=RuntimeError()), \
                    patch("agents.general_reasoning.configured", return_value=True), \
                    patch("agents.general_reasoning.chat", side_effect=error):
                result = run(self.question, mode="reasoning", db_path=self.db)
            self.assertEqual(result["fallback_reason"], category)
            self.assertEqual(result["reasoning_trace"][-1]["error_category"], category)
            self.assertNotIn("private-provider-message", json.dumps(result))

    def test_whole_paragraph_and_excess_claims_are_rejected_even_if_their_quotes_exist(self):
        original = copy.deepcopy(self.draft)
        self.draft["claims"][0]["supports"][0]["quote"] = self.rows[0]["text"][:reasoning.MAX_QUOTE + 1]
        self.assertEqual(len(self.draft["claims"][0]["supports"][0]["quote"]), reasoning.MAX_QUOTE + 1)
        self.assertEqual(self.ask()["fallback_reason"], "invalid_quote")
        self.draft = copy.deepcopy(original)
        self.draft["claims"] *= reasoning.MAX_CLAIMS + 1
        self.assertEqual(self.ask()["fallback_reason"], "invalid_claims")


if __name__ == "__main__":
    unittest.main()
