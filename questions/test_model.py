import io
import json
import unittest
from unittest.mock import patch

from config.llm import chat
from agents.qa_agent import run, _render_model_json, _answer_format
from agents.verifier_agent import required_fields


class ModelTest(unittest.TestCase):
    def setUp(self):
        self.cve = "CVE-2024-37032"
        self.eid = self.cve + "/FIXTURE"
        self.record = {"item": {"cve_id": self.cve, "description": "Synthetic source", "raw_data": {}},
                       "cvss": {"score": 8.8}, "evidence_chunks": [{"citation_id": self.eid,
                       "text": "Synthetic CVSS 8.8 fixture.", "url": "https://example.org/fixture",
                       "locator": "metrics/0", "text_kind": "automatic_structured_extract"}]}
        self.settings = {"base_url": "http://127.0.0.1:11434/v1", "model": "fixture", "api_key": "ollama"}

    def test_chat_sends_bounded_output_and_optional_format(self):
        result = {"choices": [{"message": {"content": "  test  "}, "finish_reason": "stop"}]}
        captured = []
        def response(request, **kwargs):
            captured.append(json.loads(request.data))
            return io.BytesIO(json.dumps(result).encode())
        with patch("config.llm.load_settings", return_value=self.settings), patch("config.llm.urllib.request.urlopen", side_effect=response):
            self.assertEqual(chat([{"role": "user", "content": "fixture"}], response_format={"type": "json_object"}), "test")
        self.assertEqual(captured[0]["max_tokens"], 768)
        self.assertEqual(captured[0]["response_format"]["type"], "json_object")

    def test_empty_and_truncated_model_answers_rejected(self):
        for content, reason in (("", "stop"), ("partial", "length"), (None, "stop")):
            payload = {"choices": [{"message": {"content": content}, "finish_reason": reason}]}
            with self.subTest(content=content), patch("config.llm.load_settings", return_value=self.settings), patch("config.llm.urllib.request.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
                with self.assertRaises(RuntimeError):
                    chat([])

    def test_local_schema_only_allows_given_chunk_citations(self):
        with patch("config.settings.load_settings", return_value=self.settings):
            schema = _answer_format([self.record])
        ids = schema["json_schema"]["schema"]["properties"]["claims"]["items"]["properties"]["citations"]["items"]["enum"]
        self.assertEqual(ids, [self.eid])
        with patch("config.settings.load_settings", return_value=dict(self.settings, base_url="https://example.org/v1")):
            self.assertEqual(_answer_format([self.record]), {"type": "json_object"})

    def test_structured_answer_preserves_explicit_citation(self):
        raw = json.dumps({"claims": [{"text": "CVSS 为 8.8。", "citations": [self.eid]}]})
        self.assertEqual(_render_model_json(raw, [self.record]), "CVSS 为 8.8。 [%s]" % self.eid)
        with patch("agents.qa_agent.search", return_value=[self.record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=raw):
            result = run(self.cve + " 的 CVSS 是多少？")
        self.assertTrue(result["used_model"])
        self.assertTrue(result["model_attempted"])

    def test_invented_missing_or_summary_citation_cannot_be_auto_attached(self):
        for citations in ([], ["unknown"], ["1"], [9]):
            raw = json.dumps({"claims": [{"text": "CVSS 为 8.8。", "citations": citations}]})
            with self.subTest(citations=citations), self.assertRaises(ValueError):
                _render_model_json(raw, [self.record])

    def test_invalid_score_and_call_failure_fall_back_with_honest_mode(self):
        raw = json.dumps({"claims": [{"text": "CVSS 为 9.8。", "citations": [self.eid]}]})
        with patch("agents.qa_agent.search", return_value=[self.record]), patch("agents.qa_agent.configured", return_value=True):
            for options in ({"return_value": raw}, {"side_effect": TimeoutError("fixture timeout")}):
                with self.subTest(options=options), patch("agents.qa_agent.chat", **options):
                    result = run(self.cve + " 的 CVSS 是多少？")
                    self.assertFalse(result["used_model"])
                    self.assertTrue(result["model_attempted"])
                    self.assertIn("模型回答未采用", result["answer"])
                    self.assertNotIn("未调用大模型", result["answer"])

    def test_secondary_provider_missing_poc_and_version_boundaries_are_checked(self):
        report = {"cvss": {"score": 8.8, "version": "3.1", "source": "vendor@example.org"},
                  "affected_ranges": [{"version": "*", "versionEndExcluding": "0.1.34", "qualifiers": {}}],
                  "poc_candidates": [{"url": "https://example.org/exploit"}]}
        self.record["item"]["raw_data"]["automatic_assessment"] = report
        self.assertTrue(required_fields("CVSS 3.1 评分提供者为 NVD，基础分为 8.8。", [self.record], "CVSS 评分提供者？"))
        self.assertFalse(required_fields("CVSS 3.1 基础分为 8.8，评分提供者 vendor@example.org。", [self.record], "CVSS 评分提供者？"))
        self.assertTrue(required_fields("版本 <= 0.1.34。", [self.record], "受影响版本范围？"))
        self.assertFalse(required_fields("版本 < 0.1.34。", [self.record], "受影响版本范围？"))
        self.assertTrue(required_fields("存在 PoC。", [self.record], "PoC 验证状态？"))
        self.assertFalse(required_fields("PoC 尚未由本项目验证。", [self.record], "PoC 验证状态？"))
