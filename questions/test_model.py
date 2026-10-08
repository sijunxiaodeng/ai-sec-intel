import io
import json
import unittest
from unittest.mock import patch

from config.llm import chat
from agents.qa_agent import run, _render_model_json, _answer_format, _extractive, _answer_tokens, _evidence_text
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

    def assessed_record(self):
        record = json.loads(json.dumps(self.record))
        record["item"]["raw_data"]["automatic_assessment"] = {
            "status": "ok", "cvss": {"score": 8.8, "version": "3.1", "severity": "HIGH",
                "source": "vendor@example.org", "metric_type": "Secondary",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "evidence_ids": [self.eid]},
            "attack_conditions": [dict(metric=k, value=v, label=label, text=text, evidence_ids=[self.eid])
                for k, v, label, text in (("AV", "N", "攻击途径", "网络"),
                    ("AC", "L", "攻击复杂度", "低"), ("PR", "L", "所需权限", "低"),
                    ("UI", "N", "用户交互", "不需要"))],
            "affected_ranges": [{"display": "fixture：版本 < 0.1.34", "requires_environment_review": False,
                "versionEndExcluding": "0.1.34", "evidence_ids": [self.eid]}],
            "technical_impact": [], "poc_candidates": [],
            "fix_records": [{"title": "Synthetic fix", "url": "https://example.org/fix", "evidence_ids": [self.eid]}],
            "warnings": ["受影响范围的排除上界不自动等于厂商确认的修复版本"],
            "evidence": record["evidence_chunks"], "asset_impact": {"reason": "Fixture only"}}
        return record

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
        self.assertNotIn("thinking", captured[0])

    def test_thinking_toggle_only_sent_to_supported_official_deepseek_models(self):
        result = {"choices": [{"message": {"content": "fixture"}, "finish_reason": "stop"}]}
        for endpoint, model, expected in (
            ("https://api.deepseek.com", "deepseek-flash", True),
            ("https://api.deepseek.com/v1", "deepseek-v4-pro", True),
            ("https://api.deepseek.com", "deepseek-v4-flash", True),
            ("https://api.deepseek.com.example.org", "deepseek-flash", False),
            ("https://example.org/v1", "deepseek-flash", False),
            ("http://127.0.0.1:11434/v1", "fixture", False)):
            captured = []
            def response(request, **kwargs):
                captured.append(json.loads(request.data))
                return io.BytesIO(json.dumps(result).encode())
            settings = dict(self.settings, base_url=endpoint, model=model)
            with self.subTest(endpoint=endpoint, model=model), patch("config.llm.load_settings", return_value=settings), patch("config.llm.urllib.request.urlopen", side_effect=response):
                self.assertEqual(chat([]), "fixture")
            self.assertEqual(captured[0].get("thinking"), {"type": "disabled"} if expected else None)

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

    def test_model_prompt_lists_only_allowed_citations_and_avoids_unrelated_metadata(self):
        record = self.assessed_record()
        self.assertNotIn("字段提取与评估边界", _evidence_text([record], "CVSS 评分？"))
        self.assertNotIn("Fixture only", _evidence_text([record], "CVSS 评分？"))
        captured = []
        def respond(messages, **kwargs):
            captured.append((messages, kwargs))
            return json.dumps({"claims": [{"text": "CVSS 3.1 基础分为 8.8。", "citations": [self.eid]}]})
        with patch("agents.qa_agent.search", return_value=[record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", side_effect=respond):
            self.assertTrue(run(self.cve + " 的 CVSS 评分？")["used_model"])
        suffix = captured[0][0][-1]["content"].split("允许的 citations 标识（只能照抄清单中的值）：", 1)[1]
        self.assertEqual(json.loads(suffix), [self.eid])
        self.assertEqual(captured[0][1]["max_tokens"], 768)

    def test_complex_branch_output_budget_is_bounded(self):
        record = self.assessed_record()
        report = record["item"]["raw_data"]["automatic_assessment"]
        report["affected_ranges"] = [dict(report["affected_ranges"][0], display="fixture：版本 = 1.0-rc%d" % i) for i in range(8)]
        self.assertEqual(_answer_tokens([record], "受影响版本范围？"), 1536)
        self.assertEqual(_answer_tokens([record], "CVSS 评分？"), 768)

    def test_complete_multi_topic_answer_can_exceed_twelve_claims_but_is_bounded(self):
        texts = ["来源版本分支为 1.0-rc%d。" % i for i in range(8)]
        texts += ["按 CVSS 向量解释，%s。" % field for field in (
            "易受攻击系统保密性影响无", "易受攻击系统完整性影响无", "易受攻击系统可用性影响高",
            "后续系统保密性影响无", "后续系统完整性影响无", "后续系统可用性影响无")]
        texts += ["CVSS 4.0 基础分为 8.7。", "评分提供者 vendor@example.org。", "PoC 尚未由本项目验证。"]
        claims = [{"text": text, "citations": [self.eid]} for text in texts]
        self.assertEqual(len(_render_model_json(json.dumps({"claims": claims}), [self.record]).splitlines()), 17)
        with self.assertRaises(ValueError):
            _render_model_json(json.dumps({"claims": claims + claims}), [self.record])

    def test_structured_answer_preserves_explicit_citation(self):
        raw = json.dumps({"claims": [{"text": "CVSS 为 8.8。", "citations": [self.eid]}]})
        self.assertEqual(_render_model_json(raw, [self.record]), "CVSS 为 8.8。 [%s]" % self.eid)
        with patch("agents.qa_agent.search", return_value=[self.record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=raw):
            result = run(self.cve + " 的 CVSS 是多少？")
        self.assertTrue(result["used_model"])
        self.assertTrue(result["model_attempted"])

    def test_duplicate_inline_citation_is_rendered_once(self):
        raw = json.dumps({"claims": [{"text": "CVSS 为 8.8。 [%s]" % self.eid,
                                    "citations": [self.eid, self.eid]}]})
        self.assertEqual(_render_model_json(raw, [self.record]).count("[%s]" % self.eid), 1)

    def test_conditions_question_cannot_accept_privileges_only(self):
        record = self.assessed_record()
        question = self.cve + " 的利用条件和所需权限是什么？"
        for text in ("所需权限：低。", "按 CVSS 向量解释，所需权限：低。"):
            with self.subTest(text=text):
                issues = required_fields(text, [record], question)
                for label in ("攻击途径", "攻击复杂度", "用户交互"):
                    self.assertTrue(any(label in issue for issue in issues))
        raw = json.dumps({"claims": [{"text": "所需权限：低。", "citations": [self.eid]}]})
        with patch("agents.qa_agent.search", return_value=[record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=raw):
            result = run(question)
        self.assertFalse(result["used_model"])
        for expected in ("攻击途径：网络", "攻击复杂度：低", "所需权限：低", "用户交互：不需要", "按 CVSS 向量解释"):
            self.assertIn(expected, result["answer"])

    def test_conditions_accept_complete_paraphrase_and_limit_narrow_question(self):
        record = self.assessed_record()
        complete = "按 CVSS 向量解释：网络攻击、低复杂度、低权限，无需用户交互。"
        self.assertFalse(required_fields(complete, [record], "利用条件和所需权限？"))
        self.assertFalse(required_fields("按 CVSS 向量解释，所需权限：低。", [record], "所需权限？"))
        self.assertTrue(required_fields("网络攻击、低复杂度、低权限，无需用户交互。", [record], "利用条件？"))
        record["item"]["raw_data"]["automatic_assessment"]["attack_conditions"][2].update(value="N", text="无")
        self.assertTrue(required_fields("按 CVSS 向量解释，所需权限：低。", [record], "所需权限？"))
        self.assertFalse(required_fields("按 CVSS 向量解释，无需权限。", [record], "所需权限？"))

    def test_cvss4_conditions_retain_additional_attack_requirements(self):
        record = self.assessed_record()
        record["item"]["raw_data"]["automatic_assessment"]["attack_conditions"].append(
            {"metric": "AT", "value": "P", "label": "附加攻击要求", "text": "存在"})
        text = "按 CVSS 向量解释：网络攻击、低复杂度、低权限，无需用户交互。"
        self.assertTrue(any("附加攻击要求" in issue for issue in required_fields(text, [record], "攻击条件？")))
        self.assertFalse(required_fields(text + "附加攻击要求：存在。", [record], "攻击条件？"))

    def test_fallback_only_shows_relevant_warning_and_requested_source_text(self):
        record = self.assessed_record()
        original = "Synthetic disclosure timeline."
        record["evidence_chunks"].append({"citation_id": self.cve + "/ARTICLE", "text": original,
            "relation_type": "direct_analysis", "topics": ["remediation"]})
        metric_answer = _extractive([record], "CVSS 评分？", model_attempted=True)
        self.assertNotIn("排除上界", metric_answer)
        self.assertNotIn("资产匹配", metric_answer)
        fix_answer = _extractive([record], "应该怎么修复？", model_attempted=True)
        self.assertEqual(fix_answer.count("排除上界"), 1)
        self.assertIn("本项目未测试修复效果", fix_answer)
        self.assertNotIn(original, fix_answer)
        self.assertIn(original, _extractive([record], "修复文章的原文？"))
        record["item"]["raw_data"]["automatic_assessment"]["warnings"].append("最近一次 NVD 获取失败，沿用上次成功快照")
        self.assertIn("最近一次 NVD 获取失败", _extractive([record], "CVSS 评分？"))

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
