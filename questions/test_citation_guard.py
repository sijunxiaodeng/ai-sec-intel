import copy
import json
import unittest
from unittest.mock import patch

from agents.citation_guard import claim_issues
from agents.qa_agent import _render_model_json, run
from agents.verifier_agent import run as verify


class CitationGuardTest(unittest.TestCase):
    def setUp(self):
        self.cve = "CVE-2024-37032"
        def chunk(name, locator, text, relation="vulnerability_record", value=None):
            result = {"citation_id": self.cve + "/" + name, "locator": locator, "text": text,
                      "relation_type": relation, "url": "https://example.org/fixture", "text_kind": "automatic_source_extract"}
            if value:
                result["structured_value"] = value
            return result
        self.metric = {"source": "vendor@example.org", "cvssData": {"version": "3.1", "baseScore": 8.8}}
        self.cvss = chunk("CVSS", "metrics/cvssMetricV31/0；字符 [0,100)", json.dumps(self.metric), value=self.metric)
        self.ssvc = chunk("SSVC", "metrics/ssvcV203/0", '{"ssvcData":{"options":[{"exploitation":"none"}]}}')
        self.desc = chunk("DESC", "descriptions/0", "Ollama does not validate the digest format.")
        self.versions = chunk("RANGE", "configurations/0", "Ollama version < 0.1.34")
        self.fix = chunk("FIX", "title", "validate the digest format", "fix_record")
        self.merge = chunk("MERGE", "merge_metadata", '{"merged":true}', "fix_record")
        self.record = {"item": {"cve_id": self.cve, "raw_data": {}}, "cvss": {"score": 8.8},
                       "evidence_chunks": [self.cvss, self.ssvc, self.desc, self.versions, self.fix, self.merge]}

    def test_wrong_existing_ssvc_citation_cannot_support_vulnerability_cause(self):
        text = "Ollama 未校验 digest 格式，从而错误处理模型路径。"
        self.assertTrue(claim_issues(text, [self.ssvc]))
        self.assertFalse(claim_issues(text, [self.desc]))
        raw = json.dumps({"claims": [{"text": text, "citations": [self.ssvc["citation_id"]]}]})
        with self.assertRaisesRegex(ValueError, "不支持"):
            _render_model_json(raw, [self.record])
        self.assertFalse(verify(text + " [%s]" % self.ssvc["citation_id"], [self.record])["passed"])

    def test_cvss_range_and_merge_cannot_swap_structured_fields(self):
        for text, wrong, right in (
            ("CVSS 3.1 基础分为 8.8。", self.versions, self.cvss),
            ("受影响版本范围是版本 < 0.1.34。", self.cvss, self.versions),
            ("该修复记录已合并。", self.fix, self.merge),
            ("SSVC 数据记录利用状态为 none。", self.cvss, self.ssvc)):
            with self.subTest(text=text):
                self.assertTrue(claim_issues(text, [wrong]))
                self.assertFalse(claim_issues(text, [right]))

    def test_cited_metric_values_checked_even_when_other_metric_exists(self):
        other = copy.deepcopy(self.cvss)
        other["citation_id"] = self.cve + "/OTHER"
        other["structured_value"] = {"source": "other@example.org", "cvssData": {"version": "4.0", "baseScore": 8.7}}
        self.record["evidence_chunks"].append(other)
        self.assertTrue(claim_issues("CVSS 4.0 基础分为 8.7。", [self.cvss]))
        self.assertTrue(claim_issues("CVSS 3.1 基础分为 8.8，评分提供者 other@example.org。", [self.cvss]))
        self.assertFalse(claim_issues("CVSS 4.0 基础分为 8.7，评分提供者 other@example.org。", [other]))

    def test_local_state_does_not_get_external_citation(self):
        for text in ("本项目未测试修复效果。", "记录中未提供修复版本。", "当前知识库没有修复记录。"):
            self.assertTrue(claim_issues(text, [self.versions]))
        answer = "CVSS 3.1 基础分为 8.8。 [%s]\n系统记录：本项目未测试修复效果。" % self.cvss["citation_id"]
        self.assertTrue(verify(answer, [self.record])["passed"])

    def test_reference_url_words_do_not_become_vulnerability_claims(self):
        ref = dict(self.desc, locator="references/0")
        self.assertFalse(claim_issues("NVD 标为 Exploit 的候选参考：https://example.org/rce/digest/gguf。", [ref]))
        self.assertTrue(claim_issues("NVD 候选参考：https://example.org/rce。漏洞成因是 digest 校验缺失。", [ref]))

    def test_free_text_not_claimed_as_fully_verified(self):
        text = dict(self.desc, locator="正文；字符 [0,200)")
        self.assertFalse(claim_issues("漏洞成因是 digest 校验缺失。", [text]))
        answer = "漏洞成因是 digest 校验缺失。 [%s]" % text["citation_id"]
        record = dict(self.record, evidence_chunks=[text])
        self.assertIn("完整语义仍需复核", verify(answer, [record])["notes"][0])

    def test_multi_field_claim_needs_support_for_every_recognized_category(self):
        text = "CVSS 3.1 基础分为 8.8，受影响版本范围是版本 < 0.1.34。"
        self.assertTrue(claim_issues(text, [self.cvss]))
        self.assertFalse(claim_issues(text, [self.cvss, self.versions]))

    def test_bad_claim_falls_back_and_project_state_is_appended_locally(self):
        report = {"status": "ok", "cvss": None, "attack_conditions": [], "technical_impact": [],
                  "affected_ranges": [], "poc_candidates": [], "warnings": [], "evidence": [self.fix],
                  "fix_records": [{"title": "validate the digest format", "url": "https://example.org/fix",
                                   "validation": "not_tested", "evidence_ids": [self.fix["citation_id"]]}]}
        self.record["item"]["raw_data"]["automatic_assessment"] = report
        raw = json.dumps({"claims": [{"text": "Ollama 未校验 digest 格式。", "citations": [self.ssvc["citation_id"]]}]})
        with patch("agents.qa_agent.search", return_value=[self.record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=raw):
            result = run(self.cve + " 应该怎么修复？")
        self.assertFalse(result["used_model"])
        state = next(line for line in result["answer"].splitlines() if line.startswith("系统记录："))
        self.assertIn("本项目未测试修复效果", state)
        self.assertNotIn("[", state)
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])

    def test_good_model_poc_claim_preserved_with_local_validation_state(self):
        ref = dict(self.desc, citation_id=self.cve + "/REF", locator="references/0", text='{"url":"https://example.org/poc","tags":["Exploit"]}')
        self.record["evidence_chunks"].append(ref)
        self.record["item"]["raw_data"]["automatic_assessment"] = {
            "status": "ok", "cvss": None, "attack_conditions": [], "technical_impact": [], "affected_ranges": [],
            "fix_records": [], "warnings": [], "evidence": [ref],
            "poc_candidates": [{"url": "https://example.org/poc", "validation": "not_run", "evidence_ids": [ref["citation_id"]]}]}
        raw = json.dumps({"claims": [{"text": "NVD 标为 Exploit 的候选参考为 https://example.org/poc。", "citations": [ref["citation_id"]]}]})
        with patch("agents.qa_agent.search", return_value=[self.record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=raw):
            result = run(self.cve + " 的 PoC 是否由本项目验证？")
        self.assertTrue(result["used_model"])
        self.assertIn("系统记录：本项目未运行复现", result["answer"])
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])
