"""Completeness checks survive missing scores and topic-only restrictions."""
import copy
import json
import unittest
from unittest.mock import patch

from agents import qa_agent
from agents.verifier_agent import required_fields
from questions import test_patch_candidates as fixtures


class RequiredFieldCoverageTest(unittest.TestCase):
    setUp = fixtures.PatchCandidateTest.setUp
    fetch = fixtures.PatchCandidateTest.fetch
    prepare = fixtures.PatchCandidateTest.prepare

    def source_record(self):
        report = self.prepare()
        record = copy.deepcopy(self.record)
        record["item"]["raw_data"]["automatic_assessment"] = report
        record["cvss"] = report["cvss"] or {}
        record["evidence_chunks"] = report["evidence"]
        return record

    def test_model_omission_of_real_patch_is_rejected_when_nvd_has_no_cvss(self):
        self.nvd["metrics"] = {}
        record = self.source_record()
        report = record["item"]["raw_data"]["automatic_assessment"]
        self.assertIsNone(report["cvss"])
        self.assertEqual(len(report["patch_candidates"]), 1)
        exploit = report["poc_candidates"][0]
        raw = json.dumps({"claims": [{"text": "NVD 标为 Exploit 的候选参考：%s。" % exploit["url"],
                                      "citations": exploit["evidence_ids"]}]})
        with patch.object(qa_agent, "search", return_value=[record]), \
             patch.object(qa_agent, "configured", return_value=True), \
             patch.object(qa_agent, "chat", return_value=raw):
            result = qa_agent.run("有哪些补丁？", cve_id=self.cve)
        self.assertFalse(result["used_model"])
        self.assertTrue(result["model_attempted"])
        self.assertIn("标为 Patch", result["steps"][-1]["detail"])
        self.assertIn(self.fix, result["answer"])
        self.assertIn("尚未据此确认修复效果或修复版本", result["answer"])

    def test_missing_score_does_not_skip_version_or_poc_boundaries(self):
        self.nvd["metrics"] = {}
        record = self.source_record()
        issues = required_fields("只列出了来源名称。", [record], "受影响版本范围和 PoC 验证状态？")
        self.assertTrue(any("版本范围" in issue for issue in issues))
        self.assertTrue(any("PoC" in issue for issue in issues))
        self.assertFalse(any("CVSS" in issue for issue in issues))

    def test_only_technical_impact_still_requires_all_available_impact_fields(self):
        record = self.source_record()
        answer = "按 CVSS 向量解释，可用性影响：高。"
        for question in ("仅说明技术影响，不讨论版本范围。", "只讨论危害。", "不要只列可用性，还要技术影响。"):
            with self.subTest(question=question):
                issues = required_fields(answer, [record], question)
                self.assertTrue(any("保密性" in issue for issue in issues))
                self.assertTrue(any("完整性" in issue for issue in issues))
        full = "按 CVSS 向量解释，保密性影响：高；完整性影响：高；可用性影响：高。"
        self.assertEqual(required_fields(full, [record], "仅说明技术影响。"), [])

    def test_explicit_component_limit_keeps_only_its_required_fields(self):
        record = self.source_record()
        for question in ("仅说明可用性影响。", "技术影响是什么？只列出可用性。"):
            with self.subTest(question=question):
                self.assertEqual(required_fields("按 CVSS 向量解释，可用性影响：高。", [record], question), [])
                issues = required_fields("按 CVSS 向量解释，保密性影响：高。", [record], question)
                self.assertTrue(any("可用性" in issue for issue in issues))
                self.assertFalse(any("完整性" in issue for issue in issues))
        pair = "按 CVSS 向量解释，保密性影响：高；完整性影响：高。"
        self.assertEqual(required_fields(pair, [record], "仅说明保密性和完整性。"), [])
        self.assertTrue(required_fields("可用性影响：高。", [record], "仅说明可用性。"))

    def test_component_limit_preserves_both_cvss4_system_scopes(self):
        self.nvd["metrics"] = {"cvssMetricV40": [{"source": "fixture@example.org", "type": "Primary", "cvssData": {
            "version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH",
            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}}]}
        record = self.source_record()
        incomplete = "按 CVSS 向量解释，易受攻击系统可用性影响：高。"
        issues = required_fields(incomplete, [record], "仅说明可用性影响。")
        self.assertTrue(any("后续系统可用性" in issue for issue in issues))
        self.assertFalse(any("保密性" in issue or "完整性" in issue for issue in issues))
        self.assertEqual(required_fields(incomplete + "后续系统可用性影响：无。", [record], "仅说明可用性影响。"), [])


if __name__ == "__main__":
    unittest.main()
