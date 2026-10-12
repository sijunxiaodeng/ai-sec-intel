"""One cited scoring row must support every explicit CVSS attribute."""
import copy
import json
import unittest
from unittest.mock import patch

from agents.citation_guard import claim_issues
from agents.qa_agent import _render_model_json, run
from agents.verifier_agent import required_fields


class CVSSBindingTest(unittest.TestCase):
    def setUp(self):
        self.cve = "CVE-2024-37032"
        self.vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        self.first = self.chunk("FIRST", "3.1", 8.8, "HIGH", self.vector, "first@example.org", "Secondary")
        self.second = self.chunk("SECOND", "3.1", 9.8, "CRITICAL", self.vector.replace("PR:L", "PR:N"), "second@example.org", "Primary")
        self.record = self.assessed([self.first, self.second])

    def chunk(self, identifier, version, score, severity, vector, source, metric_type):
        value = {"source": source, "type": metric_type, "cvssData": {"version": version, "baseScore": score,
                 "baseSeverity": severity, "vectorString": vector}}
        return {"citation_id": self.cve + "/" + identifier, "locator": "metrics/cvssMetricV" + version.replace(".", "") + "/0",
                "text": json.dumps(value), "structured_value": value, "relation_type": "vulnerability_record",
                "url": "https://example.org/offline", "text_kind": "automatic_source_extract"}

    def assessed(self, chunks):
        metrics = []
        for chunk in chunks:
            row, data = chunk["structured_value"], chunk["structured_value"]["cvssData"]
            metrics.append({"score": data["baseScore"], "severity": data["baseSeverity"], "version": data["version"],
                            "vector": data["vectorString"], "source": row["source"], "metric_type": row["type"],
                            "evidence_ids": [chunk["citation_id"]]})
        report = {"status": "ok", "cvss": metrics[0], "cvss_candidates": metrics, "attack_conditions": [],
                  "affected_ranges": [], "technical_impact": [], "poc_candidates": [], "fix_records": [],
                  "warnings": [], "evidence": chunks}
        return {"item": {"cve_id": self.cve, "raw_data": {"automatic_assessment": report}},
                "cvss": metrics[0], "evidence_chunks": chunks}

    def answer(self, text, citations=None, record=None):
        record = copy.deepcopy(record or self.record)
        raw = json.dumps({"claims": [{"text": text, "citations": citations or [self.first["citation_id"]]}]})
        with patch("agents.qa_agent.search", return_value=[record]), patch("agents.qa_agent.configured", return_value=True), \
                patch("agents.qa_agent.chat", return_value=raw), patch("agents.qa_agent._answer_format", return_value={"type": "json_object"}):
            return run(self.cve + " 的 CVSS 评分、严重等级、向量和评分来源是什么？")

    def test_wrong_severity_and_full_vector_do_not_get_adopted(self):
        for text in ("CVSS 3.1 基础分为 8.8，严重等级低；向量 " + self.vector + "；评分来源 first@example.org。",
                     "CVSS 3.1 基础分为 8.8，严重等级高；向量 " + self.vector.replace("PR:L", "PR:N") + "；评分来源 first@example.org。"):
            with self.subTest(text=text):
                self.assertTrue(claim_issues(text, [self.first]))
                result = self.answer(text)
                self.assertFalse(result["used_model"])
                self.assertIn("严重等级 高", result["answer"])
                self.assertIn(self.vector, result["answer"])

    def test_each_attribute_is_bound_to_same_row_even_if_both_are_cited(self):
        for text in ("CVSS 3.1 基础分为 8.8，评分来源 second@example.org。",
                     "CVSS 3.1 基础分为 8.8，严重等级严重。",
                     "CVSS 3.1 基础分为 8.8，类型 Primary。"):
            with self.subTest(text=text):
                self.assertTrue(claim_issues(text, [self.first, self.second]))

    def test_pr_and_other_components_are_checked_against_vector(self):
        for text in ("按 CVSS 向量解释，所需权限：无。", "按 CVSS 向量解释，PR:N。", "按 CVSS 向量解释，保密性影响：低。"):
            self.assertTrue(claim_issues(text, [self.first]))
        self.assertFalse(claim_issues("按 CVSS 向量解释，所需权限：低。", [self.first]))
        self.assertFalse(claim_issues("按 CVSS 向量解释：网络攻击、低复杂度、低权限，无需用户交互。", [self.first]))

    def test_normal_and_alternative_source_answers_are_adopted(self):
        for chunk, score, level, vector in ((self.first, 8.8, "高", self.vector),
                                            (self.second, 9.8, "严重", self.vector.replace("PR:L", "PR:N"))):
            text = "CVSS 3.1 基础分为 %s，严重等级%s；向量 %s；评分来源 %s。" % (score, level, vector, chunk["structured_value"]["source"])
            result = self.answer(text, [chunk["citation_id"]])
            self.assertTrue(result["used_model"])
            self.assertFalse(required_fields(result["answer"], result["evidence"], "CVSS 评分、严重等级、向量和评分来源？"))
        raw = json.dumps({"claims": [{"text": "CVSS 3.1 基础分为 8.8，评分来源 first@example.org。", "citations": [self.first["citation_id"]]},
                                     {"text": "CVSS 3.1 基础分为 9.8，评分来源 second@example.org。", "citations": [self.second["citation_id"]]}]})
        self.assertEqual(len(_render_model_json(raw, [self.record]).splitlines()), 2)

    def test_vector_order_is_not_confused_with_different_metric_values(self):
        parts = self.vector.split("/")
        reordered = "/".join(parts[:1] + list(reversed(parts[1:])))
        self.assertFalse(claim_issues("CVSS 3.1 基础分为 8.8，向量 " + reordered, [self.first]))
        self.assertFalse(claim_issues("CVSS 3.1 基础分为 8.8，向量 " + self.vector + ".", [self.first]))
        self.assertFalse(claim_issues("按 CVSS 向量解释，不需要高权限。", [self.first]))

    def test_explicit_alternative_provider_conditions_are_not_checked_as_default_provider(self):
        text = "按 CVSS 向量解释，所需权限：无；评分记录来源 second@example.org。"
        self.assertFalse(claim_issues(text, [self.second]))
        self.assertFalse(required_fields(text, [self.record], "所需权限？"))

    def test_missing_or_truncated_metric_evidence_cannot_support_structured_claim(self):
        for chunks in ([], [dict(self.first, structured_value=None, text="truncated JSON")],
                       [dict(self.first, structured_value=None, text="Synthetic CVSS 8.8 fixture.", locator="metrics/0")]):
            self.assertTrue(claim_issues("CVSS 3.1 基础分为 8.8，严重等级高。", chunks))
        partial = copy.deepcopy(self.first)
        partial["structured_value"]["cvssData"]["vectorString"] = "CVSS:3.1/PR:L"
        self.assertTrue(claim_issues("CVSS 3.1 基础分为 8.8，向量 CVSS:3.1/PR:L。", [partial]))
        invalid = copy.deepcopy(self.first)
        invalid["structured_value"]["cvssData"]["baseScore"] = True
        self.assertTrue(claim_issues("CVSS 3.1 基础分为 1。", [invalid]))
        changed = copy.deepcopy(self.first)
        changed["structured_value"]["cvssData"]["baseScore"] = 9.8
        self.assertTrue(claim_issues("CVSS 3.1 基础分为 9.8。", [changed]))

    def test_cvss3_and_cvss4_fields_are_kept_separate(self):
        vector4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        fourth = self.chunk("FOURTH", "4.0", 9.3, "CRITICAL", vector4, "fourth@example.org", "Primary")
        self.assertFalse(claim_issues("按 CVSS 向量解释，附加攻击要求：无，易受攻击系统保密性影响：高，用户交互：被动交互。", [fourth]))
        self.assertTrue(claim_issues("按 CVSS 向量解释，附加攻击要求：无。", [self.first]))
        self.assertTrue(claim_issues("按 CVSS 向量解释，影响范围变化：未变化，C:H。", [fourth]))
        self.assertTrue(claim_issues("按 CVSS 向量解释，用户交互：主动交互。", [self.first]))
        self.assertFalse(claim_issues("CVSS 4.0 基础分为 9.3，严重等级严重；向量 " + vector4, [fourth]))

    def test_nvd_alias_only_matches_nvd_scoring_provider(self):
        self.assertTrue(claim_issues("CVSS 3.1 基础分为 8.8，评分来源 NVD。", [self.first]))
        nvd = self.chunk("NVD", "3.1", 8.8, "HIGH", self.vector, "nvd@nist.gov", "Primary")
        self.assertFalse(claim_issues("CVSS 3.1 基础分为 8.8，评分来源 NVD。", [nvd]))
        self.assertTrue(claim_issues("CVSS 3.1 基础分为 8.8，评分来源 GitHub。", [self.first]))
        self.assertFalse(claim_issues("CVSS 3.1 基础分为 8.8，评分来源 first@example.org.", [self.first]))
        self.assertFalse(claim_issues("CVSS 3.1 基础分为 8.8，不是由NVD评分，评分来源 first@example.org。", [self.first]))

    def test_cvss2_literal_vector_can_be_preserved_without_applying_v3_privileges(self):
        legacy = self.chunk("V2", "2.0", 7.5, "HIGH", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "nvd@nist.gov", "Primary")
        self.assertFalse(claim_issues("CVSS 2.0 基础分为 7.5，向量 AV:N/AC:L/Au:N/C:P/I:P/A:P。", [legacy]))
        self.assertTrue(claim_issues("CVSS 2.0 基础分为 7.5，向量 AV:N/AC:L/Au:M/C:P/I:P/A:P。", [legacy]))
        self.assertTrue(claim_issues("CVSS 2.0 基础分为 7.5，PR:N。", [legacy]))

    def test_missing_field_claims_only_match_a_row_where_value_is_actually_missing(self):
        text = "CVSS 3.1 基础分为 8.8，严重等级未提供，向量未提供，评分来源 first@example.org。"
        self.assertTrue(claim_issues(text, [self.first]))
        partial = copy.deepcopy(self.first)
        partial["structured_value"]["cvssData"].update(baseSeverity=None, vectorString=None)
        partial["text"] = json.dumps(partial["structured_value"])
        self.assertFalse(claim_issues(text, [partial]))
        self.assertTrue(self.answer(text, record=self.assessed([partial]))["used_model"])


if __name__ == "__main__":
    unittest.main()
