"""Positive PoC claims cannot borrow mutable flags or another CVE's evidence."""
import unittest
from agents.verifier_agent import run

A, B = "CVE-2024-37032", "CVE-2025-0312"


def record(cve, validation="not_run", url="https://example.org/candidate-a", text="Source candidate reference."):
    return {"item": {"cve_id": cve, "raw_data": {}}, "poc": [{"url": url, "validation": validation}],
            "evidence_chunks": [{"citation_id": cve + "/BODY", "locator": "body", "text": text,
                                 "url": url, "relation_type": "direct_analysis"}]}


class PocClaimBindingTest(unittest.TestCase):
    def test_verified_on_other_cve_cannot_authorize_the_target(self):
        evidence = [record(A), record(B, "verified", "https://example.org/candidate-b")]
        result = run(A + " 的 PoC 已验证可用 [" + A + "/BODY]", evidence)
        self.assertFalse(result["passed"])
        self.assertTrue(any("实验台账" in value for value in result["notes"]))

    def test_other_candidate_or_naked_verified_flags_do_not_prove_an_experiment(self):
        for status in ("verified", "runtime_verified"):
            with self.subTest(status=status):
                source = record(A, status, "https://example.org/another-candidate")
                answer = A + " 的 PoC https://example.org/candidate-a 已复现成功 [" + A + "/BODY]"
                result = run(answer, [source])
                self.assertFalse(result["passed"])
                self.assertTrue(any("具体候选" in value for value in result["notes"]))

    def test_even_matching_candidate_url_and_untrusted_test_chunk_cannot_self_authorize(self):
        source = record(A, "runtime_verified", text="PoC 已复现成功")
        source["poc"][0]["evidence_ids"] = [A + "/BODY"]
        source["evidence_chunks"][0]["text_kind"] = "runtime_test"
        result = run(A + " 的 PoC https://example.org/candidate-a 已复现成功 [" + A + "/BODY]", [source])
        self.assertFalse(result["passed"])
        self.assertTrue(any("实验台账" in value for value in result["notes"]))

    def test_explicit_target_and_citation_owner_must_match(self):
        result = run(A + " 的 PoC 已验证可用 [" + B + "/BODY]", [record(A), record(B, "verified")])
        self.assertFalse(result["passed"])
        self.assertTrue(any("引用所属" in value for value in result["notes"]))

    def test_missing_cve_or_only_card_number_is_not_experiment_evidence(self):
        for text in ("PoC 已验证可用 [" + A + "/BODY]", A + " 的 PoC 已验证可用 [1]"):
            with self.subTest(text=text):
                self.assertFalse(run(text, [record(A, "verified")])["passed"])

    def test_other_cve_negative_in_parallel_clause_does_not_hide_positive_claim(self):
        for separator in ("；", "，", "。 "):
            with self.subTest(separator=separator):
                answer = A + " 的 PoC 已验证可用 [" + A + "/BODY]" + separator + B + " 的 PoC 未验证 [" + B + "/BODY]"
                self.assertFalse(run(answer, [record(A), record(B, "verified")])["passed"])
        for text in ("资产未登记，但 PoC 已验证可用", "未认证攻击者的 PoC 已复现成功"):
            self.assertFalse(run(A + "：" + text + " [" + A + "/BODY]", [record(A, "verified")])["passed"])

    def test_negative_and_not_run_descriptions_are_not_false_positive_success_claims(self):
        for text in ("PoC 未验证", "PoC 尚未运行复现", "不能认定 PoC 已验证可用", "无法确认 PoC 已复现", "PoC 已验证可用的说法未经证实", "PoC is not verified", "PoC has not yet been verified", "PoC 状态为 not_run；修复效果 not_tested"):
            with self.subTest(text=text):
                answer = A + "：" + text + " [" + A + "/BODY]"
                self.assertTrue(run(answer, [record(A)])["passed"])
        answer = A + " 的 PoC 未验证 [" + A + "/BODY]，" + B + " 的 PoC 尚未复现 [" + B + "/BODY]"
        self.assertTrue(run(answer, [record(A), record(B)])["passed"])

    def test_reverse_wording_english_and_status_success_cannot_bypass(self):
        for text in ("已成功复现 PoC", "PoC has been successfully reproduced", "PoC validation: runtime_verified", "利用代码已经验证可用"):
            with self.subTest(text=text):
                self.assertFalse(run(A + "：" + text + " [" + A + "/BODY]", [record(A, "verified")])["passed"])

    def test_supported_source_statement_is_attributed_not_a_project_experiment(self):
        source = record(A, text="PoC 已复现成功")
        answer = A + "：来源声称 PoC 已复现成功。 [" + A + "/BODY]\n本项目未运行验证。"
        self.assertTrue(run(answer, [source])["passed"])
        self.assertFalse(run(A + "：本项目 PoC 已复现成功。 [" + A + "/BODY]", [source])["passed"])

    def test_source_exploit_tag_does_not_support_a_verified_source_claim(self):
        source = record(A, text='{"url":"https://example.org/candidate-a","tags":["Exploit"]}')
        source["evidence_chunks"][0]["locator"] = "references/0"
        answer = A + "：来源声称 PoC 已验证可用 [" + A + "/BODY]"
        self.assertFalse(run(answer, [source])["passed"])
        self.assertTrue(run(A + "：NVD 将 PoC 候选参考标为 Exploit，本项目未运行。\n候选链接 [" + A + "/BODY]", [source])["passed"])

    def test_unrelated_source_attribution_does_not_authorize_a_project_claim(self):
        source = record(A, text="PoC 已验证可用")
        for answer in (A + "：PoC 已验证可用 [" + A + "/BODY]，来源声称资产需要核对。",
                       A + "：来源声称功能稳定。PoC 已验证可用 [" + A + "/BODY]"):
            with self.subTest(answer=answer):
                self.assertFalse(run(answer, [source])["passed"])


if __name__ == "__main__":
    unittest.main()
