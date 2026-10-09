"""按问题裁剪字段时不能反向省略明确请求或把事实否定当省略指令。"""
import copy
import unittest
from unittest.mock import patch

from agents.question_scope import policy_scope_only, positive_question, topics
from agents.qa_agent import run
from agents.verifier_agent import required_fields
from questions.test_conversation import record, A, B


class QuestionScopeTest(unittest.TestCase):
    def records(self):
        rows = [record(A, 8.8), record(B, 7.5)]
        for row in rows:
            report = row["item"]["raw_data"]["automatic_assessment"]
            eid = report["cvss"]["evidence_ids"]
            report["affected_ranges"] = [{"display": "fixture：版本 < 1.2.3", "versionEndExcluding": "1.2.3", "evidence_ids": eid, "requires_environment_review": False}]
            report["attack_conditions"] = [{"label": "所需权限", "text": "低", "metric": "PR", "value": "L", "evidence_ids": eid}]
            report["technical_impact"] = [{"label": "可用性影响", "text": "高", "evidence_ids": eid}]
            report["fix_records"] = [{"title": "Synthetic repair", "url": "https://example.org/pull/1", "evidence_ids": eid}]
        return rows

    def answer(self, question):
        rows = self.records()
        with patch("agents.qa_agent.search", side_effect=[[rows[0]], [rows[1]]]), patch("agents.qa_agent.chat") as model:
            result = run(question)
        model.assert_not_called()
        return result["answer"]

    def test_score_and_version_comparison_does_not_add_repair_or_attack_fields(self):
        answer = self.answer(f"对比 {A} 和 {B} 的评分和版本范围")
        for wanted in ("8.8", "7.5", "< 1.2.3", "评分记录来源", "基础分最高", "[" + A + "/FIXTURE]", "[" + B + "/FIXTURE]"):
            self.assertIn(wanted, answer)
        for extra in ("所需权限", "可用性影响", "关联修复记录", "修复效果", "修复版本"):
            self.assertNotIn(extra, answer)

    def test_versions_only_does_not_rank_scores_or_add_negated_fields(self):
        answer = self.answer(f"对比 {A} 和 {B} 的版本范围，不要补充评分和修复")
        self.assertIn("< 1.2.3", answer)
        for extra in ("CVSS", "基础分最高", "修复记录", "所需权限"):
            self.assertNotIn(extra, answer)

    def test_explicit_repair_and_conditions_request_remains_complete(self):
        answer = self.answer(f"比较 {A} 和 {B} 的利用条件和修复记录")
        for wanted in ("所需权限", "关联修复记录", "本项目未测试修复效果", "修复版本需核对厂商公告"):
            self.assertIn(wanted, answer)
        self.assertNotIn("基础分最高", answer)

    def test_explicit_no_ranking_keeps_scores_without_ranking(self):
        answer = self.answer(f"分别列 {A} 和 {B} 的评分，不排序")
        self.assertIn("8.8", answer); self.assertNotIn("基础分最高", answer)

    def test_missing_requested_field_does_not_fall_back_to_unrelated_fields(self):
        answer = self.answer(f"比较 {A} 和 {B} 的 PoC 验证状态")
        self.assertIn("没有本轮所问字段的可引用事实", answer)
        self.assertNotIn("CVSS", answer)
        self.assertNotIn("< 1.2.3", answer)

    def test_factual_negation_and_not_only_instruction_keep_required_fields(self):
        for q in ("攻击条件：不需要用户交互吗？", "不要只列评分，还要版本范围", "不要遗漏版本范围", "不要漏掉利用条件", "不要省略用户交互条件"):
            self.assertEqual(positive_question(q), q)
        self.assertEqual(topics("不要只列评分，还要版本范围"), {"cvss", "versions"})
        rows = self.records()
        self.assertFalse(required_fields("版本 < 1.2.3。", rows[:1], "版本范围，不要评分"))
        self.assertTrue(required_fields("未列条件。", rows[:1], "利用条件，不需要用户交互吗？"))

    def test_do_not_omit_directive_keeps_version_field_and_validation(self):
        answer = self.answer(f"比较 {A} 和 {B} 的评分，不要遗漏版本范围。")
        self.assertIn("< 1.2.3", answer)
        self.assertTrue(required_fields("CVSS 3.1 基础分为 8.8。", self.records()[:1], "评分，不要遗漏受影响版本范围"))

    def test_unknown_positive_comparison_scope_does_not_restore_excluded_topic(self):
        answer = self.answer(f"对比 {A} 和 {B}，不要评分和修复")
        self.assertIn("请明确", answer)
        self.assertNotIn("基础分为", answer)

    def test_policy_shortcut_only_handles_explicit_scope_date_questions(self):
        docs = {"doc": {"title": "人工智能生成合成内容标识办法", "content_scope": "policy_articles"}}
        self.assertTrue(policy_scope_only("请摘录标识办法的适用范围及施行条款，不判断我是否属于监管对象。", docs))
        for q in ("请摘录标识办法的适用范围和第十二条", "这个办法适用于我们公司吗？", "请解释隐式标识要求", "适用范围和标识要求"):
            self.assertFalse(policy_scope_only(q, docs))
        other = copy.deepcopy(docs); other["doc"]["content_scope"] = "catalog_only"
        self.assertFalse(policy_scope_only("适用范围及施行条款", other))


if __name__ == "__main__": unittest.main()
