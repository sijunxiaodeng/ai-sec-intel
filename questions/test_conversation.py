import threading
import unittest
from unittest.mock import patch
from agents.conversation import SessionStore, SessionError, resolve
from agents.qa_agent import run as qa_run
from agents.verifier_agent import run as verify
from rag.evidence import CVE

A, B = "CVE-2024-37032", "CVE-2025-0312"


def record(cve, score, version="3.1"):
    eid = cve + "/FIXTURE"
    metric = {"score": score, "version": version, "severity": "HIGH", "vector": "", "source": "fixture",
              "metric_type": "Primary", "evidence_ids": [eid]}
    report = {"status": "partial", "cvss": metric, "affected_ranges": [], "attack_conditions": [],
              "technical_impact": [], "fix_records": [], "poc_candidates": [], "warnings": [],
              "evidence": [{"citation_id": eid, "text": "Synthetic score fixture.", "url": "https://example.org", "locator": "metrics", "text_kind": "automatic_structured_extract"}]}
    return {"item": {"cve_id": cve, "raw_data": {"automatic_assessment": report}}, "cvss": metric}


class ConversationTest(unittest.TestCase):
    def setUp(self):
        self.store = SessionStore()
        self.calls = []

    def answer(self, question, *, cve_ids):
        self.calls.append((question, cve_ids))
        return {"answer": "fixture", "evidence": [{"item": {"cve_id": c}} for c in cve_ids],
                "used_model": False, "steps": [], "verdict": {"passed": True, "notes": []}}

    def test_followup_resolves_entity_without_reusing_assistant_as_evidence(self):
        first = self.store.run("介绍 " + A, "", "", self.answer)
        second = self.store.run("那应该怎么修复？", "", first["session_id"], self.answer)
        self.assertEqual(second["context"]["cve_ids"], [A])
        self.assertEqual(second["turn"], 2)
        self.assertEqual(self.calls[-1], ("那应该怎么修复？", [A]))
        self.assertEqual(len(second["history"]), 2)

    def test_new_explicit_entity_overrides_pin_and_previous(self):
        first = self.store.run(A, "", "", self.answer)
        second = self.store.run(B + " 的评分", A, first["session_id"], self.answer)
        self.assertEqual(second["context"]["cve_ids"], [B])
        self.assertIn("覆盖", second["context"]["notice"])

    def test_independent_session_and_ambiguous_first_question(self):
        self.store.run(A, "", "", self.answer)
        result = self.store.run("那怎么修复？", "", "", self.answer)
        self.assertEqual(result["evidence"], [])
        self.assertIn("无法确定", result["answer"])

    def test_unknown_answer_clears_context_instead_of_returning_to_old_cve(self):
        first = self.store.run(A, "", "", self.answer)
        unknown = self.store.run("CVE-2099-99999", "", first["session_id"], lambda *a, **k: SessionStore._empty("没有情报"))
        following = self.store.run("那怎么修复？", "", unknown["session_id"], self.answer)
        self.assertIn("无法确定", following["answer"])

    def test_product_question_does_not_inherit_previous_cve(self):
        self.assertEqual(resolve("vllm 的风险", previous=[A])[0], [])

    def test_comparison_scope_survives_followup_but_assets_require_one(self):
        first = self.store.run(A + " 和 " + B, "", "", self.answer)
        second = self.store.run("那它们的版本范围呢？", "", first["session_id"], self.answer)
        self.assertEqual(second["context"]["cve_ids"], [A, B])
        assets = self.store.run("我们的资产呢？", "", first["session_id"], self.answer)
        self.assertEqual(assets["evidence"], [])

    def test_expiry_invalid_id_capacity_and_history_bound(self):
        now = [0]
        store = SessionStore(capacity=1, ttl=5, max_turns=2, clock=lambda: now[0])
        first = store.run(A, "", "", self.answer)
        with self.assertRaises(SessionError):
            store.run(A, "", "", self.answer)
        with self.assertRaises(SessionError):
            store.run(A, "", "../../file", self.answer)
        for _ in range(3):
            last = store.run("评分", "", first["session_id"], self.answer)
        self.assertEqual(len(last["history"]), 2)
        now[0] = 6
        with self.assertRaises(SessionError):
            store.run(A, "", first["session_id"], self.answer)
        self.assertNotEqual(store.run(A, "", "", self.answer)["session_id"], first["session_id"])

    def test_other_sessions_can_run_while_one_is_busy(self):
        entered, release = threading.Event(), threading.Event()
        def slow(*args, **kwargs):
            entered.set()
            release.wait(3)
            return self.answer(*args, **kwargs)
        worker = threading.Thread(target=lambda: self.store.run(A, "", "", slow))
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.store.run(B, "", "", self.answer)["context"]["cve_ids"], [B])
        finally:
            release.set()
            worker.join(3)

    def test_cross_cve_retrieval_is_separate_and_same_version_comparison_is_cited(self):
        def retrieve(query, *, cve_id, **kwargs):
            self.assertEqual(set(CVE.findall(query)), {cve_id})
            return [record(cve_id, 8.8 if cve_id == A else 7.5)]
        with patch("agents.qa_agent.search", side_effect=retrieve):
            result = qa_run("比较 " + A + " 和 " + B)
        self.assertIn("基础分最高的是 " + A, result["answer"])
        self.assertEqual([r["item"]["cve_id"] for r in result["evidence"]], [A, B])
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])

    def test_different_versions_not_ranked_and_unknown_comparison_refused(self):
        def retrieve(query, *, cve_id, **kwargs):
            return [record(cve_id, 8.8, "3.1" if cve_id == A else "4.0")]
        with patch("agents.qa_agent.search", side_effect=retrieve):
            result = qa_run("比较 " + A + " 和 " + B)
        self.assertIn("不同 CVSS 版本", result["answer"])
        self.assertNotIn("基础分最高", result["answer"])
        with patch("agents.qa_agent.search", side_effect=lambda *a, cve_id, **k: [record(A, 8.8)] if cve_id == A else []):
            self.assertEqual(qa_run(A + " 和 CVE-2099-99999")["evidence"], [])

    def test_score_cannot_be_attributed_to_other_cve_citation(self):
        records = [record(A, 8.8), record(B, 7.5)]
        for row in records:
            row["evidence_chunks"] = row["item"]["raw_data"]["automatic_assessment"]["evidence"]
        self.assertFalse(verify("CVSS 为 8.8 [%s/FIXTURE]" % B, records)["passed"])
        self.assertTrue(verify("CVSS 为 8.8 [%s/FIXTURE]" % A, records)["passed"])

    def test_api_history_expiry_and_legacy_body(self):
        from fastapi.testclient import TestClient
        from api.app import app
        with patch("api.app.sessions", self.store), patch("api.app.run_answer", side_effect=self.answer):
            client = TestClient(app)
            first = client.post("/api/ask", json={"question": A}).json()
            second = client.post("/api/ask", json={"question": "那怎么修复？", "session_id": first["session_id"]})
            self.assertEqual(second.status_code, 200)
            self.assertEqual(second.json()["context"]["cve_ids"], [A])
            self.assertEqual(client.post("/api/ask", json={"question": "评分", "session_id": "0" * 32}).status_code, 409)
            self.assertEqual(client.post("/api/ask", json={"question": "x" * 4001}).status_code, 422)
