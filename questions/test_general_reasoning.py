"""Contract regressions with synthetic unseen topics, not accuracy evaluation."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.library_qa import run
from rag.library import detail, ingest_document
from questions.test_reference_text import response


class GeneralReasoningTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.ids, self.rows = [], []
        # Zephyr and Orion are deliberately synthetic, absent from the fixed
        # topic registry. This exercises data-driven decomposition/retrieval.
        texts = ["Zephyr encrypted feature cache uses the Orion erasure protocol. "
                 "This AI security fixture documents the cache boundary for a hypothetical service. ",
                 "The Orion erasure protocol removes cached feature vectors but retains audit metadata. "
                 "This AI security fixture describes retained audit metadata in a hypothetical service. "]
        for index, text in enumerate(texts):
            candidate = {"url": "https://research.example/fixture-%d" % index,
                         "document_type": "research_article", "source_name": "Synthetic Research",
                         "source_id": "fixture-%d" % index}
            item = ingest_document(candidate, self.db,
                                   lambda url, content=text: response(url, content * 4, "text/plain"))
            self.assertEqual(item["status"], "ok", item)
            self.ids.append(item["document_id"])
            self.rows.append(detail(item["document_id"], self.db)["evidence"][0])
        self.question = "Zephyr cache erasure 是否会删除全部 audit metadata？"
        self.plan = {"subquestions": ["Zephyr erasure protocol", "Orion erasure audit metadata"],
                     "ambiguities": [], "missing_premises": []}
        self.supports = [{"citation_id": row["citation_id"], "quote": row["text"].split(". ")[0] + "."}
                         for row in self.rows]
        self.draft = {"claims": [{"text": "Zephyr 使用 Orion 擦除协议；按该协议，缓存向量被删除但审计元数据仍保留。",
                                  "kind": "inference", "supports": self.supports, "assumptions": []}],
                      "conflicts": [], "missing_premises": []}
        self.verify = {"claims": [{"claim_id": "C1", "verdict": "supported"}],
                       "conflicts": [], "missing_premises": []}

    def model(self, messages, **kwargs):
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 5)
        payload = json.loads(messages[-1]["content"])
        if "initial_evidence" in payload:
            return json.dumps(self.plan)
        if "draft" in payload:
            return json.dumps(self.verify)
        return json.dumps(self.draft)

    def ask(self, **kwargs):
        with patch("rag.library._dense", side_effect=RuntimeError()), \
                patch("agents.general_reasoning.configured", return_value=True), \
                patch("agents.general_reasoning.chat", side_effect=self.model):
            return run(self.question, mode="reasoning", db_path=self.db, **kwargs)

    def test_unknown_topic_chains_two_documents_with_auditable_local_searches(self):
        result = self.ask()
        self.assertTrue(result["used_model"])
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["reasoning_status"], "answered")
        self.assertEqual({row["document_id"] for row in result["evidence"]}, set(self.ids))
        searches = [item for item in result["reasoning_trace"] if item.get("tool") == "local_library_search"]
        self.assertEqual([item["query"] for item in searches], [self.question] + self.plan["subquestions"])
        self.assertEqual(result["reasoning_claims"][0]["supports"], self.supports)
        self.assertFalse(result["verdict"]["semantic_accuracy_measured"])

    def test_followup_retrieval_can_find_evidence_absent_from_initial_results(self):
        def staged_search(query, *args, **kwargs):
            selected = self.rows[1] if query.startswith("Orion") else self.rows[0]
            return {"mode": "bm25", "evidence": [selected]}
        with patch("agents.general_reasoning.search", side_effect=staged_search):
            result = self.ask()
        self.assertEqual(len(result["evidence"]), 2)
        self.assertEqual(result["reasoning_trace"][0]["new_evidence"], 1)

    def test_forged_quote_falls_back_without_displaying_generated_conclusion(self):
        self.draft["claims"][0]["supports"][0]["quote"] = "This fabricated quote does not exist in the archive."
        self.draft["claims"][0]["text"] = "FORGED CONCLUSION"
        result = self.ask()
        self.assertFalse(result["used_model"])
        self.assertEqual(result["fallback_reason"], "quote_not_in_archive")
        self.assertNotIn("FORGED CONCLUSION", result["answer"])
        self.assertIn("原文摘录", result["answer"])

    def test_unknown_citation_falls_back(self):
        self.draft["claims"][0]["supports"][0]["citation_id"] = "DOC-ffffffffffffffff/LIB-fake"
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "unknown_or_duplicate_citation")

    def test_repeated_evidence_does_not_count_as_two_inference_premises(self):
        self.draft["claims"][0]["supports"][1] = self.draft["claims"][0]["supports"][0]
        self.assertEqual(self.ask()["fallback_reason"], "unknown_or_duplicate_citation")

    def test_verifier_can_reject_semantically_false_claim_with_valid_quotes(self):
        self.draft["claims"][0]["text"] = "Zephyr deletes every audit record."
        self.verify["claims"][0]["verdict"] = "contradicted"
        result = self.ask()
        self.assertFalse(result["used_model"])
        self.assertEqual(result["fallback_reason"], "no_supported_claims")
        self.assertNotIn("Zephyr deletes every audit record.", result["answer"])

    def test_source_conflict_suppresses_conclusion_instead_of_choosing_a_side(self):
        self.verify["conflicts"] = [{"description": "两份资料对同一部署的保留范围无法统一。",
                                     "supports": self.supports}]
        result = self.ask()
        self.assertEqual(result["reasoning_status"], "partial")
        self.assertEqual(result["reasoning_claims"], [])
        self.assertIn("来源冲突", result["answer"])
        self.assertNotIn(self.draft["claims"][0]["text"], result["answer"])
        self.assertEqual(len(result["evidence"]), 2)

    def test_entity_ambiguity_and_missing_version_prevent_unconditional_inference(self):
        self.plan["ambiguities"] = ["Zephyr 可能指不同部署，请明确部署名称。"]
        self.plan["missing_premises"] = ["请提供部署所采用的协议版本。"]
        result = self.ask()
        self.assertEqual(result["reasoning_status"], "partial")
        self.assertEqual(result["reasoning_claims"], [])
        self.assertIn("协议版本", result["answer"])

    def test_empty_or_incomplete_verification_is_not_accepted(self):
        self.verify["claims"] = []
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "incomplete_verification")
        self.assertFalse(result["used_model"])

    def test_source_instructions_cannot_extend_the_available_tool_schema(self):
        self.plan["tool"] = "execute_shell"
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "invalid_schema")
        self.assertFalse(result["used_model"])

    def test_budget_exhaustion_falls_back_without_model_request(self):
        with patch("agents.general_reasoning.MODEL_BUDGET_SECONDS", 0), \
                patch("agents.general_reasoning.chat") as model:
            result = self.ask()
        self.assertEqual(result["fallback_reason"], "reasoning_budget_exhausted")
        self.assertFalse(result["model_attempted"])
        model.assert_not_called()

    def test_provider_failure_does_not_expose_response_or_credentials(self):
        with patch("rag.library._dense", side_effect=RuntimeError()), \
                patch("agents.general_reasoning.configured", return_value=True), \
                patch("agents.general_reasoning.chat", side_effect=RuntimeError("secret-response-body")):
            result = run(self.question, mode="reasoning", db_path=self.db)
        self.assertEqual(result["fallback_reason"], "reasoning_request_failed")
        self.assertNotIn("secret-response-body", json.dumps(result))

    def test_disabled_model_keeps_exact_excerpts_and_identifies_fallback(self):
        result = self.ask(use_model=False)
        self.assertFalse(result["used_model"])
        self.assertEqual(result["fallback_reason"], "model_disabled")
        self.assertIn("未执行通用推理", result["answer"])

    def test_invalid_mode_and_missing_document_are_rejected(self):
        with self.assertRaises(ValueError):
            run(self.question, mode="execute", db_path=self.db)
        with self.assertRaises(ValueError):
            self.ask(document_ids=["DOC-ffffffffffffffff"])


if __name__ == "__main__":
    unittest.main()
