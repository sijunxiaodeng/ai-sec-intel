"""Rule-bound candidate behaviour, not measured taxonomy accuracy."""
import hashlib
import json
import unittest

from enrichment.risk_taxonomy import candidates


class RiskTaxonomyTest(unittest.TestCase):
    def report(self, description):
        cve = {"id": "CVE-2026-90000", "descriptions": [{"lang": "en", "value": description}]}
        body = json.dumps({"vulnerabilities": [{"cve": cve}]}).encode()
        return candidates(cve, {"retrieved_at": "2026-10-14T00:00:00Z"}, hashlib.sha256(body).hexdigest())

    def test_explicit_prompt_and_system_prompt_mechanisms_have_versioned_labels(self):
        result = self.report("An LLM prompt injection allows system prompt extraction.")
        items = {r["rule_id"]: r for r in result["items"]}
        self.assertEqual(items["prompt_injection"]["owasp"][0]["id"], "LLM01:2025")
        self.assertEqual(items["prompt_injection"]["mitre_atlas"][0]["id"], "AML.T0051")
        self.assertEqual(items["system_prompt_extraction"]["mitre_atlas"][0]["id"], "AML.T0056")
        self.assertEqual(items["system_prompt_extraction"]["mitre_atlas"][0]["version"], "2026.09")
        ids = {r["citation_id"] for r in result["evidence"]}
        for row in items.values():
            self.assertTrue(set(row["evidence_ids"]) <= ids)
            self.assertEqual(row["review_status"], "not_reviewed")
        self.assertIn("不是 OWASP/MITRE", result["notice"])
        self.assertIsNone(result["independent_accuracy"])

    def test_general_infrastructure_cve_has_no_forced_llm_category(self):
        result = self.report("Ollama has a path traversal and unsafe deserialization vulnerability.")
        self.assertEqual(result["status"], "empty")
        self.assertEqual(result["items"], [])

    def test_supply_chain_and_resource_require_ai_context_in_same_sentence(self):
        self.assertEqual(self.report("A malicious package causes resource exhaustion.")["items"], [])
        self.assertEqual(self.report("A malicious package exists. An LLM service is mentioned separately.")["items"], [])
        result = self.report("A malicious model causes resource exhaustion in the Ollama inference service.")
        self.assertEqual({r["rule_id"] for r in result["items"]}, {"ai_supply_chain", "unbounded_ai_consumption"})

    def test_explicit_training_data_poisoning_and_chinese_mechanisms(self):
        result = self.report("训练数据投毒、系统提示词泄漏与提示词注入。智能体越权。")
        self.assertEqual({r["rule_id"] for r in result["items"]}, {
            "training_data_poisoning", "system_prompt_extraction", "prompt_injection", "excessive_agent_authority"})

    def test_explicit_negative_descriptions_do_not_receive_tags(self):
        for text in ("The model is not susceptible to prompt injection.",
                     "The service is not vulnerable to a prompt injection.",
                     "There is no evidence of system prompt leakage.",
                     "该模型不存在提示词注入风险。", "未发现系统提示词泄漏。"):
            with self.subTest(text=text):
                self.assertEqual(self.report(text)["items"], [])

    def test_negative_sentence_does_not_hide_later_positive_mechanism(self):
        result = self.report("The model is not susceptible to prompt injection. A later attack enables prompt injection.")
        self.assertEqual([r["rule_id"] for r in result["items"]], ["prompt_injection"])
        citation = result["evidence"][0]
        self.assertIn("A later attack", citation["text"])
        self.assertNotIn("not susceptible", citation["text"])

    def test_sensitive_information_does_not_invent_api_exfiltration_technique(self):
        result = self.report("A membership inference attack can expose training data.")
        self.assertEqual(result["items"][0]["owasp"][0]["id"], "LLM02:2025")
        self.assertEqual(result["items"][0]["mitre_atlas"], [])

    def test_repeated_triggers_are_deduplicated_and_bad_descriptions_are_ignored(self):
        cve = {"id": "CVE-2026-90000", "descriptions": [None, {"value": 42},
               {"lang": "en", "value": "prompt injection and prompt injection"},
               {"lang": "zh", "value": "提示词注入"}]}
        result = candidates(cve, {}, "synthetic-source-hash")
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["source_language"], "en")

    def test_excerpt_uses_true_description_offset_and_retains_source_hash(self):
        result = self.report("An LLM prompt injection allows extraction.")
        row = result["evidence"][0]
        self.assertIn("descriptions/0/value；字符 [0,", row["locator"])
        self.assertEqual(json.loads(row["text"]), "An LLM prompt injection allows extraction.")
        self.assertEqual(len(row["source_response_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
