"""Contract regressions with synthetic unseen topics, not accuracy evaluation."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.library_qa import run
from rag.library import detail, ingest_document
from rag.evidence import _connection
from questions.test_reference_text import response


class GeneralReasoningTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        settings = patch("agents.general_reasoning.load_settings", return_value={"reasoning_budget_seconds": 30})
        settings.start()
        self.addCleanup(settings.stop)
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
        for row in self.rows:
            self.assertEqual(len(row["source_response_sha256"]), 64)
            self.assertEqual(len(row["text_sha256"]), 64)
        self.question = "Zephyr cache erasure 是否会删除全部 audit metadata？"
        self.plan = {"subquestions": ["Zephyr erasure protocol", "Orion erasure audit metadata"],
                     "ambiguities": [], "missing_premises": []}
        self.supports = [{"citation_id": row["citation_id"], "quote": row["text"].split(". ")[0] + "."}
                         for row in self.rows]
        self.draft = {"claims": [{"text": "Zephyr 使用 Orion 擦除协议；按该协议，缓存向量被删除但审计元数据仍保留。",
                                  "kind": "inference", "supports": self.supports, "assumptions": []}],
                      "conflicts": [], "missing_premises": []}
        self.verify = {"claims": [{"claim_id": "C1", "verdict": "supported", "scope_verdict": "preserved",
                                  "counter_supports": [], "reason": "The source scopes and conditions are preserved."}],
                       "conflicts": [], "missing_premises": []}

    def model(self, messages, **kwargs):
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 30)
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

    def test_reasoning_deadline_uses_deployment_budget(self):
        captured = []
        original = self.model
        def respond(messages, **kwargs):
            captured.append(kwargs["timeout"])
            # The fixture schema is identical; only the outer deadline changes.
            return original(messages, **dict(kwargs, timeout=min(kwargs["timeout"], 30)))
        self.model = respond
        with patch("agents.general_reasoning.load_settings", return_value={"reasoning_budget_seconds": 60}):
            result = self.ask()
        self.assertTrue(result["used_model"])
        self.assertEqual(len(captured), 3)
        self.assertTrue(all(30 < timeout <= 60 for timeout in captured), captured)

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
        self.verify["claims"][0]["counter_supports"] = [self.supports[1]]
        result = self.ask()
        self.assertFalse(result["used_model"])
        self.assertEqual(result["fallback_reason"], "no_supported_claims")
        self.assertNotIn("Zephyr deletes every audit record.", result["answer"])

    def test_source_conflict_suppresses_conclusion_instead_of_choosing_a_side(self):
        self.verify["conflicts"] = [{"description": "两份资料对同一部署的保留范围无法统一。",
                                     "supports": self.supports, "relation": "contradiction", "affected_claim_ids": ["C1"]}]
        result = self.ask()
        self.assertEqual(result["reasoning_status"], "partial")
        self.assertEqual(result["reasoning_claims"], [])
        self.assertIn("模型提示的待核对差异", result["answer"])
        self.assertNotIn(self.draft["claims"][0]["text"], result["answer"])
        self.assertEqual(len(result["evidence"]), 2)

    def test_entity_ambiguity_and_missing_version_prevent_unconditional_inference(self):
        self.plan["ambiguities"] = ["Zephyr 可能指不同部署，请明确部署名称。"]
        self.plan["missing_premises"] = ["请提供部署所采用的协议版本。"]
        self.verify["claims"][0].update(verdict="insufficient", scope_verdict="unclear",
                                        reason="The deployment and protocol version for this claim are unknown.")
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
        with patch("agents.general_reasoning.reasoning_time_budget", return_value=0), \
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

    def test_two_different_chunks_of_one_document_cannot_form_cross_document_inference(self):
        candidate = {"url":"https://research.example/fixture-0", "document_type":"research_article",
                     "source_name":"Synthetic Research", "source_id":"fixture-0"}
        text = "Zephyr encrypted feature cache uses the Orion erasure protocol. This AI security fixture documents the cache boundary for a hypothetical service. "
        ingest_document(candidate, self.db, lambda url: response(url, text * 20, "text/plain"))
        chunks = detail(self.ids[0], self.db)["evidence"]
        self.assertGreaterEqual(len(chunks), 2)
        self.draft["claims"][0]["supports"] = [{"citation_id": row["citation_id"], "quote":row["text"][:120]} for row in chunks[:2]]
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "cross_document_support_required")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])

    def change_source(self):
        candidate = {"url":"https://research.example/fixture-0", "document_type":"research_article",
                     "source_name":"Synthetic Research", "source_id":"fixture-0"}
        text = "Zephyr no longer documents Orion erasure as its current cache protocol. This revised AI security fixture requires re-checking the service configuration. "
        changed = ingest_document(candidate, self.db, lambda url: response(url, text * 4, "text/plain"))
        self.assertTrue(changed["changed"])

    def assert_source_update_is_fallback(self, stage):
        self.draft["claims"][0]["text"] = "STALE MODEL CONCLUSION"
        def model(messages, **kwargs):
            payload = json.loads(messages[-1]["content"])
            value = self.model(messages, **kwargs)
            current_stage = "decompose" if "initial_evidence" in payload else "verify" if "draft" in payload else "synthesize"
            if current_stage == stage:
                self.change_source()
            return value
        with patch("rag.library._dense", side_effect=RuntimeError()), \
             patch("agents.general_reasoning.configured", return_value=True), \
             patch("agents.general_reasoning.chat", side_effect=model):
            result = run(self.question, mode="reasoning", db_path=self.db)
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])
        self.assertNotIn("STALE MODEL CONCLUSION", result["answer"])
        current = detail(self.ids[0], self.db)
        self.assertNotEqual(current["source_response_sha256"], self.rows[0]["source_response_sha256"])
        for row in result["evidence"]:
            if row["document_id"] == self.ids[0]:
                self.assertEqual(row["source_response_sha256"], current["source_response_sha256"])

    def test_source_update_during_decomposition_discards_old_conclusion(self):
        self.assert_source_update_is_fallback("decompose")

    def test_source_update_during_synthesis_discards_old_conclusion(self):
        self.assert_source_update_is_fallback("synthesize")

    def test_source_update_during_verification_discards_old_conclusion(self):
        self.assert_source_update_is_fallback("verify")

    def verify_after_change(self, change):
        self.draft["claims"][0]["text"] = "STALE MODEL CONCLUSION"
        def model(messages, **kwargs):
            payload = json.loads(messages[-1]["content"])
            value = self.model(messages, **kwargs)
            if "draft" in payload:
                change()
            return value
        with patch("rag.library._dense", side_effect=RuntimeError()), \
             patch("agents.general_reasoning.configured", return_value=True), \
             patch("agents.general_reasoning.chat", side_effect=model):
            return run(self.question, mode="reasoning", document_ids=self.ids, db_path=self.db)

    def test_revision_metadata_change_is_detected_even_with_identical_quotes(self):
        def change():
            with _connection(self.db) as con:
                value = json.loads(con.execute("SELECT payload FROM library_documents WHERE document_id=?", (self.ids[0],)).fetchone()[0])
                value["version"] = "fixture-revision-2"
                con.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(value),self.ids[0]))
        result = self.verify_after_change(change)
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertNotIn("STALE MODEL CONCLUSION", result["answer"])

    def test_document_text_hash_change_is_detected_with_the_same_snapshot_and_quotes(self):
        def change():
            with _connection(self.db) as con:
                value = json.loads(con.execute("SELECT payload FROM library_documents WHERE document_id=?", (self.ids[0],)).fetchone()[0])
                value["text_sha256"] = hashlib.sha256(b"changed full-document metadata").hexdigest()
                con.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(value),self.ids[0]))
        result = self.verify_after_change(change)
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertNotIn("STALE MODEL CONCLUSION", result["answer"])

    def test_current_evidence_set_is_rechecked_not_only_document_hashes(self):
        def change():
            with _connection(self.db) as con:
                value = dict(self.rows[0], citation_id=self.rows[0]["citation_id"] + "-rebound")
                con.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(value),self.rows[0]["evidence_id"]))
        result = self.verify_after_change(change)
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertFalse(result["used_model"])
        self.assertNotIn("STALE MODEL CONCLUSION", result["answer"])

    def test_corrupt_source_snapshot_during_verification_never_reuses_old_text(self):
        def change():
            with _connection(self.db) as con:
                con.execute("UPDATE library_snapshots SET body=? WHERE document_id=?", (b"corrupt snapshot", self.ids[0]))
        result = self.verify_after_change(change)
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["evidence"], [])
        self.assertNotIn("STALE MODEL CONCLUSION", result["answer"])

    def test_missing_snapshot_hash_is_not_assumed_to_be_verified(self):
        import agents.general_reasoning as reasoner
        original_detail = reasoner.detail
        def incomplete(doc_id, db):
            doc = original_detail(doc_id, db)
            doc.pop("source_response_sha256")
            return doc
        with patch("agents.general_reasoning.detail", side_effect=incomplete):
            result = self.ask()
        self.assertEqual(result["fallback_reason"], "unverifiable_evidence_snapshot")
        self.assertFalse(result["used_model"])
        self.assertFalse(result["model_attempted"])

    def forge_index_text(self):
        """Change a real SQLite row and rehash it without changing archived bytes."""
        forged = "Zephyr cache erasure removes all audit metadata. This AI security sentence is forged."
        with _connection(self.db) as con:
            raw_sha, body = con.execute("SELECT digest,body FROM library_snapshots WHERE document_id=?", (self.ids[0],)).fetchone()
            self.assertNotIn(forged.encode(), body)
            row = json.loads(con.execute("SELECT payload FROM evidence WHERE evidence_id=?", (self.rows[0]["evidence_id"],)).fetchone()[0])
            row["text"] = forged
            row["text_sha256"] = hashlib.sha256(forged.encode()).hexdigest()
            con.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(row), row["evidence_id"]))
            after_sha, after_body = con.execute("SELECT digest,body FROM library_snapshots WHERE document_id=?", (self.ids[0],)).fetchone()
        self.assertEqual((raw_sha, body), (after_sha, after_body))
        self.assertEqual(row["source_response_sha256"], raw_sha)
        return forged

    def test_rehashed_forged_index_before_retrieval_cannot_be_used_as_an_original_quote(self):
        forged = self.forge_index_text()
        self.draft["claims"] = [{"text": "FORGED INDEX CONCLUSION", "kind": "finding",
                                 "supports": [{"citation_id": self.rows[0]["citation_id"], "quote": forged}], "assumptions": []}]
        current = detail(self.ids[0], self.db)
        self.assertEqual(current["integrity_status"], "incomplete_or_invalid")
        self.assertEqual(current["evidence"], [])
        result = self.ask()
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])
        self.assertNotIn("FORGED INDEX CONCLUSION", result["answer"])
        self.assertNotIn(forged, result["answer"])
        self.assertNotIn(self.ids[0], {row["document_id"] for row in result["evidence"]})

    def assert_rehashed_index_attack_during_model_is_rejected(self, stage):
        self.draft["claims"][0]["text"] = "MODEL CONCLUSION AFTER INDEX ATTACK"
        forged_texts = []
        def model(messages, **kwargs):
            payload = json.loads(messages[-1]["content"])
            value = self.model(messages, **kwargs)
            current = "decompose" if "initial_evidence" in payload else "verify" if "draft" in payload else "synthesize"
            if current == stage:
                forged_texts.append(self.forge_index_text())
            return value
        with patch("rag.library._dense", side_effect=RuntimeError()), \
                patch("agents.general_reasoning.configured", return_value=True), \
                patch("agents.general_reasoning.chat", side_effect=model):
            result = run(self.question, mode="reasoning", db_path=self.db)
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])
        self.assertEqual(len(forged_texts), 1)
        self.assertNotIn(forged_texts[0], result["answer"])
        self.assertNotIn("MODEL CONCLUSION AFTER INDEX ATTACK", result["answer"])
        self.assertNotIn(self.ids[0], {row["document_id"] for row in result["evidence"]})

    def test_rehashed_index_attack_during_decomposition_cannot_enter_followup_evidence(self):
        self.assert_rehashed_index_attack_during_model_is_rejected("decompose")

    def test_rehashed_index_attack_during_synthesis_cannot_be_accepted(self):
        self.assert_rehashed_index_attack_during_model_is_rejected("synthesize")

    def test_rehashed_index_attack_after_supported_verdict_cannot_be_accepted(self):
        self.assert_rehashed_index_attack_during_model_is_rejected("verify")


if __name__ == "__main__":
    unittest.main()
