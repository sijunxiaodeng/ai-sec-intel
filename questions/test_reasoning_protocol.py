"""Real request serialization with a fake HTTP peer; archives remain authoritative."""
import copy
import io
import json
import os
import unittest
import urllib.request
from unittest.mock import patch

from agents import general_reasoning as reasoning
from config import llm
from questions import test_general_reasoning as fixtures


class ReasoningProtocolTest(unittest.TestCase):
    def setUp(self):
        fixtures.GeneralReasoningTest.setUp(self)
        self.config = {"reasoning_budget_seconds": 30, "base_url": "http://127.0.0.1:11434/v1",
                       "model": "fixture", "api_key": ""}
        for setting in (patch.object(reasoning, "load_settings", return_value=self.config),
                        patch.object(llm, "load_settings", return_value=self.config),
                        patch.dict(os.environ, {"OFFLINE_DEMO": "0"})):
            setting.start()
            self.addCleanup(setting.stop)

    ask = fixtures.GeneralReasoningTest.ask

    def model(self, messages, **kwargs):
        result = json.loads(fixtures.GeneralReasoningTest.model(self, messages, **kwargs))
        payload = json.loads(messages[-1]["content"])
        if "quote_options" in payload:
            for item in result.get("claims", []) + result.get("conflicts", []):
                if "supports" not in item:
                    continue
                choices = []
                for support in item["supports"]:
                    match = next((option for option in payload["quote_options"]
                                  if all(option[key] == support.get(key) for key in ("citation_id", "quote"))), None)
                    selected = {"quote_id": match["quote_id"] if match else "UNKNOWN"}
                    selected.update({key: value for key, value in support.items()
                                     if key not in ("citation_id", "quote")})
                    choices.append(selected)
                item["supports"] = choices
        return json.dumps(result)

    def http_requests(self):
        requests = []
        fixture_model = self.model

        def respond(request, **kwargs):
            body = json.loads(request.data)
            requests.append(body)
            answer = fixture_model(body["messages"], timeout=kwargs["timeout"])
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": answer}}]}).encode())

        self.model = llm.chat
        with patch.object(urllib.request.OpenerDirector, "open", side_effect=respond):
            result = self.ask()
        return result, requests

    def assert_closed_object(self, schema, fields):
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(fields))
        self.assertEqual(set(schema["properties"]), set(fields))

    def test_all_three_schemas_reach_http_and_bind_current_evidence_and_claims(self):
        # One citation appears only during follow-up retrieval. The synthesis
        # schema must bind the final evidence pool, not the original search.
        def staged_search(query, *args, **kwargs):
            row = self.rows[1] if query.startswith("Orion") else self.rows[0]
            return {"mode": "bm25", "evidence": [row]}

        with patch.object(reasoning, "search", side_effect=staged_search):
            result, requests = self.http_requests()
        self.assertTrue(result["used_model"], result)
        self.assertEqual(len(requests), 3)
        schemas = []
        for body, stage in zip(requests, ("decompose", "synthesize", "verify")):
            output = body["response_format"]
            self.assertEqual(output["type"], "json_schema")
            self.assertTrue(output["json_schema"]["strict"])
            self.assertEqual(output["json_schema"]["name"], "library_reasoning_" + stage)
            schemas.append(output["json_schema"]["schema"])
        self.assert_closed_object(schemas[0], ("subquestions", "ambiguities", "missing_premises"))
        self.assertEqual(schemas[0]["properties"]["subquestions"]["minItems"], 1)
        self.assertEqual(schemas[0]["properties"]["subquestions"]["maxItems"], 2)
        for schema in schemas[1:]:
            self.assert_closed_object(schema, ("claims", "conflicts", "missing_premises"))
        kinds = schemas[1]["properties"]["claims"]["items"]["anyOf"]
        for claim in kinds:
            self.assert_closed_object(claim, ("text", "kind", "supports", "assumptions"))
        claim = next(item for item in kinds if item["properties"]["kind"]["enum"] == ["finding"])
        support = claim["properties"]["supports"]["items"]
        self.assert_closed_object(support, ("quote_id",))
        choices = json.loads(requests[1]["messages"][-1]["content"])["quote_options"]
        self.assertEqual(set(support["properties"]["quote_id"]["enum"]),
                         {option["quote_id"] for option in choices})
        self.assertEqual({option["citation_id"] for option in choices},
                         {row["citation_id"] for row in self.rows})
        self.assertTrue(all(len(option["quote"]) <= reasoning.MAX_QUOTE for option in choices))
        by_id = {item["quote_id"]: item for item in choices}
        documents = {row["citation_id"]: row["document_id"] for row in self.rows}
        inference = next(item for item in kinds if item["properties"]["kind"]["enum"] == ["inference"])
        for pair in inference["properties"]["supports"]["enum"]:
            self.assertEqual(len({documents[by_id[item["quote_id"]]["citation_id"]] for item in pair}), 2)
        verify = schemas[2]["properties"]["claims"]
        self.assertEqual((verify["minItems"], verify["maxItems"]), (1, 1))
        self.assert_closed_object(verify["items"], ("claim_id", "verdict"))
        self.assertEqual(verify["items"]["properties"]["claim_id"]["enum"], ["C1"])
        self.assertEqual(set(verify["items"]["properties"]["verdict"]["enum"]),
                         {"supported", "contradicted", "insufficient"})
        self.assertEqual(result["reasoning_claims"][0]["supports"], self.supports)
        for body in requests[1:]:
            payload = json.loads(body["messages"][-1]["content"])
            self.assertTrue(all("text" not in row for row in payload["evidence"]))
            self.assertLessEqual(sum(len(option["quote"]) for option in payload["quote_options"]),
                                 reasoning.MAX_LOCAL_QUOTE_CHARACTERS)
        verifier = json.loads(requests[2]["messages"][-1]["content"])
        self.assertTrue(all(set(item) == {"quote_id"} for claim in verifier["draft"]["claims"]
                            for item in claim["supports"]))

    def test_remote_requests_retain_json_object_mode(self):
        self.config.update(base_url="https://example.org/v1", api_key="fixture-key")
        result, requests = self.http_requests()
        self.assertTrue(result["used_model"], result)
        self.assertEqual([body["response_format"] for body in requests], [{"type": "json_object"}] * 3)
        for endpoint in ("http://localhost:8000/v1", "https://localhost.example.org:11434/v1"):
            self.config["base_url"] = endpoint
            self.assertEqual(reasoning._response_format("decompose", {}), {"type": "json_object"})

    def test_schema_does_not_allow_invalid_provider_output_to_bypass_local_checks(self):
        original_draft, original_verify = copy.deepcopy(self.draft), copy.deepcopy(self.verify)
        for case, reason in (("extra_top_field", "invalid_schema"),
                             ("extra_support_field", "invalid_schema"),
                             ("forged_quote", "unknown_quote_choice"),
                             ("extra_verdict_field", "invalid_schema")):
            with self.subTest(case=case):
                self.draft, self.verify = copy.deepcopy(original_draft), copy.deepcopy(original_verify)
                self.draft["claims"][0]["text"] = "INVALID GENERATED CONCLUSION"
                if case == "extra_top_field":
                    self.draft["description"] = "Not a permitted field"
                elif case == "extra_support_field":
                    self.draft["claims"][0]["supports"][0]["description"] = "Not a permitted field"
                elif case == "forged_quote":
                    self.draft["claims"][0]["supports"][0]["quote"] = "This quotation is not in the source archive."
                else:
                    self.verify["claims"][0]["text"] = "Not a permitted field"
                result = self.ask()
                self.assertFalse(result["used_model"])
                self.assertEqual(result["fallback_reason"], reason)
                self.assertEqual(result["reasoning_claims"], [])
                self.assertNotIn("INVALID GENERATED CONCLUSION", result["answer"])

    def test_empty_draft_verification_has_zero_items_and_no_invalid_empty_enum(self):
        choices = reasoning._quote_options({row["citation_id"]: row for row in self.rows})
        schema = reasoning._response_format("verify", {"evidence": self.rows, "draft": {"claims": []},
                    "quote_options": [dict(quote_id=key, **item) for key, item in choices.items()]})
        claims = schema["json_schema"]["schema"]["properties"]["claims"]
        self.assertEqual((claims["minItems"], claims["maxItems"]), (0, 0))
        self.assertNotIn("enum", claims["items"]["properties"]["claim_id"])

    def test_local_choices_still_require_cross_document_inference(self):
        self.draft["claims"][0]["supports"][1] = self.draft["claims"][0]["supports"][0]
        self.assertEqual(self.ask()["fallback_reason"], "unknown_or_duplicate_citation")

    def test_local_choices_do_not_override_semantic_contradiction_or_missing_conditions(self):
        self.verify["claims"][0]["verdict"] = "contradicted"
        self.assertEqual(self.ask()["fallback_reason"], "no_supported_claims")
        self.verify["claims"][0]["verdict"] = "supported"
        self.draft["claims"][0]["kind"] = "conditional"
        self.assertEqual(self.ask()["fallback_reason"], "invalid_assumptions")

    def test_source_change_during_local_choice_synthesis_discards_resolved_quotes(self):
        original = self.model

        def model(messages, **kwargs):
            value = original(messages, **kwargs)
            payload = json.loads(messages[-1]["content"])
            if "quote_options" in payload and "draft" not in payload:
                fixtures.GeneralReasoningTest.change_source(self)
            return value

        self.model = model
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "evidence_changed_or_invalid")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])

    def test_identical_draft_and_verifier_differences_are_shown_once_with_uncertainty(self):
        description = "两份资料的保留条件需要进一步核对。"
        self.draft["conflicts"] = [{"description": description, "supports": copy.deepcopy(self.supports)}]
        self.verify["conflicts"] = [{"description": description, "supports": copy.deepcopy(self.supports[::-1])}]
        result = self.ask()
        self.assertEqual(len(result["conflicts"]), 1, result)
        self.assertEqual(result["reasoning_trace"][-1]["conflicts"], 1)
        self.assertEqual(result["answer"].count("模型提示的待核对差异：" + description), 1)
        self.assertNotIn("来源冲突", result["answer"])
        self.assertEqual(result["reasoning_status"], "partial")

    def test_different_text_or_quoted_support_is_never_merged_as_an_identical_difference(self):
        description = "两份资料的保留条件需要进一步核对。"
        original = {"description": description, "supports": copy.deepcopy(self.supports)}
        different_quote = copy.deepcopy(original)
        different_quote["supports"][1]["quote"] = self.rows[1]["text"].split(". ")[1] + "."
        for changed in (dict(original, description="两份资料的适用版本需要进一步核对。"), different_quote):
            with self.subTest(changed=changed):
                self.draft["conflicts"] = [copy.deepcopy(original)]
                self.verify["conflicts"] = [changed]
                result = self.ask()
                self.assertEqual(len(result["conflicts"]), 2, result)
                self.assertEqual(result["answer"].count("模型提示的待核对差异："), 2)

    def test_apparently_duplicate_difference_cannot_bypass_verifier_schema_validation(self):
        original = {"description": "两份资料的保留条件需要进一步核对。", "supports": copy.deepcopy(self.supports)}
        self.draft["conflicts"] = [original]
        self.verify["conflicts"] = [dict(original, unrequested_field="must reject")]
        result = self.ask()
        self.assertEqual(result["fallback_reason"], "invalid_schema")
        self.assertFalse(result["used_model"])
        self.assertEqual(result["reasoning_claims"], [])


class QuoteChoiceTest(unittest.TestCase):
    def test_local_payload_bounds_complete_quotes_preserves_multiple_sources_and_never_repeats_draft_quotes(self):
        evidence, documents = {}, {}
        for index in range(reasoning.MAX_EVIDENCE):
            doc_id, citation_id = "doc%d" % index, "citation%d" % index
            sentences = ["Source %d statement %d does not delete audit metadata unless the separate policy authorizes "
                         "this exact action under the stated deployment conditions and the validated access controls."
                         % (index, number) for number in range(4)]
            evidence[citation_id] = {"document_id": doc_id, "citation_id": citation_id,
                                     "content_scope": "abstract", "text": " ".join(sentences)}
            documents[doc_id] = {"title": "Overlong metadata " * 100, "version": "complete-version-1"}
        choices = reasoning._bounded_quote_options(evidence, ["doc15"])
        self.assertLessEqual(len(choices), reasoning.MAX_LOCAL_QUOTE_OPTIONS)
        self.assertLessEqual(sum(len(option["quote"]) for option in choices.values()),
                             reasoning.MAX_LOCAL_QUOTE_CHARACTERS)
        chosen_docs = {evidence[option["citation_id"]]["document_id"] for option in choices.values()}
        self.assertGreaterEqual(len(chosen_docs), 2)
        self.assertIn("doc15", chosen_docs)
        # Every first pass visits another source, so a long first document cannot
        # crowd out the other sources before the budget is used.
        self.assertEqual(len(chosen_docs), len(choices))
        for option in choices.values():
            self.assertIn(option["quote"], evidence[option["citation_id"]]["text"])
            self.assertTrue(option["quote"].endswith("."))
            self.assertIn("does not", option["quote"])
            self.assertIn("unless", option["quote"])
        payload = reasoning._compact_evidence_payload(evidence, documents, choices)
        first = next(iter(choices.values()))
        draft = {"claims": [{"claim_id": "C1", "text": "An explicitly conditional source finding.",
                              "kind": "finding", "supports": [first], "assumptions": []}],
                 "conflicts": [], "missing_premises": []}
        payload["draft"] = reasoning._compact_draft(draft, choices)
        serialized = json.dumps(payload)
        self.assertEqual(serialized.count(first["quote"]), 1)
        self.assertNotIn("Overlong metadata", serialized)
        self.assertTrue(all(set(row) == {"citation_id", "document_id", "content_scope"}
                            for row in payload["evidence"]))
        self.assertTrue(all(row["version"] == "complete-version-1" for row in payload["documents"]))

    def test_choices_are_contiguous_and_keep_negations_and_long_sentence_conditions(self):
        negative = "The protocol does not delete audit metadata unless a separate policy authorizes it."
        long_sentence = "The protocol cannot " + "delete records " * 30 + "unless authorized."
        text = "A short harmless source introduction. " + negative + " " + long_sentence
        evidence = {"source": {"text": text}}
        choices = reasoning._quote_options(evidence)
        quotes = [item["quote"] for item in choices.values()]
        self.assertIn(negative, quotes)
        self.assertFalse(any("cannot" in quote for quote in quotes))
        for quote in quotes:
            self.assertIn(quote, text)
            self.assertLessEqual(len(quote), reasoning.MAX_QUOTE)
        # No whitespace normalization that could make a near-match look exact.
        preserved = "The protocol does not\tdelete any audit metadata."
        self.assertEqual(next(iter(reasoning._quote_options({"source": {"text": preserved}}).values()))["quote"],
                         preserved)
        wrapped = "The protocol does not delete audit metadata\nunless a separate policy authorizes it."
        self.assertEqual(next(iter(reasoning._quote_options({"source": {"text": wrapped}}).values()))["quote"], wrapped)

    def test_unknown_choice_extra_fields_and_tampered_registry_never_pass_source_validation(self):
        text = "The protocol does not delete any audit metadata."
        evidence = {"source": {"text": text}}
        choices = reasoning._quote_options(evidence)
        with self.assertRaisesRegex(reasoning.ReasoningError, "unknown_quote_choice"):
            reasoning._supports([{"quote_id": "invented"}], evidence, quote_options=choices)
        with self.assertRaisesRegex(reasoning.ReasoningError, "invalid_schema"):
            reasoning._supports([{"quote_id": "Q1", "quote": text}], evidence, quote_options=choices)
        choices["Q1"]["quote"] = "The protocol deletes every audit record."
        with self.assertRaisesRegex(reasoning.ReasoningError, "quote_not_in_archive"):
            reasoning._supports([{"quote_id": "Q1"}], evidence, quote_options=choices)

    def test_quote_ids_do_not_make_two_chunks_of_one_document_independent_sources(self):
        evidence = {"a": {"document_id": "same", "text": "The cache uses the erasure protocol."},
                    "b": {"document_id": "same", "text": "The erasure protocol retains audit metadata."}}
        choices = reasoning._quote_options(evidence)
        draft = {"claims": [{"text": "The cache retains audit metadata.", "kind": "inference",
                             "supports": [{"quote_id": "Q1"}, {"quote_id": "Q2"}], "assumptions": []}],
                 "conflicts": [], "missing_premises": []}
        with self.assertRaisesRegex(reasoning.ReasoningError, "cross_document_support_required"):
            reasoning._synthesis(draft, evidence, choices)


if __name__ == "__main__":
    unittest.main()
