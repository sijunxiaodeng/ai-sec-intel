"""Claim-level review routing; synthetic judgments do not measure model accuracy."""
import copy
import unittest
from unittest.mock import patch

from agents import general_reasoning as reasoning
from questions import test_general_reasoning as fixtures
from questions import test_reasoning_protocol as protocol


class ClaimReviewTest(unittest.TestCase):
    def setUp(self):
        fixtures.GeneralReasoningTest.setUp(self)

    model = fixtures.GeneralReasoningTest.model
    ask = fixtures.GeneralReasoningTest.ask

    def two_claims_in_one_paragraph(self):
        first, second = self.rows[0]["text"].split(". ")[:2]
        self.draft["claims"] = [{"text": sentence + ".", "kind": "finding", "assumptions": [],
                                  "supports": [{"citation_id": self.rows[0]["citation_id"], "quote": sentence + "."}]}
                                 for sentence in (first, second)]
        original = copy.deepcopy(self.verify["claims"][0])
        self.verify["claims"] = [dict(original, claim_id="C1"), dict(original, claim_id="C2")]

    def difference(self, relation="difference", affected=()):
        return {"description": "The reviewers identify a bounded source difference.",
                "supports": copy.deepcopy(self.supports), "relation": relation,
                "affected_claim_ids": list(affected)}

    def test_ordinary_difference_does_not_reject_claims_sharing_its_paragraph(self):
        self.two_claims_in_one_paragraph()
        self.verify["conflicts"] = [self.difference(affected=["C1"])]
        result = self.ask()
        self.assertEqual([item["claim_id"] for item in result["reasoning_claims"]], ["C1", "C2"])
        self.assertEqual(result["reasoning_trace"][-1]["rejected"], [])
        self.assertEqual(result["reasoning_status"], "partial")

    def test_linked_contradiction_rejects_only_target_even_when_other_claim_uses_same_paragraph(self):
        self.two_claims_in_one_paragraph()
        self.verify["conflicts"] = [self.difference("contradiction", ["C1"])]
        result = self.ask()
        self.assertEqual([item["claim_id"] for item in result["reasoning_claims"]], ["C2"])
        rejected = result["reasoning_trace"][-1]["rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["claim_id"], "C1")
        self.assertEqual(rejected[0]["verdict"], "supported")
        self.assertEqual(rejected[0]["rejection_reasons"], ["linked_contradiction"])

    def test_scope_broadening_and_counterevidence_are_auditable_and_do_not_spread_to_other_claims(self):
        self.two_claims_in_one_paragraph()
        self.verify["claims"][0].update(scope_verdict="broadened", counter_supports=[self.supports[0]],
                                         reason="The claim expands a limited scope beyond the cited source.")
        result = self.ask()
        self.assertEqual([item["claim_id"] for item in result["reasoning_claims"]], ["C2"])
        rejected = result["reasoning_trace"][-1]["rejected"][0]
        self.assertEqual(rejected["rejection_reasons"], ["scope_broadened", "counterevidence_present"])
        self.assertEqual(rejected["counter_supports"], [self.supports[0]])
        self.assertIn("limited scope", rejected["reason"])

    def test_global_gap_does_not_veto_unrelated_supported_inference(self):
        self.plan["missing_premises"] = ["The deployment's cost has not been supplied."]
        self.plan["ambiguities"] = ["An unrelated deployment name needs clarification."]
        result = self.ask()
        self.assertEqual(len(result["reasoning_claims"]), 1)
        self.assertEqual(result["reasoning_claims"][0]["kind"], "inference")
        self.assertEqual(result["reasoning_status"], "partial")
        self.verify["claims"][0].update(verdict="insufficient", scope_verdict="unclear",
                                         reason="The missing deployment version directly affects this inference.")
        result = self.ask()
        self.assertEqual(result["reasoning_claims"], [])
        self.assertEqual(result["reasoning_trace"][-1]["rejected"][0]["rejection_reasons"],
                         ["verifier_insufficient", "scope_unclear"])

    def test_invalid_difference_relation_or_claim_mapping_is_rejected_before_filtering(self):
        for value, expected in ((self.difference("contradiction"), "unbound_contradiction"),
                                (self.difference("contradiction", ["C99"]), "unknown_affected_claim"),
                                (self.difference("contradiction", ["C1", "C1"]), "unknown_affected_claim"),
                                (self.difference("guess", ["C1"]), "invalid_difference_relation")):
            with self.subTest(expected=expected):
                self.verify["conflicts"] = [value]
                result = self.ask()
                self.assertEqual(result["fallback_reason"], expected)
                self.assertFalse(result["used_model"])

    def test_local_counter_choices_and_remote_exact_quotes_share_strict_validation(self):
        self.verify["claims"][0].update(verdict="contradicted", counter_supports=[self.supports[1]])
        remote = self.ask()
        self.assertEqual(remote["reasoning_trace"][-1]["rejected"][0]["counter_supports"], [self.supports[1]])
        self.model = protocol.ReasoningProtocolTest.model.__get__(self, type(self))
        with patch.object(reasoning, "load_settings", return_value={"reasoning_budget_seconds": 30,
                                                                   "base_url": "http://localhost:11434/v1"}):
            local = self.ask()
            self.assertEqual(local["reasoning_trace"][-1]["rejected"][0]["counter_supports"], [self.supports[1]])
            self.verify["claims"][0]["counter_supports"][0] = dict(self.supports[1], quote="A fabricated counter quotation.")
            self.assertEqual(self.ask()["fallback_reason"], "unknown_quote_choice")
        self.model = fixtures.GeneralReasoningTest.model.__get__(self, type(self))
        self.assertEqual(self.ask()["fallback_reason"], "quote_not_in_archive")

    def test_counterevidence_is_required_for_contradicted_or_broadened_judgment(self):
        for changes in ({"verdict": "contradicted"}, {"scope_verdict": "broadened"}):
            with self.subTest(changes=changes):
                original = copy.deepcopy(self.verify["claims"][0])
                self.verify["claims"][0].update(changes)
                self.assertEqual(self.ask()["fallback_reason"], "unsubstantiated_counterevidence")
                self.verify["claims"][0] = original

    def test_same_description_and_quotes_with_different_claim_impact_are_not_deduplicated(self):
        self.two_claims_in_one_paragraph()
        self.draft["conflicts"] = [self.difference("difference", ["C1"])]
        self.verify["conflicts"] = [self.difference("contradiction", ["C1"])]
        result = self.ask()
        self.assertEqual(len(result["conflicts"]), 2)
        self.assertEqual([item["claim_id"] for item in result["reasoning_claims"]], ["C2"])


if __name__ == "__main__":
    unittest.main()
