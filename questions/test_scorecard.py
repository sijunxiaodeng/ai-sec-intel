import copy
import json
from pathlib import Path
import tempfile
import unittest

from questions.evaluate import load_dataset
from questions.scorecard import compile_scorecard


def report(*, relation=False):
    review = {"reviewer": "independent-reviewer", "independent_human": True,
              "reasoning_kind": "multi_hop", "reasoning_explained": True}
    result = {"mode": "model", "dataset_sha256": "a" * 64, "dataset_cases": 1,
              "source_manifest": [{"response_sha256": "b" * 64}], "summary": {"cases": 1}}
    if relation:
        review.update(source_supported=True, relevant=True, conditions_preserved=True, synthesis_correct=True)
        result["rows"] = [{"case_id": "R1", "elapsed_http_seconds": 1.2, "automatic_passed": True,
                           "model_attempted": True, "used_model": True, "manual_review": review}]
    else:
        review.update(correct=True, citations_supported=True)
        result["cases"] = [{"id": "Q1", "seconds": 0.2, "automatic_passed": True,
                            "model_attempted": True, "response": {"used_model": False}, "manual_review": review}]
    return result


class ScorecardTest(unittest.TestCase):
    def test_unreviewed_and_reviewed_subset_do_not_become_full_accuracy(self):
        data = report()
        second = copy.deepcopy(data["cases"][0]); second["id"] = "Q2"
        second["manual_review"]["correct"] = None
        data["cases"].append(second); data["dataset_cases"] = 2; data["summary"]["cases"] = 2
        result = compile_scorecard([data])
        self.assertEqual(result["summary"]["reviewed_subset_accuracy"], 1)
        self.assertIsNone(result["summary"]["independent_accuracy"])
        self.assertFalse(result["measurement_complete"])
        self.assertIsNone(result["competition_passed"])

    def test_independence_requires_reviewer_declaration(self):
        data = report()
        data["cases"][0]["manual_review"]["independent_human"] = False
        self.assertIsNone(compile_scorecard([data])["summary"]["independent_accuracy"])
        data["cases"][0]["manual_review"].update(independent_human=True, reviewer=" ")
        self.assertIsNone(compile_scorecard([data])["summary"]["independent_accuracy"])

    def test_model_fallback_and_http_scope_remain_separate(self):
        result = compile_scorecard([report(), report(relation=True)])
        self.assertEqual(result["summary"]["independent_accuracy"], 1)
        self.assertEqual(result["summary"]["model_fallback"], 1)
        self.assertEqual(result["summary"]["local_http_cases"], 1)
        self.assertFalse(result["summary"]["all_cases_local_http_under_5s"])
        self.assertEqual(result["accepted_model"]["cases"], 1)

    def test_false_citation_or_relation_condition_is_incorrect(self):
        data = report(relation=True)
        data["rows"][0]["manual_review"]["conditions_preserved"] = False
        self.assertEqual(compile_scorecard([data])["summary"]["independent_accuracy"], 0)

    def test_unfrozen_source_or_selected_cases_cannot_earn_full_accuracy(self):
        for change in ({"dataset_sha256": None}, {"dataset_cases": 3},
                       {"source_manifest": [{"response_sha256": None}]}):
            with self.subTest(change=change):
                data = report(); data.update(change)
                self.assertIsNone(compile_scorecard([data])["summary"]["independent_accuracy"])

    def test_does_not_infer_multihop_from_cross_document_endpoint(self):
        data = report(relation=True)
        data["rows"][0]["manual_review"].pop("reasoning_kind")
        result = compile_scorecard([data])
        self.assertNotIn("multi_hop", result["by_reasoning_kind"])
        self.assertEqual(result["reasoning_kinds"], {"unclassified": 1})

    def test_repeated_cases_and_mixed_modes_are_rejected(self):
        with self.assertRaises(ValueError):
            compile_scorecard([report(), report()])
        different_mode = report(relation=True); different_mode["mode"] = "rules"
        with self.assertRaises(ValueError):
            compile_scorecard([report(), different_mode])

    def test_invalid_latency_or_truncated_count_is_rejected(self):
        for seconds in (float("nan"), float("inf"), -1, True):
            data = report(); data["cases"][0]["seconds"] = seconds
            with self.assertRaises(ValueError):
                compile_scorecard([data])
        data = report(); data["summary"]["cases"] = 2
        with self.assertRaises(ValueError):
            compile_scorecard([data])

    def test_custom_dataset_requires_unique_ids_and_human_review_criteria(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "frozen.json"
            dataset = {"sources": [{"url": "https://example.com"}], "cases": [
                {"id": "H1", "question": "何时应拒答？", "expected_cves": [], "review_checklist": "核对证据边界"}]}
            path.write_text(json.dumps(dataset), encoding="utf-8")
            self.assertEqual(load_dataset(path), dataset)
            dataset["cases"].append(dict(dataset["cases"][0]))
            path.write_text(json.dumps(dataset), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_dataset(path)
