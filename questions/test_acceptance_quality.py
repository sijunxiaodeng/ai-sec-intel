"""Acceptance records must not turn incomplete/AI/automatic checks into accuracy."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from acceptance import quality
from acceptance.storage import connect


def report(kinds=("single_fact", "comparison"), **changes):
    value = {
        "schema_version": 1, "run_at": "2026-10-15T03:00:00+00:00",
        "dataset_sha256": "a" * 64, "dataset_cases": len(kinds),
        "dataset_case_ids": [f"Q{i+1}" for i in range(len(kinds))],
        "dataset_visibility": "held_out", "model": "test-model", "mode": "model",
        "source_manifest": [{"url": "https://example.test/frozen", "response_sha256": "b" * 64}],
        "summary": {"automatic_passed": 999, "manual_accuracy": 1},
        "cases": [{"id": f"Q{i+1}", "question": f"Frozen question {i+1}?", "reasoning_kind": kind,
                   "seconds": i + .25, "automatic_passed": i == 0,
                   "failures": [] if i == 0 else ["a rule did not match"],
                   "response": {"answer": "preserved answer", "used_model": i == 0,
                                "evidence_chunks": [{"url": "https://example.test/frozen", "text": "frozen source text", "source_response_sha256": "b" * 64}]}}
                  for i, kind in enumerate(kinds)],
    }
    value.update(changes)
    return value


def review(kind="single_fact", **changes):
    value = {"reviewer": "Declared reviewer", "reviewer_type": "human", "independent": True,
             "reasoning_kind": kind, "correct": True, "citations_supported": True,
             "conditions_preserved": True, "reasoning_valid": True,
             "note": "Compared the answer and qualifiers with the frozen source.", "expected_revision": 0}
    value.update(changes)
    return value


class AcceptanceQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "acceptance.sqlite3"

    def load(self, payload=None):
        return quality.import_report(payload or report(), self.db)

    def submit(self, run_id, case="Q1", **changes):
        return quality.review_case(run_id, case, review(**changes), self.db)

    def test_original_report_is_preserved_but_untrusted_aggregates_and_manual_labels_are_not_scores(self):
        payload = report()
        payload["cases"][0]["manual_review"] = {"correct": True, "independent_human": True, "reviewer": "AI claims human"}
        result = self.load(payload)
        stats = result["statistics"]
        self.assertEqual((stats["automatic_passed"], stats["automatic_failed"]), (1, 1))
        self.assertEqual(stats["reviewed_cases"], 0)
        self.assertIsNone(stats["independent_accuracy"])
        self.assertIsNone(stats["confidence_interval_95"])
        self.assertEqual(result["original_report"], payload)
        self.assertEqual(result["cases"][0]["prediction"], "preserved answer")
        self.assertEqual(result["model"], "test-model")
        payload["cases"][0]["response"]["answer"] = "mutated after import"
        self.assertEqual(quality.get_run(result["run_id"], self.db)["cases"][0]["prediction"], "preserved answer")

    def test_same_observations_dedup_despite_summary_labels_case_order_and_wrapper(self):
        payload = report()
        first = self.load(payload)
        payload["summary"] = {"automatic_passed": 0}
        payload["cases"][0]["manual_review"] = {"correct": True}
        payload["cases"].reverse()
        second = self.load({"report": payload, "title": "different title", "purpose": "acceptance"})
        self.assertFalse(second["created"])
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual(quality.list_runs(self.db)["total"], 1)
        self.assertEqual(second["statistics"]["cases"], 2)
        self.assertEqual(second["original_report"], first["original_report"])

    def test_new_run_does_not_pool_old_cases_or_reviews(self):
        first = self.load()
        self.submit(first["run_id"])
        second = self.load(report(run_at="2026-10-16T03:00:00Z"))
        self.assertTrue(second["created"])
        self.assertEqual(quality.list_runs(self.db)["total"], 2)
        self.assertEqual(second["statistics"]["reviewed_cases"], 0)
        self.assertEqual(second["statistics"]["cases"], 2)

    def test_source_commit_wrapper_preserves_original_report_and_run_identity(self):
        payload = report()
        original_id = quality._validate_import(payload)[3]
        result = self.load({"report": payload, "source_commit": "AB" * 20})
        self.assertEqual(result["source_commit"], "ab" * 20)
        self.assertEqual(result["original_report"], payload)
        self.assertEqual(result["run_id"], original_id)
        exported = quality.export_run(result["run_id"], self.db)
        self.assertEqual(exported["run"]["source_commit"], "ab" * 20)
        duplicate = self.load({"report": payload, "source_commit": "ab" * 20})
        self.assertFalse(duplicate["created"])
        self.assertEqual(duplicate["source_commit"], "ab" * 20)
        with self.assertRaisesRegex(ValueError, "immutable imported run"):
            self.load({"report": payload, "source_commit": "cd" * 20})

    def test_source_commit_is_optional_strict_full_sha_and_cannot_conflict(self):
        self.assertIsNone(self.load()["source_commit"])
        for commit in ("abcdef1", "g" * 40, [], " " + "a" * 40):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                self.load({"report": report(), "source_commit": commit})
        value = report(source_commit="a" * 40)
        with self.assertRaisesRegex(ValueError, "differs"):
            self.load({"report": value, "source_commit": "b" * 40})

    def test_missing_duplicate_or_mismatched_manifest_cases_rejected(self):
        for mutate in (
            lambda p: p["cases"].pop(),
            lambda p: p["cases"][1].update(id="Q1"),
            lambda p: p.update(dataset_cases=True),
            lambda p: p.update(dataset_case_ids=["Q1"]),
            lambda p: p.update(dataset_case_ids=["Q1", "Q1"]),
        ):
            value = report()
            mutate(value)
            with self.subTest(payload=value), self.assertRaises(ValueError):
                self.load(value)
        self.assertEqual(quality.list_runs(self.db)["total"], 0)

    def test_reduced_dataset_reusing_sha_cannot_inflate_denominator(self):
        self.load()
        reduced = report(kinds=("single_fact",), run_at="later")
        with self.assertRaisesRegex(ValueError, "different case set"):
            self.load(reduced)
        self.assertEqual(quality.list_runs(self.db)["total"], 1)

    def test_sha_and_nested_finite_values_checked(self):
        for mutate in (
            lambda p: p.update(dataset_sha256="abc"),
            lambda p: p["source_manifest"][0].update(response_sha256="bad"),
            lambda p: p["cases"][0].update(seconds=float("inf")),
            lambda p: p["summary"].update(median=float("nan")),
            lambda p: p["cases"][0]["response"].update(score=float("-inf")),
            lambda p: p["cases"][0].update(seconds=-1),
            lambda p: p["cases"][0].update(seconds=True),
            lambda p: p["cases"][0].update(automatic_passed=1),
            lambda p: p["cases"][0].update(failures=["real failure"]),
        ):
            value = report()
            mutate(value)
            with self.subTest(payload=value), self.assertRaises(ValueError):
                self.load(value)

    def test_evidence_hash_mismatch_and_unmatched_text_are_rejected(self):
        value = report()
        chunk = value["cases"][0]["response"]["evidence_chunks"][0]
        chunk["source_response_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "source hash"):
            self.load(value)
        chunk["source_response_sha256"] = "b" * 64
        chunk["text_sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "text_sha256"):
            self.load(value)
        chunk["text_sha256"] = hashlib.sha256(chunk["text"].encode()).hexdigest()
        self.assertTrue(self.load(value)["source_hashes_complete"])

    def test_conflicting_manifest_hashes_rejected(self):
        value = report()
        value["source_manifest"].append({"url": "https://example.test/frozen", "response_sha256": "e" * 64})
        with self.assertRaisesRegex(ValueError, "conflicting hashes"):
            self.load(value)

    def test_partial_reviews_never_get_full_accuracy_or_wilson_but_complete_group_does(self):
        result = self.load()
        result = self.submit(result["run_id"])["summary"]
        stats = result["statistics"]
        self.assertEqual((stats["reviewed_cases"], stats["unreviewed_cases"]), (1, 1))
        self.assertEqual(stats["reviewed_subset_accuracy"], 1)
        self.assertEqual(stats["reviewed_subset_denominator"], 1)
        self.assertIsNone(stats["independent_accuracy"])
        self.assertIsNone(stats["confidence_interval_95"])
        self.assertEqual(stats["by_kind"]["basic"]["independent_accuracy"], 1)
        self.assertEqual(stats["by_kind"]["basic"]["independent_denominator"], 1)
        self.assertIsNone(stats["by_kind"]["complex"]["independent_accuracy"])

    def test_full_independent_reviews_use_all_necessary_checks_and_wilson(self):
        run_id = self.load()["run_id"]
        self.submit(run_id)
        final = self.submit(run_id, "Q2", kind="comparison", conditions_preserved=False)["summary"]
        stats = final["statistics"]
        self.assertEqual(stats["independent_accuracy"], .5)
        self.assertEqual(stats["independent_denominator"], 2)
        self.assertEqual(stats["confidence_interval_95"]["n"], 2)
        self.assertAlmostEqual(stats["confidence_interval_95"]["lower"], .0945312057)
        self.assertIsNone(stats["competition_pass"])
        self.assertFalse(stats["identity_authenticated"])

    def test_ai_or_nonindependent_human_cannot_become_independent_score(self):
        for kwargs in ({"reviewer_type": "ai", "independent": True}, {"reviewer_type": "human", "independent": False}):
            with self.subTest(kwargs=kwargs):
                run_id = self.load(report(kinds=("single_fact",), run_at=str(kwargs)))["run_id"]
                stats = self.submit(run_id, **kwargs)["summary"]["statistics"]
                self.assertEqual(stats["reviewed_subset_accuracy"], 1)
                self.assertEqual(stats["independent_reviewed_cases"], 0)
                self.assertIsNone(stats["independent_accuracy"])

    def test_null_necessary_checks_are_incomplete_not_false_or_pass(self):
        run_id = self.load()["run_id"]
        stats = self.submit(run_id, conditions_preserved=None)["summary"]["statistics"]
        self.assertEqual(stats["reviewed_cases"], 1)
        self.assertEqual(stats["incomplete_review_cases"], 1)
        self.assertEqual(stats["reviewed_subset_denominator"], 0)
        self.assertIsNone(stats["reviewed_subset_accuracy"])
        stats = self.submit(run_id, "Q2", kind="comparison", reasoning_valid=None)["summary"]["statistics"]
        self.assertEqual(stats["incomplete_review_cases"], 2)

    def test_basic_fact_does_not_require_fabricated_reasoning_chain(self):
        run_id = self.load(report(kinds=("single_fact",)))["run_id"]
        stats = self.submit(run_id, reasoning_valid=None)["summary"]["statistics"]
        self.assertEqual(stats["independent_accuracy"], 1)

    def test_refusal_without_evidence_may_leave_citations_null(self):
        value = report(kinds=("refusal",))
        value["cases"][0]["response"].pop("evidence_chunks")
        run_id = self.load(value)["run_id"]
        stats = self.submit(run_id, kind="refusal", citations_supported=None, reasoning_valid=None)["summary"]["statistics"]
        self.assertEqual(stats["independent_accuracy"], 1)

    def test_refusal_with_evidence_still_requires_citation_check(self):
        run_id = self.load(report(kinds=("refusal",)))["run_id"]
        stats = self.submit(run_id, kind="refusal", citations_supported=None)["summary"]["statistics"]
        self.assertIsNone(stats["independent_accuracy"])

    def test_missing_hashes_or_case_manifest_prevent_independent_metric(self):
        for key in ("dataset_sha256", "source_manifest", "dataset_case_ids"):
            value = report(kinds=("single_fact",), run_at=key)
            value.pop(key)
            run_id = self.load(value)["run_id"]
            stats = self.submit(run_id)["summary"]["statistics"]
            self.assertIsNone(stats["independent_accuracy"])
            self.assertIsNone(stats["confidence_interval_95"])
            self.assertEqual(stats["reviewed_subset_accuracy"], 1)

    def test_unclassified_cases_block_claiming_complete_group_from_selected_subset(self):
        value = report(kinds=(None, None))
        run_id = self.load(value)["run_id"]
        stats = self.submit(run_id)["summary"]["statistics"]
        self.assertEqual(stats["unclassified_cases"], 1)
        self.assertIsNone(stats["by_kind"]["basic"]["independent_accuracy"])
        self.assertIn("unclassified_cases", stats["by_kind"]["basic"]["independent_blockers"])

    def test_posthoc_classification_allows_complete_run_but_never_independent_group_rates(self):
        run_id = self.load(report(kinds=("single_fact", None)))["run_id"]
        self.submit(run_id)
        stats = self.submit(run_id, "Q2", kind="comparison")["summary"]["statistics"]
        self.assertEqual(stats["independent_accuracy"], 1)
        self.assertEqual(stats["independent_denominator"], 2)
        self.assertEqual(stats["classification_not_frozen_cases"], 1)
        self.assertEqual(stats["unclassified_cases"], 0)
        for group in ("basic", "complex"):
            self.assertIsNone(stats["by_kind"][group]["independent_accuracy"])
            self.assertIn("group_classification_not_frozen", stats["by_kind"][group]["independent_blockers"])
            self.assertEqual(stats["by_kind"][group]["reviewed_subset_accuracy"], 1)

    def test_comparison_and_multiturn_are_not_evidence_of_multihop_accuracy(self):
        kinds = ("single_fact", "refusal", "comparison", "multi_turn", "multi_hop", "other")
        run_id = self.load(report(kinds=kinds))["run_id"]
        for index, kind in enumerate(kinds, 1):
            self.submit(run_id, f"Q{index}", kind=kind)
        groups = quality.get_run(run_id, self.db)["statistics"]["by_kind"]
        self.assertEqual({k: v["cases"] for k, v in groups.items()}, {"basic": 2, "complex": 2, "multi_hop": 1, "other": 1, "enrichment": 0})
        self.assertEqual(groups["multi_hop"]["independent_denominator"], 1)

    def test_frozen_classification_cannot_be_downgraded_to_avoid_reasoning_check(self):
        run_id = self.load()["run_id"]
        with self.assertRaisesRegex(ValueError, "frozen case classification"):
            self.submit(run_id, "Q2")
        self.assertEqual(quality.get_run(run_id, self.db)["cases"][1]["revision"], 0)

    def test_append_correction_preserves_ai_identity_and_original_record(self):
        run_id = self.load(report(kinds=("single_fact",)))["run_id"]
        self.submit(run_id, reviewer_type="ai", independent=False, correct=False)
        self.submit(run_id, expected_revision=1, correct=True)
        case = quality.get_run(run_id, self.db)["cases"][0]
        self.assertEqual(case["revision"], 2)
        self.assertEqual([r["reviewer_type"] for r in case["review_history"]], ["ai", "human"])
        self.assertFalse(case["review_history"][0]["correct"])
        self.assertTrue(case["latest_review"]["correct"])
        self.assertNotIn("latest_review", case["original_case"])

    def test_stale_revision_never_overwrites_review(self):
        run_id = self.load()["run_id"]
        self.submit(run_id)
        with self.assertRaises(quality.RevisionConflict):
            self.submit(run_id, correct=False)
        case = quality.get_run(run_id, self.db)["cases"][0]
        self.assertEqual(len(case["review_history"]), 1)
        self.assertTrue(case["latest_review"]["correct"])

    def test_concurrent_revision_zero_has_exactly_one_winner(self):
        run_id = self.load()["run_id"]
        barrier = threading.Barrier(2)
        def write(name):
            barrier.wait(timeout=10)
            try:
                self.submit(run_id, reviewer=name)
                return "success"
            except quality.RevisionConflict:
                return "conflict"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(write, ["one", "two"]))
        self.assertCountEqual(outcomes, ["success", "conflict"])
        self.assertEqual(len(quality.get_run(run_id, self.db)["cases"][0]["review_history"]), 1)

    def test_strict_review_payload_and_missing_objects(self):
        run_id = self.load()["run_id"]
        for changes in ({"correct": 1}, {"independent": 1}, {"expected_revision": True}, {"reviewer": " "}, {"note": None}, {"reasoning_kind": "guess"}, {"reasoning_kind": []}, {"reviewer_type": "model"}, {"reviewer_type": {}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.submit(run_id, **changes)
        invalid = review()
        invalid.pop("conditions_preserved")
        with self.assertRaises(ValueError):
            quality.review_case(run_id, "Q1", invalid, self.db)
        with self.assertRaises(KeyError):
            self.submit(run_id, "missing")
        with self.assertRaises(KeyError):
            quality.get_run("missing", self.db)

    def test_malformed_import_types_and_unknown_schema_are_validation_errors(self):
        for key, value in (("kind", []), ("purpose", {}), ("dataset_visibility", []), ("schema_version", 2), ("schema_version", True)):
            payload = report()
            payload[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.load(payload)
        payload = report()
        payload["cases"][0]["reasoning_kind"] = []
        with self.assertRaises(ValueError):
            self.load(payload)
        payload = report()
        payload["cases"][0]["response"]["used_model"] = 1
        with self.assertRaises(ValueError):
            self.load(payload)

    def test_qa_cannot_be_reclassified_as_an_enrichment_fact_unit_during_review(self):
        run_id = self.load(report(kinds=(None,)))["run_id"]
        with self.assertRaisesRegex(ValueError, "evaluation unit"):
            self.submit(run_id, kind="enrichment")

    def test_missing_citation_digest_blocks_full_score_even_with_complete_manifest(self):
        payload = report(kinds=("single_fact",))
        payload["cases"][0]["response"]["evidence_chunks"][0]["source_response_sha256"] = None
        run_id = self.load(payload)["run_id"]
        stats = self.submit(run_id)["summary"]["statistics"]
        self.assertIn("source_hashes_missing", stats["independent_blockers"])

    def test_database_forbids_changes_to_original_and_review_history(self):
        run_id = self.load()["run_id"]
        self.submit(run_id)
        for statement in ("UPDATE quality_runs SET report_json='{}'", "DELETE FROM quality_cases", "UPDATE quality_reviews SET revision=99", "DELETE FROM quality_reviews", "DELETE FROM quality_datasets"):
            with self.subTest(sql=statement), self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                with connect(self.db) as connection:
                    connection.execute(statement)

    def test_enrichment_fact_units_and_export_are_explicit_and_complete(self):
        value = report(kinds=("enrichment",), kind="enrichment", evaluation_unit="fact_unit")
        value["cases"][0].update(prediction={"version": "1.2"}, reference={"version": "1.2"}, context=[{"url": "https://example.test/frozen", "response_sha256": "b" * 64, "text": "Version 1.2"}])
        result = self.load({"report": value, "title": "版本事实单元", "purpose": "acceptance"})
        self.assertEqual(result["evaluation_unit"], "fact_unit")
        self.assertEqual(result["title"], "版本事实单元")
        self.assertEqual(result["purpose"], "acceptance")
        self.submit(result["run_id"], kind="enrichment")
        exported = quality.export_run(result["run_id"], self.db)
        self.assertEqual(exported["run"]["original_report"], value)
        self.assertEqual(exported["run"]["statistics"]["by_kind"]["enrichment"]["independent_accuracy"], 1)
        self.assertEqual(len(exported["run"]["cases"][0]["review_history"]), 1)
        self.assertIn("identity", exported["run"]["scoring_policy"])

    def test_enrichment_requires_fact_unit_prediction_reference_context(self):
        value = report(kinds=("enrichment",), kind="enrichment")
        with self.assertRaisesRegex(ValueError, "fact units require"):
            self.load(value)
        value["evaluation_unit"] = "case"
        with self.assertRaisesRegex(ValueError, "fact_unit"):
            self.load(value)

    def known_report(self):
        path = Path(__file__).resolve().parent / "qa_evaluation.json"
        raw = path.read_bytes()
        dataset = json.loads(raw)
        urls = {s["url"] for s in dataset["sources"]}
        urls.update(u for s in dataset["sources"] for u in s.get("extra_urls", []))
        return {"dataset_sha256": hashlib.sha256(raw).hexdigest(), "dataset_cases": len(dataset["cases"]),
                "source_manifest": [{"url": u, "response_sha256": "b" * 64} for u in sorted(urls)],
                "cases": [{"id": c["id"], "question": c["question"], "history": c.get("history", []), "response": {"answer": "saved"}} for c in dataset["cases"]]}

    def test_known_public_dataset_cannot_be_relabelled_held_out(self):
        value = self.known_report()
        value["dataset_visibility"] = "held_out"
        result = self.load({"report": value, "purpose": "acceptance", "title": "not a blind set"})
        self.assertEqual(result["dataset_visibility"], "public_development")
        self.assertTrue(result["dataset_case_manifest_complete"])
        self.assertTrue(result["source_hashes_complete"])
        self.assertEqual(result["statistics"]["unclassified_cases"], 0)
        self.assertEqual(result["cases"][0]["reasoning_kind"], "single_fact")
        self.assertEqual(result["cases"][30]["reasoning_kind"], "comparison")
        self.assertEqual(result["statistics"]["by_kind"]["multi_hop"]["cases"], 0)
        self.assertEqual(result["statistics"]["by_kind"]["complex"]["cases"], 6)

    def test_known_dataset_validates_full_case_set_and_frozen_questions_history(self):
        for mutate in (
            lambda p: (p["cases"].pop(), p.update(dataset_cases=35)),
            lambda p: p["cases"][0].update(question="easier question"),
            lambda p: p["cases"][24].update(history=[]),
        ):
            value = self.known_report()
            mutate(value)
            with self.subTest(), self.assertRaises(ValueError):
                self.load(value)


if __name__ == "__main__":
    unittest.main()
