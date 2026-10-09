"""Offline regressions for classification trust and resumable model budgets."""
from __future__ import annotations

import json
from contextlib import closing
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai_pipeline.priority_v5 import plan_batch
from ai_pipeline.store import ClassificationStore
from ai_pipeline.worker import run_batch
from ai_pipeline.worker_v5 import run_priority_batch
from classification.ai_relevance import AIRelevanceClassifier
from classification.hybrid_classifier import HybridAIClassifier
from classification.semantic_judge import SemanticJudge, SemanticJudgeResult


class FakeJudge:
    def __init__(self, *, configured=True, fail=False, positive=True, confidence=0.9):
        self.configured = configured
        self.fail = fail
        self.positive = positive
        self.confidence = confidence
        self.calls = []
        self.callback = None

    def is_configured(self):
        return self.configured

    def judge(self, **record):
        self.calls.append(record["cve_id"])
        if self.callback:
            self.callback()
        if self.fail:
            raise RuntimeError("provider failed at https://example.test?api_key=TEST_SECRET")
        return SemanticJudgeResult(
            self.positive, "ai_infrastructure" if self.positive else "non_ai",
            self.confidence, "Classification supported by supplied text", ["LLM"],
        )


class RuleClassificationTests(unittest.TestCase):
    def setUp(self):
        self.rules = AIRelevanceClassifier()

    def test_structured_ai_product_is_accepted_without_model(self):
        model = FakeJudge()
        result = HybridAIClassifier(model).classify(product="ollama")
        self.assertTrue(result.is_ai_related)
        self.assertEqual(result.decision_source, "rule_positive")
        self.assertEqual(model.calls, [])

    def test_unrelated_description_mentions_require_semantic_review(self):
        model = FakeJudge(positive=False)
        result = HybridAIClassifier(model).classify(
            product="ordinary-router", description="This router can connect to ollama."
        )
        self.assertFalse(result.is_ai_related)
        self.assertEqual(result.decision_source, "semantic_judge")
        self.assertEqual(len(model.calls), 1)

    def test_ambiguous_and_generic_phrases_are_not_automatic_positives(self):
        for text in (
            "All knowns are available to the router", "autogen produces a makefile",
            "Power transformers management firmware", "model repository with model artifact",
            "multi-agent monitoring with a rag pipeline",
        ):
            with self.subTest(text=text):
                self.assertFalse(self.rules.classify(title=text, description=text).is_ai_related)

    def test_package_identity_handles_ecosystem_prefix(self):
        result = self.rules.classify(package_names=["pip:transformers"])
        self.assertTrue(result.is_ai_related)
        self.assertIn("package:transformers", result.evidence)

    def test_cpe_product_separators_keep_project_identity(self):
        for product in ("open_webui", "open-webui", "triton_inference_server", "onnx_runtime"):
            with self.subTest(product=product):
                result = self.rules.classify(package_names=["cpe:" + product])
                self.assertTrue(result.is_ai_related)

    def test_affected_product_wins_over_incidental_description_projects(self):
        result = self.rules.classify(
            product="ollama", description="langchain langgraph llamaindex clients may connect"
        )
        self.assertTrue(result.is_ai_related)
        self.assertEqual(result.category, "ai_infrastructure")

    def test_explicit_prompt_injection_has_application_category(self):
        result = self.rules.classify(description="An attacker performs prompt injection.")
        self.assertTrue(result.is_ai_related)
        self.assertEqual(result.category, "ai_application_agent")

    def test_keyword_substrings_do_not_route_to_model(self):
        model = FakeJudge()
        result = HybridAIClassifier(model).classify(
            title="An array fragment is returned verbatim by firmware"
        )
        self.assertFalse(result.is_ai_related)
        self.assertEqual(result.decision_source, "rule_negative")
        self.assertEqual(model.calls, [])

    def test_unavailable_or_failed_model_is_unknown_and_redacted(self):
        for model in (FakeJudge(configured=False), FakeJudge(fail=True)):
            with self.subTest(configured=model.configured):
                result = HybridAIClassifier(model).classify(description="A novel LLM gateway")
                self.assertIsNone(result.is_ai_related)
                self.assertEqual(result.category, "unknown")
                self.assertTrue(result.needs_review)
                self.assertNotIn("TEST_SECRET", result.reason)


class SemanticValidationTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "is_ai_related": True, "category": "ai_infrastructure", "confidence": 0.95,
            "reason": "The vulnerable path performs LLM inference", "evidence": ["LLM inference"],
        }
        self.record = {"description": "An LLM inference server contains a vulnerable loader."}

    def test_valid_response_has_verbatim_source_evidence(self):
        result = SemanticJudge._normalize_result(self.valid, "", self.record)
        self.assertTrue(result.is_ai_related)
        self.assertEqual(result.evidence, ["LLM inference"])

    def test_invalid_schema_does_not_become_a_verdict(self):
        variations = [
            {"is_ai_related": "false"}, {"is_ai_related": 1},
            {"category": "non_ai"}, {"confidence": "0.9"}, {"confidence": True},
            {"confidence": float("nan")}, {"confidence": float("inf")},
            {"confidence": 1.01}, {"confidence": -0.1}, {"reason": ""},
            {"evidence": "LLM inference"}, {"evidence": [42]}, {"evidence": []},
            {"evidence": ["An invented AI product fact"]}, {"evidence": ["LL"]},
            {"extra": "ignore"},
        ]
        for variation in variations:
            with self.subTest(variation=variation):
                with self.assertRaises(ValueError):
                    SemanticJudge._normalize_result({**self.valid, **variation}, "", self.record)
        with self.assertRaises(ValueError):
            SemanticJudge._normalize_result([], "", self.record)
        with self.assertRaises(ValueError):
            SemanticJudge._normalize_result({"is_ai_related": False}, "", self.record)

    def test_negative_verdict_requires_matching_category(self):
        invalid = {**self.valid, "is_ai_related": False}
        with self.assertRaises(ValueError):
            SemanticJudge._normalize_result(invalid, "", self.record)
        result = SemanticJudge._normalize_result(
            {**invalid, "category": "non_ai", "evidence": []}, "", self.record
        )
        self.assertFalse(result.is_ai_related)

    def test_api_response_is_validated_without_network_access(self):
        response = Mock()
        response.json.return_value = {"choices": [{"message": {"content": json.dumps(self.valid)}}]}
        with patch.dict("os.environ", {"LLM_CHAT_COMPLETIONS_URL": ""}), patch(
            "classification.semantic_judge.requests.post", return_value=response
        ) as post:
            judge = SemanticJudge(api_base="https://example.test/v1", api_key="", model="fake")
            result = judge.judge(**self.record)
            self.assertTrue(result.is_ai_related)
            self.assertEqual(post.call_count, 1)
            response.json.return_value["choices"][0]["message"]["content"] = {"invalid": "shape"}
            with self.assertRaises(ValueError):
                judge.judge(**self.record)


class ClassificationQueueTests(unittest.TestCase):
    version = "regression-v1"
    workers = (run_batch, run_priority_batch)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def make_store(self, records):
        self.counter += 1
        path = Path(self.temp.name) / f"queue-{self.counter}.db"
        with closing(sqlite3.connect(path)) as con, con:
            con.execute("""CREATE TABLE unified_vulnerabilities (
                cve_id TEXT PRIMARY KEY, payload_json TEXT, content_sha256 TEXT,
                first_seen_at TEXT, content_updated_at TEXT)""")
            for cve, payload in records:
                con.execute("INSERT INTO unified_vulnerabilities VALUES (?,?,?,?,?)", (
                    cve, json.dumps({"cve_id": cve, **payload}), "hash-" + cve,
                    "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00",
                ))
        return ClassificationStore(path)

    def rows(self, store):
        with store.connect() as con:
            return {row["cve_id"]: dict(row) for row in con.execute("SELECT * FROM ai_classifications")}

    def make_due(self, store, cve):
        with store.connect() as con:
            con.execute("UPDATE ai_classifications SET retry_after=? WHERE cve_id=?",
                        ("2020-01-01T00:00:00+00:00", cve))

    def test_zero_budget_queues_semantic_work_without_rewriting_old_queue(self):
        for worker in self.workers:
            with self.subTest(worker=worker.__name__):
                store = self.make_store([("CVE-2026-0001", {"description": "A novel LLM gateway"})])
                model = FakeJudge()
                classifier = HybridAIClassifier(model)
                stats = worker(store.db_path, self.version, 5, 0, classifier, verbose=False)
                row = self.rows(store)["CVE-2026-0001"]
                self.assertEqual(row["state"], "pending_llm")
                self.assertIsNone(row["ai_related"])
                self.assertIsNone(row["confidence"])
                self.assertEqual(stats["semantic_calls"], 0)
                self.assertEqual(model.calls, [])
                worker(store.db_path, self.version, 5, 0, classifier, verbose=False)
                self.assertEqual(self.rows(store)["CVE-2026-0001"]["attempts"], 1)

    def test_semantic_errors_remain_unknown_with_cooldown(self):
        for worker in self.workers:
            with self.subTest(worker=worker.__name__):
                store = self.make_store([("CVE-2026-0001", {"description": "A novel LLM gateway"})])
                model = FakeJudge(fail=True)
                classifier = HybridAIClassifier(model)
                stats = worker(store.db_path, self.version, 5, 1, classifier, verbose=False)
                row = self.rows(store)["CVE-2026-0001"]
                self.assertEqual(row["state"], "retry")
                self.assertIsNone(row["ai_related"])
                self.assertEqual(row["ai_category"], "unknown")
                self.assertNotIn("TEST_SECRET", row["error_text"])
                self.assertIn("route:llm", json.loads(row["evidence_json"]))
                self.assertEqual(stats["semantic_calls"], 1)
                worker(store.db_path, self.version, 5, 1, classifier, verbose=False)
                self.assertEqual(len(model.calls), 1)
                self.make_due(store, "CVE-2026-0001")
                model.fail = False
                worker(store.db_path, self.version, 5, 1, classifier, verbose=False)
                self.assertEqual(self.rows(store)["CVE-2026-0001"]["state"], "classified")
                self.assertEqual(len(model.calls), 2)

    def test_missing_configuration_does_not_count_a_model_request(self):
        for worker in self.workers:
            with self.subTest(worker=worker.__name__):
                store = self.make_store([("CVE-2026-0001", {"description": "A novel LLM gateway"})])
                model = FakeJudge(configured=False)
                stats = worker(store.db_path, self.version, 5, 1, HybridAIClassifier(model), verbose=False)
                self.assertEqual(stats["semantic_calls"], 0)
                self.assertEqual(model.calls, [])
                self.assertIsNone(self.rows(store)["CVE-2026-0001"]["ai_related"])

    def test_zero_budget_still_processes_local_retry(self):
        for worker in self.workers:
            with self.subTest(worker=worker.__name__):
                store = self.make_store([("CVE-2026-0001", {"title": "ordinary router"})])
                row = store.fresh(self.version, 1)[0]
                store.record(row, self.version, "retry", error="Temporary local failure")
                self.make_due(store, row["cve_id"])
                stats = worker(store.db_path, self.version, 5, 0, HybridAIClassifier(FakeJudge()), verbose=False)
                self.assertEqual(stats["classified"], 1)
                self.assertEqual(self.rows(store)[row["cve_id"]]["state"], "classified")

    def test_old_semantic_backlog_receives_the_single_model_budget(self):
        for worker in self.workers:
            with self.subTest(worker=worker.__name__):
                store = self.make_store([
                    ("CVE-2026-0001", {"description": "An old LLM gateway"}),
                    ("CVE-2026-0002", {"description": "A fresh LLM gateway"}),
                ])
                old = next(row for row in store.fresh(self.version, 5) if row["cve_id"] == "CVE-2026-0001")
                store.record(old, self.version, "pending_llm")
                model = FakeJudge()
                stats = worker(store.db_path, self.version, 2, 1, HybridAIClassifier(model), verbose=False)
                self.assertEqual(model.calls, ["CVE-2026-0001"])
                self.assertEqual(stats["semantic_calls"], 1)
                self.assertEqual(self.rows(store)["CVE-2026-0002"]["state"], "pending_llm")

    def test_pending_priority_does_not_starve_older_low_risk_rows(self):
        store = self.make_store([
            ("CVE-2026-0001", {"description": "LLM gateway"}),
            ("CVE-2026-0002", {"description": "LLM gateway", "known_exploited": True}),
        ])
        for row in store.fresh(self.version, 5):
            store.record(row, self.version, "pending_llm")
        with store.connect() as con:
            con.execute("UPDATE ai_classifications SET updated_at=? WHERE cve_id=?",
                        ("2020-01-01T00:00:00+00:00", "CVE-2026-0001"))
        selected, _ = plan_batch(store, self.version, HybridAIClassifier(FakeJudge()), 1, 1)
        self.assertEqual(selected[0].row["cve_id"], "CVE-2026-0001")

    def test_changed_content_cannot_commit_stale_success_or_positive_stats(self):
        for worker in self.workers:
            with self.subTest(worker=worker.__name__):
                store = self.make_store([("CVE-2026-0001", {"description": "A novel LLM gateway"})])
                model = FakeJudge()
                def change_content():
                    with store.connect() as con:
                        con.execute("UPDATE unified_vulnerabilities SET content_sha256='new-content'")
                model.callback = change_content
                stats = worker(store.db_path, self.version, 1, 1, HybridAIClassifier(model), verbose=False)
                self.assertEqual(stats["stale_skipped"], 1)
                self.assertEqual(stats["classified"], 0)
                self.assertEqual(stats["positive"], 0)
                self.assertEqual(self.rows(store), {})

    def test_review_is_not_exported_as_confirmed_ai(self):
        store = self.make_store([("CVE-2026-0001", {"description": "A novel LLM gateway"})])
        stats = run_priority_batch(store.db_path, self.version, 1, 1,
                                   HybridAIClassifier(FakeJudge(confidence=0.5)), verbose=False)
        self.assertEqual(stats["needs_review"], 1)
        self.assertEqual(store.stats(self.version)["classified_ai_positive"], 0)
        self.assertEqual(store.stats(self.version)["review_ai_positive"], 1)
        output = Path(self.temp.name) / "confirmed.jsonl"
        self.assertEqual(store.export_jsonl(output, self.version, only_ai=True), 0)


if __name__ == "__main__":
    unittest.main()
