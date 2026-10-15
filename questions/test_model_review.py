"""Actual B stores/changefeed with synthetic sources and a fake model only."""
from contextlib import closing, ExitStack
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from automation import model_review as review
from config import llm, settings


class ModelSettingsTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "settings.json"
        self.stack.enter_context(patch.object(settings, "LOCAL", self.path))
        self.stack.enter_context(patch.dict(os.environ, {"OFFLINE_DEMO": "0"}))

    def test_local_without_key_is_ready_but_remote_or_lookalikes_are_not(self):
        for endpoint, expected in (
            ("http://127.0.0.1:11434/v1", True), ("http://localhost:11434/v1", True),
            ("http://[::1]:11434/v1", True), ("https://example.org/v1", False),
            ("http://localhost.example.org/v1", False), ("http://127.0.0.1:99999/v1", False),
            ("http://user@localhost/v1", False), ("http://localhost/v1?key=x", False),
        ):
            with self.subTest(endpoint=endpoint):
                settings.save_settings({"base_url": endpoint, "model": "fixture"})
                self.assertEqual(llm.configured(), expected)
                self.assertEqual(settings.public_settings()["llm_ready"], expected)
                self.assertFalse(settings.public_settings()["has_key"])
        settings.save_settings({"base_url": "https://example.org/v1", "api_key": "synthetic-fixture-value"})
        self.assertTrue(llm.configured())
        settings.save_settings({"base_url": "http://example.org/v1"})
        self.assertFalse(llm.configured())
        settings.save_settings({"base_url": "http://localhost/v1", "model": ""})
        self.assertFalse(llm.configured())

    def test_settings_validate_before_atomic_write_and_keep_existing_key(self):
        settings.save_settings({"api_key": "synthetic-fixture-value", "model_review_enabled": True,
                               "model_review_timeout_seconds": 180, "reasoning_budget_seconds": 60})
        settings.save_settings({"api_key": "", "model_review_max_calls": 0})
        self.assertEqual(settings.load_settings()["api_key"], "synthetic-fixture-value")
        self.assertEqual(settings.public_settings()["model_review_max_calls"], 0)
        before = self.path.read_bytes()
        for update in ({"model_review_max_calls": -1}, {"model_review_enabled": "true"},
                       {"model_review_daily_max_calls": True}, {"reasoning_budget_seconds": 10000},
                       {"model_reasoning_effort": "unsupported"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                settings.save_settings(update)
            self.assertEqual(before, self.path.read_bytes())

    def test_local_request_has_no_authorization_or_proxy_and_blocks_redirects(self):
        settings.save_settings({"base_url": "http://127.0.0.1:11434/v1", "model": "fixture",
                               "model_reasoning_effort": "none"})
        captured = {}
        original = urllib.request.build_opener
        def build(*handlers):
            captured["handlers"] = handlers
            return original(*handlers)
        def respond(request, **kwargs):
            captured["request"] = request
            captured["timeout"] = kwargs["timeout"]
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode())
        with patch.object(urllib.request, "build_opener", side_effect=build), \
                patch.object(urllib.request.OpenerDirector, "open", side_effect=respond):
            self.assertEqual(llm.chat([], timeout=90), "ok")
        self.assertIsNone(captured["request"].get_header("Authorization"))
        self.assertEqual(captured["timeout"], 90)
        self.assertEqual(json.loads(captured["request"].data)["reasoning_effort"], "none")
        self.assertTrue(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies == {}
                            for h in captured["handlers"]))
        redirect = next(h for h in captured["handlers"] if isinstance(h, llm._NoRedirect))
        with self.assertRaises(RuntimeError):
            redirect.redirect_request(captured["request"], None, 302, "redirect", {}, "https://example.org")


class ModelReviewTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "intelligence.db"
        self.stack.enter_context(patch.object(settings, "LOCAL", Path(directory) / "settings.json"))
        self.stack.enter_context(patch.dict(os.environ, {"OFFLINE_DEMO": "0", "TEAM_INTEL_MODE": "embed"}))
        settings.save_settings({"base_url": "http://127.0.0.1:11434/v1", "model": "fixture",
                               "model_review_enabled": True})
        self.components = review._components()
        self.version = self.components[-1]
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.executescript("""
                CREATE TABLE unified_vulnerabilities(cve_id TEXT PRIMARY KEY, payload_json TEXT,
                    content_sha256 TEXT, content_updated_at TEXT);
                CREATE TABLE knowledge_documents(document_id TEXT PRIMARY KEY, payload_json TEXT,
                    content_sha256 TEXT, content_updated_at TEXT);
            """)
        self.cves = self.components[0](self.path)
        self.documents = self.components[1](self.path)
        self.model = self.stack.enter_context(patch.object(review, "chat", side_effect=self.answer))
        # No test may accidentally reach an endpoint if an adapter is bypassed.
        self.stack.enter_context(patch.object(urllib.request.OpenerDirector, "open",
                                             side_effect=AssertionError("Unexpected network")))

    def sql(self, query, parameters=()):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(query, parameters)]

    def seed(self, kind="cve", entity="fixture-1"):
        payload = {"title": "Zephyr service report", "description": "The assistant may disclose private data."}
        if kind == "cve":
            payload["cve_id"] = entity
            table, key = "unified_vulnerabilities", "cve_id"
        else:
            payload.update(content_type="research_article")
            table, key = "knowledge_documents", "document_id"
        row = {key: entity, "payload_json": json.dumps(payload), "content_sha256": "hash-" + entity}
        self.sql(f"INSERT INTO {table} VALUES(?,?,?,?)", (entity, row["payload_json"], row["content_sha256"], "2026-01-01"))
        if kind == "cve":
            self.cves.record(row, self.version, "pending_llm")
        else:
            result = self.components[5](None, "unknown", 0, "Ambiguous assistant", [], "rule_review", True)
            self.documents.record(row, self.version, result)
        return row

    def answer(self, messages, **options):
        self.assertEqual(options["timeout"], settings.load_settings()["model_review_timeout_seconds"])
        record = json.loads(messages[-1]["content"])
        self.assertIn("assistant", record["description"])
        return json.dumps({"is_ai_related": True, "category": "ai_application_agent", "confidence": .91,
                           "reason": "Synthetic classification", "evidence": ["assistant"]})

    def test_cve_and_document_use_shared_model_and_publish_versioned_changefeed(self):
        self.seed()
        self.seed("document", "doc-1")
        before = self.sql("SELECT MAX(seq) n FROM team_changes")[0]["n"]
        report = review.run_batch(self.path)
        self.assertEqual(report["attempted"], 2, report)
        self.assertEqual(report["accepted"], 2, report)
        self.assertEqual(report["committed"], 2, report)
        self.assertEqual(report["status"], "success", report)
        for table in ("ai_classifications", "document_ai_classifications"):
            row = self.sql("SELECT * FROM " + table)[0]
            self.assertEqual((row["state"], row["ai_related"], row["classifier_version"]),
                             ("classified", 1, self.version))
            self.assertEqual(row["decision_source"], "semantic_judge")
        changed = self.sql("SELECT * FROM team_changes WHERE seq>?", (before,))
        self.assertEqual({row["kind"] for row in changed}, {"cve", "document"})
        state = review.state(self.path)
        self.assertEqual(state["pending"], {"cve": 0, "document": 0})
        self.assertEqual(state["used_today"], 2)

    def test_local_schema_reaches_http_body_for_both_queues(self):
        self.seed()
        self.seed("document", "doc-1")
        requests = []

        def respond(request, **kwargs):
            body = json.loads(request.data)
            requests.append(body)
            answer = self.answer(body["messages"], timeout=kwargs["timeout"])
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": answer}}]}).encode())

        # Exercise the real shared adapter and serialized request, with network
        # interception at its final boundary rather than mocking the format.
        self.model.side_effect = llm.chat
        with patch.object(urllib.request.OpenerDirector, "open", side_effect=respond):
            result = review.run_batch(self.path)
        self.assertEqual((result["accepted"], result["committed"]), (2, 2), result)
        self.assertEqual(len(requests), 2)
        fields = {"is_ai_related", "category", "confidence", "reason", "evidence"}
        for body in requests:
            output = body["response_format"]
            self.assertEqual(output["type"], "json_schema")
            self.assertTrue(output["json_schema"]["strict"])
            schema = output["json_schema"]["schema"]
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), fields)
            self.assertEqual(set(schema["properties"]), fields)
            self.assertEqual(schema["properties"]["evidence"]["type"], "array")
            self.assertEqual(schema["properties"]["evidence"]["items"]["type"], "string")
            self.assertEqual(schema["properties"]["confidence"]["minimum"], 0)
            self.assertEqual(schema["properties"]["confidence"]["maximum"], 1)
        prompt = next(body["messages"][0]["content"] for body in requests
                      if "knowledge document" in body["messages"][0]["content"])
        example = json.JSONDecoder().raw_decode(prompt[prompt.index('{"is_ai_related"'):])[0]
        self.assertEqual(set(example), fields)
        self.assertIsInstance(example["evidence"], list)
        self.assertIn("never a single string", prompt)
        self.assertIn("Never add fields", prompt)

    def test_remote_provider_keeps_json_object_protocol(self):
        self.seed("document", "doc-1")
        settings.save_settings({"base_url": "https://example.org/v1", "api_key": "fixture-key"})
        requests = []

        def respond(request, **kwargs):
            body = json.loads(request.data)
            requests.append(body)
            answer = self.answer(body["messages"], timeout=kwargs["timeout"])
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": answer}}]}).encode())

        self.model.side_effect = llm.chat
        with patch.object(urllib.request.OpenerDirector, "open", side_effect=respond):
            result = review.run_batch(self.path)
        self.assertEqual(result["committed"], 1, result)
        self.assertEqual(requests[0]["response_format"], {"type": "json_object"})
        # A different local compatibility server must not inherit Ollama's format.
        self.assertEqual(review._review_format({"base_url": "http://localhost:8000/v1"}),
                         {"type": "json_object"})
        self.assertEqual(review._review_format({"base_url": "https://localhost.example.org:11434/v1"}),
                         {"type": "json_object"})

    def test_document_invalid_protocol_and_unproven_evidence_never_write_verdict(self):
        valid = {"is_ai_related": True, "category": "ai_application_agent", "confidence": .91,
                 "reason": "Synthetic classification", "evidence": ["assistant"]}
        invalid = (
            dict(valid, evidence="assistant"),
            dict(valid, description="Extra unrequested field"),
            dict(valid, evidence=[]),
            dict(valid, evidence=["fabricated source quotation"]),
            dict(valid, category="non_ai"),
        )
        for index, value in enumerate(invalid):
            with self.subTest(value=value):
                entity = "invalid-document-" + str(index)
                self.seed("document", entity)
                before = self.sql("SELECT * FROM document_ai_classifications WHERE document_id=?", (entity,))
                changes = self.sql("SELECT MAX(seq) n FROM team_changes")[0]["n"]
                self.model.side_effect = None
                self.model.return_value = json.dumps(value)
                result = review.run_batch(self.path)
                self.assertEqual((result["attempted"], result["accepted"], result["committed"]),
                                 (1, 0, 0), result)
                self.assertEqual(self.sql("SELECT * FROM document_ai_classifications WHERE document_id=?",
                                          (entity,)), before)
                self.assertEqual(self.sql("SELECT * FROM team_changes WHERE seq>?", (changes,)), [])
                self.assertEqual(self.sql("SELECT status,error_type FROM model_review_calls WHERE entity_id=?",
                                          (entity,)), [{"status": "retry", "error_type": "ValueError"}])

    def test_disabled_missing_model_zero_budget_and_mirror_do_not_spend_or_initialize(self):
        for update, reason in (({"model_review_enabled": False}, "disabled"),
                               ({"model_review_enabled": True, "base_url": "https://example.org/v1"}, "model_not_configured"),
                               ({"base_url": "http://localhost/v1", "model_review_max_calls": 0}, "zero_budget")):
            settings.save_settings(update)
            self.assertEqual(review.run_batch(self.path)["reason"], reason)
        settings.save_settings({"model_review_max_calls": 2})
        (self.path.parent / ".writer-mode").write_text("actions-mirror\n")
        self.assertEqual(review.run_batch(self.path)["reason"], "read_only_mirror")
        self.assertFalse(self.sql("SELECT name FROM sqlite_master WHERE name='model_review_calls'"))
        self.model.assert_not_called()

    def test_one_call_rounds_alternate_and_daily_budget_survives_memory_reset(self):
        self.seed()
        self.seed("cve", "fixture-2")
        self.seed("document", "doc-1")
        settings.save_settings({"model_review_max_calls": 1, "model_review_daily_max_calls": 2})
        first, second = review.run_batch(self.path), review.run_batch(self.path)
        self.assertEqual(first["items"][0]["kind"], "cve")
        self.assertEqual(second["items"][0]["kind"], "document")
        review._LATEST.clear()
        self.assertEqual(review.state(self.path)["used_today"], 2)
        self.assertEqual(review.run_batch(self.path)["reason"], "daily_budget_exhausted")
        self.assertEqual(self.model.call_count, 2)

    def test_invalid_evidence_keeps_unknown_and_respects_retry_cooldown(self):
        self.seed()
        self.seed("document", "doc-1")
        self.model.side_effect = lambda *args, **kwargs: json.dumps({"is_ai_related": True,
            "category": "ai_application_agent", "confidence": .99, "reason": "Synthetic forged claim",
            "evidence": ["unseen fabricated evidence"]})
        report = review.run_batch(self.path)
        self.assertEqual((report["attempted"], report["accepted"]), (2, 0), report)
        self.assertEqual(self.sql("SELECT ai_related,state FROM ai_classifications")[0],
                         {"ai_related": None, "state": "retry"})
        self.assertEqual(self.sql("SELECT ai_related,state FROM document_ai_classifications")[0],
                         {"ai_related": None, "state": "review"})
        self.assertEqual(review.run_batch(self.path)["reason"], "no_ready_candidates")
        self.assertEqual(self.model.call_count, 2)
        self.assertEqual(review.state(self.path)["queue"]["cve"]["cooldown"], 1)
        self.assertEqual(review.state(self.path)["queue"]["document"]["cooldown"], 1)

    def test_source_changed_during_model_call_does_not_commit_stale_verdict(self):
        self.seed()
        def change_source(messages, **kwargs):
            self.sql("UPDATE unified_vulnerabilities SET content_sha256='changed'")
            return self.answer(messages, **kwargs)
        self.model.side_effect = change_source
        report = review.run_batch(self.path)
        self.assertEqual((report["attempted"], report["accepted"], report["committed"]), (1, 1, 0), report)
        self.assertEqual(report["items"][0]["status"], "stale")
        self.assertEqual(self.sql("SELECT state FROM ai_classifications")[0]["state"], "pending_llm")

    def test_disable_between_requests_stops_next_charge(self):
        self.seed()
        self.seed("document", "doc-1")
        def disable(messages, **kwargs):
            settings.save_settings({"model_review_enabled": False})
            return self.answer(messages, **kwargs)
        self.model.side_effect = disable
        report = review.run_batch(self.path)
        self.assertEqual(report["attempted"], 1, report)
        self.assertEqual(report["items"][1]["reason"], "disabled")
        self.assertEqual(self.model.call_count, 1)

    def test_crashed_attempt_is_charged_and_three_attempts_require_human_review(self):
        self.seed("document", "doc-1")
        review._initialize(self.path)
        row = review._candidates(self.path, self.version, 1)[0]
        for index in range(3):
            review._reserve(self.path, row, self.version, "crashed-" + str(index))
        self.sql("UPDATE model_review_calls SET started_epoch=0")
        self.assertEqual(review.run_batch(self.path)["reason"], "no_ready_candidates")
        self.assertEqual(review.state(self.path)["used_today"], 3)
        self.assertEqual(review.state(self.path)["queue"]["document"],
                         {"ready": 0, "cooldown": 0, "manual_review": 1})
        self.model.assert_not_called()

    def test_readonly_status_does_not_create_tables_and_does_not_expose_provider_failure(self):
        self.assertEqual(review.state(self.path)["used_today"], 0)
        self.assertFalse(self.sql("SELECT name FROM sqlite_master WHERE name='model_review_calls'"))
        self.seed("document", "doc-1")
        self.model.side_effect = RuntimeError("synthetic-secret-like-provider-message")
        report = review.run_batch(self.path)
        self.assertEqual(report["attempted"], 1)
        self.assertNotIn("synthetic-secret", json.dumps(report) + json.dumps(review.state(self.path)))
        self.assertEqual(self.sql("SELECT error_type FROM model_review_calls")[0]["error_type"], "RuntimeError")

    def test_collection_classification_lock_prevents_concurrent_model_work(self):
        from intelligence.monitoring.lock import ProcessFileLock
        self.seed()
        with ProcessFileLock(self.path.parent / ".ai_classification.lock"):
            result = review.run_batch(self.path)
        self.assertEqual(result["reason"], "busy")
        self.model.assert_not_called()
        self.assertFalse(self.sql("SELECT name FROM sqlite_master WHERE name='model_review_calls'"))

    def test_fresh_rule_backlog_and_outdated_verdicts_are_not_sent_to_model(self):
        self.seed()
        self.sql("UPDATE ai_classifications SET classifier_version='old-classifier'")
        self.seed("document", "doc-1")
        self.sql("UPDATE knowledge_documents SET content_sha256='changed'")
        self.sql("INSERT INTO unified_vulnerabilities VALUES('fresh', '{}', 'freshhash', '2026-01-02')")
        self.assertEqual(review.run_batch(self.path)["reason"], "no_ready_candidates")
        self.model.assert_not_called()
        self.assertEqual(len(self.sql("SELECT * FROM ai_classifications")), 1)

    def test_valid_negative_is_distinct_from_model_failure(self):
        self.seed()
        self.seed("document", "doc-1")
        self.model.side_effect = lambda *args, **kwargs: json.dumps({"is_ai_related": False,
            "category": "non_ai", "confidence": .93, "reason": "The assistant is a generic UI helper.",
            "evidence": ["assistant"]})
        result = review.run_batch(self.path)
        self.assertEqual((result["accepted"], result["committed"]), (2, 2), result)
        for table in ("ai_classifications", "document_ai_classifications"):
            self.assertEqual(self.sql("SELECT state,ai_related FROM " + table)[0],
                             {"state": "classified", "ai_related": 0})


if __name__ == "__main__":
    unittest.main()
