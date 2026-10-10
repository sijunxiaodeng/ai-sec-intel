"""Offline provider gating, request caps and real process-group deadline tests."""
from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
from ai_pipeline.store import ClassificationStore
from deployment import deepseek_review as review


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "intelligence.db"
        with sqlite3.connect(self.db) as con:
            con.executescript("""
                CREATE TABLE unified_vulnerabilities (
                    cve_id TEXT PRIMARY KEY,payload_json TEXT,content_sha256 TEXT,
                    first_seen_at TEXT,content_updated_at TEXT);
                CREATE TABLE collector_state (collector TEXT PRIMARY KEY,last_success_at TEXT);
                INSERT INTO collector_state VALUES ('NVD','ORIGINAL_CURSOR');
            """)
            for index in range(5):
                cve = f"CVE-2026-{10000 + index}"
                payload = {"cve_id": cve, "description": "A novel LLM gateway vulnerability"}
                con.execute("INSERT INTO unified_vulnerabilities VALUES (?,?,?,?,?)", (
                    cve, json.dumps(payload), "hash-" + cve, "ORIGINAL_FIRST_SEEN", "2026-10-10T00:00:00Z",
                ))
        self.store = ClassificationStore(self.db)

    def status_file(self):
        return json.loads((self.db.parent / "deepseek_status.json").read_text())

    def test_missing_key_and_disabled_phase_never_start_a_child(self):
        for kwargs, reason in (({"api_key": ""}, "missing_api_key"),
                               ({"api_key": "TEST_KEY", "enabled": False}, "disabled")):
            with self.subTest(reason=reason), patch.object(review.subprocess, "Popen") as process:
                result = review.run_review(self.db, **kwargs)
                process.assert_not_called()
                self.assertEqual(result["status"], "skipped")
                self.assertEqual(result["reason_category"], reason)
                self.assertEqual(result["semantic_calls"], 0)
                self.assertNotIn("TEST_KEY", json.dumps(self.status_file()))

    def test_excessive_budget_or_unsafe_model_is_rejected_before_a_child(self):
        for kwargs in ({"max_llm_calls": 3}, {"model": "deepseek-chat\nTEST_KEY"}, {"timeout_seconds": 61}):
            with self.subTest(kwargs=kwargs), patch.object(review.subprocess, "Popen") as process:
                result = review.run_review(self.db, api_key="TEST_KEY", **kwargs)
                process.assert_not_called()
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["reason_category"], "invalid_configuration")
                self.assertNotIn("TEST_KEY", json.dumps(result))

    def test_child_environment_excludes_source_keys_and_configurable_provider_urls(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "GH_SECRET", "NVD_API_KEY": "NVD_SECRET",
                                     "LLM_CHAT_COMPLETIONS_URL": "https://foreign.test/?key=SECRET"}):
            env = review._child_environment("TEST_KEY", "deepseek-chat")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("NVD_API_KEY", env)
        self.assertEqual(env["LLM_CHAT_COMPLETIONS_URL"], "")
        self.assertEqual(env["DEEPSEEK_API_KEY"], "TEST_KEY")

    def test_real_classifier_stops_at_two_mocked_provider_requests(self):
        response = Mock()
        response.json.return_value = {"choices": [{"message": {"content": json.dumps({
            "is_ai_related": True, "category": "ai_infrastructure", "confidence": 0.95,
            "reason": "The supplied record describes an LLM gateway", "evidence": ["LLM"],
        })}}]}
        progress = self.db.parent / "progress.json"
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "TEST_KEY"}), patch(
            "classification.semantic_judge.requests.post", return_value=response
        ) as post, patch("classification.semantic_judge.load_dotenv") as dotenv:
            code = review._worker(self.db, progress, "deepseek-chat", 2)
        self.assertEqual(code, 0)
        self.assertEqual(post.call_count, 2)
        dotenv.assert_not_called()
        for call in post.call_args_list:
            self.assertEqual(call.args[0], review.OFFICIAL_URL)
            self.assertEqual(call.kwargs["timeout"], 20)
        data = review._read_progress(progress)
        self.assertEqual(data["semantic_calls"], 2)
        self.assertEqual(data["semantic_success"], 2)
        with self.store.connect() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM ai_classifications WHERE state='classified'").fetchone()[0], 2)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM ai_classifications WHERE state='pending_llm'").fetchone()[0], 3)
        self.assertNotIn("TEST_KEY", progress.read_text())

    def test_provider_authentication_errors_remain_unknown_and_are_redacted(self):
        error = requests.HTTPError("https://provider.test/?key=TEST_KEY BODY_SECRET",
                                   response=SimpleNamespace(status_code=401))
        progress = self.db.parent / "progress.json"
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "TEST_KEY"}), patch(
            "classification.semantic_judge.requests.post", side_effect=error
        ) as post:
            review._worker(self.db, progress, "deepseek-chat", 2)
        data = review._read_progress(progress)
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["retry"], 2)
        self.assertEqual(data["reason_category"], "authentication_failed")
        self.assertEqual(post.call_count, 2)
        with self.store.connect() as con:
            rows = con.execute("SELECT ai_related,reason,error_text FROM ai_classifications WHERE state='retry'").fetchall()
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertIsNone(row["ai_related"])
            self.assertNotIn("TEST_KEY", repr(tuple(row)))
            self.assertNotIn("BODY_SECRET", repr(tuple(row)))
        self.assertNotIn("TEST_KEY", progress.read_text())

    @unittest.skipUnless(os.name == "posix", "Cloud deadline uses a POSIX process group")
    def test_timeout_kills_descendants_and_preserves_already_committed_classification(self):
        row = self.store.fresh("fixture", 1)[0]
        self.store.record(row, "fixture", "pending_llm")
        marker, descendant_pid = self.db.parent / "escaped.txt", self.db.parent / "descendant.pid"
        child_code = """
import json, pathlib, sqlite3, subprocess, sys, time
db, progress, marker, pidfile, cve = sys.argv[1:]
with sqlite3.connect(db) as con:
    con.execute("UPDATE ai_classifications SET state='classified',ai_related=1,decision_source='semantic_judge',attempts=attempts+1 WHERE cve_id=?", (cve,))
pathlib.Path(progress).write_text(json.dumps({'status':'running','semantic_calls':2,'semantic_success':1,'retry':0,'reason_category':'completed'}))
code = "import pathlib,sys,time; time.sleep(1); pathlib.Path(sys.argv[1]).write_text('escaped')"
child = subprocess.Popen([sys.executable,'-c',code,marker])
pathlib.Path(pidfile).write_text(str(child.pid))
print('TEST_KEY RAW_PROVIDER_RESPONSE', flush=True)
time.sleep(20)
"""
        def command(db, progress, max_calls, model):
            return [sys.executable, "-c", child_code, str(db), str(progress), str(marker), str(descendant_pid), row["cve_id"]]
        with patch.object(review, "_worker_command", side_effect=command), redirect_stdout(io.StringIO()) as output:
            result = review.run_review(self.db, api_key="TEST_KEY", timeout_seconds=.35, run_id="test-timeout")
        self.assertTrue(descendant_pid.exists(), "fixture must actually spawn a descendant before the deadline")
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["reason_category"], "wall_timeout")
        self.assertEqual(result["semantic_calls"], 2)
        self.assertEqual(result["semantic_success"], 1)
        self.assertEqual(result["committed_classifications"], 1)
        time.sleep(1.05)
        self.assertFalse(marker.exists(), "descendant must not survive the process-group deadline")
        with self.store.connect() as con:
            self.assertEqual(con.execute("SELECT first_seen_at FROM unified_vulnerabilities LIMIT 1").fetchone()[0], "ORIGINAL_FIRST_SEEN")
            self.assertEqual(con.execute("SELECT last_success_at FROM collector_state").fetchone()[0], "ORIGINAL_CURSOR")
            self.assertEqual(con.execute("PRAGMA quick_check").fetchone()[0], "ok")
        self.assertNotIn("TEST_KEY", output.getvalue() + json.dumps(self.status_file()))
        self.assertNotIn("RAW_PROVIDER_RESPONSE", output.getvalue())

    def test_invalid_progress_cannot_expose_server_text_or_claim_extra_paid_calls(self):
        path = self.db.parent / "bad_progress.json"
        path.write_text(json.dumps({"status": "success", "semantic_calls": 3, "semantic_success": 3,
                                    "retry": 0, "reason_category": "completed", "key": "TEST_KEY"}))
        self.assertIsNone(review._read_progress(path))
        path.write_text(json.dumps({"status": "success", "semantic_calls": 1, "semantic_success": 1,
                                    "retry": 0, "reason_category": "completed", "raw": "TEST_KEY"}))
        self.assertNotIn("TEST_KEY", json.dumps(review._read_progress(path)))

    def test_main_failure_is_safe_and_does_not_fail_the_backup_step(self):
        with patch.object(review, "run_review", side_effect=RuntimeError("TEST_KEY RAW_BODY")), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(review.main(["--db", str(self.db)]), 0)
        self.assertIn("::notice::", output.getvalue())
        self.assertNotIn("TEST_KEY", output.getvalue())
        self.assertNotIn("RAW_BODY", output.getvalue())

    def test_workflow_keeps_model_secret_out_of_the_collection_step(self):
        source = (review.ROOT.parent / ".github/workflows/intelligence-collect.yml").read_text()
        self.assertIn("CLASSIFY_V5_MAX_LLM_CALLS: '0'", source)
        self.assertIn("default: true", source)
        self.assertEqual(source.count("DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}"), 1)
        collection = source.split("      - name: Collect public intelligence", 1)[1].split(
            "      - name: Review ambiguous intelligence with DeepSeek", 1
        )[0]
        self.assertNotIn("DEEPSEEK_API_KEY", collection)
        phase = source.split("      - name: Review ambiguous intelligence with DeepSeek", 1)[1].split(
            "      - name: Prepare consistent SQLite snapshot", 1
        )[0]
        self.assertIn("env.DEEPSEEK_KEY_AVAILABLE == 'true'", phase)
        self.assertIn("continue-on-error: true", phase)


if __name__ == "__main__":
    unittest.main()
