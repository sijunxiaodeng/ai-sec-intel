"""Cloud reporting must distinguish acquisition, documents and model execution."""
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ai_pipeline.store import ClassificationStore
from deployment.actions_report import (
    DEFAULT_CLOUD_STARTED_AT, build_report, escape_workflow_data, main,
    model_facts, notice_line, render_summary,
)
from monitoring.source_registry import get_sources
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

NOW = datetime(2026, 10, 10, 15, tzinfo=timezone.utc)
BASELINE = "2026-10-08T00:00:00Z"
VERSION = "test-current-version"
SECRET = "fixture-never-export-this-secret"


class FakeClient:
    def run(self, run_id):
        return {"id": run_id, "head_branch": "main", "event": "schedule",
                "created_at": "2026-10-10T14:55:00Z", "run_started_at": "2026-10-10T14:55:30Z"}
    def runs(self, workflow, branch):
        return iter([{"id": 41, "head_branch": "main", "event": "schedule",
                      "created_at": "2026-10-10T13:55:00Z", "run_started_at": "2026-10-10T13:58:00Z"}])


class ActionsReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "data"
        self.database = self.directory / "intelligence.db"
        SQLiteIntelligenceStore(self.database)
        SQLiteDocumentStore(self.database)
        ClassificationStore(self.database)
        self.specs = [spec for spec in get_sources() if spec.name in {"NVD", "GITHUB_ADVISORY", "ARXIV_AI_SECURITY"}]
        (self.directory / "monitoring_baseline.json").write_text(json.dumps({"started_at": BASELINE}))
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE source_observation_baselines(source TEXT PRIMARY KEY, source_category TEXT, started_at TEXT)")
            for spec in self.specs:
                connection.execute("INSERT INTO source_observation_baselines VALUES (?,?,?)", (spec.name, spec.category, BASELINE))
        self.add_cve("CVE-2026-10001", "2026-10-09T00:00:00Z", "2026-10-09T06:00:00Z")
        self.add_cve("CVE-2026-10002", "2026-10-09T15:00:00Z", "2026-10-09T15:10:00Z")
        self.add_cve("CVE-2026-10003", "2026-10-09T13:00:00Z", "2026-10-09T20:00:00Z")
        with sqlite3.connect(self.database) as connection:
            connection.execute("""INSERT INTO source_items SELECT 'GITHUB_ADVISORY',source_id,cve_id,
                                  payload_json,content_sha256,first_seen_at,last_seen_at,content_updated_at
                                  FROM source_items WHERE cve_id='CVE-2026-10001'""")
            published, seen = "2026-10-09T02:00:00Z", "2026-10-09T11:00:00Z"
            payload = json.dumps({"published_at": published, "title": SECRET, "raw_data": {}})
            connection.execute("""INSERT INTO knowledge_documents VALUES
                ('paper-1','ARXIV_AI_SECURITY','academic_paper','paper',?,?,?, ?,NULL,'[]',?,'paper-hash',?,?,?)""",
                (SECRET, SECRET, "https://example.test/public-paper", published, payload, seen, seen, seen))
        monitoring = {"status": "partial", "started_at": "2026-10-10T14:56:00Z", "finished_at": NOW.isoformat(),
                      "sources": {"NVD": {"status": "partial", "recent_success": True, "pending": True,
                                          "error": SECRET},
                                  "GITHUB_ADVISORY": {"status": "success", "recent_success": True, "pending": False},
                                  "ARXIV_AI_SECURITY": {"status": "failed", "pending": False, "error": SECRET}}}
        (self.directory / "monitoring_status.json").write_text(json.dumps(monitoring))

    def add_cve(self, cve_id, published, seen):
        payload = json.dumps({"published_at": published, "publication_source": "NVD",
                              "sources": ["NVD"], "description": SECRET})
        with sqlite3.connect(self.database) as connection:
            connection.execute("INSERT INTO unified_vulnerabilities VALUES (?,?,?,?,?)", (cve_id, payload, cve_id, seen, seen))
            connection.execute("INSERT INTO source_items VALUES ('NVD',?,?,?,?,?,?,?)",
                               (cve_id, cve_id, payload, cve_id, seen, seen, seen))

    def report(self, **kwargs):
        return build_report(self.directory, root=self.root, run_id=42, now=NOW,
                            version=VERSION, specs=self.specs, client=kwargs.pop("client", FakeClient()), **kwargs)

    def test_old_breach_retained_cloud_breach_visible_and_rolling_subset_not_overall_pass(self):
        report = self.report()
        periods = report["latency"]
        self.assertEqual(periods["full_observation_period"]["summary"]["samples"], 3)
        self.assertEqual(periods["full_observation_period"]["summary"]["breached_6h"], 2)
        self.assertEqual(periods["since_cloud_deployment"]["summary"]["samples"], 2)
        self.assertEqual(periods["since_cloud_deployment"]["summary"]["breached_6h"], 1)
        self.assertEqual(periods["since_cloud_deployment"]["monitored_since"], "2026-10-09T12:05:16+00:00")
        self.assertEqual(periods["last_24h"]["summary"]["samples"], 1)
        self.assertEqual(periods["last_24h"]["summary"]["breached_6h"], 0)
        self.assertTrue(periods["last_24h"]["rolling_window"])
        summary = render_summary(report, run_id=42)
        self.assertIn("不替代整体指标", summary)
        self.assertNotIn("整体达标", summary)
        self.assertIn("cloud_breach=1", notice_line(report))

    def test_duplicates_and_paper_counts_stay_in_independent_coverage_column(self):
        report = self.report()
        self.assertEqual(report["latency"]["full_observation_period"]["summary"]["samples"], 3)
        self.assertEqual(report["coverage"]["per_source_precise_samples"], 5)
        self.assertEqual(report["coverage"]["per_source_delayed_records"], 4)
        self.assertEqual(report["sources"]["by_source"]["NVD"]["recent_success"], True)
        self.assertEqual(report["sources"]["by_source"]["NVD"]["pending_backfill"], True)
        self.assertEqual(report["sources"]["observation_scope"], "current_run")
        self.assertEqual(report["sources"]["partial"], 1)
        self.assertEqual(report["sources"]["failed"], 1)

    def test_current_hash_and_classifier_version_exclude_stale_classification(self):
        cases = [("classified", "rule_positive", "same", VERSION),
                 ("classified", "semantic_judge", "same", VERSION),
                 ("review", "semantic_judge", "same", VERSION),
                 ("pending_llm", "", "same", VERSION), ("retry", "", "same", VERSION),
                 ("classified", "rule_positive", "old-hash", VERSION),
                 ("classified", "semantic_judge", "same", "old-version")]
        for index, (state, source, hash_value, version) in enumerate(cases):
            cve_id = f"CVE-2026-{20000 + index}"
            self.add_cve(cve_id, "2020-01-01T00:00:00Z", "2026-10-09T15:00:00Z")
            with sqlite3.connect(self.database) as connection:
                connection.execute("""INSERT INTO ai_classifications
                    (cve_id,content_sha256,classifier_version,state,ai_related,decision_source,reason,updated_at)
                    VALUES (?,?,?,?,?,?,?,?)""", (cve_id, cve_id if hash_value == "same" else hash_value,
                                                  version, state, 1, source, SECRET, NOW.isoformat()))
        facts = self.report()["classification"]
        self.assertEqual((facts["total_cves"], facts["valid_current"], facts["unclassified_or_stale"]), (10, 5, 5))
        self.assertEqual((facts["classified"], facts["rule"], facts["semantic"], facts["review"]), (2, 1, 2, 1))
        self.assertEqual((facts["pending_llm"], facts["retry"]), (1, 1))

    def test_current_model_counters_distinguish_verified_response_from_commit(self):
        model = {"run_id": "42", "status": "partial", "provider": "deepseek", "model": "deepseek-chat",
                 "reason_category": "invalid_response", "semantic_calls": 2, "semantic_success": 1,
                 "retry": 1, "max_llm_calls": 2, "committed_classifications": 0, "committed_retries": 1,
                 "started_at": "2026-10-10T14:57:00Z", "finished_at": NOW.isoformat(),
                 "api_key": SECRET, "response_body": SECRET, "exception": SECRET}
        (self.directory / "deepseek_status.json").write_text(json.dumps(model))
        report = self.report()
        notice = notice_line(report)
        self.assertIn("model_attempts=2", notice)
        self.assertIn("model_accepted=1", notice)
        self.assertIn("model_committed=0", notice)
        self.assertIn("model_reason=invalid_response", notice)
        self.assertNotIn(SECRET, json.dumps(report) + notice + render_summary(report, run_id=42))

    def test_stale_model_and_stale_report_never_claim_current_execution(self):
        (self.directory / "deepseek_status.json").write_text(json.dumps({"run_id": 41, "status": "success",
                                  "provider": "deepseek", "semantic_calls": 2, "semantic_success": 2}))
        model = model_facts(self.directory, 42)
        self.assertEqual((model["status"], model["reason_category"], model["semantic_calls"]),
                         ("not_executed", "stale_run", 0))
        report = self.report()
        summary = render_summary(report, run_id=43, collection_outcome="failure", snapshot_outcome="success")
        self.assertIn("本轮时效、分类和模型执行均为未知", summary)
        self.assertNotIn("精确样本", summary)
        self.assertIn("采集步骤：failure", summary)

    def test_read_only_reporting_does_not_touch_first_seen_or_original_baseline(self):
        before_baseline = (self.directory / "monitoring_baseline.json").read_bytes()
        with sqlite3.connect(self.database) as connection:
            before_rows = connection.execute("SELECT * FROM unified_vulnerabilities ORDER BY cve_id").fetchall()
            before_schema = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
        self.report()
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(before_rows, connection.execute("SELECT * FROM unified_vulnerabilities ORDER BY cve_id").fetchall())
            self.assertEqual(before_schema, connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall())
        self.assertEqual(before_baseline, (self.directory / "monitoring_baseline.json").read_bytes())

    def test_imprecise_future_negative_and_malformed_rows_are_not_live_evidence(self):
        self.add_cve("CVE-2026-30001", "2026-10-10", "2026-10-10T14:00:00Z")
        self.add_cve("CVE-2026-30002", "2026-10-10T14:00:00Z", "2026-10-10T13:00:00Z")
        self.add_cve("CVE-2026-30003", "2026-10-11T00:00:00Z", "2026-10-11T01:00:00Z")
        with sqlite3.connect(self.database) as connection:
            connection.execute("INSERT INTO unified_vulnerabilities VALUES ('CVE-2026-30004','[]','bad',?,?)", (NOW.isoformat(), NOW.isoformat()))
        facts = self.report()["latency"]["full_observation_period"]
        self.assertEqual(facts["summary"]["samples"], 3)
        self.assertEqual(facts["excluded"], {"missing_or_imprecise_time": 1, "negative_delay": 1,
                                           "future_timestamp": 1, "invalid_payload": 1})

    def test_observed_schedule_gap_is_not_the_configured_fifteen_minutes(self):
        schedule = self.report()["schedule"]
        self.assertEqual(schedule["configured_interval_seconds"], 900)
        self.assertEqual(schedule["creation_interval_seconds"], 3600)
        self.assertEqual(schedule["start_interval_seconds"], 3450)
        self.assertEqual(schedule["current_start_delay_seconds"], 30)
        self.assertIn("schedule_gap_s=3600", notice_line(self.report()))

    def test_metadata_api_error_is_unknown_without_leaking_body_or_breaking_report(self):
        client = FakeClient()
        with patch.object(client, "run", side_effect=RuntimeError(SECRET)):
            report = self.report(client=client)
        self.assertEqual(report["schedule"]["reason_category"], "github_metadata_unavailable")
        self.assertEqual(report["latency"]["status"], "ok")
        self.assertNotIn(SECRET, json.dumps(report))

    def test_timeout_old_source_status_is_labeled_previous_run(self):
        status_path = self.directory / "monitoring_status.json"
        status = json.loads(status_path.read_text())
        status["finished_at"] = "2026-10-10T13:00:00Z"
        status_path.write_text(json.dumps(status))
        report = self.report()
        self.assertEqual(report["sources"]["observation_scope"], "previous_run")
        self.assertIn("上一轮完整结果，不能冒充本轮", render_summary(report, run_id=42))

    def test_notice_control_escaping_and_allowlisted_states_prevent_command_injection(self):
        self.assertEqual(escape_workflow_data("a%\r\n\x00\x1b"), "a%25%0D%0A%00%1B")
        report = self.report()
        report["model"] = {"status": f"success\n::error::{SECRET}", "reason_category": SECRET,
                           "semantic_calls": SECRET, "semantic_success": -1}
        notice = notice_line(report)
        self.assertNotIn("\n", notice)
        self.assertNotIn(SECRET, notice)
        self.assertIn("deepseek_status=unknown", notice)
        self.assertIn("model_attempts=unknown", notice)

    def test_record_and_summary_cli_use_current_run_file_without_model_or_network(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(output):
            self.assertEqual(main(["record", "--directory", str(self.directory), "--run-id", "42"]), 0)
        current = json.loads((self.directory / "actions_report.json").read_text())
        self.assertEqual(current["run_id"], "42")
        self.assertIn("::notice title=B cloud facts::", output.getvalue())
        destination = self.root / "summary.md"
        env = {"GITHUB_STEP_SUMMARY": str(destination), "COLLECTION_OUTCOME": "success", "SNAPSHOT_OUTCOME": "success"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(main(["summary", "--directory", str(self.directory), "--run-id", "43"]), 0)
        self.assertIn("本轮时效、分类和模型执行均为未知", destination.read_text())

    def test_missing_database_is_not_created_and_report_remains_useful(self):
        self.database.unlink()
        report = self.report()
        self.assertEqual(report["latency"]["status"], "unavailable")
        self.assertFalse(self.database.exists())
        self.assertIn("cve_samples=unknown", notice_line(report))


if __name__ == "__main__":
    unittest.main()
