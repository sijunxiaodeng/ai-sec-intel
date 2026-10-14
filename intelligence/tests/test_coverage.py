"""Offline evidence checks: empty polls, precise deadline, provenance and freshness."""
import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from monitoring.coverage import coverage_report, _summary as source_latency_summary
from monitoring.metrics import _summary as cve_latency_summary

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
BASELINE = "2026-10-08T00:00:00Z"


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.addCleanup(self.con.close)
        self.con.executescript("""
          CREATE TABLE source_items(source TEXT,cve_id TEXT,payload_json TEXT,first_seen_at TEXT);
          CREATE TABLE unified_vulnerabilities(cve_id TEXT,content_sha256 TEXT);
          CREATE TABLE ai_classifications(cve_id TEXT,content_sha256 TEXT,classifier_version TEXT,state TEXT,ai_related INTEGER);
          CREATE TABLE knowledge_documents(document_id TEXT,source TEXT,source_category TEXT,payload_json TEXT,published_at TEXT,first_seen_at TEXT,content_sha256 TEXT);
          CREATE TABLE document_ai_classifications(document_id TEXT,content_sha256 TEXT,classifier_version TEXT,state TEXT,ai_related INTEGER);
          CREATE TABLE collector_runs(id INTEGER,collector TEXT,started_at TEXT,finished_at TEXT,status TEXT,fetched_count INTEGER,error_text TEXT);
          CREATE TABLE document_source_runs(id INTEGER,source TEXT,source_category TEXT,started_at TEXT,finished_at TEXT,status TEXT,fetched_count INTEGER,error_text TEXT);
          CREATE TABLE source_observation_baselines(source TEXT,source_category TEXT,started_at TEXT);
        """)
        self.specs = [SimpleNamespace(name="NVD", category="vulnerability_database", enabled=True)]

    def baseline(self, source="NVD", category="vulnerability_database", started=BASELINE):
        self.con.execute("INSERT INTO source_observation_baselines VALUES(?,?,?)", (source, category, started))

    def source_item(self, published, seen, source="NVD", cve="CVE-2026-10000"):
        self.con.execute("INSERT INTO source_items VALUES(?,?,?,?)", (source, cve, json.dumps({"published_at": published}), seen))

    def doc(self, source, category, published, seen="2026-10-08T11:50:00Z", ai=True,
            *, classified=True, digest="current", version="v1", state="classified"):
        identifier = "doc-" + str(self.con.execute("SELECT COUNT(*) FROM knowledge_documents").fetchone()[0])
        self.con.execute("INSERT INTO knowledge_documents VALUES(?,?,?,?,?,?,?)", (identifier, source, category,
            json.dumps({"document_id": identifier, "published_at": published,
                        "raw_data": {"ai_security_related": ai}}), published, seen, "current"))
        if classified:
            self.con.execute("INSERT INTO document_ai_classifications VALUES(?,?,?,?,?)",
                             (identifier, digest, version, state, int(ai)))

    def report(self, **kwargs):
        return coverage_report(self.con, self.specs, now=NOW, classifier_version="v1", **kwargs)

    def test_seven_empty_successes_do_not_prove_seven_categories_or_sla(self):
        categories = ["vulnerability_database", "security_community", "vendor_advisory", "security_blog",
                      "academic_paper", "technical_standard", "policy_regulation"]
        self.specs = [SimpleNamespace(name=str(index), category=category) for index, category in enumerate(categories)]
        for spec in self.specs:
            self.con.execute("INSERT INTO collector_runs VALUES(1,?,'2026-10-08T11:50:00Z','2026-10-08T11:51:00Z','success',0,NULL)", (spec.name,))
        report = self.report()
        self.assertEqual(report["configured_category_count"], 7)
        self.assertTrue(report["all_sources_fresh"])
        self.assertEqual(report["observed_source_categories"], [])
        self.assertFalse(report["required_categories_observed"])
        self.assertEqual(report["sla_evidence"], "insufficient_samples")

    def test_strict_boundary_uses_seconds_before_rounding(self):
        self.baseline()
        for index, published in enumerate(("2026-10-08T05:50:00.001", "2026-10-08T05:50:00.000", "2026-10-08T05:49:59.999")):
            self.source_item(published, "2026-10-08T11:50:00Z", cve=f"CVE-2026-1000{index}")
        live = self.report()["per_source_live_latency"]["NVD"]["live"]
        self.assertEqual(live["under_6h"], 1)
        self.assertEqual(live["breached_6h"], 2)
        self.assertEqual(self.report()["sla_evidence"], "breached")

    def test_current_hash_version_classified_positive_only_counts_ai(self):
        for index in range(5):
            self.source_item("2026-10-08T11:00:00.000", "2026-10-08T11:50:00Z", cve=f"CVE-2026-1000{index}")
            self.con.execute("INSERT INTO unified_vulnerabilities VALUES(?, 'current')", (f"CVE-2026-1000{index}",))
        for index, digest, version, state, positive in (
                (0, "current", "v1", "classified", 1), (1, "old", "v1", "classified", 1),
                (2, "current", "v0", "classified", 1), (3, "current", "v1", "review", 1),
                (4, "current", "v1", "classified", 0)):
            self.con.execute("INSERT INTO ai_classifications VALUES(?,?,?,?,?)", (f"CVE-2026-1000{index}", digest, version, state, positive))
        self.assertEqual(self.report()["counts_by_source"]["NVD"]["ai_records"], 1)
        self.assertEqual(coverage_report(self.con, self.specs, now=NOW)["observed_ai_categories"], [])

    def test_unknown_publication_blocks_all_sample_claim_and_kev_never_uses_date_added(self):
        self.baseline()
        self.source_item("2026-10-08T11:00:00.000", "2026-10-08T11:50:00Z")
        self.source_item("2026-10-08", "2026-10-08T11:50:00Z", cve="CVE-2026-10001")
        self.specs.append(SimpleNamespace(name="CISA_KEV", category="government_alert"))
        self.baseline("CISA_KEV", "government_alert")
        self.source_item("2026-10-08T11:00:00Z", "2026-10-08T11:50:00Z", source="CISA_KEV")
        report = self.report()
        self.assertEqual(report["sla_evidence"], "insufficient_samples")
        self.assertEqual(report["unknown_live_timing"], 2)
        self.assertEqual(report["per_source_live_latency"]["CISA_KEV"]["live"]["samples"], 0)

    def test_discovery_scope_stale_and_review_documents_do_not_prove_ai_coverage(self):
        self.specs = [SimpleNamespace(name="BLOG", category="security_blog")]
        for attributes in (
            {"classified": False}, {"digest": "old"}, {"version": "v0"},
            {"state": "review"}, {"ai": False}, {},
        ):
            self.doc("BLOG", "security_blog", "2026-10-08T11:40:00Z", **attributes)
        counts = self.report()["counts_by_source"]["BLOG"]
        self.assertEqual(counts["source_records"], 6)
        self.assertEqual(counts["ai_records"], 1)

    def test_new_source_baseline_excludes_backfill_and_separates_source_categories(self):
        self.specs.append(SimpleNamespace(name="BLOG", category="security_blog"))
        self.baseline("BLOG", "security_blog", "2026-10-08T11:30:00Z")
        self.doc("BLOG", "security_blog", "2026-10-08T10:00:00Z")
        self.doc("BLOG", "security_blog", "2026-10-08T11:40:00Z")
        report = self.report()
        self.assertEqual(report["observed_ai_categories"], ["security_blog"])
        self.assertEqual(report["per_source_live_latency"]["BLOG"]["live"]["samples"], 1)
        self.assertEqual(report["per_source_live_latency"]["BLOG"]["all_observed_including_backfill"]["samples"], 2)

    def test_later_failed_timeout_does_not_hide_behind_recent_success(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-10-08T11:50:00Z','2026-10-08T11:51:00Z','success',3,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(2,'NVD','2026-10-08T11:55:00Z','2026-10-08T11:57:00Z','failed',0,'TimeoutExpired')")
        health = self.report()["freshness_by_source"]["NVD"]
        self.assertEqual(health["status"], "timeout")
        self.assertFalse(health["healthy"])
        self.assertEqual(health["last_success_at"], "2026-10-08T11:51:00Z")

    def test_timeout_reusing_earlier_cycle_start_still_overrides_success(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-10-08T11:50:01Z','2026-10-08T11:50:20Z','success',3,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(2,'NVD','2026-10-08T11:50:00Z','2026-10-08T11:52:00Z','failed',0,'TimeoutError')")
        health = self.report()['freshness_by_source']['NVD']
        self.assertEqual(health['latest_run_status'], 'failed')
        self.assertEqual(health['status'], 'timeout')

    def test_stale_success_and_future_success_are_not_healthy(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-10-08T11:30:00Z','2026-10-08T11:31:00Z','success',1,NULL)")
        self.assertEqual(self.report()["freshness_by_source"]["NVD"]["status"], "stale")
        self.con.execute("INSERT INTO collector_runs VALUES(2,'NVD','2026-10-08T12:01:00Z','2026-10-08T12:02:00Z','success',1,NULL)")
        self.assertEqual(self.report()["freshness_by_source"]["NVD"]["status"], "unknown")

    def test_mismatched_categories_and_explicit_non_ai_standard_do_not_inflate_ai_coverage(self):
        self.specs = [SimpleNamespace(name="NIST", category="technical_standard")]
        self.doc("NIST", "technical_standard", None, ai=False)
        self.doc("NIST", "policy_regulation", None)
        self.doc("UNREGISTERED", "academic_paper", None)
        report = self.report()
        self.assertEqual(report["observed_source_categories"], ["technical_standard"])
        self.assertEqual(report["observed_ai_categories"], [])
        self.assertEqual(report["mismatched_document_categories"], 1)
        self.assertEqual(report["unregistered_sources"], ["UNREGISTERED"])

    def test_seven_categories_need_records_and_do_not_count_duplicate_source_specs(self):
        categories = ["vulnerability_database", "security_community", "vendor_advisory", "security_blog",
                      "academic_paper", "technical_standard", "policy_regulation"]
        self.specs = [SimpleNamespace(name=str(index), category=category) for index, category in enumerate(categories)]
        for spec in self.specs:
            self.doc(spec.name, spec.category, "2026-10-08T11:40:00Z")
            self.baseline(spec.name, spec.category)
        self.specs.append(SimpleNamespace(name="0", category="invented_category"))
        self.specs.append(SimpleNamespace(name="disabled", category="another_category", enabled=False))
        report = self.report()
        self.assertEqual(report["observed_ai_category_count"], 7)
        self.assertTrue(report["required_categories_observed"])
        self.assertEqual(report["sla_evidence"], "observed_samples_under_6h")
        self.assertEqual(report["configured_category_count"], 7)
        self.assertEqual(len(report["skipped_sources"]), 2)

    def test_missing_tables_gracefully_report_unknown_without_database_mutation(self):
        con = sqlite3.connect(":memory:")
        self.addCleanup(con.close)
        con.execute("PRAGMA query_only=ON")
        before = con.execute("SELECT name,sql FROM sqlite_master").fetchall()
        report = coverage_report(con, self.specs, now=NOW)
        self.assertEqual(report["sla_evidence"], "insufficient_samples")
        self.assertEqual(report["freshness_by_source"]["NVD"]["status"], "never_run")
        self.assertEqual(con.execute("SELECT name,sql FROM sqlite_master").fetchall(), before)

    def test_precise_record_without_own_baseline_does_not_prove_live_sla(self):
        self.source_item("2026-10-08T11:00:00.000", "2026-10-08T11:50:00Z")
        report = self.report()
        latency = report["per_source_live_latency"]["NVD"]
        self.assertEqual(latency["live"]["samples"], 0)
        self.assertEqual(latency["all_observed_including_backfill"]["samples"], 1)
        self.assertEqual(latency["excluded"]["missing_baseline"], 1)
        self.assertEqual(report["sla_evidence"], "insufficient_samples")

    def test_unknown_registered_category_is_not_invented_coverage(self):
        self.specs.append(SimpleNamespace(name="UNKNOWN", category="new_adapter_class"))
        self.doc("UNKNOWN", "new_adapter_class", "2026-10-08T11:40:00Z")
        report = self.report()
        self.assertEqual(report["configured_category_count"], 1)
        self.assertIn("new_adapter_class", report["skipped_categories"])
        self.assertEqual(report["observed_source_categories"], [])

    def test_backfill_failure_with_earlier_attempt_time_does_not_hide_behind_window_success(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-10-08T11:55:00Z','2026-10-08T11:56:00Z','success',1,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(2,'NVD','2026-10-08T11:50:00Z','2026-10-08T11:57:00Z','failed',0,'RuntimeError')")
        health = self.report()["freshness_by_source"]["NVD"]
        self.assertEqual(health["status"], "failed")
        self.assertFalse(health["healthy"])
        self.assertEqual(health["last_success_at"], "2026-10-08T11:56:00Z")

    def test_latest_success_with_unusable_finish_time_does_not_inherit_old_freshness(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-10-08T11:50:00Z','2026-10-08T11:51:00Z','success',1,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(2,'NVD','2026-10-08T11:55:00Z','unknown','success',1,NULL)")
        health = self.report()["freshness_by_source"]["NVD"]
        self.assertEqual(health["status"], "unknown")
        self.assertFalse(health["healthy"])
        self.assertIsNone(health["seconds_since_success"])

    def test_cve_summary_strict_fields_do_not_use_legacy_inclusive_six_hour_count(self):
        summary = cve_latency_summary([21599.999 / 3600, 6, 21600.001 / 3600])
        self.assertEqual(summary["under_6h"], 1)
        self.assertEqual(summary["breached_6h"], 2)
        self.assertEqual(summary["within_6h"], 2)  # Compatibility field has a different contract.

    def test_average_latency_does_not_mix_empty_sample_with_zero_delay(self):
        for summarize, values in ((cve_latency_summary, [0, 1, 5]),
                                  (source_latency_summary, [0, 3600, 18000])):
            self.assertEqual(summarize(values)["mean_hours"], 2)
            self.assertIsNone(summarize([])["mean_hours"])

    def test_full_week_attempt_history_reports_gap_and_failure_without_claiming_uptime(self):
        # A recorded run every 15 minutes over a week still cannot prove that a
        # process stayed up between runs or nobody intervened.
        boundary = NOW - timedelta(days=7)
        rows = []
        for index in range(673):
            started = boundary + timedelta(minutes=15 * index)
            if index == 672:
                finished = started
            else:
                finished = started + timedelta(seconds=10)
            rows.append((index + 1, "NVD", started.isoformat(), finished.isoformat(), "success", 0, None))
        self.con.executemany("INSERT INTO collector_runs VALUES(?,?,?,?,?,?,?)", rows)
        history = self.report()["recorded_polling_history_by_source"]["NVD"]
        self.assertTrue(history["has_seven_day_history"])
        self.assertEqual(history["cadence_evidence"], "recorded_attempts_within_limit")
        self.assertEqual(history["max_observed_gap_seconds"], 900)
        self.assertFalse(history["continuous_uptime_verified"])
        self.assertFalse(history["unattended_operation_verified"])
        self.con.execute("DELETE FROM collector_runs WHERE id BETWEEN 400 AND 402")
        self.con.execute("UPDATE collector_runs SET status='failed',error_text='HTTPError: HTTP 429' WHERE id=500")
        history = self.report()["recorded_polling_history_by_source"]["NVD"]
        self.assertEqual(history["recorded_failures"], 1)
        self.assertEqual(history["observed_gaps_over_limit"], 1)
        self.assertEqual(history["max_observed_gap_seconds"], 3600)
        self.assertEqual(history["cadence_evidence"], "observed_polling_gaps")
        self.assertIn("source_polling_gap", {a["code"] for a in self.report()["source_alerts"]})

    def test_old_attempt_anchors_week_boundary_but_future_or_invalid_run_does_not_prove_history(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-09-30T12:00:00Z','2026-09-30T12:01:00Z','success',0,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(2,'NVD','2026-10-08T11:50:00Z','2026-10-08T11:51:00Z','success',0,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(3,'NVD','2026-10-09T12:00:00Z','2026-10-09T12:01:00Z','success',0,NULL)")
        self.con.execute("INSERT INTO collector_runs VALUES(4,'NVD','2026-09-29T12:00:00Z','bad-time','success',0,NULL)")
        history = self.report()["recorded_polling_history_by_source"]["NVD"]
        self.assertEqual(history["invalid_run_timestamps"], 2)
        self.assertEqual(history["oldest_recorded_attempt_at"], "2026-09-30T12:00:00+00:00")
        self.assertEqual(history["max_observed_gap_seconds"], 7 * 86400 - 600)
        self.assertEqual(history["recorded_attempts"], 1)
        self.assertEqual(history["cadence_evidence"], "observed_polling_gaps")

    def test_latest_failed_validation_raises_actionable_alert_without_exposing_error_text(self):
        self.con.execute("INSERT INTO collector_runs VALUES(1,'NVD','2026-10-08T11:50:00Z','2026-10-08T11:51:00Z','failed',0,?)",
                         ("ValueError: credential=https://user:secret@example.org",))
        report = self.report()
        self.assertEqual(report["freshness_by_source"]["NVD"]["latest_error_category"], "validation_failure")
        self.assertIn("source_validation_failure", {a["code"] for a in report["source_alerts"]})
        self.assertNotIn("secret", json.dumps(report))
        self.assertEqual(report["recorded_polling_history_by_source"]["NVD"]["cadence_evidence"], "insufficient_history")

    def test_ai_latency_subset_excludes_unclassified_and_stale_verdicts(self):
        self.baseline()
        for index, published in enumerate(("2026-10-08T01:00:00Z", "2026-10-08T11:00:00Z", "2026-10-08T10:00:00Z")):
            identifier = f"CVE-2026-1000{index}"
            self.source_item(published, "2026-10-08T11:50:00Z", cve=identifier)
            self.con.execute("INSERT INTO unified_vulnerabilities VALUES(?, 'current')", (identifier,))
        self.con.execute("INSERT INTO ai_classifications VALUES('CVE-2026-10000','current','v1','classified',1)")
        self.con.execute("INSERT INTO ai_classifications VALUES('CVE-2026-10002','old','v1','classified',1)")
        report = self.report()
        self.assertEqual(report["live_precise_samples"], 3)
        self.assertEqual(report["ai_live_precise_samples"], 1)
        self.assertEqual(report["ai_violations_ge_6h"], 1)
        self.assertEqual(report["per_source_ai_live_latency"]["NVD"]["live"]["mean_hours"], 10.833333)
        self.assertEqual(report["ai_unknown_live_timing"], 0)

    def test_ai_document_latency_requires_current_completed_positive_verdict(self):
        self.specs = [SimpleNamespace(name="BLOG", category="security_blog")]
        self.baseline("BLOG", "security_blog")
        self.doc("BLOG", "security_blog", "2026-10-08T11:00:00Z")
        self.doc("BLOG", "security_blog", "2026-10-08T08:00:00Z", state="review")
        self.doc("BLOG", "security_blog", "2026-10-08T09:00:00Z", ai=False)
        report = self.report()
        self.assertEqual(report["ai_live_precise_samples"], 1)
        self.assertEqual(report["per_source_ai_live_latency"]["BLOG"]["live"]["mean_hours"], 0.833333)


if __name__ == "__main__":
    unittest.main()
