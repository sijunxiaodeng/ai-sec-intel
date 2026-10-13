"""Synthetic boundary tests, not independently labelled contest results."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate_observation import observation_report, quality_report

START = "2026-10-10T00:00:00Z"
END = "2026-10-11T00:00:00Z"
AS_OF = "2026-10-11T08:00:00Z"


class ObservationTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "observations.sqlite3"
        with sqlite3.connect(self.db) as con:
            con.executescript("""
              CREATE TABLE source_items(source,source_id,payload_json,first_seen_at);
              CREATE TABLE unified_vulnerabilities(cve_id,payload_json,first_seen_at);
              CREATE TABLE knowledge_documents(source,document_id,payload_json,published_at,first_seen_at);
            """)

    def record(self, identity, published, seen, source="NVD"):
        payload = json.dumps({"published_at": published, "publication_source": source, "sources": [source]})
        with sqlite3.connect(self.db) as con:
            con.execute("INSERT INTO source_items VALUES(?,?,?,?)", (source, identity, payload, seen))
            con.execute("INSERT INTO unified_vulnerabilities VALUES(?,?,?)", (identity, payload, seen))

    def report(self, **kwargs):
        return observation_report(self.db, start=START, end=END, as_of=AS_OF, **kwargs)

    def test_raw_second_boundary_distinguishes_user_and_contest(self):
        for identity, seen in (("under", "2026-10-10T05:59:59.999Z"),
                               ("equal", "2026-10-10T06:00:00Z"),
                               ("over", "2026-10-10T06:00:00.001Z")):
            self.record(identity, START, seen)
        for table in ("source_items", "unified_vulnerabilities"):
            window = self.report()["metrics"][table]["window"]
            self.assertEqual(window["strict_under_6h"], 1)
            self.assertEqual(window["contest_within_6h"], 2)
            self.assertEqual(window["strict_breaches_ge_6h"], 2)
            self.assertEqual(window["contest_breaches_gt_6h"], 1)

    def test_historical_breach_retained_and_late_ingestion_counts(self):
        self.record("old", "2026-10-09T00:00:00Z", "2026-10-10T01:00:00Z")
        self.record("late", "2026-10-10T23:00:00Z", "2026-10-11T07:00:00Z")
        self.record("exclusive-end", END, "2026-10-11T01:00:00Z")
        data = self.report()["metrics"]["unified_vulnerabilities"]
        self.assertEqual(data["window"]["samples"], 1)
        self.assertEqual(data["window"]["max_seconds"], 8 * 3600)
        self.assertEqual(data["historical_breaches"][0]["record_id"], "old")
        self.assertEqual(data["historical_backfill"]["samples"], 1)
        self.assertEqual(data["all_observed"]["samples"], 3)

    def test_imprecise_kev_future_and_negative_are_never_pass_samples(self):
        self.record("date", "2026-10-10", "2026-10-10T01:00:00Z")
        self.record("kev", START, "2026-10-10T01:00:00Z", "CISA_KEV")
        self.record("future", START, "2026-10-12T00:00:00Z")
        self.record("negative", START, "2026-10-09T23:00:00Z")
        self.record("offsetless-non-nvd", "2026-10-10T00:00:00", "2026-10-10T01:00:00Z", "BLOG")
        result = self.report()
        data = result["metrics"]["source_items"]
        self.assertEqual(data["window"]["samples"], 0)
        self.assertEqual(data["excluded"]["missing_or_imprecise_time"], 2)
        self.assertEqual(data["excluded"]["kev_listing_is_not_original_publication"], 1)
        self.assertIsNone(result["sla_verified"])

    def test_nvd_documented_utc_and_document_precise_time(self):
        self.record("nvd", "2026-10-10T00:00:00.000", "2026-10-10T01:00:00Z")
        with sqlite3.connect(self.db) as con:
            con.execute("INSERT INTO knowledge_documents VALUES(?,?,?,?,?)",
                        ("BLOG", "document-1", "{}", "2026-10-10T08:00:00+08:00", "2026-10-10T01:00:00Z"))
        self.assertEqual(self.report()["metrics"]["source_items"]["window"]["samples"], 1)
        self.assertEqual(self.report()["metrics"]["knowledge_documents"]["window"]["max_seconds"], 3600)

    def test_report_does_not_write_or_migrate_database(self):
        self.record("unchanged", START, "2026-10-10T01:00:00Z")
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        self.report()
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        with sqlite3.connect(self.db) as con:
            con.execute("DROP TABLE knowledge_documents")
        self.assertFalse(self.report()["metrics"]["knowledge_documents"]["available"])

    def test_malformed_payload_is_excluded_without_breaking_report(self):
        with sqlite3.connect(self.db) as con:
            con.execute("INSERT INTO source_items VALUES(?,?,?,?)", ("NVD", "broken", "[]", START))
            con.execute("INSERT INTO unified_vulnerabilities VALUES(?,?,?)",
                        ("bad-source", json.dumps({"publication_source": {}, "published_at": START}), START))
        reports = self.report()["metrics"]
        self.assertEqual(reports["source_items"]["excluded"]["invalid_payload"], 1)
        self.assertEqual(reports["unified_vulnerabilities"]["excluded"]["invalid_publication_source"], 1)

    def test_invalid_windows_and_missing_db_do_not_create_files(self):
        for start, end, as_of in ((END, START, AS_OF), (START, AS_OF, END), ("2026-10-10", END, AS_OF)):
            with self.assertRaises(ValueError):
                observation_report(self.db, start=start, end=end, as_of=as_of)
        missing = self.db.with_name("missing.sqlite3")
        with self.assertRaises(FileNotFoundError):
            observation_report(missing, start=START, end=END, as_of=AS_OF)
        self.assertFalse(missing.exists())

    def test_cli_new_report_only_and_no_unlabelled_accuracy(self):
        report_path = self.db.with_name("report.json")
        command = [sys.executable, str(ROOT / "scripts" / "evaluate_observation.py"),
                   "--db", str(self.db), "--start", START, "--end", END, "--as-of", AS_OF,
                   "--output", str(report_path)]
        done = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIsNone(json.loads(report_path.read_text())["quality"])
        before = report_path.read_bytes()
        duplicate = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(duplicate.returncode, 2)
        self.assertEqual(report_path.read_bytes(), before)


class QualityTest(unittest.TestCase):
    def labels(self):
        return {"schema_version": 1,
                "classification": [{"id": "tp", "expected": True, "predicted": True},
                                   {"id": "fp", "expected": False, "predicted": True},
                                   {"id": "fn", "expected": True, "predicted": False},
                                   {"id": "tn", "expected": False, "predicted": False}],
                "enrichment": [{"id": "record", "expected_facts": ["cvss=9.8", "kev=true"],
                                "predicted_facts": ["cvss=9.8", "epss=0.1"]}],
                "qa": [{"id": "q1", "correct": True, "citations_supported": True,
                        "latency_seconds": 5, "used_model": True},
                       {"id": "q2", "correct": False, "citations_supported": False,
                        "latency_seconds": 5.001, "used_model": False}]}

    def test_confusion_denominators_and_five_second_boundary(self):
        report = quality_report(self.labels())
        self.assertEqual(report["classification"]["precision"], .5)
        self.assertEqual(report["classification"]["recall"], .5)
        self.assertEqual(report["classification"]["accuracy"], .5)
        self.assertEqual(report["enrichment"]["precision"], .5)
        self.assertEqual(report["enrichment"]["recall"], .5)
        self.assertEqual(report["enrichment"]["exact_record_accuracy"], 0)
        self.assertEqual(report["qa"]["accuracy"], .5)
        self.assertEqual(report["qa"]["over_5_seconds"], 1)
        self.assertFalse(report["qa"]["all_responses_within_5_seconds"])

    def test_partial_labels_keep_headline_metrics_null(self):
        labels = self.labels()
        labels["classification"][0]["expected"] = None
        labels["enrichment"][0]["expected_facts"] = None
        labels["qa"][0].update(correct=None, citations_supported=None, latency_seconds=None)
        report = quality_report(labels)
        for key in ("precision", "recall", "accuracy"):
            self.assertIsNone(report["classification"][key])
        self.assertIsNone(report["enrichment"]["precision"])
        self.assertIsNone(report["qa"]["accuracy"])
        self.assertIsNone(report["qa"]["citation_support_rate"])
        self.assertIsNone(report["qa"]["all_responses_within_5_seconds"])
        self.assertIsNone(report["independence_verified"])

    def test_empty_samples_and_undefined_precision_are_null(self):
        report = quality_report({"schema_version": 1})
        self.assertIsNone(report["qa"]["accuracy"])
        self.assertIsNone(report["classification"]["precision"])
        labels = {"schema_version": 1, "classification": [{"id": "negative", "expected": False, "predicted": False}]}
        report = quality_report(labels)["classification"]
        self.assertIsNone(report["precision"])
        self.assertIsNone(report["recall"])
        self.assertEqual(report["accuracy"], 1)

    def test_invalid_truthiness_duplicates_and_latency_rejected(self):
        for section, key, value in (("classification", "expected", "true"),
                                    ("qa", "correct", 1), ("qa", "latency_seconds", float("nan")),
                                    ("qa", "latency_seconds", -1), ("qa", "latency_seconds", True),
                                    ("enrichment", "expected_facts", "fact")):
            labels = self.labels()
            labels[section][0][key] = value
            with self.assertRaises(ValueError):
                quality_report(labels)
        labels = self.labels()
        labels["qa"].append(deepcopy(labels["qa"][0]))
        with self.assertRaises(ValueError):
            quality_report(labels)


if __name__ == "__main__":
    unittest.main()
