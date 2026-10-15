"""Synthetic local observation tests; no upstream requests or model calls."""
from datetime import datetime, timedelta, timezone
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from acceptance import observation as obs
from acceptance import storage

START = datetime(2020, 1, 1, tzinfo=timezone.utc)


class ObservationWindowTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.acceptance = Path(temporary.name) / "acceptance.sqlite3"
        self.b = Path(temporary.name) / "intelligence.db"
        with closing(sqlite3.connect(self.b)) as con, con:
            con.executescript("""
              CREATE TABLE source_items(source TEXT,source_id TEXT,cve_id TEXT,payload_json TEXT,
                first_seen_at TEXT,content_updated_at TEXT,content_sha256 TEXT,PRIMARY KEY(source,source_id));
              CREATE TABLE knowledge_documents(source TEXT,document_id TEXT,payload_json TEXT,
                published_at TEXT,first_seen_at TEXT,content_updated_at TEXT,content_sha256 TEXT,url TEXT);
              CREATE TABLE collector_runs(id INTEGER PRIMARY KEY,collector TEXT,started_at TEXT,
                finished_at TEXT,status TEXT,fetched_count INTEGER,error_text TEXT);
              CREATE TABLE document_source_runs(id INTEGER PRIMARY KEY,source TEXT,source_category TEXT,
                started_at TEXT,finished_at TEXT,status TEXT,fetched_count INTEGER,error_text TEXT);
            """)
        self.window = self.create()

    def stamp(self, hours=0, seconds=0):
        return obs._iso(START + timedelta(hours=hours, seconds=seconds))

    def create(self, **payload):
        return obs.create_window({"name": "Synthetic observation", "sources": ["NVD"], **payload},
                                 db_path=self.acceptance, now=START)

    def record(self, identity="CVE-2020-1", publication=1, seen=2, source="NVD", cve=None,
               updated=None, payload_extra=None):
        publication = self.stamp(publication) if isinstance(publication, (int, float)) else publication
        seen = self.stamp(seen) if isinstance(seen, (int, float)) else seen
        updated = updated or seen
        payload = {"published_at": publication, "url": "https://example.test/item/" + identity, **(payload_extra or {})}
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("INSERT OR REPLACE INTO source_items VALUES(?,?,?,?,?,?,?)",
                        (source, identity, cve or identity, json.dumps(payload), seen, updated, storage.canonical_hash(payload)))

    def document(self, identity="doc-1", publication=1, seen=2, source="NVD"):
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("INSERT INTO knowledge_documents VALUES(?,?,?,?,?,?,?,?)",
                        (source, identity, "{}", self.stamp(publication), self.stamp(seen), self.stamp(seen), "a" * 64, "https://example.test/item/" + identity))

    def tick(self, hours, window=None):
        return obs.tick(db_path=self.acceptance, intelligence_db=self.b, now=START + timedelta(hours=hours))

    def get(self, hours, window=None):
        return obs.get_window((window or self.window)["id"], db_path=self.acceptance, now=START + timedelta(hours=hours))

    def inventory(self, items=None, **extra):
        return {"schema_version": 1, "source": "NVD", "scope": self.window["scope"],
                "captured_at": self.stamp(73), "coverage_start": self.stamp(), "coverage_end": self.stamp(72),
                "reference_url": "https://example.test/inventory", "response_sha256": "b" * 64,
                "completeness_declaration": True,
                "items": items if items is not None else [self.item("CVE-2020-1", 1)], **extra}

    def item(self, identity, publication, scope=True):
        return {"id": identity, "published_at": self.stamp(publication) if isinstance(publication, (int, float)) else publication,
                "url": "https://example.test/item/" + identity, "in_scope": scope}

    def import_list(self, payload, at=73):
        with patch.object(storage, "now_iso", return_value=self.stamp(at)):
            return obs.import_inventory(self.window["id"], payload, db_path=self.acceptance)

    def test_creation_freezes_server_policy_and_precise_utc(self):
        self.assertEqual(self.window["start_at"], self.stamp())
        self.assertEqual(self.window["end_at"], self.stamp(72))
        self.assertEqual(self.window["maturity_end_at"], self.stamp(96))
        self.assertEqual(self.window["threshold_hours"], [6, 12, 24])
        self.assertEqual(self.window["snapshots_count"], 0)
        self.assertIsNone(self.window["metrics"]["inventory"]["recall"])
        for payload in ({"start_at": self.stamp(-72)}, {"end_at": self.stamp()},
                        {"duration_hours": 0}, {"duration_hours": True}, {"maturity_hours": 25},
                        {"sources": "NVD"}, {"sources": ["NVD", "NVD"]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.create(**payload)

    def test_default_sources_are_server_resolved_and_frozen(self):
        with patch.object(obs, "_default_sources", return_value=["NVD", "BLOG"]):
            window = self.create(sources=[])
        self.assertEqual(window["sources"], ["BLOG", "NVD"])

    def test_tick_reads_real_sqlite_without_writing_production(self):
        self.record()
        before = hashlib.sha256(self.b.read_bytes()).hexdigest()
        self.tick(3)
        self.assertEqual(hashlib.sha256(self.b.read_bytes()).hexdigest(), before)
        report = self.get(3)
        self.assertEqual(report["metrics"]["observed"]["eligible_count"], 1)
        self.assertEqual(report["metrics"]["observed"]["latency"]["max_seconds"], 3600)
        self.assertIsNone(report["sla_verified"])

    def test_exact_six_hour_boundary_and_later_thresholds(self):
        self.record("equal", publication=1, seen=7)
        self.record("over", publication=1, seen=self.stamp(7, .001))
        self.record("thirteen", publication=1, seen=14)
        self.tick(15)
        counts = self.get(15)["metrics"]["observed"]["by_threshold"]
        self.assertEqual((counts["6"]["collected"], counts["6"]["late"]), (1, 2))
        self.assertEqual(counts["12"]["late"], 1)
        self.assertEqual(counts["24"]["collected"], 3)

    def test_no_inventory_never_turns_collected_subset_into_recall(self):
        self.record()
        self.tick(73)
        inv = self.get(73)["metrics"]["inventory"]
        self.assertIsNone(inv["recall"])
        self.assertFalse(inv["source_coverage_complete"])
        self.assertIsNone(inv["sla_verified"])

    def test_inventory_matching_missing_and_distinct_deadlines(self):
        self.record()
        self.tick(78)
        self.import_list(self.inventory([self.item("CVE-2020-1", 1), self.item("missing", 71)]), at=78)
        rows = self.get(78)["metrics"]["inventory"]["items"]
        self.assertEqual(rows[0]["thresholds"], {"6": "collected", "12": "collected", "24": "collected"})
        self.assertEqual(rows[1]["thresholds"], {"6": "missing", "12": "not_due", "24": "not_due"})
        self.tick(96)
        inv = self.get(96)["metrics"]["inventory"]
        self.assertEqual(inv["by_threshold"]["24"]["missing"], 1)
        self.assertEqual(inv["recall"], .5)
        self.assertFalse(inv["completeness_verified"])

    def test_all_unmatched_never_produce_zero_latency(self):
        self.tick(96)
        self.import_list(self.inventory([self.item("missing", 1)]), at=96)
        inv = self.get(96)["metrics"]["inventory"]
        self.assertEqual(inv["recall"], 0)
        self.assertEqual(inv["by_threshold"]["6"]["missing"], 1)
        self.assertIsNone(inv["latency"]["max_seconds"])
        self.assertEqual(inv["latency"]["samples"], 0)

    def test_inventory_is_once_per_source_even_identical_import(self):
        payload = self.inventory()
        self.import_list(payload)
        with self.assertRaisesRegex(ValueError, "cannot be replaced"):
            self.import_list(payload)
        with closing(sqlite3.connect(self.acceptance)) as con, con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM observation_inventories").fetchone()[0], 1)

    def test_inventory_validation_and_scope_alignment(self):
        variants = [
            {"source": "OTHER"}, {"scope": "not frozen scope"}, {"schema_version": True},
            {"captured_at": self.stamp(80)}, {"coverage_end": self.stamp(74)},
            {"coverage_start": self.stamp(-1)}, {"captured_at": "2020-01-04"},
            {"response_sha256": "bad"}, {"completeness_declaration": "yes"},
            {"items": [self.item("same", 1), self.item("same", 2)]},
            {"items": [self.item("CVE-2020-1", 1), self.item("cve-2020-1", 2)]},
            {"items": [self.item("outside", 72)]},
            {"items": [self.item("unknown", "not-a-date")]},
            {"items": [self.item("scope", 1, "true")]},
            {"reference_url": "file:///secret"},
        ]
        for extra in variants:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.import_list(self.inventory(**extra))

    def test_response_body_integrity_optional_and_never_origin_certification(self):
        body = '<feed><entry id="1" /></feed>'
        digest = hashlib.sha256(body.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.import_list(self.inventory(response_body=body))
        with self.assertRaisesRegex(ValueError, "4 MiB"):
            self.import_list(self.inventory(response_body="x" * (4 * 1024 * 1024 + 1)))
        result = self.import_list(self.inventory(response_body=body, response_sha256=digest))
        self.assertTrue(result["inventories"][0]["response_hash_verified"])
        self.assertFalse(result["inventories"][0]["completeness_verified"])

    def test_date_only_unknown_scope_and_out_of_scope_not_passes(self):
        self.tick(96)
        result = self.import_list(self.inventory([
            self.item("date", "2020-01-02"), self.item("unknown", 1, None), self.item("excluded", 1, False)
        ]), at=96)
        counts = result["metrics"]["inventory"]["by_threshold"]["6"]
        self.assertEqual((counts["unknown"], counts["excluded"], counts["denominator"]), (2, 1, 0))
        self.assertIsNone(result["metrics"]["inventory"]["recall"])

    def test_kev_and_preexisting_revisions_are_excluded_or_unknown(self):
        window = self.create(sources=["NVD", "CISA_KEV"])
        self.record("kev", 1, 2, source="CISA_KEV")
        self.record("revision", 1, seen=-1, updated=self.stamp(2))
        self.record("date", "2020-01-02", seen=2)
        self.tick(3)
        excluded = self.get(3, window)["metrics"]["observed"]["excluded"]
        self.assertEqual(excluded["kev_listing_is_not_original_publication"], 1)
        self.assertEqual(excluded["preexisting_first_seen_with_publication_revision"], 1)
        self.assertEqual(excluded["missing_or_imprecise_publication_time"], 1)

    def test_historical_records_keep_backfill_exclusion(self):
        self.record("backfill", publication=-24, seen=1)
        self.tick(2)
        result = self.get(2)["metrics"]["observed"]
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["excluded"]["outside_publication_window"], 1)
        self.assertIsNone(result["latency"]["max_seconds"])

    def test_document_id_and_unambiguous_cve_alias_matching(self):
        self.document("doc-1")
        self.record("GHSA-test", cve="CVE-2020-55")
        self.tick(96)
        alias_item = self.item("CVE-2020-55", 1)
        alias_item["url"] = "https://example.test/item/GHSA-test"
        result = self.import_list(self.inventory([self.item("doc-1", 1), alias_item]), at=96)
        self.assertEqual(result["metrics"]["inventory"]["by_threshold"]["6"]["collected"], 2)

    def test_native_id_and_cve_alias_cannot_score_same_record_twice(self):
        self.record("GHSA-test", cve="CVE-2020-55")
        self.tick(96)
        result = self.import_list(self.inventory([self.item("CVE-2020-55", 1), self.item("GHSA-test", 1)]), at=96)
        inv = result["metrics"]["inventory"]
        self.assertEqual(inv["by_threshold"]["6"]["collected"], 1)
        self.assertEqual(inv["by_threshold"]["6"]["unknown"], 1)
        self.assertIsNone(inv["recall"])

    def test_ambiguous_cve_alias_is_unknown(self):
        self.record("GHSA-a", cve="CVE-2020-55")
        self.record("GHSA-b", cve="CVE-2020-55")
        self.tick(96)
        result = self.import_list(self.inventory([self.item("CVE-2020-55", 1)]), at=96)
        self.assertEqual(result["metrics"]["inventory"]["items"][0]["reason"], "ambiguous_identity")

    def test_append_only_compact_versions_and_hash_linked_snapshots(self):
        self.record(payload_extra={"large_raw_body": "a" * 1000000})
        self.tick(3)
        self.tick(4)
        self.record(updated=self.stamp(5), payload_extra={"changed": True})
        self.tick(5)
        with closing(sqlite3.connect(self.acceptance)) as con, con:
            rows = con.execute("SELECT content_json FROM observation_records ORDER BY id").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertLess(sum(len(r[0]) for r in rows), 3000)
            snapshots = con.execute("SELECT content_json,sha256 FROM observation_snapshots ORDER BY id").fetchall()
        self.assertEqual(len(snapshots), 3)
        self.assertEqual(json.loads(snapshots[1][0])["record_versions"], [])
        self.assertEqual(json.loads(snapshots[2][0])["previous_sha256"], snapshots[1][1])
        self.assertEqual(json.loads(rows[0][0])["first_seen_at"], self.stamp(2))

    def test_same_tick_is_idempotent_and_clock_reversal_not_written(self):
        self.record()
        self.tick(3)
        self.tick(3)
        self.tick(2)
        self.assertEqual(self.get(3)["snapshots_count"], 1)
        with self.assertRaisesRegex(ValueError, "clock precedes"):
            self.get(2)

    def test_return_to_previous_record_content_keeps_new_observation_version(self):
        self.record(updated=self.stamp(3), payload_extra={"revision": "a"})
        self.tick(3)
        self.record(updated=self.stamp(4), payload_extra={"revision": "b"})
        self.tick(4)
        # Timestamp also belongs to the compact evidence; explicitly exercise
        # equal content with an immutable version returning after an intervening one.
        with storage.connect(self.acceptance) as con:
            rows = list(con.execute("SELECT content_json FROM observation_records ORDER BY id"))
            first = json.loads(rows[0][0])
            ids = obs._save_versions(con, "observation_records", self.window["id"], [first], self.stamp(5))
            self.assertEqual(len(ids), 1)
            latest = obs._latest_versions(con, "observation_records", self.window["id"])
            self.assertEqual(json.loads(latest[0]["content_json"]), first)

    def test_restart_resumes_and_shutdown_gap_is_not_success(self):
        self.record()
        self.tick(3)
        self.tick(10)
        report = self.get(10)
        self.assertEqual(report["coverage"]["heartbeat_max_gap_seconds"], 7 * 3600)
        self.assertGreater(report["coverage"]["missing_heartbeat_intervals"], 400)
        self.assertEqual(report["coverage"]["source_run_history"][0]["success"], 0)
        self.assertEqual(report["coverage"]["source_run_history"][0]["latest_status"], "unknown")

    def test_database_failure_is_durable_and_does_not_invent_later_absence(self):
        self.tick(73)
        self.import_list(self.inventory([self.item("missing", 71)]))
        obs.tick(db_path=self.acceptance, intelligence_db=self.b.with_name("missing.db"), now=START + timedelta(hours=96))
        report = self.get(96)
        self.assertEqual(report["coverage"]["database_failures"], 1)
        self.assertEqual(report["coverage"]["latest_database_status"], "failed")
        self.assertEqual(report["evidence_as_of"], self.stamp(73))
        self.assertEqual(report["metrics"]["inventory"]["items"][0]["thresholds"]["6"], "not_due")
        with self.assertRaises(ValueError):
            obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=96))

    def test_runs_keep_failure_partial_and_sampling_is_not_run_frequency(self):
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("INSERT INTO collector_runs VALUES(1,'NVD',?,?,'failed',0,'HTTP 429')", (self.stamp(1), self.stamp(2)))
            con.execute("INSERT INTO document_source_runs VALUES(1,'NVD','academic_paper',?,?,'partial',10,'page changed')", (self.stamp(2), self.stamp(3)))
        self.tick(4)
        self.tick(4 + 1 / 60)
        coverage = self.get(4 + 1 / 60)["coverage"]
        history = coverage["source_run_history"][0]
        self.assertEqual((history["runs"], history["failed"], history["partial"]), (2, 1, 1))
        self.assertEqual(history["latest_status"], "partial")
        self.assertEqual(coverage["snapshot_interval_seconds"], 60)

    def test_freeze_refuses_future_empty_and_stale_evidence(self):
        with self.assertRaisesRegex(ValueError, "72-hour"):
            obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=1))
        self.tick(73)
        with self.assertRaisesRegex(ValueError, "Empty"):
            obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=73))
        self.record()
        self.tick(74)
        # Record's old update time cannot be invented as a newly seen row.
        with self.assertRaisesRegex(ValueError, "stale"):
            obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=75))

    def test_freeze_retains_not_due_and_is_immutable_after_b_changes(self):
        self.record("CVE-2020-1", publication=71, seen=72)
        self.tick(73)
        self.import_list(self.inventory([self.item("CVE-2020-1", 71), self.item("missing", 71)]))
        frozen = obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=73))
        self.assertEqual(frozen["metrics"]["inventory"]["items"][1]["thresholds"]["24"], "not_due")
        self.assertIsNone(frozen["metrics"]["inventory"]["recall"])
        self.assertEqual(storage.canonical_hash(frozen["frozen_report"]), frozen["frozen_sha256"])
        self.record("missing", publication=71, seen=74)
        self.tick(74)
        later = self.get(100)
        self.assertEqual(later["frozen_sha256"], frozen["frozen_sha256"])
        self.assertEqual(later["metrics"], frozen["metrics"])
        with self.assertRaises(ValueError):
            obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=100))
        with self.assertRaises(ValueError):
            self.import_list(self.inventory(), at=100)

    def test_maximum_maturity_stops_sampling_and_late_wakeup_is_explicit(self):
        self.record()
        self.tick(97)
        self.tick(98)
        report = self.get(98)
        self.assertEqual(report["snapshots_count"], 1)
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["evidence_as_of"], self.stamp(97))
        self.assertEqual(report["coverage"]["late_capture_seconds"], 3600)
        frozen = obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=98))
        self.assertEqual(frozen["evidence_as_of"], self.stamp(97))
        self.assertEqual(frozen["frozen_at"], self.stamp(98))

    def test_freeze_detects_changed_snapshot_or_record_versions(self):
        self.record()
        self.tick(73)
        with closing(sqlite3.connect(self.acceptance)) as con, con:
            con.execute("UPDATE observation_records SET content_json=json_set(content_json,'$.source_content_sha256','tampered')")
        with self.assertRaisesRegex(ValueError, "integrity"):
            obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=73))

    def test_frozen_report_integrity_is_rechecked_on_read(self):
        self.record()
        self.tick(73)
        obs.freeze_window(self.window["id"], db_path=self.acceptance, now=START + timedelta(hours=73))
        with closing(sqlite3.connect(self.acceptance)) as con, con:
            con.execute("UPDATE observation_windows SET frozen_json='{}'")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.get(74)

    def test_partial_inventory_cannot_claim_whole_window_recall(self):
        self.record()
        self.tick(96)
        result = self.import_list(self.inventory(coverage_end=self.stamp(48)), at=96)
        self.assertFalse(result["metrics"]["inventory"]["source_coverage_complete"])
        self.assertIsNone(result["metrics"]["inventory"]["recall"])

    def test_inventory_cannot_override_original_publication_to_improve_latency(self):
        self.record(publication=1, seen=10)
        self.tick(96)
        result = self.import_list(self.inventory([self.item("CVE-2020-1", 9)]), at=96)
        self.assertEqual(result["metrics"]["observed"]["by_threshold"]["6"]["late"], 1)
        case = result["metrics"]["inventory"]["items"][0]
        self.assertEqual(case["reason"], "source_publication_time_conflict")
        self.assertEqual(case["source_published_at"], self.stamp(1))
        self.assertEqual(case["thresholds"]["6"], "unknown")
        self.assertIsNone(result["metrics"]["inventory"]["recall"])

    def test_equivalent_timezones_do_not_create_publication_conflict(self):
        self.record(publication=1, seen=2)
        self.tick(96)
        result = self.import_list(self.inventory([self.item("CVE-2020-1", "2020-01-01T09:00:00+08:00")]), at=96)
        self.assertEqual(result["metrics"]["inventory"]["by_threshold"]["6"]["collected"], 1)

    def test_exact_id_with_conflicting_url_is_not_credited(self):
        self.record()
        self.tick(96)
        item = self.item("CVE-2020-1", 1)
        item["url"] = "https://example.test/different-article"
        result = self.import_list(self.inventory([item]), at=96)
        self.assertEqual(result["metrics"]["inventory"]["items"][0]["reason"], "source_url_conflict")

    def test_real_hashed_document_identity_matches_upstream_id_and_url(self):
        self.window = self.create(sources=["ARXIV_AI_SECURITY"])
        upstream = "http://arxiv.org/abs/2410.00001v1"
        hashed = "doc-" + hashlib.sha256(("ARXIV_AI_SECURITY\0" + upstream).encode()).hexdigest()
        self.document(hashed, source="ARXIV_AI_SECURITY")
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("UPDATE knowledge_documents SET url=?", (upstream,))
        self.tick(96)
        item = self.item(upstream, 1)
        item["url"] = upstream
        result = self.import_list(self.inventory([item], source="ARXIV_AI_SECURITY"), at=96)
        self.assertEqual(result["metrics"]["inventory"]["by_threshold"]["6"]["collected"], 1)
        self.assertIn(hashed, result["metrics"]["inventory"]["items"][0]["matched_record_key"])

    def test_unhashed_upstream_arxiv_id_can_match_exact_unique_url(self):
        self.window = self.create(sources=["ARXIV_AI_SECURITY"])
        upstream = "http://arxiv.org/abs/2410.00001v1"
        hashed = "doc-" + hashlib.sha256(("ARXIV_AI_SECURITY\0" + upstream).encode()).hexdigest()
        self.document(hashed, source="ARXIV_AI_SECURITY")
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("UPDATE knowledge_documents SET url=?", (upstream,))
        self.tick(96)
        item = self.item("2410.00001", 1)
        item["url"] = upstream
        result = self.import_list(self.inventory([item], source="ARXIV_AI_SECURITY"), at=96)
        self.assertEqual(result["metrics"]["inventory"]["by_threshold"]["6"]["collected"], 1)

    def test_osv_composite_id_matches_explicit_raw_upstream_advisory(self):
        self.window = self.create(sources=["OSV"])
        self.record("GHSA-test:CVE-2020-1", source="OSV", cve="CVE-2020-1",
                    payload_extra={"url": "https://osv.dev/vulnerability/GHSA-test", "raw_data": {"id": "GHSA-test"}})
        self.tick(96)
        item = self.item("GHSA-test", 1)
        item["url"] = "https://osv.dev/vulnerability/GHSA-test"
        result = self.import_list(self.inventory([item], source="OSV"), at=96)
        self.assertEqual(result["metrics"]["inventory"]["by_threshold"]["6"]["collected"], 1)

    def test_osv_raw_and_document_materializations_cannot_double_score(self):
        ghsa, cve = "GHSA-demo-aaaa-bbbb", "CVE-2020-1234"
        composite = ghsa + ":" + cve
        hashed = "doc-" + hashlib.sha256(("OSV\0" + ghsa).encode()).hexdigest()
        url = "https://osv.dev/vulnerability/" + ghsa
        self.record(composite, source="OSV", cve=cve, seen=2,
                    payload_extra={"url": url, "raw_data": {"id": ghsa}})
        self.document(hashed, source="OSV", seen=10)
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("UPDATE knowledge_documents SET url=?,payload_json=?",
                        (url, json.dumps({"raw_data": {"advisory": {"id": ghsa}}})))
        for order in ((ghsa, composite), (composite, ghsa)):
            with self.subTest(order=order):
                self.window = self.create(sources=["OSV"])
                self.tick(96)
                items = [{**self.item(identity, 1), "url": url} for identity in order]
                metrics = self.import_list(self.inventory(items, source="OSV"), at=96)["metrics"]["inventory"]
                for hours in ("6", "12", "24"):
                    self.assertEqual(metrics["by_threshold"][hours]["unknown"], 2)
                    self.assertEqual(metrics["by_threshold"][hours]["denominator"], 0)
                    self.assertIsNone(metrics["by_threshold"][hours]["within_rate"])
                self.assertIsNone(metrics["recall"])
                self.assertEqual(metrics["latency"]["samples"], 0)
                self.assertEqual({item["reason"] for item in metrics["items"]}, {"duplicate_upstream_identity"})

    def test_duplicate_upstream_id_is_unknown_even_when_materialized_urls_differ(self):
        self.window = self.create(sources=["OSV"])
        upstream = "GHSA-shared-advisory"
        identities = (upstream + ":CVE-2020-1", upstream + ":CVE-2020-2")
        for identity in identities:
            self.record(identity, source="OSV", payload_extra={"raw_data": {"id": upstream}})
        self.tick(96)
        metrics = self.import_list(self.inventory([self.item(i, 1) for i in identities], source="OSV"), at=96)["metrics"]["inventory"]
        self.assertEqual(metrics["by_threshold"]["6"]["unknown"], 2)
        self.assertEqual(metrics["by_threshold"]["6"]["denominator"], 0)
        self.assertIsNone(metrics["recall"])
        self.assertEqual({item["reason"] for item in metrics["items"]}, {"duplicate_upstream_identity"})

    def test_absent_record_table_cannot_prove_missing_item(self):
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("DROP TABLE source_items")
        self.tick(96)
        result = self.import_list(self.inventory(), at=96)
        self.assertEqual(result["metrics"]["inventory"]["by_threshold"]["6"]["unknown"], 1)
        self.assertIsNone(result["metrics"]["inventory"]["recall"])

    def test_initial_and_changed_deployment_commits_are_both_visible(self):
        with patch.object(obs, "_source_commit", return_value="a" * 40):
            self.window = self.create()
        with patch.object(obs, "_source_commit", return_value="b" * 40):
            self.tick(1)
        result = self.get(1)
        self.assertEqual(result["source_commit"], "a" * 40)
        self.assertEqual(result["versions_seen"], ["a" * 40, "b" * 40])

    def test_absent_document_table_cannot_prove_missing_paper(self):
        self.window = self.create(sources=["ARXIV_AI_SECURITY"])
        with closing(sqlite3.connect(self.b)) as con, con:
            con.execute("DROP TABLE knowledge_documents")
        self.tick(96)
        result = self.import_list(self.inventory(source="ARXIV_AI_SECURITY"), at=96)
        item = result["metrics"]["inventory"]["items"][0]
        self.assertEqual(item["thresholds"]["6"], "unknown")
        self.assertEqual(item["reason"], "source_record_snapshot_unavailable")
        self.assertIsNone(result["metrics"]["inventory"]["recall"])

    def test_observed_detail_preserves_timing_evidence(self):
        self.record()
        self.tick(3)
        item = self.get(3)["metrics"]["observed"]["items"][0]
        self.assertEqual(item["published_at"], self.stamp(1))
        self.assertEqual(item["first_seen_at"], self.stamp(2))
        self.assertEqual(item["delay_seconds"], 3600)
        self.assertTrue(item["record_key"].startswith("source_items:NVD:"))

    def test_modified_configuration_and_inventory_hashes_are_rejected(self):
        self.import_list(self.inventory())
        with closing(sqlite3.connect(self.acceptance)) as con, con:
            con.execute("UPDATE observation_inventories SET content_json=json_set(content_json,'$.completeness_declaration',0)")
        with self.assertRaisesRegex(ValueError, "Inventory integrity"):
            self.get(73)
        with closing(sqlite3.connect(self.acceptance)) as con, con:
            con.execute("UPDATE observation_windows SET config_json=json_set(config_json,'$.name','changed')")
        with self.assertRaisesRegex(ValueError, "configuration integrity"):
            self.get(73)

    def test_missing_second_source_inventory_cannot_claim_overall_recall(self):
        self.window = self.create(sources=["NVD", "BLOG"])
        self.record()
        self.tick(96)
        result = self.import_list(self.inventory(), at=96)
        self.assertFalse(result["metrics"]["inventory"]["source_coverage_complete"])
        self.assertIsNone(result["metrics"]["inventory"]["recall"])


if __name__ == "__main__":
    unittest.main()
