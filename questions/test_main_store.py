"""Regression checks for migration, field updates and concurrent main writers."""

import copy
from concurrent.futures import ProcessPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database import store


def _configure_paths(directory):
    root = Path(directory)
    store.DATA = root
    store.DB_PATH = root / "knowledge.sqlite3"
    store.KB_PATH = root / "knowledge.json"
    store.CARDS_PATH = root / "cards.json"
    store.CARDS_JS_PATH = root / "cards.js"
    store.SEED_CARDS_PATH = root / "seed.json"
    store.RUNS_PATH = root / "runs.json"


def _record(cve_id="CVE-2026-12345", *, updated="2026-10-10T01:00:00Z", source="NVD", description="Original facts", score=8.0):
    return {"item": {"cve_id": cve_id, "source": source, "title": "A real vulnerability",
                     "description": description, "published_at": "2026-10-09T23:00:00Z",
                     "collected_at": "2026-10-10T00:00:00Z", "affected": ["example < 1.0"],
                     "raw_data": {"content_updated_at": updated, "cvss_source": source}},
            "cvss": {"score": score, "version": "3.1", "source": source},
            "epss": {"status": "error"}, "kev": {"status": "not_listed"}}


def _concurrent_writer(directory, worker):
    _configure_paths(directory)
    os.environ["MAIN_KB_DB_PATH"] = str(store.DB_PATH)
    os.environ["MAIN_IMPORT_DEMO_CARDS"] = "0"
    for number in range(10):
        row = _record("CVE-2026-%05d" % (20000 + worker * 10 + number))
        store.upsert([row])
        shared = _record("CVE-2026-99999")
        shared["references"] = ["https://example.com/worker/%d/%d" % (worker, number)]
        store.upsert([shared])
    return worker


class MainStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        constants = {key: self.root / name for key, name in {
            "DB_PATH": "knowledge.sqlite3", "KB_PATH": "knowledge.json",
            "SEED_CARDS_PATH": "seed.json", "CARDS_PATH": "cards.json",
            "CARDS_JS_PATH": "cards.js", "RUNS_PATH": "runs.json"}.items()}
        constants["DATA"] = self.root
        binding = patch.multiple(store, **constants)
        binding.start()
        self.addCleanup(binding.stop)
        environment = patch.dict(os.environ, {"MAIN_KB_DB_PATH": str(constants["DB_PATH"]), "MAIN_IMPORT_DEMO_CARDS": "0"})
        environment.start()
        self.addCleanup(environment.stop)

    def sql(self, statement):
        with sqlite3.connect(store.database_path()) as con:
            return con.execute(statement).fetchall()

    def test_legacy_migration_runs_once_and_preserves_first_seen(self):
        row = _record()
        row["item"]["collected_at"] = "2026-10-01T12:00:00+08:00"
        original = json.dumps([row], ensure_ascii=False)
        store.KB_PATH.write_text(original, encoding="utf-8")
        store.RUNS_PATH.write_text(json.dumps([{"kind": "newest", "steps": []}, {"kind": "older", "steps": []}]), encoding="utf-8")
        self.assertEqual(store.load_kb()[0]["item"]["collected_at"], row["item"]["collected_at"])
        self.assertEqual(store.latest_run()["kind"], "newest")
        self.assertEqual(store.KB_PATH.read_text(encoding="utf-8"), original)
        store.KB_PATH.write_text("[]", encoding="utf-8")
        self.assertEqual(len(store.load_kb()), 1)
        self.assertEqual(self.sql("SELECT count(*) FROM knowledge_revisions")[0][0], 1)

    def test_empty_database_does_not_implicitly_import_demo(self):
        store.SEED_CARDS_PATH.write_text(json.dumps([_record()]), encoding="utf-8")
        self.assertEqual(store.load_kb(), [])
        self.assertFalse(store.CARDS_PATH.exists())

    def test_demo_import_requires_opt_in_and_runtime_exports_do_not_touch_seed(self):
        seed = json.dumps([_record()])
        store.SEED_CARDS_PATH.write_text(seed, encoding="utf-8")
        with patch.dict(os.environ, {"MAIN_IMPORT_DEMO_CARDS": "1"}):
            self.assertEqual(len(store.load_kb()), 1)
        store.upsert([_record(description="Updated")])
        self.assertEqual(store.SEED_CARDS_PATH.read_text(encoding="utf-8"), seed)
        self.assertTrue(store.CARDS_PATH.exists())
        self.assertTrue(store.CARDS_JS_PATH.read_text(encoding="utf-8").startswith("window.CARDS = "))

    def test_corrupt_legacy_data_is_reported_without_demo_fallback(self):
        store.KB_PATH.write_text("broken json", encoding="utf-8")
        store.SEED_CARDS_PATH.write_text(json.dumps([_record()]), encoding="utf-8")
        with patch.dict(os.environ, {"MAIN_IMPORT_DEMO_CARDS": "1"}), self.assertRaises(ValueError):
            store.load_kb()

    def test_new_success_replaces_error_and_new_kev_membership_updates(self):
        store.upsert([_record()])
        changed = _record(updated="2026-10-10T03:00:00Z")
        changed["epss"] = {"status": "ok", "score": "0.42", "date": "2026-10-10"}
        changed["kev"] = {"status": "listed", "date_added": "2026-10-10"}
        store.upsert([changed])
        found = store.get_record(changed["item"]["cve_id"])
        self.assertEqual(found["epss"]["score"], "0.42")
        self.assertEqual(found["kev"]["status"], "listed")
        failed = _record(updated="2026-10-10T04:00:00Z")
        failed["kev"] = {"status": "error"}
        store.upsert([failed])
        self.assertEqual(store.load_kb()[0]["epss"]["score"], "0.42")
        self.assertEqual(store.load_kb()[0]["kev"]["status"], "listed")

    def test_newer_authoritative_cvss_can_decrease_and_business_fields_update(self):
        store.upsert([_record(score=9.8, description="Old long description with withdrawn conditions")])
        corrected = _record(updated="2026-10-10T03:00:00+00:00", description="Corrected", score=7.0)
        corrected["item"]["affected"] = ["example < 0.9"]
        corrected["item"]["collected_at"] = "2026-10-10T04:00:00Z"
        store.upsert([corrected])
        result = store.load_kb()[0]
        self.assertEqual(result["cvss"]["score"], 7.0)
        self.assertEqual(result["item"]["description"], "Corrected")
        self.assertEqual(result["item"]["affected"], ["example < 0.9"])
        self.assertEqual(result["item"]["collected_at"], "2026-10-10T00:00:00Z")
        self.assertEqual(result["item"]["raw_data"]["cvss_score"], 7.0)

    def test_stale_or_low_authority_updates_do_not_replace_current_facts(self):
        store.upsert([_record(updated="2026-10-10T04:00:00Z", score=7.0)])
        store.upsert([_record(updated="2026-10-10T02:00:00Z", description="Stale", score=9.8)])
        store.upsert([_record(updated="2026-10-10T06:00:00Z", source="BLOG", description="Unverified copy", score=10.0)])
        row = store.load_kb()[0]
        self.assertEqual(row["cvss"]["score"], 7.0)
        self.assertEqual(row["item"]["description"], "Original facts")
        self.assertEqual(set(row["item"]["sources"]), {"NVD", "BLOG"})

    def test_explicit_source_update_is_not_blocked_by_later_legacy_migration_time(self):
        legacy = _record(score=1.0)
        legacy["item"]["raw_data"].pop("content_updated_at")
        store.KB_PATH.write_text(json.dumps([legacy]), encoding="utf-8")
        store.load_kb()
        store.upsert([_record(updated="2026-10-10T02:00:00Z", score=9.0)])
        self.assertEqual(store.load_kb()[0]["cvss"]["score"], 9.0)

    def test_stale_reader_snapshot_cannot_erase_concurrent_records_or_new_fields(self):
        store.upsert([_record()])
        stale = store.load_kb()
        store.upsert([_record(updated="2026-10-10T04:00:00Z", description="Current"), _record("CVE-2026-67890")])
        store.save_kb(stale)
        self.assertEqual(len(store.load_kb()), 2)
        self.assertEqual(store.get_record("CVE-2026-12345")["item"]["description"], "Current")

    def test_unchanged_observations_do_not_grow_revision_history(self):
        row = _record()
        store.upsert([row])
        before = self.sql("SELECT count(*) FROM knowledge_revisions")[0][0]
        store.upsert([copy.deepcopy(row)])
        self.assertEqual(self.sql("SELECT count(*) FROM knowledge_revisions")[0][0], before)

    def test_concurrent_processes_preserve_every_record_and_shared_reference(self):
        store.load_kb()  # Also test competing writer transactions, not just migration.
        with ProcessPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(_concurrent_writer, [self.temp.name] * 6, range(6)))
        self.assertEqual(len(results), 6)
        self.assertEqual(len(store.load_kb()), 61)
        shared = store.get_record("CVE-2026-99999")
        self.assertEqual(len(shared["references"]), 60)
        self.assertEqual(self.sql("PRAGMA journal_mode")[0][0], "wal")
        self.assertEqual(self.sql("PRAGMA integrity_check")[0][0], "ok")

    def test_sync_commit_is_atomic_and_failure_keeps_old_cursor(self):
        store.set_sync_cursor("B", {"seq": 1})
        with patch.object(store, "export_cards", side_effect=OSError("export failure")), self.assertRaises(OSError):
            store.apply_sync_page([_record()], source="B", cursor={"seq": 2})
        self.assertEqual(store.get_sync_cursor("B"), {"seq": 1})
        self.assertEqual(store.load_kb(), [])
        store.apply_sync_page([_record()], source="B", cursor={"seq": 2})
        self.assertEqual(store.get_sync_cursor("B"), {"seq": 2})
        self.assertEqual(len(store.load_kb()), 1)

    def test_scope_retraction_retains_history_and_valid_upsert_restores(self):
        store.upsert([_record()])
        self.assertEqual(store.retract(["CVE-2026-12345"]), 1)
        self.assertIsNone(store.get_record("CVE-2026-12345"))
        self.assertEqual(store.load_kb(), [])
        archived = store.get_record("CVE-2026-12345", include_out_of_scope=True)
        self.assertFalse(archived["item"]["raw_data"]["_store"]["in_scope"])
        store.upsert([_record(updated="2026-10-10T04:00:00Z")])
        self.assertEqual(len(store.load_kb()), 1)
        self.assertEqual(self.sql("SELECT event FROM knowledge_revisions ORDER BY id"), [("upsert",), ("retract",), ("upsert",)])

    def test_feed_reset_retracts_only_absent_records_owned_by_that_feed(self):
        store.upsert([_record("CVE-2026-11111")])
        store.apply_sync_page([_record(), _record("CVE-2026-22222")], source="B", cursor={"epoch": "old", "seq": 20, "base_url": "http://b-api:8765"})
        store.apply_sync_page([_record()], source="B", cursor={"epoch": "new", "seq": 1, "base_url": "http://b-api:8765", "reset": True})
        self.assertEqual({row["item"]["cve_id"] for row in store.load_kb()}, {"CVE-2026-11111", "CVE-2026-12345"})
        self.assertIsNotNone(store.get_record("CVE-2026-22222", include_out_of_scope=True))

    def test_stale_feed_cycle_cannot_regress_cursor_or_retract_new_records(self):
        store.apply_sync_page([_record(), _record("CVE-2026-22222")], source="B", cursor={"epoch": "same", "seq": 20})
        with self.assertRaises(store.StaleSyncPage):
            store.apply_sync_page([_record()], source="B", cursor={"epoch": "same", "seq": 10})
        self.assertEqual(store.get_sync_cursor("B"), {"epoch": "same", "seq": 20})
        self.assertEqual(len(store.load_kb()), 2)

    def test_feed_cas_rejects_competing_snapshot_and_persists_no_transient_keys(self):
        old = {"epoch": "same", "seq": 20, "base_url": "http://b-api:8765"}
        store.apply_sync_page([_record()], source="B", cursor=old)
        new = dict(old, seq=30, expected_cursor=old)
        store.apply_sync_page([_record(), _record("CVE-2026-22222")], source="B", cursor=new)
        with self.assertRaises(store.StaleSyncPage):
            store.apply_sync_page([], source="B", cursor=dict(old, epoch="restored", seq=1, reset=True, expected_cursor=old))
        current = {"epoch": "same", "seq": 30, "base_url": "http://b-api:8765"}
        self.assertEqual(store.get_sync_cursor("B"), current)
        self.assertEqual(len(store.load_kb()), 2)
        store.apply_sync_page([_record()], source="B", cursor=dict(old, epoch="restored", seq=1, reset=True, expected_cursor=current))
        self.assertEqual(store.get_sync_cursor("B"), dict(old, epoch="restored", seq=1))
        self.assertEqual(len(store.load_kb()), 1)

    def test_run_history_is_transactional_and_not_truncated_at_twenty(self):
        for number in range(25):
            store.append_run([{"number": number}], "collect")
        self.assertEqual(self.sql("SELECT count(*) FROM knowledge_runs")[0][0], 25)
        self.assertEqual(store.latest_run()["steps"], [{"number": 24}])
        self.assertTrue(store.latest_run()["run_id"])

    def test_withdrawal_without_main_record_is_persistent_and_new_acceptance_clears_it(self):
        self.assertEqual(store.retract(["CVE-2026-12345"]), 1)
        self.assertEqual(store.retracted_ids(), {"CVE-2026-12345"})
        self.assertEqual(store.retract(["CVE-2026-12345"]), 0)
        self.assertEqual(self.sql("SELECT event FROM knowledge_revisions"), [("retract",)])
        store.upsert([_record()])
        self.assertEqual(store.retracted_ids(), set())
        self.assertEqual(len(store.load_kb()), 1)

    def test_enrichment_cas_cannot_reactivate_withdrawn_record(self):
        store.upsert([_record()])
        snapshot = store.load_kb()[0]
        expected = {"CVE-2026-12345": store.source_revision(snapshot)}
        snapshot["epss"] = {"status": "ok", "score": .7}
        store.retract(["CVE-2026-12345"])
        self.assertEqual(store.apply_enrichment([snapshot], expected), [])
        self.assertEqual(store.load_kb(), [])
        self.assertEqual(store.retracted_ids(), {"CVE-2026-12345"})

    def test_enrichment_cas_rejects_old_source_and_never_modifies_upstream_item(self):
        store.upsert([_record()])
        snapshot = store.load_kb()[0]
        expected = {"CVE-2026-12345": store.source_revision(snapshot)}
        result = copy.deepcopy(snapshot)
        result["item"]["title"] = "Untrusted derived title"
        result["item"]["raw_data"]["classification"] = {"is_ai_related": False}
        result["item"]["raw_data"]["automatic_assessment"] = {"status": "confirmed"}
        result["epss"] = {"status": "ok", "score": .5}
        self.assertEqual(store.apply_enrichment([result], expected), ["CVE-2026-12345"])
        accepted = store.load_kb()[0]
        self.assertEqual(accepted["item"]["title"], snapshot["item"]["title"])
        self.assertNotIn("classification", accepted["item"]["raw_data"])
        self.assertEqual(accepted["item"]["raw_data"]["automatic_assessment"]["status"], "confirmed")
        self.assertEqual(store.source_revision(accepted), expected["CVE-2026-12345"])
        store.upsert([_record(updated="2026-10-10T04:00:00Z", description="New source facts")])
        self.assertEqual(store.apply_enrichment([result], expected), [])

    def test_enrichment_worker_must_own_current_unexpired_lease(self):
        import time
        store.upsert([_record()])
        snapshot = store.load_kb()[0]
        expected = {"CVE-2026-12345": store.source_revision(snapshot)}
        snapshot["epss"] = {"status": "ok", "score": .5}
        with sqlite3.connect(store.database_path()) as con:
            con.execute("CREATE TABLE processing_jobs (id INTEGER PRIMARY KEY,cve_id TEXT,status TEXT,lease_token TEXT,lease_until REAL,revision TEXT)")
            con.execute("INSERT INTO processing_jobs VALUES(1,?,'running','current',?,?)",
                        ("CVE-2026-12345", time.time() + 60, expected["CVE-2026-12345"]))
        bad = {"CVE-2026-12345": {"id": 1, "lease_token": "reclaimed"}}
        good = {"CVE-2026-12345": {"id": 1, "lease_token": "current"}}
        self.assertEqual(store.apply_enrichment([snapshot], expected, bad), [])
        self.assertEqual(store.apply_enrichment([snapshot], expected, good), ["CVE-2026-12345"])
        with sqlite3.connect(store.database_path()) as con:
            con.execute("UPDATE processing_jobs SET lease_until=?", (time.time() - 1,))
        self.assertEqual(store.apply_enrichment([snapshot], expected, good), [])


if __name__ == "__main__":
    unittest.main()
