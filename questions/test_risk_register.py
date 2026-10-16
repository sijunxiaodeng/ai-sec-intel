"""Real temporary SQLite regressions; no model, network or deployment scans."""
import copy
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from enrichment import risk_register as risks
from enrichment.assets import Asset, import_assets, load_assets
from enrichment.assessment import _empty, _walk_config


@contextmanager
def _db(path):
    conn = sqlite3.connect(path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


class RiskRegisterTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.main = Path(temporary.name) / "knowledge.sqlite3"
        self.assets = Path(temporary.name) / "assets.sqlite3"
        self.asset = Asset(asset_id="ai-01", name="登记 Ollama", vendor="ollama", product="ollama",
                           version="0.1.33", exposure="internet").model_dump()
        import_assets({"assets": [self.asset]}, self.assets)
        self.record = {"item": {"cve_id": "CVE-2024-37032", "title": "Fixture risk",
                                "product": "ollama", "raw_data": {}}}
        self.save_source(self.record)
        self.assessment = _empty("CVE-2024-37032", "Synthetic SQLite regression")
        row = next(_walk_config({"cpeMatch": [{"vulnerable": True,
            "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.1.34"}]}, "configurations/0"))
        row["evidence_ids"] = ["CVE-2024-37032/FIXTURE"]
        self.assessment.update(status="partial", affected_ranges=[row],
                               source={"sha256": "synthetic", "retrieved_at": "2026-01-01T00:00:00Z"},
                               evidence=[{"citation_id": row["evidence_ids"][0], "text": "Synthetic version bound."}])

    def save_source(self, record):
        with _db(self.main) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS knowledge_records (cve_id TEXT PRIMARY KEY,payload_json TEXT,first_seen_at TEXT,updated_at TEXT)")
            conn.execute("INSERT OR REPLACE INTO knowledge_records VALUES(?,?,?,?)",
                         (record["item"]["cve_id"], json.dumps(record), "fixture", "fixture"))

    def evaluate(self, **kwargs):
        options = {"assessment": self.assessment, "db_path": self.main, "asset_db": self.assets}
        options.update(kwargs)
        return risks.evaluate_record(self.record, **options)

    def get(self):
        return risks.get_risk("ai-01", "CVE-2024-37032", db_path=self.main, asset_db=self.assets)

    def disposition(self, status, **kwargs):
        return risks.update_disposition("ai-01", "CVE-2024-37032", status,
                                        db_path=self.main, asset_db=self.assets, **kwargs)

    def test_upsert_idempotence_and_reimport_timestamp_ignored(self):
        before = risks.inventory_fingerprint(asset_db=self.assets)
        first = self.evaluate(run_id="run-1")
        import_assets({"assets": [self.asset]}, self.assets)
        self.assertEqual(before, risks.inventory_fingerprint(asset_db=self.assets))
        second = self.evaluate(run_id="run-2")
        self.assertEqual((first["created"], second["created"], second["updated"]), (1, 0, 0))
        current = self.get()
        self.assertEqual(current["status"], "matched_version")
        self.assertEqual(current["run_id"], "run-2")
        self.assertEqual(len(current["history"]), 1)
        self.assertEqual(current["priority"], "优先核查")
        self.assertEqual(current["validation"], "not_tested")
        self.assertTrue(current["evidence"])

    def test_unrelated_products_do_not_create_risk_rows(self):
        import_assets({"assets": [dict(self.asset, asset_id="other", vendor="vllm", product="vllm")]}, self.assets)
        result = self.evaluate()
        self.assertEqual(result["evaluated"], 1)
        self.assertEqual([a["asset_id"] for a in risks.candidate_assets(self.record, load_assets(self.assets), self.assessment)], ["ai-01"])

    def test_component_pages_include_empty_inventory_and_count_all_cves(self):
        import_assets({"assets": [dict(self.asset, asset_id="empty", product="vllm", vendor="vllm")]}, self.assets)
        for index in range(35):
            cve = "CVE-2026-%05d" % (index + 10000)
            record, report = copy.deepcopy(self.record), copy.deepcopy(self.assessment)
            record["item"]["cve_id"] = report["cve_id"] = cve
            self.save_source(record)
            risks.evaluate_record(record, assessment=report, db_path=self.main, asset_db=self.assets)
        page = risks.list_risk_assets(db_path=self.main, asset_db=self.assets, limit=1)
        self.assertEqual((page["total"], page["inventory_total"], page["risk_total"]), (2, 2, 35))
        self.assertEqual(page["items"][0]["total_cves"], 35)
        self.assertEqual(page["items"][0]["counts"]["matched_version"], 35)
        following = risks.list_risk_assets(db_path=self.main, asset_db=self.assets, limit=1, offset=1)
        self.assertEqual(following["items"][0]["asset_id"], "empty")
        self.assertEqual(following["items"][0]["total_cves"], 0)
        cves = risks.list_risks(db_path=self.main, asset_db=self.assets, asset_id="ai-01", limit=20, offset=20)
        self.assertEqual((cves["total"], len(cves["items"])), (35, 15))
        self.assertEqual({row["asset_id"] for row in cves["items"]}, {"ai-01"})
        filtered = risks.list_risk_assets(db_path=self.main, asset_db=self.assets, status="matched_version")
        self.assertEqual((filtered["total"], filtered["inventory_total"], filtered["risk_total"]), (1, 2, 35))

    def test_component_revision_tracks_disposition_and_inventory_invalidation(self):
        self.evaluate()
        first = risks.list_risk_assets(db_path=self.main, asset_db=self.assets)["items"][0]
        self.evaluate(run_id="unchanged-run")
        same = risks.list_risk_assets(db_path=self.main, asset_db=self.assets)["items"][0]
        self.assertEqual(first["revision"], same["revision"], "worker timestamps must not redraw open forms")
        self.disposition("in_progress", note="checking source")
        changed = risks.list_risk_assets(db_path=self.main, asset_db=self.assets)["items"][0]
        self.assertNotEqual(first["revision"], changed["revision"])
        import_assets({"assets": [dict(self.asset, version="0.1.34")]}, self.assets)
        expired = risks.list_risk_assets(db_path=self.main, asset_db=self.assets, status="invalidated")
        self.assertEqual(expired["items"][0]["counts"]["invalidated"], 1)
        self.assertEqual(expired["items"][0]["asset"]["version"], "0.1.34")
        self.assertEqual(risks.list_risk_assets(db_path=self.main, asset_db=self.assets, status="matched_version")["total"], 0)
        with self.assertRaises(ValueError):
            risks.list_risk_assets(db_path=self.main, asset_db=self.assets, status="bad")

    def test_missing_ranges_exact_product_is_unknown_and_unclosable(self):
        missing = _empty("CVE-2024-37032", "No range")
        self.evaluate(assessment=missing)
        self.assertEqual(self.get()["status"], "unknown")
        with self.assertRaisesRegex(ValueError, "才能验证关闭"):
            self.disposition("resolved", note="I think it is fixed")
        self.assertEqual(self.get()["verification"], "unverified")

    def test_raw_nvd_cpe_routes_empty_product_but_does_not_supply_impact_proof(self):
        record = copy.deepcopy(self.record)
        record["item"]["product"] = ""
        record["item"]["raw_data"] = {"raw_by_source": {"NVD": [{"id": record["item"]["cve_id"],
            "configurations": [{"nodes": [{"children": [{"cpeMatch": [{"vulnerable": True,
                "criteria": self.assessment["affected_ranges"][0]["criteria"]}]}]}]}]}]}}
        self.assertEqual(len(risks.candidate_assets(record, load_assets(self.assets))), 1)
        self.record = record
        self.save_source(record)
        self.evaluate(assessment=_empty("CVE-2024-37032", "Archive unavailable"))
        self.assertEqual(self.get()["status"], "unknown")
        self.assertEqual(self.get()["evidence_ids"], [])
        raw_nvd = record["item"]["raw_data"]["raw_by_source"]["NVD"][0]
        raw_nvd["id"] = "CVE-2024-99999"
        self.assertEqual(risks.candidate_assets(record, load_assets(self.assets)), [])

    def test_affected_package_cpe_is_candidate_and_environment_cpe_is_not(self):
        record = copy.deepcopy(self.record)
        record["item"]["product"] = ""
        record["item"]["raw_data"] = {"affected_packages": [{"cpe": self.assessment["affected_ranges"][0]["criteria"]}]}
        self.assertEqual(len(risks.candidate_assets(record, load_assets(self.assets))), 1)
        record["item"]["raw_data"] = {"configurations": [{"cpeMatch": [{"vulnerable": False,
            "criteria": self.assessment["affected_ranges"][0]["criteria"]}]}]}
        self.assertEqual(risks.candidate_assets(record, load_assets(self.assets)), [])

    def test_fix_and_poc_fields_keep_their_citations_and_not_run_status(self):
        self.assessment["fix_records"] = [{"title": "Fixture advisory", "url": "https://example.test/fix",
                                           "evidence_ids": ["CVE-2024-37032/FIX"], "validation": "not_tested"}]
        self.assessment["poc_candidates"] = [{"url": "https://example.test/poc", "status": "candidate_reference",
                                              "validation": "not_run", "evidence_ids": ["CVE-2024-37032/POC"]}]
        self.assessment["evidence"] += [{"citation_id": "CVE-2024-37032/FIX", "text": "Synthetic fix text."},
                                        {"citation_id": "CVE-2024-37032/POC", "text": "Synthetic PoC label."}]
        self.evaluate()
        current = self.get()
        self.assertEqual(current["poc_candidates"][0]["validation"], "not_run")
        self.assertEqual(current["fix_records"], self.assessment["fix_records"])
        self.assertEqual(len(current["evidence"]), 3)
        self.assertTrue(current["uncertainties"])

    def test_version_change_invalidates_then_clears_and_can_be_verified(self):
        self.evaluate()
        self.disposition("in_progress", note="升级计划")
        import_assets({"assets": [dict(self.asset, version="0.1.34")]}, self.assets)
        self.assertEqual(self.get()["invalidation_reason"], "asset_changed")
        with self.assertRaises(ValueError):
            self.disposition("resolved", note="尚未重评")
        self.evaluate()
        current = self.get()
        self.assertEqual((current["status"], current["lifecycle"]), ("not_matched", "cleared"))
        self.assertEqual(current["disposition"], "in_progress")
        closed = self.disposition("resolved", note="登记版本已升级；当前来源范围未命中", expected_fingerprint=current["fingerprint"])
        self.assertEqual(closed["verification"], "verified")
        self.assertEqual(closed["validation"], "not_tested")
        import_assets({"assets": [self.asset]}, self.assets)
        self.evaluate()
        reopened = self.get()
        self.assertEqual(reopened["status"], "matched_version")
        self.assertEqual(reopened["disposition"], "pending_review")
        self.assertEqual(reopened["verification"], "unverified")

    def test_unknown_does_not_preserve_resolved_on_data_change(self):
        import_assets({"assets": [dict(self.asset, version="0.1.34")]}, self.assets)
        self.evaluate()
        self.disposition("resolved", note="当前版本范围未命中")
        import_assets({"assets": [dict(self.asset, version="nightly")]}, self.assets)
        self.evaluate()
        current = self.get()
        self.assertEqual((current["status"], current["disposition"], current["verification"]),
                         ("unknown", "pending_review", "unverified"))

    def test_source_revision_invalidates_and_old_job_cannot_overwrite(self):
        self.evaluate()
        newer = copy.deepcopy(self.record)
        newer["item"]["title"] = "Revised source"
        self.save_source(newer)
        self.assertEqual(self.get()["invalidation_reason"], "source_changed")
        stale = self.evaluate()
        self.assertEqual(stale["reason"], "stale_source_revision")
        self.record = newer
        self.evaluate()
        self.assertEqual(self.get()["title"], "Revised source")

    def test_withdrawal_and_tombstone_invalidate_without_claiming_fixed(self):
        self.evaluate()
        self.disposition("accepted_risk", note="业务审批接受当前已知风险")
        with _db(self.main) as conn:
            conn.execute("CREATE TABLE scope_tombstones(cve_id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO scope_tombstones VALUES(?)", (self.record["item"]["cve_id"],))
        current = self.get()
        self.assertEqual(current["invalidation_reason"], "source_retracted")
        self.assertEqual(current["disposition"], "pending_review")
        self.assertEqual(self.evaluate()["status"], "skipped")
        with self.assertRaises(ValueError):
            self.disposition("resolved", note="源撤回不是已修复")

    def test_nested_nvd_rejection_invalidates(self):
        self.evaluate()
        self.record["item"]["raw_data"]["raw_by_source"] = {"NVD": [{"id": "CVE-2024-37032", "vulnStatus": "Rejected"}]}
        self.save_source(self.record)
        self.assertEqual(self.get()["invalidation_reason"], "source_retracted")
        self.assertEqual(self.evaluate()["reason"], "source_retracted")

    def test_asset_delete_invalidates_and_read_filter_paginates(self):
        import_assets({"assets": [dict(self.asset, asset_id="ai-02", version="")]}, self.assets)
        self.evaluate()
        with _db(self.assets) as conn:
            conn.execute("DELETE FROM assets WHERE asset_id='ai-01'")
        self.assertEqual(self.get()["invalidation_reason"], "asset_removed")
        listing = risks.list_risks(db_path=self.main, asset_db=self.assets, limit=1)
        self.assertEqual(listing["total"], 2)
        self.assertEqual(len(listing["items"]), 1)
        pending = risks.list_risks(db_path=self.main, asset_db=self.assets, status="unknown")
        self.assertEqual(pending["total"], 1)

    def test_stale_inventory_rejects_before_write_and_midflight_rolls_back(self):
        original = risks.inventory_fingerprint(asset_db=self.assets)
        import_assets({"assets": [dict(self.asset, version="0.1.34")]}, self.assets)
        with self.assertRaises(risks.StaleInventory):
            self.evaluate(expected_inventory_fingerprint=original)
        real_fingerprint = risks.inventory_fingerprint
        calls = 0

        def changed(*args, **kwargs):
            nonlocal calls
            calls += 1
            return real_fingerprint(*args, **kwargs) if calls == 1 else "changed-during-evaluation"

        with patch.object(risks, "inventory_fingerprint", side_effect=changed):
            with self.assertRaises(risks.StaleInventory):
                self.evaluate()
        self.assertIsNone(self.get())

    def test_disposition_validation_and_fingerprint_compare_and_swap(self):
        self.evaluate()
        with self.assertRaises(ValueError):
            self.disposition("not-a-state")
        with self.assertRaises(ValueError):
            self.disposition("accepted_risk")
        with self.assertRaisesRegex(ValueError, "评估已更新"):
            self.disposition("in_progress", expected_fingerprint="stale")
        self.assertEqual(self.get()["disposition"], "pending")

    def test_concurrent_workers_write_one_current_row_and_one_revision(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda index: self.evaluate(run_id=str(index)), range(8)))
        self.assertEqual(sum(result["created"] for result in outcomes), 1)
        with _db(self.main) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM asset_risks").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM asset_risk_history").fetchone()[0], 1)

    def test_default_guard_does_not_accept_unstored_source(self):
        with _db(self.main) as conn:
            conn.execute("DELETE FROM knowledge_records")
        self.assertEqual(self.evaluate()["reason"], "record_removed")
        self.assertIsNone(self.get())

    def test_processing_lease_is_checked_inside_transaction(self):
        from automation.processing import StaleWork
        from database.store import source_revision
        with _db(self.main) as conn:
            conn.execute("CREATE TABLE processing_jobs(id INTEGER PRIMARY KEY,cve_id TEXT,revision TEXT,status TEXT,lease_token TEXT,lease_until REAL,stage TEXT)")
            conn.execute("INSERT INTO processing_jobs VALUES(?,?,?,?,?,?,?)",
                         (4, self.record["item"]["cve_id"], source_revision(self.record), "running", "current-lease", time.time() + 60, "investigate"))
        with self.assertRaises(StaleWork):
            self.evaluate(job_id=4, run_id="4-old-lease")
        self.assertIsNone(self.get())
        self.evaluate(job_id=4, run_id="4-current-lease")
        self.assertEqual(self.get()["job_id"], 4)
        with _db(self.main) as conn:
            conn.execute("UPDATE processing_jobs SET lease_until=0 WHERE id=4")
        with self.assertRaises(StaleWork):
            self.evaluate(job_id=4, run_id="4-current-lease")


if __name__ == "__main__":
    unittest.main()
