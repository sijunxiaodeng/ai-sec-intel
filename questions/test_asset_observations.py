"""Temporary offline fixtures; never contact any advertised IP or provider."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from enrichment import asset_observations as observations
from enrichment.assets import import_assets, load_assets
from rag.evidence import _connection


class AssetObservationsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "observations.sqlite3"
        self.now = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
        timer = patch.object(observations, "_now", return_value=self.now)
        timer.start()
        self.addCleanup(timer.stop)
        for target in ("socket.socket", "socket.getaddrinfo"):
            blocker = patch(target, side_effect=AssertionError("network is forbidden in offline observations"))
            blocker.start()
            self.addCleanup(blocker.stop)
        self.row = {"ip_str": "203.0.113.10", "port": 11434, "transport": "tcp", "product": "Ollama",
                    "version": "0.1.33", "timestamp": "2026-10-12T09:00:00.000000",
                    "cpe23": ["cpe:2.3:a:ollama:ollama:0.1.33:*:*:*:*:*:*:*"]}
        self.assessment = {"cve_id": "CVE-2024-37032", "status": "ok", "affected_ranges": [
            {"criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.1.34",
             "display": "ollama < 0.1.34", "pointer": "configurations/0/cpeMatch/0", "evidence_ids": ["CVE-2024-37032/RANGE"]}],
            "evidence": [{"citation_id": "CVE-2024-37032/RANGE", "text": "Synthetic source range."}], "warnings": []}

    def preview(self, row=None, **kwargs):
        return observations.preview_export("shodan", json.dumps({"matches": [row or self.row]}), is_demo=True, **kwargs)

    def save(self, rows=None, **kwargs):
        return observations.import_export("shodan", json.dumps({"matches": rows or [self.row]}), is_demo=True, db_path=self.db, **kwargs)

    def assess(self, row=None):
        return observations.evaluate_observations(self.assessment, self.preview(row)["items"])

    def test_preview_has_bound_hashes_locator_and_does_not_write(self):
        raw = json.dumps({"matches": [self.row]})
        preview = observations.preview_export("shodan", raw, is_demo=True)
        self.assertFalse(self.db.exists())
        item = preview["items"][0]
        self.assertEqual(item["source_response_sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(item["locator"], "/matches/0")
        self.assertEqual(item["identity_status"], "exact_cpe")
        self.assertEqual(item["time_status"], "current")
        self.assertEqual(item["observed_at"], "2026-10-12T09:00:00+00:00")
        self.assertEqual(item["provenance"], "user_supplied_provider_export")

    def test_demo_range_match_is_never_real_asset_or_runtime_verified(self):
        report = self.assess()
        self.assertEqual(report["counts"]["matched_version"], 1)
        self.assertEqual(report["demo_count"], 1)
        self.assertEqual(report["real_internet_count"], 0)
        self.assertEqual(report["real_internet_candidate_count"], 0)
        result = report["results"][0]
        self.assertEqual(result["validation"], "not_tested")
        self.assertTrue(result["asset"]["is_demo"])
        self.assertIn("OBSERVATION/", result["observation_evidence_ids"][0])
        self.assertIn("未验证提供商", report["warnings"][0])

    def test_shodan_array_and_jsonl_locators(self):
        rows = [self.row, dict(self.row, ip_str="203.0.113.11")]
        self.assertEqual(observations.preview_export("shodan", json.dumps(rows), is_demo=True)["items"][1]["locator"], "/1")
        lines = json.dumps(rows[0]) + "\n\n" + json.dumps(rows[1])
        self.assertEqual(observations.preview_export("shodan", lines, is_demo=True)["items"][1]["locator"], "line:3")

    def test_fofa_columns_are_explicit_never_guessed_and_port_string_valid(self):
        fields = ["ip", "port", "product", "product.version", "lastupdatetime"]
        content = json.dumps({"results": [["203.0.113.10", "11434", "Ollama", "0.1.33", "2026-10-12T09:00:00+00:00"]]})
        with self.assertRaises(ValueError):
            observations.preview_export("fofa", content, is_demo=True)
        preview = observations.preview_export("fofa", content, fields, is_demo=True)
        self.assertEqual(preview["items"][0]["version"], "0.1.33")
        self.assertEqual(preview["items"][0]["port"], 11434)
        self.assertEqual(preview["items"][0]["locator"], "/results/0")
        for bad in (fields + ["title"], ["ip", "ip"], "ip,port", ["api_key"]):
            with self.subTest(fields=bad), self.assertRaises(ValueError):
                observations.preview_export("fofa", content, bad, is_demo=True)

    def test_fofa_objects_and_naive_time_do_not_claim_current(self):
        row = {"ip": "203.0.113.10", "port": "11434", "product": "ollama", "product.version": "0.1.33", "lastupdatetime": "2026-10-12 09:00:00"}
        preview = observations.preview_export("fofa", json.dumps({"results": [row]}), is_demo=True)
        self.assertEqual(preview["items"][0]["time_status"], "unknown")
        self.assertEqual(observations.evaluate_observations(self.assessment, preview["items"])["counts"]["unknown"], 1)
        row["surprise"] = "unofficial key"
        with self.assertRaises(ValueError):
            observations.preview_export("fofa", json.dumps([row]), is_demo=True)

    def test_fofa_same_array_different_column_interpretations_preserve_conflict(self):
        content = json.dumps({"results": [["203.0.113.10", "11434", "Ollama", "0.1.33", "2026-10-12T09:00:00Z"]]})
        fields = ["ip", "port", "product", "product.version", "lastupdatetime"]
        alternative = ["ip", "port", "product", "title", "lastupdatetime"]
        first = observations.import_export("fofa", content, fields, is_demo=True, db_path=self.db)
        second = observations.import_export("fofa", content, alternative, is_demo=True, db_path=self.db)
        self.assertEqual(first["imported"], 1)
        self.assertEqual(second["imported"], 1)
        self.assertNotEqual(first["items"][0]["observation_id"], second["items"][0]["observation_id"])
        loaded = observations.load_observations(self.db)
        self.assertEqual(loaded[0]["history_count"], 2)
        self.assertEqual(loaded[0]["identity_status"], "conflict")
        self.assertEqual(observations.evaluate_observations(self.assessment, loaded)["counts"]["unknown"], 1)

    def test_offsets_future_dates_stale_and_missing_times(self):
        for timestamp, expected in (("2026-10-12T17:00:00+08:00", "current"),
                                    ("2026-10-12T10:00:01Z", "invalid"),
                                    ("2026-08-12T10:00:00Z", "stale"),
                                    ("2026-10-12", "invalid"), ("2026-99-12T09:00:00Z", "invalid"),
                                    (None, "unknown"), (1750000000, "invalid")):
            with self.subTest(timestamp=timestamp):
                row = dict(self.row, timestamp=timestamp)
                self.assertEqual(self.preview(row)["items"][0]["time_status"], expected)
                if expected != "current":
                    self.assertEqual(self.assess(row)["counts"]["unknown"], 1)

    def test_stored_future_time_does_not_become_valid_when_clock_catches_up(self):
        self.save([dict(self.row, timestamp="2026-10-13T09:00:00Z")])
        with patch.object(observations, "_now", return_value=self.now + timedelta(days=2)):
            loaded = observations.load_observations(self.db)
        self.assertEqual(loaded[0]["time_status"], "invalid")

    def test_loaded_observation_becomes_stale_at_read_and_at_evaluation(self):
        self.save()
        loaded = observations.load_observations(self.db)
        with patch.object(observations, "_now", return_value=self.now + timedelta(days=31)):
            self.assertEqual(observations.load_observations(self.db)[0]["time_status"], "stale")
            self.assertEqual(observations.evaluate_observations(self.assessment, loaded)["counts"]["unknown"], 1)

    def test_missing_version_fuzzy_product_and_banner_ports_remain_unknown(self):
        for changes in ({"version": "", "cpe23": []}, {"product": "Ollama Server", "cpe23": []},
                        {"product": "", "version": "", "cpe23": [], "data": "Ollama 0.1.33"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.assess(dict(self.row, **changes))["counts"]["unknown"], 1)

    def test_cpe_conflicting_identity_version_and_multiple_candidates_are_unknown(self):
        for changes in ({"product": "other"}, {"version": "0.1.34"},
                        {"cpe23": self.row["cpe23"] + ["cpe:2.3:a:other:other:0.1.33:*:*:*:*:*:*:*"]},
                        {"cpe": ["cpe:/a:other:other:0.1.33"]},
                        {"cpe23": ["cpe:2.3:a:ollama:olla*:0.1.33:*:*:*:*:*:*:*"]}):
            with self.subTest(changes=changes):
                self.assertEqual(self.assess(dict(self.row, **changes))["counts"]["unknown"], 1)

    def test_cpe_qualifiers_bound_to_same_observation(self):
        row = dict(self.row, cpe23=["cpe:2.3:a:ollama:ollama:0.1.33:rc0:*:*:*:windows:*:*"])
        observed = self.preview(row)["items"][0]
        self.assertEqual(observed["qualifiers"], {"update": "rc0", "target_sw": "windows"})
        report = copy.deepcopy(self.assessment)
        report["affected_ranges"][0]["criteria"] = "cpe:2.3:a:ollama:ollama:*:rc0:*:*:*:linux:*:*"
        self.assertEqual(observations.evaluate_observations(report, [observed])["counts"]["not_matched"], 1)

    def test_legacy_cpe_qualifier_conflict_never_silently_matches(self):
        row = dict(self.row, cpe23=["cpe:2.3:a:ollama:ollama:0.1.33:rc0:*:*:*:*:*:*"],
                   cpe=["cpe:/a:ollama:ollama:0.1.33:rc1"])
        self.assertEqual(self.assess(row)["counts"]["unknown"], 1)
        row["cpe"] = ["cpe:/a:ollama:ollama:0.1.33:rc0:enterprise"]
        self.assertEqual(self.assess(row)["counts"]["unknown"], 1)
        row["cpe"] = ["cpe:/a:ollama:ollama:0.1.33:rc0"]
        self.assertEqual(self.preview(row)["items"][0]["identity_status"], "exact_cpe")

    def test_documentation_reserved_addresses_require_demo_and_private_is_not_internet(self):
        for address in ("203.0.113.10", "192.0.2.1", "198.51.100.1", "2001:db8::1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                observations.preview_export("shodan", json.dumps([dict(self.row, ip_str=address)]))
        item = observations.preview_export("shodan", json.dumps([dict(self.row, ip_str="10.0.0.1")]))["items"][0]
        self.assertFalse(item["is_internet"])
        self.assertEqual(observations.evaluate_observations(self.assessment, [item])["real_internet_count"], 0)

    def test_public_address_count_does_not_prove_exploitation(self):
        item = observations.preview_export("shodan", json.dumps([dict(self.row, ip_str="8.8.8.8")]))["items"][0]
        report = observations.evaluate_observations(self.assessment, [item])
        self.assertEqual(report["real_internet_candidate_count"], 1)
        self.assertEqual(report["results"][0]["validation"], "not_tested")

    def test_site_local_and_translated_nonpublic_ipv6_not_internet(self):
        for address in ("fec0::1", "::ffff:10.0.0.1", "2002:0a00:0001::1"):
            with self.subTest(address=address):
                item = observations.preview_export("shodan", json.dumps([dict(self.row, ip_str=address)]), is_demo=True)["items"][0]
                self.assertFalse(item["is_internet"])

    def test_import_preserves_history_reimport_idempotent_and_separate_inventory(self):
        inventory = self.db.with_name("assets.sqlite3")
        original = {"asset_id": "own", "name": "owned", "vendor": "ollama", "product": "ollama", "version": "0.1.33"}
        import_assets({"assets": [original]}, inventory)
        first = self.save()
        self.assertEqual(first["imported"], 1)
        second = self.save()
        self.assertEqual(second["imported"], 0)
        self.assertEqual(second["unchanged"], 1)
        self.assertEqual(load_assets(inventory)[0]["version"], "0.1.33")
        self.assertEqual(observations.load_observations(self.db)[0]["history_count"], 1)

    def test_older_import_cannot_replace_newer_snapshot(self):
        self.save([dict(self.row, timestamp="2026-10-12T09:30:00Z", version="0.1.34", cpe23=[])])
        self.save([dict(self.row, timestamp="2026-10-11T09:00:00Z")])
        saved = observations.load_observations(self.db)[0]
        self.assertEqual(saved["version"], "0.1.34")
        self.assertEqual(saved["history_count"], 2)
        self.assertEqual(observations.evaluate_observations(self.assessment, [saved])["counts"]["not_matched"], 1)

    def test_equal_time_conflicts_never_choose_success_and_keep_both_rows(self):
        self.save()
        self.save([dict(self.row, version="0.1.34", cpe23=[])])
        loaded = observations.load_observations(self.db)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["identity_status"], "conflict")
        self.assertEqual(loaded[0]["history_count"], 2)
        report = observations.evaluate_observations(self.assessment, loaded)
        self.assertEqual(report["counts"]["unknown"], 1)
        self.assertEqual(report["results"][0]["provider_observation"]["history_count"], 2)

    def test_untimed_conflicting_update_cannot_claim_newer_or_safe(self):
        self.save()
        self.save([dict(self.row, timestamp=None, version="0.1.34", cpe23=[])])
        loaded = observations.load_observations(self.db)[0]
        self.assertEqual(loaded["identity_status"], "conflict")
        self.assertEqual(observations.evaluate_observations(self.assessment, [loaded])["counts"]["unknown"], 1)

    def test_tampered_row_and_recomputed_self_hash_fail_against_original_export(self):
        self.save()
        with _connection(self.db) as conn:
            raw = json.loads(conn.execute("SELECT raw_row FROM observation_rows").fetchone()[0])
            raw["version"] = "0.1.34"
            changed = observations._json(raw)
            conn.execute("UPDATE observation_rows SET raw_row=?,raw_digest=?", (changed, observations._sha(changed)))
        with self.assertRaises(ValueError):
            observations.load_observations(self.db)

    def test_export_digest_demo_and_locator_tampering_fail_closed(self):
        for sql in ("UPDATE observation_exports SET digest='tampered'", "UPDATE observation_exports SET is_demo=0", "UPDATE observation_rows SET locator='/matches/999'"):
            with self.subTest(sql=sql):
                path = self.db.with_name("tamper-%s.sqlite3" % observations._sha(sql)[:8])
                observations.import_export("shodan", json.dumps([self.row]), is_demo=True, db_path=path)
                with _connection(path) as conn:
                    conn.execute(sql)
                with self.assertRaises(ValueError):
                    observations.load_observations(path)

    def test_deleted_conflicting_row_cannot_silently_clear_conflict(self):
        self.save()
        self.save([dict(self.row, version="0.1.34", cpe23=[])])
        with _connection(self.db) as conn:
            conn.execute("DELETE FROM observation_rows WHERE observation_id=(SELECT observation_id FROM observation_rows LIMIT 1)")
        with self.assertRaises(ValueError):
            observations.load_observations(self.db)

    def test_export_field_type_tampering_is_value_error(self):
        self.save()
        with _connection(self.db) as conn:
            conn.execute("UPDATE observation_exports SET body=x'00'")
        with self.assertRaises(ValueError):
            observations.load_observations(self.db)

    def test_invalid_batch_does_not_change_existing_rows(self):
        self.save()
        with self.assertRaises(ValueError):
            self.save([dict(self.row, ip_str="203.0.113.11"), dict(self.row, port=True)])
        self.assertEqual(len(observations.load_observations(self.db)), 1)

    def test_bounded_history_rejects_atomically_and_retains_existing_export(self):
        self.save()
        with patch.object(observations, "MAX_OBSERVATIONS", 1), self.assertRaises(ValueError):
            self.save([dict(self.row, ip_str="203.0.113.11")])
        with patch.object(observations, "MAX_EXPORTS", 1), self.assertRaises(ValueError):
            self.save([dict(self.row, ip_str="203.0.113.11")])
        with patch.object(observations, "MAX_STORAGE_BYTES", 1), self.assertRaises(ValueError):
            self.save([dict(self.row, ip_str="203.0.113.11")])
        self.assertEqual(len(observations.load_observations(self.db)), 1)
        with _connection(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM observation_exports").fetchone()[0], 1)

    def test_provider_types_secret_keys_duplicate_json_errors_and_size_limits(self):
        for provider, content, kwargs in (("other", "[]", {}), ("shodan", "", {}), ("shodan", "[]", {"is_demo": "false"}),
                                         ("shodan", '{"matches":[],"matches":[]}', {}),
                                         ("shodan", '{"matches":[],"api_key":"do not save"}', {}),
                                         ("shodan", '{"matches":[],"extra":{"Authorization":"hidden"}}', {}),
                                         ("fofa", '{"error":true,"results":[]}', {}),
                                         ("shodan", '[NaN]', {})):
            with self.subTest(provider=provider, content=content), self.assertRaises(ValueError):
                observations.preview_export(provider, content, **kwargs)
        with self.assertRaises(ValueError):
            observations.preview_export("shodan", " " * (observations.MAX_EXPORT_BYTES + 1))
        with self.assertRaises(ValueError):
            observations.preview_export("shodan", json.dumps([self.row] * 501), is_demo=True)
        for changes in ({"ip_str": "example.org"}, {"port": 0}, {"port": 65536}, {"port": "11434"}, {"product": 7}, {"cpe23": {"bad": True}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.preview(dict(self.row, **changes))

    def test_missing_database_never_created_and_corrupt_database_is_value_error(self):
        self.assertEqual(observations.load_observations(self.db), [])
        self.assertFalse(self.db.exists())
        self.db.write_text("not SQLite", encoding="utf-8")
        with self.assertRaises(ValueError):
            observations.load_observations(self.db)
        with self.assertRaises(ValueError):
            self.save()

    def test_evaluation_leaves_input_unchanged_and_preserves_source_conditions(self):
        preview = self.preview()["items"]
        before = copy.deepcopy((preview, self.assessment))
        observations.evaluate_observations(self.assessment, preview)
        self.assertEqual((preview, self.assessment), before)
        for status in ("invalid_evidence", "insufficient_evidence"):
            assessment = dict(self.assessment, status=status)
            self.assertEqual(observations.evaluate_observations(assessment, preview)["counts"]["unknown"], 1)

    def test_sample_payload_is_explicit_demo_and_offline_importable(self):
        path = Path(observations.__file__).parent / "samples" / "passive_assets_demo.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertIs(payload["is_demo"], True)
        report = observations.preview_export(payload["provider"], payload["content"], payload["fields"], is_demo=True)
        self.assertTrue(all(row["is_demo"] for row in report["items"]))
        self.assertEqual(sum(row["is_internet"] for row in report["items"]), 0)


if __name__ == "__main__":
    unittest.main()
