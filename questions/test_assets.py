"""资产导入和匹配使用临时库；不扫描资产或访问网络。"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pydantic import ValidationError
from enrichment.assets import Asset, AssetImport, _check, _compare, import_assets, load_assets, impact_report, inventory_evidence
from enrichment.assessment import _empty, _walk_config
from enrichment.sample import load_sample


class AssetsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "assets.sqlite3"
        self.asset = Asset(asset_id="ai-01", name="测试组件", vendor="ollama", product="ollama", version="0.1.33").dict()
        self.match = {"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.1.34"}
        self.report = _empty("CVE-2024-37032", "fixture")
        self.report.update(status="partial")
        self.row = self.make_row()
        self.report["affected_ranges"] = [self.row]
        self.report["evidence"] = [{"citation_id": self.row["evidence_ids"][0], "text": "Synthetic CPE source."}]

    def make_row(self, match=None, **node):
        row = next(_walk_config(dict(node, cpeMatch=[match or self.match]), "configurations/0"))
        row["evidence_ids"] = ["CVE-2024-37032/AUTO-FIXTURE"]
        return row

    def test_numeric_versions_compare_by_components_not_strings(self):
        self.assertGreater(_compare("0.1.10", "0.1.9"), 0)
        self.assertEqual(_compare("v1.0.0", "1.0"), 0)
        self.assertLess(_compare("1.9", "1.10"), 0)
        self.assertIsNone(_compare("1.0-rc1", "1.0"))
        self.assertIsNone(_compare("nightly", "1.0"))

    def test_all_four_version_boundaries(self):
        for key, version, expected in (("versionStartIncluding", "0.1.34", "matched_version"),
                                       ("versionStartExcluding", "0.1.34", "not_matched"),
                                       ("versionEndIncluding", "0.1.34", "matched_version"),
                                       ("versionEndExcluding", "0.1.34", "not_matched")):
            with self.subTest(key=key):
                match = {"vulnerable": True, "criteria": self.match["criteria"], key: version}
                asset = dict(self.asset, version=version)
                self.assertEqual(_check(asset, self.make_row(match))[0], expected)
        self.assertEqual(_check(self.asset, self.row)[0], "matched_version")

    def test_exact_version_and_prerelease_qualifier(self):
        match = {"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:0.11.5:rc0:*:*:*:*:*:*"}
        row = self.make_row(match)
        asset = dict(self.asset, version="0.11.5")
        self.assertEqual(_check(asset, row)[0], "unknown")
        asset["qualifiers"] = {"update": "rc0"}
        self.assertEqual(_check(asset, row)[0], "matched_version")
        asset["qualifiers"] = {"update": "rc1"}
        self.assertEqual(_check(asset, row)[0], "not_matched")
        asset["qualifiers"] = {"update": "rc0"}
        asset["version"] = "0.11.5-rc0"
        self.assertEqual(_check(asset, row)[0], "unknown")

    def test_platform_and_not_applicable_qualifiers(self):
        match = {"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:0.1.33:-:*:*:*:windows:*:*"}
        row = self.make_row(match)
        self.assertEqual(_check(self.asset, row)[0], "unknown")
        self.assertEqual(_check(dict(self.asset, qualifiers={"update": "-", "target_sw": "windows"}), row)[0], "matched_version")
        self.assertEqual(_check(dict(self.asset, qualifiers={"update": "-", "target_sw": "linux"}), row)[0], "not_matched")

    def test_missing_and_unsupported_versions_stay_unknown(self):
        for version in ("", "nightly", "0.1.34-rc0", "1.0+vendor.2"):
            self.assertEqual(_check(dict(self.asset, version=version), self.row)[0], "unknown")
        row = self.make_row({"vulnerable": True, "criteria": self.match["criteria"]})
        self.assertEqual(_check(self.asset, row)[0], "unknown")

    def test_product_identity_does_not_use_fuzzy_names(self):
        for fields in ({"vendor": "other"}, {"product": "ollama-webui"}, {"part": "o"}):
            self.assertEqual(_check(dict(self.asset, **fields), self.row)[0], "not_matched")
        with self.assertRaises(ValidationError):
            Asset(**dict(self.asset, product="Ollama Server"))

    def test_complex_config_and_patterns_are_unknown(self):
        for flags in ({"operator": "AND"}, {"negate": True}):
            self.assertEqual(_check(self.asset, self.make_row(**flags))[0], "unknown")
        for criteria in ("cpe:2.3:a:ollama:olla*:*:*:*:*:*:*:*:*", "not-a-cpe", "cpe:2.3:a:ollama:olla\\:ma:*:*:*:*:*:*:*:*"):
            row = dict(self.row, criteria=criteria)
            self.assertEqual(_check(self.asset, row)[0], "unknown")

    def test_or_ranges_and_priority_keep_match_state(self):
        other = self.make_row({"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:0.0.1:*:*:*:*:*:*:*"})
        self.report["affected_ranges"].append(other)
        high = dict(self.asset, exposure="internet", criticality="high", authentication="required")
        result = impact_report(self.report, [high])["results"][0]
        self.assertEqual(result["status"], "matched_version")
        self.assertEqual(result["priority"], "优先核查")
        self.assertEqual(result["validation"], "not_tested")
        self.assertEqual(impact_report(self.report, [self.asset])["results"][0]["status"], "matched_version")

    def test_empty_invalid_or_uncited_sources_do_not_assert_safe(self):
        for status in ("invalid_evidence", "insufficient_evidence"):
            report = copy.deepcopy(self.report)
            report["status"] = status
            self.assertEqual(impact_report(report, [self.asset])["results"][0]["status"], "unknown")
        self.report["affected_ranges"][0]["evidence_ids"] = []
        self.assertEqual(impact_report(self.report, [self.asset])["results"][0]["status"], "unknown")
        self.assertEqual(impact_report(self.report, [])["status"], "empty_inventory")

    def test_import_updates_ids_and_preserves_other_assets(self):
        first = import_assets({"assets": [self.asset, dict(self.asset, asset_id="ai-02")]}, self.db)
        self.assertEqual(first["created"], 2)
        second = import_assets({"assets": [dict(self.asset, version="0.1.34")]}, self.db)
        self.assertEqual(second["updated"], 1)
        self.assertEqual(second["total"], 2)
        saved = load_assets(self.db)
        self.assertEqual(saved[0]["version"], "0.1.34")
        self.assertEqual(saved[1]["version"], "0.1.33")
        self.assertTrue(saved[0]["recorded_at"])
        self.assertEqual(saved[0]["inventory_source"], "user_declared")

    def test_invalid_batch_is_atomic_and_duplicates_rejected(self):
        import_assets({"assets": [self.asset]}, self.db)
        original = self.db.read_bytes()
        bad = dict(self.asset, asset_id="ai-02", version=42)
        with self.assertRaises(ValidationError):
            import_assets({"assets": [dict(self.asset, version="0.1.34"), bad]}, self.db)
        self.assertEqual(original, self.db.read_bytes())
        for payload in ({"assets": [self.asset, self.asset]}, {"assets": []}, {"assets": [self.asset], "extra": "wrong"}):
            with self.assertRaises(ValidationError):
                import_assets(payload, self.db)

    def test_batch_limits_and_strict_fields(self):
        with self.assertRaises(ValidationError):
            AssetImport(assets=[dict(self.asset, asset_id="a-%d" % i) for i in range(501)])
        for change in ({"is_demo": "false"}, {"qualifiers": {"update": 0}}, {"qualifiers": {"unrecognized": "x"}}, {"api_key": "not-allowed"}, {"asset_id": "../path"}):
            with self.assertRaises(ValidationError):
                Asset(**dict(self.asset, **change))

    def test_preview_and_matching_preserve_input(self):
        assets = [self.asset, dict(self.asset, version="0.1.34", asset_id="ai-02"), dict(self.asset, version="", asset_id="ai-03")]
        before = copy.deepcopy((assets, self.report))
        result = impact_report(self.report, assets, preview=True)
        self.assertEqual(result["counts"], {"matched_version": 1, "not_matched": 1, "unknown": 1})
        self.assertTrue(result["preview"])
        self.assertEqual((assets, self.report), before)
        self.assertFalse(self.db.exists())
        self.assertEqual(load_assets(self.db), [])
        self.assertFalse(self.db.exists())

    def test_inventory_citation_changes_when_asset_changes(self):
        a, b = inventory_evidence(self.asset), inventory_evidence(dict(self.asset, version="0.1.34"))
        self.assertNotEqual(a["citation_id"], b["citation_id"])
        self.assertEqual(a["text_kind"], "user_declared_inventory")

    def test_api_preview_import_update_and_unknown_id(self):
        from fastapi.testclient import TestClient
        from api.app import app
        record, _ = load_sample()
        record["item"]["raw_data"]["automatic_assessment"] = self.report
        client = TestClient(app)
        with patch("enrichment.assets.DEFAULT_ASSET_DB", self.db), patch("api.app.get_record", return_value=record):
            preview = client.post("/api/assets/preview", json={"assets": [self.asset], "cve_id": "CVE-2024-37032"})
            self.assertEqual(preview.status_code, 200)
            self.assertTrue(preview.json()["preview"])
            self.assertFalse(self.db.exists())
            self.assertEqual(client.post("/api/assets/import", json={"assets": [self.asset]}).json()["created"], 1)
            self.assertEqual(client.get("/api/assets").json()["count"], 1)
            self.assertEqual(client.get("/api/asset-impact/CVE-2024-37032").json()["counts"]["matched_version"], 1)
            self.assertEqual(client.post("/api/assets/import", json={"assets": [self.asset, self.asset]}).status_code, 422)
            demo = client.get("/api/assets/demo").json()
            self.assertTrue(all(r["is_demo"] for r in demo["assets"]))
        with patch("api.app.get_record", return_value=None):
            self.assertEqual(client.post("/api/assets/preview", json={"assets": [self.asset], "cve_id": "CVE-2099-99999"}).status_code, 404)

    def test_asset_qa_cites_inventory_and_range_without_calling_model(self):
        from agents.qa_agent import run
        from agents.verifier_agent import run as verify
        record, _ = load_sample()
        record["item"]["raw_data"]["automatic_assessment"] = self.report
        chunk = self.report["evidence"][0]
        chunk.update(url="https://nvd.nist.gov/vuln/detail/CVE-2024-37032", locator="configurations/0", text_kind="automatic_source_extract")
        with patch("enrichment.assets.DEFAULT_ASSET_DB", self.db), patch("rag.retrieve.get_record", return_value=record), patch("agents.qa_agent.chat") as chat:
            import_assets({"assets": [self.asset]}, self.db)
            result = run("我们的资产是否受 CVE-2024-37032 影响？")
            self.assertIn("版本命中", result["answer"])
            self.assertIn("[ASSET/", result["answer"])
            self.assertIn("[CVE-2024-37032/AUTO-FIXTURE]", result["answer"])
            self.assertTrue(verify(result["answer"], result["evidence"])["passed"])
            chat.assert_not_called()
            self.assertEqual(run("我们的资产有风险吗？")["evidence"], [])
            self.assertEqual(run("我们的资产受 CVE-2024-37032 或 CVE-2099-99999 影响吗？")["evidence"], [])
        with patch("enrichment.assets.DEFAULT_ASSET_DB", Path(str(self.db) + "-missing")):
            self.assertIn("没有你的资产清单", run("我们的资产是否受影响？")["answer"])


if __name__ == "__main__":
    unittest.main()
