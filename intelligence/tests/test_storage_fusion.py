"""Offline regression coverage for collector fusion and transactional persistence."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from collectors.base import IntelligenceItem
from fusion.merger import merge_by_cve
from storage.sqlite_store import SQLiteIntelligenceStore


def item(source="NVD", cve="CVE-2026-1234", source_id=None, **overrides):
    data = dict(
        source=source, source_id=source_id or cve, cve_id=cve,
        title=cve, description="A vulnerability", url=None,
        published_at=None, modified_at=None, severity=None,
    )
    data.update(overrides)
    return IntelligenceItem(**data)


def metric(score, version="3.1", **extra):
    return {
        "source": "nvd@nist.gov", "type": "Primary",
        "cvssData": {"version": version, "baseScore": score,
                     "vectorString": f"CVSS:{version}/AV:N", **extra},
    }


class FusionTests(unittest.TestCase):
    def test_recursive_nvd_cpe_has_authoritative_package_and_version_evidence(self):
        cpe = "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*"
        match = {"vulnerable": True, "criteria": cpe, "matchCriteriaId": "match-1",
                 "versionStartIncluding": "0.1.0", "versionEndExcluding": "0.5.0"}
        environmental = {"vulnerable": False,
                         "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}
        raw = {"configurations": [{"operator": "AND", "nodes": [{
            "operator": "OR", "children": [{"cpeMatch": [environmental, match]}],
        }]}]}
        record = item(description="A runtime vulnerability", raw_data=raw)
        original = asdict(record)
        result = merge_by_cve([record])[0]
        self.assertEqual((result.vendor, result.product), ("ollama", "ollama"))
        self.assertEqual(len(result.affected_packages), 1)
        package = result.affected_packages[0]
        self.assertEqual((package["ecosystem"], package["name"]), ("cpe", "ollama"))
        self.assertEqual(package["cpe"], cpe)
        self.assertEqual(package["versionStartIncluding"], "0.1.0")
        self.assertEqual(package["versionEndExcluding"], "0.5.0")
        self.assertEqual(package["vulnerable_version_range"], ">= 0.1.0, < 0.5.0")
        self.assertIsNone(package["first_patched_version"])
        self.assertEqual(package["match_criteria_id"], "match-1")
        self.assertEqual(package["source_id"], record.source_id)
        self.assertEqual(asdict(record), original)

        from classification.ai_relevance import AIRelevanceClassifier
        classified = AIRelevanceClassifier().classify(
            title=result.title, description=result.description,
            vendor=result.vendor, product=result.product,
            package_names=[f"{package['ecosystem']}:{package['name']}"],
        )
        self.assertTrue(classified.is_ai_related)

    def test_environmental_negated_and_malformed_cpes_do_not_create_products(self):
        valid = "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*"
        matches = [
            {"criteria": valid, "vulnerable": False},
            {"criteria": valid, "vulnerable": "true"},
            {"criteria": "cpe:2.3:a:ollama:ollama", "vulnerable": True},
            {"criteria": "cpe:2.3:a:ollama::1.0:*:*:*:*:*:*:*", "vulnerable": True},
        ]
        result = merge_by_cve([item(raw_data={"configurations": [
            {"nodes": [{"cpeMatch": matches}]},
            {"negate": True, "nodes": [{"cpeMatch": [{"criteria": valid, "vulnerable": True}]}]},
        ]})])[0]
        self.assertEqual(result.affected_packages, [])
        self.assertIsNone(result.vendor)
        self.assertIsNone(result.product)

    def test_cpe_escaped_colon_and_exact_version_are_preserved(self):
        cpe = r"cpe:2.3:a:example:tool\:server:1.2.3:*:*:*:*:*:*:*"
        result = merge_by_cve([item(raw_data={"configurations": [{"nodes": [{
            "cpeMatch": [{"vulnerable": True, "criteria": cpe}],
        }]}]})])[0]
        package = result.affected_packages[0]
        self.assertEqual(package["name"], "tool:server")
        self.assertEqual(package["cpe"], cpe)
        self.assertEqual(package["version"], "1.2.3")
        self.assertEqual(package["vulnerable_version_range"], "== 1.2.3")
        self.assertIsNone(package["first_patched_version"])

    def test_cpe_multiple_products_keep_packages_without_inventing_one_product(self):
        matches = [{"vulnerable": True,
                    "criteria": f"cpe:2.3:a:example:{product}:*:*:*:*:*:*:*:*"}
                   for product in ("one", "two")]
        result = merge_by_cve([item(raw_data={"configurations": [{
            "nodes": [{"cpeMatch": matches}],
        }]})])[0]
        self.assertEqual(len(result.affected_packages), 2)
        self.assertEqual(result.vendor, "example")
        self.assertIsNone(result.product)

    def test_normalized_cve_and_optional_hint(self):
        result = merge_by_cve([item(cve=" cve-2026-1234 ")])[0]
        self.assertEqual(result.cve_id, "CVE-2026-1234")
        self.assertEqual(result.ai_relevance_hint, 0)

    def test_selected_cvss_fields_are_coherent_and_evidence_kept(self):
        record = item(severity="HIGH", raw_data={"metrics": {
            "cvssMetricV31": [metric(7.5, baseSeverity="HIGH")],
            "cvssMetricV40": [metric(9.8, "4.0", baseSeverity="CRITICAL")],
        }})
        result = merge_by_cve([record])[0]
        self.assertEqual((result.cvss_score, result.cvss_version, result.severity),
                         (9.8, "4.0", "CRITICAL"))
        self.assertEqual(result.cvss_vector, "CVSS:4.0/AV:N")
        self.assertEqual(result.cvss_source, "NVD")
        self.assertEqual(len(result.cvss_evidence), 2)
        self.assertEqual(result.cvss_evidence[0]["source_id"], record.source_id)

    def test_primary_nvd_metric_selected_over_secondary_and_invalid(self):
        secondary = metric(4.5)
        secondary.update(source="vendor@example.test", type="Secondary")
        result = merge_by_cve([item(raw_data={"metrics": {
            "cvssMetricV40": [metric(float("nan"), "4.0")],
            "cvssMetricV31": [secondary, metric(8.1)],
        }})])[0]
        self.assertEqual(result.cvss_score, 8.1)
        self.assertEqual(result.cvss_version, "3.1")
        self.assertEqual(result.cvss_evidence[0]["metric_publisher"], "nvd@nist.gov")

    def test_cvss_v2_does_not_use_v3_critical_band(self):
        result = merge_by_cve([item(raw_data={"metrics": {
            "cvssMetricV2": [metric(10, "2.0")],
        }})])[0]
        self.assertEqual(result.severity, "HIGH")

    def test_github_new_cvss_severities_and_nvd_precedence(self):
        advisory = item("GITHUB_ADVISORY", source_id="GHSA-1", raw_data={
            "cvss_severities": {
                "cvss_v4": {"score": 9.3, "vector_string": "CVSS:4.0/AV:N"},
                "cvss_v3": {"score": 8, "vector_string": "CVSS:3.1/AV:N"},
            },
        })
        result = merge_by_cve([advisory])[0]
        self.assertEqual((result.cvss_score, result.cvss_version), (9.3, "4.0"))
        nvd = item(raw_data={"metrics": {"cvssMetricV31": [metric(7.5)]}})
        result = merge_by_cve([advisory, nvd])[0]
        self.assertEqual((result.cvss_score, result.cvss_source), (7.5, "NVD"))
        self.assertEqual(len(result.cvss_evidence), 3)

    def test_multiple_same_source_records_survive_and_order_is_stable(self):
        records = [
            item("GITHUB_ADVISORY", source_id=f"GHSA-{name}", tags=[name, "advisory"],
                 raw_data={"ghsa_id": f"GHSA-{name}", "summary": name,
                           "vulnerabilities": [{"package": {"name": name, "ecosystem": "pip"}}]})
            for name in ("b", "a")
        ]
        first = merge_by_cve(records)[0]
        second = merge_by_cve(list(reversed(records)))[0]
        self.assertEqual(asdict(first), asdict(second))
        self.assertEqual(len(first.raw_by_source["GITHUB_ADVISORY"]), 2)
        self.assertEqual(first.ghsa_ids, ["GHSA-a", "GHSA-b"])
        self.assertEqual(len(first.source_evidence), 2)
        self.assertEqual(len(first.affected_packages), 2)
        single = merge_by_cve(records[:1])[0]
        self.assertIsInstance(single.raw_by_source["GITHUB_ADVISORY"], dict)

    def test_github_v3_family_does_not_invent_minor_version(self):
        advisory = item("GITHUB_ADVISORY", source_id="GHSA-1", raw_data={
            "cvss_severities": {"cvss_v3": {"score": 8.2}},
        })
        result = merge_by_cve([advisory])[0]
        self.assertEqual(result.cvss_score, 8.2)
        self.assertIsNone(result.cvss_version)
        self.assertIsNone(result.cvss_vector)

    def test_kev_admission_is_not_publication(self):
        kev = item("CISA_KEV", published_at="2026-10-08", raw_data={"dateAdded": "2026-10-08"})
        result = merge_by_cve([kev])[0]
        self.assertIsNone(result.published_at)
        self.assertIsNone(result.publication_source)
        self.assertEqual(result.kev_date_added, "2026-10-08")
        self.assertIsNone(result.source_evidence[0]["published_at"])

    def test_publication_is_earliest_actual_date_and_modification_latest(self):
        nvd = item(published_at="2026-10-08T02:00:00Z", modified_at="2026-10-08T02:00:00Z")
        github = item("GITHUB_ADVISORY", source_id="GHSA-1",
                      published_at="2026-10-08T09:00:00+08:00",
                      modified_at="2026-10-08T04:00:00Z")
        result = merge_by_cve([nvd, github])[0]
        self.assertEqual(result.published_at, github.published_at)
        self.assertEqual(result.publication_source, "GITHUB_ADVISORY")
        self.assertEqual(result.modified_at, github.modified_at)


class SQLiteStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "intel.db"
        self.store = SQLiteIntelligenceStore(self.db)

    def query(self, sql):
        with sqlite3.connect(self.db) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql)]

    def test_canonical_payload_matches_sql_key_without_mutating_collector(self):
        record = item(cve=" cve-2026-1234 ", source_id=" NVD-1 ",
                      raw_data={"id": "cve-2026-1234", "description": "original source"})
        original = asdict(record)
        counts = self.store.ingest_batch("NVD", [record])
        self.assertEqual(counts["new_cves"], 1)
        row = self.query("SELECT * FROM source_items")[0]
        payload = json.loads(row["payload_json"])
        self.assertEqual(payload["cve_id"], row["cve_id"])
        self.assertEqual(payload["source_id"], "NVD-1")
        self.assertEqual(asdict(record), original)
        result = self.store.get_vulnerability("cve-2026-1234")
        self.assertEqual(result["source_evidence"][0]["source_id"], "NVD-1")
        self.assertEqual(result["raw_by_source"]["NVD"], original["raw_data"])

    def test_cross_run_fusion_and_multiple_advisories_are_retained(self):
        self.store.ingest_batch("NVD", [item()])
        for name in ("a", "b"):
            self.store.ingest_batch("GITHUB_ADVISORY", [item(
                "GITHUB_ADVISORY", source_id=f"GHSA-{name}",
                raw_data={"ghsa_id": f"GHSA-{name}"})])
        self.store.ingest_batch("CISA_KEV", [item("CISA_KEV", raw_data={"dateAdded": "2026-10-08"})])
        result = self.store.get_vulnerability("CVE-2026-1234")
        self.assertEqual(self.store.stats()["source_records"], 4)
        self.assertEqual(set(result["sources"]), {"NVD", "GITHUB_ADVISORY", "CISA_KEV"})
        self.assertEqual(result["ghsa_ids"], ["GHSA-a", "GHSA-b"])
        self.assertTrue(result["known_exploited"])

    def test_cve_case_only_changes_are_deduplicated(self):
        self.store.ingest_batch("NVD", [item(cve=" cve-2026-1234 ", title="same")])
        counts = self.store.ingest_batch("NVD", [item(title="same")])
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(self.store.stats()["source_records"], 1)

    def test_unchanged_run_keeps_content_hash_and_timestamp_but_updates_liveness(self):
        record = item()
        with patch("storage.sqlite_store.utc_now", return_value="2026-10-08T01:00:00+00:00"):
            self.store.ingest_batch("NVD", [record])
        original = self.query("SELECT * FROM unified_vulnerabilities")[0]
        with patch("storage.sqlite_store.utc_now", return_value="2026-10-08T02:00:00+00:00"):
            counts = self.store.ingest_batch("NVD", [record])
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(counts["refreshed_cves"], 0)
        self.assertEqual(self.query("SELECT * FROM unified_vulnerabilities")[0], original)
        self.assertEqual(self.query("SELECT last_seen_at FROM source_items")[0]["last_seen_at"],
                         "2026-10-08T02:00:00+00:00")
        self.assertEqual(self.store.stats()["collectors"][0]["last_success_at"],
                         "2026-10-08T02:00:00+00:00")

    def test_first_seen_includes_lock_wait_and_fusion_processing_and_is_preserved(self):
        stamps = ['2026-10-08T01:00:00.000000+00:00', '2026-10-08T01:10:00.000000+00:00',
                  '2026-10-08T01:11:00.123456+00:00']
        with patch('storage.sqlite_store.utc_now', side_effect=stamps):
            self.store.ingest_batch('NVD', [item()])
        self.assertEqual(self.query('SELECT first_seen_at FROM source_items')[0]['first_seen_at'], stamps[-1])
        self.assertEqual(self.query('SELECT first_seen_at FROM unified_vulnerabilities')[0]['first_seen_at'], stamps[-1])
        self.assertEqual(self.query('SELECT finished_at FROM collector_runs')[0]['finished_at'], stamps[-1])
        with patch('storage.sqlite_store.utc_now', return_value='2026-10-08T02:00:00.000000+00:00'):
            self.store.ingest_batch('NVD', [item(description='updated')])
        self.assertEqual(self.query('SELECT first_seen_at FROM source_items')[0]['first_seen_at'], stamps[-1])
        self.assertEqual(self.query('SELECT first_seen_at FROM unified_vulnerabilities')[0]['first_seen_at'], stamps[-1])

    def test_batch_failure_rolls_back_sources_fusion_state_and_run(self):
        self.store.ingest_batch("NVD", [item()])
        before = self.store.stats()
        with self.assertRaisesRegex(ValueError, "source_id"):
            self.store.ingest_batch("NVD", [item(cve="CVE-2026-9999"), item(source_id=" ")])
        self.assertEqual(self.store.stats(), before)
        self.assertEqual(len(self.query("SELECT * FROM collector_runs")), 1)
        self.assertIsNone(self.store.get_vulnerability("CVE-2026-9999"))

    def test_successful_empty_batch_and_failure_do_not_delete_history(self):
        self.store.ingest_batch("NVD", [item()])
        counts = self.store.ingest_batch("NVD", [])
        self.assertEqual(counts["fetched"], 0)
        self.store.record_failure("NVD", "offline fixture failure")
        self.assertEqual(self.store.stats()["unified_cves"], 1)
        self.assertEqual(self.store.stats()["collectors"][0]["last_fetched_count"], 0)
        self.assertEqual([r["status"] for r in self.query("SELECT status FROM collector_runs ORDER BY id")],
                         ["success", "success", "failed"])

    def test_source_cve_reassignment_refreshes_both_groups(self):
        self.store.ingest_batch("NVD", [item(source_id="record-1")])
        counts = self.store.ingest_batch("NVD", [item(cve="CVE-2026-9999", source_id="record-1")])
        self.assertEqual(counts["refreshed_cves"], 2)
        self.assertIsNone(self.store.get_vulnerability("CVE-2026-1234"))
        self.assertIsNotNone(self.store.get_vulnerability("CVE-2026-9999"))

    def test_explicit_rebuild_repairs_legacy_payload_and_is_idempotent(self):
        self.store.ingest_batch("NVD", [item()])
        with sqlite3.connect(self.db) as connection:
            row = connection.execute("SELECT payload_json FROM source_items").fetchone()
            payload = json.loads(row[0])
            payload["cve_id"] = "cve-2026-1234"
            connection.execute("UPDATE source_items SET payload_json=?", (json.dumps(payload),))
            connection.execute("UPDATE unified_vulnerabilities SET payload_json='{}', content_sha256='old'")
        counts = self.store.rebuild_unified()
        self.assertEqual(counts, {"refreshed_cves": 1, "new_cves": 0})
        self.assertEqual(self.store.get_vulnerability("CVE-2026-1234")["cve_id"], "CVE-2026-1234")
        before = self.query("SELECT * FROM unified_vulnerabilities")
        self.store.rebuild_unified()
        self.assertEqual(self.query("SELECT * FROM unified_vulnerabilities"), before)

    def test_rebuild_failure_is_transactional(self):
        self.store.ingest_batch("NVD", [item(), item(cve="CVE-2026-9999")])
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE unified_vulnerabilities SET payload_json='{}', content_sha256='old'")
            connection.execute("UPDATE source_items SET payload_json='{}' WHERE cve_id='CVE-2026-9999'")
        before = self.query("SELECT * FROM unified_vulnerabilities ORDER BY cve_id")
        with self.assertRaises(TypeError):
            self.store.rebuild_unified()
        self.assertEqual(self.query("SELECT * FROM unified_vulnerabilities ORDER BY cve_id"), before)


if __name__ == "__main__":
    unittest.main()
