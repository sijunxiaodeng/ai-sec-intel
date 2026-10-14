"""Synthetic snapshot tests; these are not independent enrichment accuracy."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from enrichment.assessment import assess, enrich_view
from enrichment.documents import digest
from enrichment.history import catalogue, components, related, weaknesses
from enrichment.sample import load_sample
from rag.ingest import ingest


class HistoryTest(unittest.TestCase):
    TARGET = "CVE-2026-90000"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / "evidence.sqlite3"

    def source(self, cve_id, published="2026-01-01T00:00:00Z", *, vendor="ollama", product="ollama", cwe="CWE-22"):
        record, _ = load_sample()
        record["item"].update(id=cve_id, cve_id=cve_id, references=[])
        record["references"] = []
        record["item"]["raw_data"]["related_documents"] = []
        cve = {"id": cve_id, "published": published,
               "descriptions": [{"lang": "en", "value": "Synthetic local snapshot for component and weakness tests."}],
               "weaknesses": [{"source": "vendor@example.org", "type": "Primary",
                               "description": [{"lang": "en", "value": cwe}]}],
               "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True,
                   "criteria": "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*" % (vendor, product),
                   "versionEndExcluding": "1.0.0"}]}]}]}
        return record, cve

    def save(self, record, cve):
        ingest(record, self.db, max_sources=1, update_index_on_ingest=False,
               fetcher=lambda url: {"body": json.dumps({"vulnerabilities": [{"cve": cve}]}).encode(),
                                    "content_type": "application/json", "url": url})

    def report(self, target):
        return assess(target, self.db)["historical_relations"]

    def test_history_requires_same_component_and_older_publication(self):
        target = self.source(self.TARGET, "2026-02-01T00:00:00")
        earlier = self.source("CVE-2025-90001")
        later = self.source("CVE-2025-90002", "2026-02-02T00:00:00Z")
        other_vendor = self.source("CVE-2025-90003", vendor="another")
        other_product = self.source("CVE-2025-90004", product="vllm")
        equal_time = self.source("CVE-2025-90005", "2026-02-01T00:00:00Z")
        for record, cve in (target, earlier, later, other_vendor, other_product, equal_time):
            self.save(record, cve)
        result = self.report(self.TARGET)
        self.assertEqual([r["cve_id"] for r in result["items"]], [earlier[1]["id"]])
        item = result["items"][0]
        self.assertEqual(item["association"], "same_component_and_weakness")
        self.assertEqual(item["review_status"], "not_reviewed")
        self.assertIn("未证明漏洞同源", item["notice"])
        ids = {r["citation_id"] for r in result["evidence"]}
        self.assertTrue(set(item["evidence_ids"]) <= ids)
        for basis in item["match_basis"]:
            self.assertTrue(set(basis["evidence_ids"]) <= ids)
        self.assertEqual({r["cve_id"] for r in result["evidence"]}, {self.TARGET, earlier[1]["id"]})
        self.assertIsNone(result["independent_precision"])

    def test_same_weakness_prioritizes_but_is_not_required(self):
        values = [self.source(self.TARGET, "2026-02-01T00:00:00Z"),
                  self.source("CVE-2025-90001", "2026-01-01T00:00:00Z"),
                  self.source("CVE-2025-90002", "2026-01-30T00:00:00Z", cwe="CWE-502")]
        for record, cve in values:
            self.save(record, cve)
        result = self.report(self.TARGET)
        self.assertEqual([r["cve_id"] for r in result["items"]], ["CVE-2025-90001", "CVE-2025-90002"])
        self.assertEqual(result["items"][1]["association"], "same_component")

    def test_missing_or_invalid_published_time_prevents_historical_claim(self):
        target = self.source(self.TARGET, "invalid")
        self.save(*target)
        self.save(*self.source("CVE-2025-90001"))
        self.assertEqual(self.report(self.TARGET)["status"], "insufficient_context")
        target[1]["published"] = "2026-02-01T00:00:00Z"
        self.save(*target)
        self.save(*self.source("CVE-2025-90001", None))
        self.assertEqual(self.report(self.TARGET)["items"], [])

    def test_timezone_offsets_compare_actual_utc_times(self):
        self.save(*self.source(self.TARGET, "2026-02-01T00:00:00Z"))
        self.save(*self.source("CVE-2025-90001", "2026-02-01T01:00:00+02:00"))
        self.assertEqual(self.report(self.TARGET)["items"][0]["cve_id"], "CVE-2025-90001")

    def test_tampered_snapshot_or_wrong_document_binding_is_excluded(self):
        self.save(*self.source(self.TARGET, "2026-02-01T00:00:00Z"))
        self.save(*self.source("CVE-2025-90001"))
        self.save(*self.source("CVE-2025-90002"))
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE source_snapshots SET body=? WHERE cve_id=?", (b"{}", "CVE-2025-90001"))
            payload = json.loads(conn.execute("SELECT payload FROM documents WHERE cve_id=?", ("CVE-2025-90002",)).fetchone()[0])
            payload["url"] = "https://example.org/untrusted"
            conn.execute("UPDATE documents SET payload=? WHERE cve_id=?", (json.dumps(payload), "CVE-2025-90002"))
        result = self.report(self.TARGET)
        self.assertEqual(result["items"], [])
        self.assertEqual(result["coverage"]["invalid_snapshots"], 2)

    def test_snapshot_payload_with_wrong_cve_does_not_create_candidate(self):
        self.save(*self.source(self.TARGET, "2026-02-01T00:00:00Z"))
        record, cve = self.source("CVE-2025-90001")
        self.save(record, cve)
        with sqlite3.connect(self.db) as conn:
            body = json.dumps({"vulnerabilities": [{"cve": dict(cve, id="CVE-2025-90002")}]}).encode()
            sha = hashlib.sha256(body).hexdigest()
            doc = json.loads(conn.execute("SELECT payload FROM documents WHERE cve_id=?", (cve["id"],)).fetchone()[0])
            doc["source_response_sha256"] = sha
            conn.execute("UPDATE source_snapshots SET digest=?,body=? WHERE cve_id=?", (sha, body, cve["id"]))
            conn.execute("UPDATE documents SET payload=? WHERE cve_id=?", (json.dumps(doc), cve["id"]))
        self.assertEqual(self.report(self.TARGET)["items"], [])

    def test_dependency_negation_wildcards_and_non_cpe_are_not_components(self):
        record, cve = self.source(self.TARGET)
        node = cve["configurations"][0]["nodes"][0]
        node["cpeMatch"][0]["vulnerable"] = False
        self.assertEqual(components(cve), {})
        node["cpeMatch"][0]["vulnerable"] = True
        node["negate"] = True
        self.assertEqual(components(cve), {})
        node.pop("negate")
        for criteria in ("cpe:2.3:a:*:ollama:*:*:*:*:*:*:*:*", "not-cpe", "cpe:2.3:a:ollama:ollama"):
            node["cpeMatch"][0]["criteria"] = criteria
            self.assertEqual(components(cve), {})

    def test_and_environment_requirement_is_explicit(self):
        target = self.source(self.TARGET, "2026-02-01T00:00:00Z")
        target[1]["configurations"][0]["operator"] = "AND"
        self.save(*target)
        self.save(*self.source("CVE-2025-90001"))
        basis = self.report(self.TARGET)["items"][0]["match_basis"]
        self.assertTrue(next(r for r in basis if r["kind"] == "same_component")["requires_environment_review"])

    def test_directory_limits_and_missing_db_are_explicit_without_writes(self):
        catalog = catalogue(self.db)
        self.assertFalse(self.db.exists())
        self.assertEqual(catalog["sources"], {})
        self.save(*self.source(self.TARGET, "2026-02-01T00:00:00Z"))
        self.save(*self.source("CVE-2025-90001"))
        catalog = catalogue(self.db, max_candidates=1)
        self.assertTrue(catalog["truncated"])
        self.assertEqual(catalog["examined_cves"], 1)
        with patch("enrichment.history.MAX_CATALOG_BYTES", 1):
            catalog = catalogue(self.db)
        self.assertTrue(catalog["truncated"])
        self.assertEqual(catalog["verified_nvd_snapshots"], 0)
        for value in (0, 401, True):
            with self.assertRaises(ValueError):
                catalogue(self.db, max_candidates=value)

    def test_bulk_view_builds_one_catalog_and_keeps_records_unmodified(self):
        records = []
        for source in (self.source(self.TARGET, "2026-02-01T00:00:00Z"), self.source("CVE-2025-90001")):
            self.save(*source)
            records.append(source[0])
        original = copy.deepcopy(records)
        with patch("enrichment.assessment.catalogue", wraps=catalogue) as build:
            result = enrich_view(records, self.db)
        self.assertEqual(build.call_count, 1)
        self.assertEqual(records, original)
        self.assertTrue(result[0]["item"]["raw_data"]["automatic_assessment"]["historical_relations"]["items"])

    def test_catalog_failure_is_visible_but_other_facts_are_kept(self):
        record, cve = self.source(self.TARGET)
        self.save(record, cve)
        with patch("enrichment.assessment.catalogue", side_effect=sqlite3.OperationalError("unavailable")):
            result = enrich_view([record], self.db)[0]["item"]["raw_data"]["automatic_assessment"]
        self.assertEqual(result["historical_relations"]["status"], "error")
        self.assertEqual(result["weaknesses"][0]["cwe_id"], "CWE-22")

    def test_weaknesses_preserve_providers_and_ignore_nvd_sentinels(self):
        record, cve = self.source(self.TARGET)
        cve["weaknesses"] += [{"source": "another@example.org", "type": "Secondary", "description": [
            {"lang": "en", "value": "CWE-22"}, {"lang": "en", "value": "NVD-CWE-noinfo"},
            {"lang": "en", "value": "CWE-0"}, {"lang": "en", "value": "CWE-22 extra"}]}]
        self.save(record, cve)
        report = assess(self.TARGET, self.db)
        self.assertEqual([r["cwe_id"] for r in report["weaknesses"]], ["CWE-22", "CWE-22"])
        self.assertEqual({r["provider"] for r in report["weaknesses"]}, {"vendor@example.org", "another@example.org"})
        returned = {r["citation_id"]: r for r in report["evidence"]}
        for weakness in report["weaknesses"]:
            citation = returned[weakness["evidence_ids"][0]]
            self.assertEqual(citation["source_response_sha256"], report["source"]["sha256"])
            self.assertIn(weakness["provider"], citation["text"])
            self.assertEqual(weakness["taxonomy_url"], "https://cwe.mitre.org/data/definitions/22.html")


if __name__ == "__main__":
    unittest.main()
