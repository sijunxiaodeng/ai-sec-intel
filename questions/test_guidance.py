import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.citation_guard import claim_issues
from agents.qa_agent import _guidance_lines, _render_model_json, run as answer
from agents.verifier_agent import required_fields, run as verify
from enrichment.guidance import formatted_facts, library_for, refresh, report
from rag.evidence import DEFAULT_DB, _connection
from rag.library import LIBRARY_DB, ingest_document, search, verified_sources

A, B = "CVE-2024-37032", "CVE-2025-0312"


class GuidanceTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.candidate = {"url": "https://www.wiz.io/blog/fixture-" + A.lower(),
                          "source_id": "fixture", "source_name": "Wiz Research", "document_type": "research_article"}
        self.title = "Ollama security research " + A
        self.article = (A + " is an Ollama AI model security vulnerability. "
                        "We recommend users upgrade Ollama to version 0.1.34 or newer. "
                        "Ollama does not support authentication out-of-the-box. "
                        "Deploy Ollama behind a reverse-proxy to enforce authentication.")
        self.body = self.html()

    def html(self):
        return ("<html><head><title>" + self.title + "</title></head><body><article><h1>" + self.title +
                "</h1><p>" + self.article + "</p></article></body></html>").encode()

    def fetch(self, url):
        return {"body": self.body, "url": url, "content_type": "application/json" if self.candidate["document_type"] == "vendor_advisory" else "text/html"}

    def ingest(self):
        result = ingest_document(self.candidate, self.db, self.fetch)
        self.assertEqual(result["status"], "ok", result)
        return result

    def guidance(self, cve=A, product="ollama"):
        return report(cve, product, self.db)

    def vendor(self, *, product="ollama", patched=">=0.1.34", extra_cve=False):
        url = "https://github.com/vllm-project/vllm/security/advisories/GHSA-abcd-efgh-ijkl"
        self.candidate = dict(self.candidate, url=url, source_name="vLLM project", document_type="vendor_advisory")
        self.payload = {"state": "published", "ghsa_id": "GHSA-abcd-efgh-ijkl", "html_url": url,
                        "summary": "AI security fixture", "description": "The Ollama AI model server requires network access to exploit this vulnerability.",
                        "identifiers": [{"type": "CVE", "value": A}],
                        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": product},
                                             "vulnerable_version_range": "<0.1.34", "patched_versions": patched}]}
        if extra_cve:
            self.payload["identifiers"].append({"type": "CVE", "value": B})
        self.body = json.dumps(self.payload).encode()
        self.ingest()

    def test_research_upgrade_retains_research_authority(self):
        self.ingest()
        g = self.guidance()
        facts = formatted_facts(g, {"remediation"})
        self.assertIn("研究方升级建议（Wiz Research）：ollama 版本 >=0.1.34。", [r["text"] for r in facts])
        self.assertFalse(g["vendor_patched_ranges"])
        self.assertTrue(all(r["authority"] == "research_recommendation" for r in g["facets"]["remediation"]))

    def test_background_mention_does_not_prove_upgrade(self):
        self.title = "AI security research overview"
        self.body = self.html()
        self.ingest()
        self.assertEqual(self.guidance()["status"], "empty")
        self.assertEqual(len(self.guidance()["sources"]), 1)

    def test_article_with_multiple_cves_does_not_bind_product_sentence(self):
        self.article += " Related work also mentions " + B + "."
        self.body = self.html()
        self.ingest()
        self.assertEqual(self.guidance()["status"], "empty")

    def test_sentence_about_other_product_does_not_bind_target(self):
        self.article = A + " concerns Ollama AI security. Upgrade Ollama and vLLM to version 0.1.34 or newer."
        self.body = self.html()
        self.ingest()
        self.assertEqual(self.guidance()["facets"]["remediation"], [])

    def test_negative_upgrade_sentence_is_not_formatted_as_positive_recommendation(self):
        self.article = A + " concerns Ollama AI security. We recommend users not upgrade Ollama to version 0.1.34 or newer."
        self.body = self.html()
        self.ingest()
        self.assertFalse(any(r["structured_value"] for r in self.guidance()["facets"]["remediation"]))

    def test_encouraged_upgrade_and_historical_scan_are_separated(self):
        self.article = (A + " concerns Ollama AI security. Ollama users are encouraged to upgrade their Ollama installation to version 0.1.34 or newer. "
                        "When scanning the internet, our scan revealed over 1,000 exposed Ollama instances.")
        self.body = self.html()
        self.ingest()
        g = self.guidance()
        self.assertEqual(g["facets"]["remediation"][0]["structured_value"]["recommended_version_range"], ">=0.1.34")
        self.assertEqual(g["facets"]["conditions"], [])

    def test_vendor_explicit_patch_field_keeps_package_and_range(self):
        self.vendor()
        g = self.guidance()
        self.assertEqual(g["vendor_patched_ranges"][0]["range"], ">=0.1.34")
        self.assertEqual(g["facets"]["versions"][0]["structured_value"]["package"]["name"], "ollama")

    def test_excluded_upper_bound_does_not_create_patch_field(self):
        self.vendor(patched=None)
        g = self.guidance()
        self.assertEqual(g["vendor_patched_ranges"], [])
        self.assertEqual(g["facets"]["remediation"], [])

    def test_package_mismatch_does_not_supply_versions(self):
        self.vendor(product="transformers")
        g = self.guidance()
        self.assertEqual(g["facets"]["versions"], [])
        self.assertEqual(g["vendor_patched_ranges"], [])
        self.assertEqual(g["facets"]["conditions"], [])

    def test_multi_cve_advisory_requires_manual_binding(self):
        self.vendor(extra_cve=True)
        self.assertEqual(self.guidance()["status"], "empty")

    def test_mutated_index_tags_do_not_associate_different_cve(self):
        self.vendor()
        with _connection(self.db) as conn:
            doc_id, raw = conn.execute("SELECT document_id,payload FROM library_documents").fetchone()
            doc = json.loads(raw)
            doc["declared_cve_ids"] = [B]
            doc["associations"] = [{"entity_id": B, "relation": "publisher_declared_identifier"}]
            conn.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(doc), doc_id))
        self.assertTrue(self.guidance()["vendor_patched_ranges"])
        self.assertEqual(self.guidance(B)["status"], "empty")

    def test_bad_raw_snapshot_is_not_used(self):
        self.ingest()
        with _connection(self.db) as conn:
            conn.execute("UPDATE library_snapshots SET body=?", (b"tampered source",))
        self.assertEqual(self.guidance()["status"], "empty")

    def test_changed_index_fragment_cannot_forge_reparsed_fact(self):
        self.ingest()
        with _connection(self.db) as conn:
            conn.execute("UPDATE evidence SET payload=?", ('{"text":"Ollama is fixed in 9.9.9"}',))
        facts = formatted_facts(self.guidance(), {"remediation"})
        self.assertTrue(facts)
        self.assertNotIn("9.9.9", str(facts))

    def test_known_withdrawal_survives_later_timeout_until_new_published_source(self):
        self.vendor()
        self.payload["withdrawn_at"] = "2026-10-09T01:00:00Z"
        self.body = json.dumps(self.payload).encode()
        self.assertTrue(ingest_document(self.candidate, self.db, self.fetch)["invalidated_previous"])
        self.assertEqual(self.guidance()["status"], "empty")
        def fail(url):
            raise TimeoutError("timeout")
        ingest_document(self.candidate, self.db, fail)
        self.assertEqual(self.guidance()["status"], "empty")
        self.assertEqual(search(A, db_path=self.db)["evidence"], [])
        self.payload.pop("withdrawn_at")
        self.body = json.dumps(self.payload).encode()
        self.ingest()
        self.assertTrue(self.guidance()["vendor_patched_ranges"])

    def test_refresh_failure_retains_dated_source(self):
        self.ingest()
        def fail(url):
            raise TimeoutError("timeout")
        ingest_document(self.candidate, self.db, fail)
        self.assertTrue(self.guidance()["sources"][0]["retained_previous"])
        self.assertTrue(self.guidance()["sources"][0]["retrieved_at"])

    def test_exact_formatted_fact_passes_but_authority_upgrade_fails(self):
        self.ingest()
        fact = formatted_facts(self.guidance(), {"remediation"})[0]
        self.assertFalse(claim_issues(fact["text"], fact["chunks"]))
        self.assertTrue(claim_issues("厂商确认 Ollama 0.1.34 已修复此漏洞。", fact["chunks"]))
        self.assertTrue(claim_issues(fact["text"].replace("0.1.34", "0.1.33"), fact["chunks"]))
        other = formatted_facts(self.guidance(), {"conditions"})[0]
        self.assertTrue(claim_issues(fact["text"], fact["chunks"] + other["chunks"]))

    def test_model_cannot_cite_only_patch_record_and_omit_upgrade(self):
        self.ingest()
        record = {"item": {"cve_id": A, "raw_data": {"related_guidance": self.guidance()}}}
        question = A + " 应该升级到哪个版本？"
        self.assertTrue(required_fields("关联修复记录：PR 4175", [record], question))
        lines = _guidance_lines(record, question)
        self.assertFalse(required_fields("\n".join(lines), [record], question))

    def test_model_rewrite_falls_back_with_cited_upgrade_and_local_state(self):
        self.ingest()
        record = {"item": {"cve_id": A, "raw_data": {"related_guidance": self.guidance()}}}
        _guidance_lines(record, A + " 升级版本")
        eid = record["evidence_chunks"][0]["citation_id"]
        raw = json.dumps({"claims": [{"text": "厂商确认 0.1.34 已修复。", "citations": [eid]}]})
        with patch("agents.qa_agent.search", return_value=[record]), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=raw):
            result = answer(A + " 升级版本")
        self.assertFalse(result["used_model"])
        self.assertTrue(result["model_attempted"])
        self.assertIn("研究方升级建议", result["answer"])
        self.assertIn("本项目未测试", result["answer"])
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])

    def test_production_library_is_not_implicitly_used_by_independent_evaluation(self):
        self.assertEqual(library_for(DEFAULT_DB), LIBRARY_DB)
        self.assertIsNone(library_for(self.db))

    def test_refresh_whitelist_and_source_errors_are_separate(self):
        record = {"item": {"cve_id": A, "product": "ollama"}, "references": [self.candidate["url"], "https://unknown.example/ai-security"]}
        with patch("rag.hybrid.update_index", return_value={"status": "fixture"}):
            result = refresh(record, self.db, fetcher=self.fetch, db_path=self.db)
        self.assertEqual(result["attempted"], 1)
        self.assertEqual(result["ok"], 1)
        self.assertEqual(result["guidance"]["status"], "ok")

    def test_plain_text_source_can_be_verified(self):
        self.body = self.article.encode()
        result = ingest_document(self.candidate, self.db, lambda url: {"url": url, "body": self.body, "content_type": "text/plain"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(verified_sources(self.db)), 1)

    def test_guidance_api_missing_record_and_refresh(self):
        from fastapi import HTTPException
        from api.app import related_guidance, refresh_guidance
        with patch("api.app.get_record", return_value=None):
            with self.assertRaises(HTTPException) as error:
                related_guidance(A)
            self.assertEqual(error.exception.status_code, 404)
        self.ingest()
        record = {"item": {"cve_id": A, "raw_data": {"related_guidance": self.guidance()}}}
        with patch("api.app.get_record", return_value=record), patch("enrichment.guidance.refresh", return_value={"ok": 1}):
            self.assertEqual(related_guidance(A)["status"], "ok")
            self.assertEqual(refresh_guidance(A), {"ok": 1})


if __name__ == "__main__":
    unittest.main()
