"""Local source-bound association checks; synthetic input, no network/models."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from enrichment.article_candidates import query_profile, report
from enrichment.documents import digest
from rag.evidence import _connection
from rag.library import ingest_document, search as actual_search

A = "CVE-2024-37032"


class ArticleCandidatesTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / "library.sqlite3"
        self.evidence_db = Path(temporary.name) / "evidence.sqlite3"
        self.record = {"item": {"cve_id": A, "product": "ollama", "description": "Ollama AI model server has a path traversal vulnerability.", "raw_data": {}}}
        self.network = patch("urllib.request.urlopen", side_effect=AssertionError("network disabled"))
        self.network_mock = self.network.start()
        self.addCleanup(self.network.stop)
        self.dense = patch("rag.library._dense", side_effect=RuntimeError("local model unavailable"))
        self.dense.start()
        self.addCleanup(self.dense.stop)

    def ingest(self, text, *, paper=False, number=0):
        if paper:
            url = "https://arxiv.org/abs/2401.%05d" % (number + 1)
            title = "AI security path traversal research"
            body = ('<html><head><meta name="citation_title" content="' + title + '"></head><body>'
                    '<blockquote class="abstract">Abstract: ' + text * 3 + '</blockquote></body></html>').encode()
            content_type = "text/html"
        else:
            url = "https://research.example/local-fixture-%d" % number
            body, content_type = (text * 3).encode(), "text/plain"
        candidate = {"url": url, "source_id": "fixture", "source_name": "Synthetic research", "document_type": "academic_paper" if paper else "research_article"}
        result = ingest_document(candidate, self.db, lambda value: {"url": value, "body": body, "content_type": content_type})
        self.assertEqual(result["status"], "ok", result)
        return result["document_id"], candidate, body, content_type

    def candidates(self, **kwargs):
        return report(self.record, library_db=self.db, evidence_db=None, **kwargs)

    def test_non_cve_paper_and_blog_are_both_local_semantic_candidates(self):
        self.ingest("LLM security research covers directory traversal in AI model storage. ", paper=True)
        self.ingest("Ollama AI security research covers directory traversal and unsafe file paths. ")
        before = copy.deepcopy(self.record)
        result = self.candidates()
        self.assertEqual({row["category"] for row in result["items"]}, {"paper", "blog"})
        self.assertTrue(all(row["status"] == "semantic_candidate" and not row["explicit_cve_mention"] for row in result["items"]))
        self.assertEqual(self.record, before)
        self.assertIsNone(result["independent_recall"])
        self.network_mock.assert_not_called()

    def test_same_product_without_security_mechanism_is_not_related(self):
        self.ingest("Ollama AI security research discusses watermark labeling and content governance. ")
        self.assertEqual(self.candidates()["items"], [])

    def test_mechanism_query_is_not_filtered_by_product_or_cve(self):
        self.ingest("LLM security path traversal protection is considered for another AI service. ", paper=True)
        with patch("enrichment.article_candidates.search", wraps=actual_search) as searched:
            result = self.candidates()
        self.assertTrue(result["items"])
        for call in searched.call_args_list:
            self.assertNotIn("cve_id", call.kwargs)
            self.assertNotIn(A, call.args[0])
        self.assertTrue(any(row["query_kind"] == "mechanism" and "ollama" not in row["query"].lower() for row in result["retrieval"]))

    def test_cwe_query_and_cwe_evidence_are_preserved(self):
        self.record["item"]["description"] = "Ollama AI model storage security issue."
        self.record["item"]["raw_data"]["weaknesses"] = [{"description": [{"value": "CWE-22"}]}]
        self.ingest("LLM security analysis refers to CWE-22 without describing a specific CVE. ")
        result = self.candidates()
        self.assertEqual(result["profile"]["cwe_ids"], ["CWE-22"])
        self.assertTrue(any(row["query_kind"] == "cwe" for row in result["retrieval"]))
        self.assertTrue(any(row["kind"] == "cwe" for row in result["items"][0]["match_basis"]))

    def test_cwe_can_be_read_from_matching_immutable_nvd_snapshot(self):
        self.record["item"]["description"] = "Ollama AI security issue."
        payload = {"vulnerabilities": [{"cve": {"id": A, "weaknesses": [{"description": [{"value": "CWE-502"}]}]}}]}
        body = json.dumps(payload).encode()
        sid = digest("https://nvd.nist.gov/vuln/detail/" + A)[:16]
        with _connection(self.evidence_db) as conn:
            conn.execute("CREATE TABLE source_snapshots(cve_id TEXT,source_id TEXT,digest TEXT,body BLOB)")
            conn.execute("INSERT INTO source_snapshots VALUES (?,?,?,?)", (A, sid, hashlib.sha256(body).hexdigest(), body))
        profile, _ = query_profile(self.record, self.evidence_db)
        self.assertEqual(profile["cwe_ids"], ["CWE-502"])
        with _connection(self.evidence_db) as conn:
            conn.execute("UPDATE source_snapshots SET body=?", (b"forged source",))
        self.assertEqual(query_profile(self.record, self.evidence_db)[0]["cwe_ids"], [])

    def test_complete_cve_mention_is_separate_and_prefix_is_not_a_mention(self):
        self.record["item"]["description"] = "Ollama AI security."
        exact, _, _, _ = self.ingest("Ollama AI security article merely mentions " + A + " in related work. ")
        for n, fake in enumerate([A + "1", "X" + A, A + "_suffix", A + "-extra"], 1):
            self.ingest("Ollama AI security article merely mentions " + fake + " in related work. ", number=n)
        items = self.candidates()["items"]
        self.assertEqual([row["document_id"] for row in items], [exact])
        self.assertTrue(items[0]["explicit_cve_mention"])
        self.assertEqual(items[0]["association"], "explicit_cve_mention")
        self.assertEqual(items[0]["status"], "semantic_candidate")

    def test_candidate_returns_exact_snippets_locations_and_snapshot_hashes(self):
        _, _, body, _ = self.ingest("Ollama AI security path traversal is described as a research mechanism. ")
        item = self.candidates()["items"][0]
        self.assertEqual(item["source_response_sha256"], hashlib.sha256(body).hexdigest())
        self.assertTrue(item["evidence_ids"])
        ids = set(item["evidence_ids"])
        for row in item["evidence"]:
            self.assertIn(row["citation_id"], ids)
            self.assertTrue(row["locator"])
            self.assertEqual(row["text_sha256"], digest(row["text"]))
            self.assertEqual(row["source_response_sha256"], item["source_response_sha256"])
        self.assertTrue(all(row["citation_id"] in ids for row in item["match_basis"]))
        for forbidden in ["affected_ranges", "cvss", "fixed_version", "asset_impact"]:
            self.assertNotIn(forbidden, item)

    def test_changed_source_recomputes_and_does_not_keep_old_candidate(self):
        doc_id, candidate, _, _ = self.ingest("Ollama AI security path traversal research. ")
        self.assertTrue(self.candidates()["items"])
        body = b"Ollama AI security research now only covers watermark governance and labeling." * 3
        ingest_document(candidate, self.db, lambda url: {"url": url, "body": body, "content_type": "text/plain"})
        self.assertFalse(any(row["document_id"] == doc_id for row in self.candidates()["items"]))

    def test_invalid_raw_snapshot_is_excluded(self):
        self.ingest("Ollama AI security path traversal research. ")
        with _connection(self.db) as conn:
            conn.execute("UPDATE library_snapshots SET body=?", (b"corrupt bytes",))
        self.assertEqual(self.candidates()["items"], [])

    def test_forged_self_consistent_index_text_does_not_become_source_evidence(self):
        self.ingest("Ollama AI security research covers watermark governance. ")
        with _connection(self.db) as conn:
            for eid, raw in conn.execute("SELECT evidence_id,payload FROM evidence").fetchall():
                row = json.loads(raw)
                row["text"] = "Ollama AI security path traversal " + A
                row["text_sha256"] = digest(row["text"])
                row["search_terms"] = row["text"]
                conn.execute("UPDATE evidence SET payload=? WHERE evidence_id=?", (json.dumps(row), eid))
        self.assertEqual(self.candidates()["items"], [])

    def test_known_invalidation_is_excluded_but_timeout_retains_dated_source(self):
        doc_id, candidate, _, _ = self.ingest("Ollama AI security path traversal research. ")
        def fail(url):
            raise TimeoutError("fixture timeout")
        ingest_document(candidate, self.db, fail)
        row = self.candidates()["items"][0]
        self.assertTrue(row["retained_previous"])
        self.assertTrue(row["retrieved_at"])
        with _connection(self.db) as conn:
            attempt = json.loads(conn.execute("SELECT payload FROM library_attempts WHERE document_id=?", (doc_id,)).fetchone()[0])
            attempt["invalidated_previous"] = True
            conn.execute("UPDATE library_attempts SET payload=? WHERE document_id=?", (json.dumps(attempt), doc_id))
        self.assertEqual(self.candidates()["items"], [])

    def test_queries_and_output_are_bounded_per_document_kind(self):
        self.record["item"]["raw_data"]["cwe"] = "CWE-22"
        for number in range(4):
            self.ingest("Ollama AI security path traversal research. ", number=number)
            self.ingest("LLM security path traversal research. ", number=number, paper=True)
        with patch("enrichment.article_candidates.search", wraps=actual_search) as searched:
            result = self.candidates(top_k=2)
        self.assertLessEqual(searched.call_count, 6)
        self.assertTrue(all(call.kwargs["top_k"] == 20 for call in searched.call_args_list))
        self.assertEqual(sum(row["category"] == "paper" for row in result["items"]), 2)
        self.assertEqual(sum(row["category"] == "blog" for row in result["items"]), 2)

    def test_missing_library_and_missing_context_are_not_negative_findings(self):
        self.assertEqual(self.candidates()["status"], "empty")
        self.assertIn("不代表", self.candidates()["detail"])
        self.record["item"].update(product="llm", description="AI security overview")
        with patch("enrichment.article_candidates.search") as searched:
            result = self.candidates()
        self.assertEqual(result["status"], "insufficient_context")
        searched.assert_not_called()

    def test_incidental_validation_checklist_is_not_related_research(self):
        self.ingest("This Ollama AI security skill follows good security practices: path traversal validation for PROJECT_DIR and idempotent file writes. ")
        self.assertEqual(self.candidates()["items"], [])

    def test_partial_local_failure_does_not_erase_other_candidates(self):
        self.ingest("Ollama AI security path traversal research. ")
        def dispatch(query, **kwargs):
            if kwargs["document_type"] == "academic_paper":
                raise RuntimeError("fixture unavailable")
            return actual_search(query, **kwargs)
        with patch("enrichment.article_candidates.search", side_effect=dispatch):
            result = self.candidates()
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["items"])
        self.assertTrue(result["warnings"])

    def test_team_summary_keeps_its_own_snapshot_identity_and_scope(self):
        from collectors.team_documents import TEAM_MEDIA
        from questions.test_team_documents import record as team_record
        source = team_record()
        source["description"] = "Ollama AI security research summary discusses path traversal."
        source["cve_ids"] = [A]  # API tags alone must not count as a source mention
        body = json.dumps(source).encode()
        candidate = {"url": source["url"], "source_id": "fixture", "source_name": source["source"],
                     "document_type": "research_article", "team_document_id": source["document_id"]}
        ingest_document(candidate, self.db, lambda url: {"url": "http://127.0.0.1:8023/api/intelligence/documents/" + source["document_id"], "body": body, "content_type": TEAM_MEDIA})
        item = self.candidates()["items"][0]
        self.assertEqual(item["content_scope"], "team_summary")
        self.assertFalse(item["explicit_cve_mention"])
        self.assertEqual(item["evidence"][0]["source_snapshot_kind"], "team_api_record")
        self.assertIn("/api/intelligence/documents/", item["evidence"][0]["snapshot_url"])

    def test_prepared_local_hybrid_retrieval_keeps_candidate_contract(self):
        self.ingest("Ollama AI security path traversal research. ")
        def dense(query, rows, db_path):
            return [dict(row, cosine_score=.8) for row in rows]
        with patch("rag.library._dense", side_effect=dense):
            result = self.candidates()
        self.assertTrue(result["items"])
        self.assertTrue(all(row["mode"] == "hybrid" for row in result["retrieval"] if row["document_type"] == "research_article"))
        self.assertFalse(result["model_attempted"])

    def test_non_utf8_source_is_reparsed_with_its_saved_encoding(self):
        text = "Ollama 模型安全研究说明目录遍历风险，这是一份用于验证编码保留的研究资料。" * 4
        url = "https://research.example/gb18030-fixture"
        candidate = {"url": url, "source_id": "fixture", "source_name": "Synthetic research", "document_type": "research_article"}
        result = ingest_document(candidate, self.db, lambda value: {"url": value, "body": text.encode("gb18030"), "content_type": "text/plain", "encoding": "gb18030"})
        self.assertEqual(result["status"], "ok")
        items = self.candidates()["items"]
        self.assertEqual(len(items), 1)
        self.assertTrue(any("目录遍历风险" in row["text"] for row in items[0]["evidence"]))

    def test_actual_get_api_reaches_local_candidates_without_model_or_network(self):
        self.ingest("Ollama AI security path traversal research. ", paper=True)
        client = TestClient(importlib.import_module("api.app").app)
        def dispatch(record, **kwargs):
            return report(record, library_db=self.db, evidence_db=None, **kwargs)
        with patch("api.app.get_record", return_value=self.record), patch("enrichment.article_candidates.report", side_effect=dispatch) as called:
            response = client.get("/api/article-candidates/" + A + "?top_k=2")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["items"][0]["category"], "paper")
        called.assert_called_once_with(self.record, top_k=2)
        self.network_mock.assert_not_called()

    def test_get_api_rejects_bad_parameters_missing_record_and_reports_errors(self):
        client = TestClient(importlib.import_module("api.app").app)
        with patch("api.app.get_record", return_value=None):
            self.assertEqual(client.get("/api/article-candidates/" + A).status_code, 404)
            self.assertEqual(client.get("/api/article-candidates/not-cve").status_code, 422)
            self.assertEqual(client.get("/api/article-candidates/" + A + "?top_k=9").status_code, 422)
        with patch("api.app.get_record", return_value=self.record), patch("enrichment.article_candidates.report", side_effect=RuntimeError("fixture unavailable")):
            self.assertEqual(client.get("/api/article-candidates/" + A).status_code, 503)


if __name__ == "__main__":
    unittest.main()
