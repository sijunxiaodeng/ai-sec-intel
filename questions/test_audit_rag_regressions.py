"""Offline regressions for routing, product scope and selected-document cost."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.qa_agent import run
from rag import library, retrieve
from rag.evidence import _connection
from rag.prepare import prepare


class QueryRoutingTests(unittest.TestCase):
    def test_polite_pronouns_do_not_change_a_cvss_question_to_assets(self):
        for wording in ("请解释", "请给我们解释", "请给本公司解释", "请帮我的同事解释"):
            with self.subTest(wording=wording), patch("agents.qa_agent.search", return_value=[]) as search, patch("enrichment.assets.answer_assets") as assets:
                run(wording + " CVE-2024-37032 的 CVSS 评分")
                search.assert_called_once()
                assets.assert_not_called()

    def test_explicit_asset_or_deployment_question_still_routes(self):
        for question in ("我们的资产受 CVE-2024-37032 影响吗？", "我们部署的 Ollama 受 CVE-2024-37032 影响吗？"):
            with self.subTest(question=question), patch("agents.qa_agent.search") as search, patch("enrichment.assets.answer_assets", return_value={"answer": "fixture"}) as assets:
                self.assertEqual(run(question)["answer"], "fixture")
                assets.assert_called_once()
                search.assert_not_called()

    def test_generic_deployment_conditions_are_not_an_inventory_request(self):
        for question in ("CVE-2024-37032 对服务器的部署条件有什么要求？", "请给我们解释 CVE-2024-37032 的部署条件"):
            with self.subTest(question=question), patch("agents.qa_agent.search", return_value=[]) as search, patch("enrichment.assets.answer_assets") as assets:
                run(question)
                search.assert_called_once()
                assets.assert_not_called()

    def test_parallel_products_union_and_explicit_joint_scope(self):
        records = [{"item": {"cve_id": cve, "product": product, "title": product + " vulnerability"}}
                   for cve, product in (("CVE-2026-10001", "Ollama"), ("CVE-2026-10002", "vLLM"), ("CVE-2026-10003", "Ollama vLLM"))]
        with patch("rag.retrieve.knowledge_records", return_value=records), patch("rag.retrieve.search_chunks", return_value={"mode": "bm25", "notice": "offline", "evidence": []}), patch("rag.retrieve._attach_guidance", side_effect=lambda row, *args: row):
            self.assertEqual(len(retrieve.search("Ollama 和 vLLM 分别有哪些漏洞？")), 3)
            self.assertEqual(len(retrieve.search("同时列出 Ollama 和 vLLM 的漏洞")), 3)
            self.assertEqual([r["item"]["cve_id"] for r in retrieve.search("同时影响 Ollama 和 vLLM 的漏洞")], ["CVE-2026-10003"])
            self.assertEqual([r["item"]["cve_id"] for r in retrieve.search("Ollama 和 vLLM 共同的漏洞")], ["CVE-2026-10003"])
            for cve in ("CVE-2026-10001", "CVE-2026-10002"):
                found = retrieve.search("对比 Ollama 和 vLLM 的版本 " + cve, cve_id=cve)
                self.assertEqual([r["item"]["cve_id"] for r in found], [cve])


class SelectedLibraryTests(unittest.TestCase):
    def test_only_selected_sources_are_reparsed_and_tampering_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "library.sqlite3"
            ids = []
            for index in range(30):
                url = "https://example.org/research/" + str(index)
                body = ("AI security prompt injection research evidence. " * 8 + str(index)).encode()
                response = {"body": body, "url": url, "content_type": "text/plain", "encoding": "utf-8", "retrieved_at": "2026-10-14T00:00:00Z"}
                result = library.ingest_document({"url": url, "document_type": "research_article", "source_name": "Offline research", "source_id": "offline"}, db, lambda _, response=response: response)
                self.assertEqual(result["status"], "ok", result)
                ids.append(result["document_id"])
            library._reparse.cache_clear()
            with patch("rag.library._dense", side_effect=RuntimeError("offline")):
                for doc_id in ids[:4]:
                    self.assertEqual(library.detail(doc_id, db)["integrity_status"], "ok")
                    hits = library.search("prompt injection", document_ids=[doc_id], db_path=db)["evidence"]
                    self.assertTrue(hits)
                    self.assertEqual({r["document_id"] for r in hits}, {doc_id})
                info = library._reparse.cache_info()
                self.assertEqual(info.misses, 4)  # Previously 8 * 30 reparses.
                self.assertEqual(info.hits, 4)
                with _connection(db) as conn:
                    rowid, payload = conn.execute("SELECT rowid,payload FROM evidence WHERE json_extract(payload,'$.document_id')=? LIMIT 1", (ids[0],)).fetchone()
                    row = json.loads(payload)
                    row["text"] = "Forged prompt injection result"
                    conn.execute("UPDATE evidence SET payload=? WHERE rowid=?", (json.dumps(row), rowid))
                self.assertEqual(library.detail(ids[0], db)["integrity_status"], "incomplete_or_invalid")
                self.assertFalse(library.search("prompt injection", document_ids=[ids[0]], db_path=db)["evidence"])
                self.assertEqual(library.search("prompt injection", document_ids=[], db_path=db)["evidence"], [])


class ProductionPrepareTests(unittest.TestCase):
    def test_production_preparation_never_imports_sample(self):
        with tempfile.TemporaryDirectory() as directory, patch("enrichment.sample.load_sample", side_effect=AssertionError("sample forbidden")), patch("rag.hybrid.build_index", return_value={"chunks": 7}) as build:
            db = Path(directory) / "production.sqlite3"
            result = prepare(db, semantic=True)
            self.assertEqual(result["mode"], "existing_evidence")
            self.assertFalse(result["demo_imported"])
            build.assert_called_once_with(db, None)
            self.assertFalse(db.exists())

    def test_historical_fixture_requires_explicit_demo_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "demo.sqlite3"
            result = prepare(db, demo=True)
            self.assertTrue(result["demo_imported"])
            self.assertEqual(result["cve_id"], "CVE-2024-37032")
            self.assertGreater(result["chunks"], 0)
