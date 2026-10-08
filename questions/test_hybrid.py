import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from enrichment.sample import load_sample
from rag.evidence import save
from rag.hybrid import _dense, config_path, fuse, search as hybrid_search
from rag.prepare import prepare as real_prepare
from rag.retrieve import search as record_search, knowledge_records, get_record
from agents.qa_agent import run as qa_run
from agents.verifier_agent import run as verify


class HybridTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "evidence.sqlite3"
        self.record, self.docs = load_sample()
        save(self.record, self.docs, self.db)
        self.addCleanup(patch.stopall)
        patch("rag.retrieve.load_kb", return_value=[]).start()
        patch("agents.qa_agent.search", side_effect=lambda q, top_k=4, cve_id="", **kwargs: record_search(q, top_k, cve_id=cve_id, db_path=self.db)).start()
        patch("agents.qa_agent.configured", return_value=False).start()

    def test_missing_model_falls_back_and_scope_stays_exact(self):
        result = hybrid_search("修复版本", db_path=self.db)
        self.assertEqual(result["mode"], "bm25")
        self.assertTrue(result["evidence"])
        self.assertIn("向量索引未就绪", result["notice"])
        self.assertEqual(hybrid_search("CVE-2099-99999 修复版本", db_path=self.db)["evidence"], [])

    def test_rrf_combines_ranks_and_keeps_dense_only_evidence(self):
        row = {"cve_id": "CVE-2024-37032", "evidence_id": "A"}
        other = dict(row, evidence_id="B")
        third = dict(row, evidence_id="C")
        ranked = fuse([row, other], [other, third], 3)
        self.assertEqual(ranked[0]["evidence_id"], "B")
        self.assertEqual(set(ranked[0]["channels"]), {"bm25", "dense"})
        self.assertEqual({r["evidence_id"] for r in ranked}, {"A", "B", "C"})

    def test_dense_channel_is_used_without_lexical_overlap(self):
        chunk = copy.deepcopy(self.docs[1]["chunks"][3])
        row = {key: value for key, value in self.docs[1].items() if key != "chunks"}
        row.update(chunk, cosine_score=0.8)
        with patch("rag.hybrid._dense", return_value=[row]):
            result = hybrid_search("怎样让系统恢复正常运转", db_path=self.db)
        self.assertEqual(result["mode"], "hybrid")
        self.assertIn("WIZ-04", [r["evidence_id"] for r in result["evidence"]])

    def test_changed_evidence_invalidates_old_vectors(self):
        from rag.evidence import _connection
        config_path(self.db).write_text(json.dumps({"enabled": True, "model": "BAAI/bge-small-zh-v1.5", "cache_dir": "unused"}), encoding="utf-8")
        with _connection(self.db) as conn:
            conn.execute("CREATE TABLE embeddings(cve_id TEXT, evidence_id TEXT, model TEXT, digest TEXT, vector TEXT)")
        with self.assertRaisesRegex(RuntimeError, "证据已更新"):
            row = dict(self.docs[0], **self.docs[0]["chunks"][0])
            _dense("CVSS", [row], self.db)
        self.assertEqual(hybrid_search("CVSS", db_path=self.db)["mode"], "bm25")

    def test_qa_returns_multidocument_citations(self):
        result = qa_run("受影响版本是什么，如何修复？有没有修复记录？", cve_id="CVE-2024-37032")
        self.assertIn("0.1.34", result["answer"])
        self.assertIn("PR #4175", result["answer"])
        chunks = result["evidence"][0]["evidence_chunks"]
        self.assertEqual({r["source_id"] for r in chunks}, {"nvd", "wiz", "fix"})
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])

    def test_unknown_focus_does_not_pull_unrelated_record(self):
        result = qa_run("CVSS 是多少？", cve_id="CVE-2099-99999")
        self.assertEqual(result["evidence"], [])
        assets = qa_run("我们的资产是否受影响？", cve_id="CVE-2024-37032")
        self.assertEqual(assets["evidence"], [])
        self.assertEqual(record_search("vllm 的修复版本是什么？", db_path=self.db), [])

    def test_model_with_invalid_citation_or_poc_claim_falls_back(self):
        for generated in ("CVSS 为 9.8 [CVE-2024-37032/NVD-02]", "已经修复 [不存在的证据]", "PoC 已验证可用 [CVE-2024-37032/NVD-03]"):
            with self.subTest(generated=generated), patch("agents.qa_agent.configured", return_value=True), patch("agents.qa_agent.chat", return_value=generated):
                result = qa_run("CVSS 评分和 PoC 验证状态是什么？", cve_id="CVE-2024-37032")
                self.assertFalse(result["used_model"])
                self.assertIn("未运行复现", result["answer"])
                self.assertTrue(verify(result["answer"], result["evidence"])["passed"])

    def test_cvss_version_is_not_mistaken_for_score(self):
        result = qa_run("CVSS 评分和向量是什么？", cve_id="CVE-2024-37032")
        self.assertTrue(verify(result["answer"], result["evidence"])["passed"])
        self.assertFalse(verify("CVSS 3.1 基础分为 9.8 [1]", result["evidence"])["passed"])

    def test_api_exposes_sample_chunks_and_preserves_legacy_evidence(self):
        try:
            from fastapi.testclient import TestClient
            from api.app import app
        except ImportError:
            self.skipTest("API 验收需要 requirements-test.txt")
        with patch("api.app.knowledge_records", side_effect=lambda: knowledge_records(self.db)), patch("api.app.get_record", side_effect=lambda cve: get_record(cve, self.db)), patch("rag.prepare.prepare", side_effect=lambda: real_prepare(self.db)), patch("agents.orchestrator.append_run"):
            client = TestClient(app)
            self.assertEqual(client.post("/api/sample").status_code, 200)
            self.assertEqual(client.get("/api/items/CVE-2024-37032").status_code, 200)
            result = client.post("/api/ask", json={"question": "受影响版本是什么，如何修复？", "cve_id": "CVE-2024-37032"})
            self.assertEqual(result.status_code, 200)
            payload = result.json()
            self.assertTrue(payload["evidence"])
            self.assertTrue(payload["evidence_chunks"])
            self.assertTrue(payload["verdict"]["passed"])
            self.assertIn("citation_id", payload["evidence_chunks"][0])
            self.assertEqual(client.post("/api/ask", json={"question": ""}).status_code, 400)
