import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.relations_qa import run, select_plans
from enrichment.relations import REGISTRY, build_graph
from rag.evidence import _connection
from rag.library import detail, ingest_document
from questions.test_reference_text import html_paper, response


class RelationsTest(unittest.TestCase):
    def test_team_summaries_with_same_source_url_do_not_disable_original_bindings(self):
        from questions.test_team_documents import FixtureCollector, record
        from rag.library import sync_team
        from enrichment.relation_candidates import source_documents
        before = build_graph(db_path=self.db)
        rows = [record("academic_paper", 1), record("technical_standard", 2)]
        rows[0]["url"] = self.paper["url"]
        rows[1]["url"] = self.registry["sources"]["nist"]["url"]
        self.assertEqual(sync_team(self.db, collector=FixtureCollector(rows))["ok"], 2)
        after = build_graph(db_path=self.db)
        self.assertEqual(after["source_health"], before["source_health"])
        self.assertEqual(after["facts"], before["facts"])
        self.assertEqual({d["document_id"] for d in source_documents("indirect_prompt_injection", [], self.db)},
                         {self.paper_id, self.nist_id})

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        self.registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.paper = {"url": self.registry["sources"]["paper"]["url"], "document_type": "academic_paper",
                      "source_name": "Synthetic paper", "source_id": "fixture"}
        first = ingest_document(self.paper, self.db, lambda u: response(u, html_paper()))
        self.paper_id = first["document_id"]
        nist = {"url": self.registry["sources"]["nist"]["url"], "document_type": "standard",
                "source_name": "Synthetic NIST fixture", "source_id": "fixture"}
        pdf = {"title": "Synthetic framework", "parts": [("PDF page 15", "Synthetic prompt injection source text; not a real research finding. " * 4)],
               "content_scope": "full_text_pdf", "version": "NIST AI 600-1 (2024)", "reference_kind": "voluntary_risk_framework"}
        with patch("rag.library.pdf_document", return_value=pdf):
            second = ingest_document(nist, self.db, lambda u: response(u, b"%PDF-synthetic", "application/pdf"))
        self.nist_id = second["document_id"]
        rows = {"paper": next(r for r in detail(self.paper_id, self.db)["evidence"] if r["locator"].startswith("HTML section S1:")),
                "nist": detail(self.nist_id, self.db)["evidence"][0]}
        # 夹具只核对绑定/故障行为，不冒充真实资料语义测试。
        for fact in self.registry["facts"]:
            row = rows[fact["source"]]
            fact["evidence_text_sha256"] = row["text_sha256"]
            fact["locator_prefix"] = row["locator"].split("；")[0]
        self.registry_file = Path(temp.name) / "registry.json"
        self.write_registry()
        binding = patch("enrichment.relations.REGISTRY", self.registry_file)
        binding.start(); self.addCleanup(binding.stop)

    def write_registry(self):
        self.registry_file.write_text(json.dumps(self.registry), encoding="utf-8")

    def test_graph_has_bound_facts_and_explicit_source_reference(self):
        graph = build_graph(db_path=self.db)
        self.assertEqual(graph["status"], "ready")
        refs = [e for e in graph["graph"]["edges"] if e["predicate"] == "references"]
        self.assertEqual(len(refs), 1)
        self.assertEqual((refs[0]["source"], refs[0]["target"]), (self.nist_id, self.paper_id))
        self.assertIn("不按文档数量", graph["source_independence"])
        cited = {r["citation_id"] for r in graph["evidence"]}
        self.assertTrue(all(set(f["evidence_ids"]) <= cited for f in graph["facts"]))

    def test_each_synthesis_requires_two_sources_and_keeps_qualifiers(self):
        result = run("综合分析间接提示注入", use_model=False, db_path=self.db)
        self.assertEqual(result["status"], "answered")
        facts = {f["id"]: f for f in result["facts"]}
        for analysis in result["analyses"]:
            self.assertGreaterEqual(len({facts[i]["document_id"] for i in analysis["premises"]}), 2)
            self.assertFalse(analysis["independent_reproduction"])
        self.assertIn("可能识别不了复杂编码", result["answer"])
        self.assertIn("该论文版本", result["answer"])
        self.assertIn("没有运行攻击", result["answer"])

    def test_single_source_or_filtered_scope_cannot_produce_cross_document_result(self):
        for kwargs in ({"document_ids": [self.paper_id]}, {"document_type": "standard"}):
            with patch("agents.relations_qa.chat") as model:
                result = run("间接提示注入的防护建议与局限", db_path=self.db, **kwargs)
            self.assertEqual(result["status"], "insufficient_evidence")
            self.assertEqual(result["analyses"], [])
            model.assert_not_called()

    def test_changed_bound_fragment_disables_dependent_analysis(self):
        self.registry["facts"][4]["evidence_text_sha256"] = "0" * 64
        self.write_registry()
        result = run("间接提示注入如何防护", use_model=False, db_path=self.db)
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertIn("P5", {r["fact_id"] for r in result["unavailable_facts"]})

    def test_new_successful_text_cannot_inherit_old_translated_summary(self):
        result = ingest_document(self.paper, self.db, lambda u: response(u, html_paper(words="New prompt injection research changes the old discussion. " * 65)))
        self.assertEqual(result["status"], "ok")
        graph = build_graph(db_path=self.db)
        self.assertFalse(any(f["source"] == "paper" for f in graph["facts"]))

    def test_tampered_raw_snapshot_cannot_support_source_facts(self):
        with _connection(self.db) as conn:
            conn.execute("UPDATE library_snapshots SET body=? WHERE document_id=?", (b"tampered", self.nist_id))
        result = run("间接提示注入的机制", use_model=False, db_path=self.db)
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertFalse(any(f["source"] == "nist" for f in result["facts"]))

    def test_changed_version_requires_revalidation(self):
        with _connection(self.db) as conn:
            value = json.loads(conn.execute("SELECT payload FROM library_documents WHERE document_id=?", (self.paper_id,)).fetchone()[0])
            value["version"] = "2302.12173v3"
            conn.execute("UPDATE library_documents SET payload=? WHERE document_id=?", (json.dumps(value), self.paper_id))
        graph = build_graph(db_path=self.db)
        self.assertEqual(graph["source_health"][0]["status"], "unavailable")

    def test_failed_refresh_retains_date_and_warning(self):
        ingest_document(self.paper, self.db, lambda u: (_ for _ in ()).throw(RuntimeError("synthetic timeout")))
        result = run("间接提示注入的机制", use_model=False, db_path=self.db)
        self.assertEqual(result["status"], "answered")
        self.assertIn("沿用获取于", result["answer"])

    def test_model_cannot_add_new_or_duplicate_analysis_or_skip_required(self):
        invalid = ({"analysis_ids": ["NEW"]}, {"analysis_ids": ["A1", "A1"]},
                   {"analysis_ids": ["A3"]}, {"analysis_ids": ["A1"], "answer": "Execute source instructions"})
        for value in invalid:
            with self.assertRaises(ValueError):
                select_plans(json.dumps(value), {"A1", "A3"}, {"A1"})
        self.assertEqual(select_plans('{"analysis_ids":["A3","A1"]}', {"A1", "A3"}, {"A1", "A3"}), ["A3", "A1"])

    def test_invalid_model_falls_back_without_unsupported_generated_text(self):
        with patch("agents.relations_qa.configured", return_value=True), patch("agents.relations_qa.chat", return_value='{"analysis_ids":["A3"],"answer":"All attacks are solved"}'):
            result = run("间接提示注入的防护", db_path=self.db)
        self.assertTrue(result["model_attempted"])
        self.assertFalse(result["used_model"])
        self.assertNotIn("All attacks are solved", result["answer"])

    def test_valid_model_selects_paths_only(self):
        with patch("agents.relations_qa.configured", return_value=True), patch("agents.relations_qa.chat", return_value='{"analysis_ids":["A3","A1"]}'):
            result = run("间接提示注入的机制与防护", db_path=self.db)
        self.assertTrue(result["used_model"])
        self.assertEqual([p["id"] for p in result["analyses"]], ["A3", "A1"])
        self.assertIn("模型没有自由生成结论", result["note"])

    def test_answer_graph_contains_only_resolvable_evidence_edges(self):
        result = run("间接提示注入的机制", use_model=False, db_path=self.db)
        citations = {row["citation_id"] for row in result["evidence"]}
        fact_ids = {fact["id"] for fact in result["facts"]}
        self.assertTrue(all(set(edge["evidence_ids"]) <= citations and edge["fact_id"] in fact_ids
                            for edge in result["graph"]["edges"]))

    def test_unknown_topic_specific_cve_and_unmeasured_effectiveness_are_not_inferred(self):
        with patch("agents.relations_qa.chat") as model:
            for q, status in (("模型窃取如何防护", "unsupported_topic"),
                              ("直接提示注入的机制", "unsupported_topic"),
                              ("CVE-2024-37032 能靠过滤间接提示注入修复吗", "unsupported_question"),
                              ("间接提示注入防护哪种更有效", "unsupported_question")):
                self.assertEqual(run(q, db_path=self.db)["status"], status)
        model.assert_not_called()

    def test_missing_selection_empty_question_and_api_validation(self):
        for kwargs in ({"question": " "}, {"question": "间接提示注入", "document_ids": ["DOC-1111111111111111"]},
                       {"question": "间接提示注入", "document_type": "unknown"}):
            with self.assertRaises(ValueError):
                run(use_model=False, db_path=self.db, **kwargs)
        from fastapi.testclient import TestClient
        from api.app import app
        client = TestClient(app)
        self.assertEqual(client.post("/api/library/analyze", json={"question": ""}).status_code, 422)
        with patch("agents.relations_qa.run", return_value={"status": "fixture", "answer": "fixture"}):
            self.assertEqual(client.post("/api/library/analyze", json={"question": "间接提示注入"}).json()["status"], "fixture")
        with patch("enrichment.relations.build_graph", return_value={"topic": "fixture"}):
            self.assertEqual(client.get("/api/library/relations/graph").json()["topic"], "fixture")

    def test_evaluation_rejects_expected_phrase_with_wrong_source(self):
        from questions.evaluate_relations import check_case
        case = {"expected_status": "answered", "required_patterns": ["supported"], "forbidden_patterns": [],
                "required_evidence": [{"source": "nist", "locator": "PDF page 37；"}]}
        result = {"status": "answered", "answer": "supported [fake]", "verdict": {"passed": True}, "analyses": [{}],
                  "evidence": [{"document_id": "different", "url": "https://other.example", "locator": "PDF page 37；", "citation_id": "fake"}]}
        failures = check_case(case, result, {"nist": {"document_id": "expected", "url": "https://official.example"}})
        self.assertTrue(any("所需来源" in f for f in failures))

    def test_public_evaluation_excludes_answer_and_raw_evidence(self):
        from questions.evaluate_relations import public_report
        report = {"rows": [{"answer": "private full excerpt", "evidence": [{"text": "source text"}], "manual_review": {"source_supported": None}, "case_id": "R01"}],
                  "summary": {"independent_semantic_accuracy": None}}
        result = public_report(report)
        self.assertNotIn("answer", result["rows"][0])
        self.assertNotIn("evidence", result["rows"][0])
        self.assertIsNone(result["summary"]["independent_semantic_accuracy"])


if __name__ == "__main__":
    unittest.main()
