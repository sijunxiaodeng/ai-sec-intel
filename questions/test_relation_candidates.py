"""合成夹具核对候选状态/来源故障；不是独立语义准确率评测。"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.relations_qa import run
from enrichment.relation_candidates import generate, list_candidates, review, reviewed_graph, validate_selections
from enrichment.relations import SUPPLY_REGISTRY, build_graph
from rag.evidence import _connection
from rag.library import detail, ingest_document
from questions.test_reference_text import response


class CandidatesTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"
        registry = json.loads(SUPPLY_REGISTRY.read_text(encoding="utf-8"))
        self.hf = {"url": registry["sources"]["hf"]["url"], "document_type": "vendor_guidance", "source_name": "Synthetic HF", "source_id": "fixture"}
        self.html = '<html><body><article><h1>LLM model security pickle fixture</h1><p>' + ('Loading an untrusted pickle LLM model file can execute arbitrary code in this synthetic fixture. A signed commit does not guarantee that the model file is safe. Scanning pickle imports is not a foolproof safety assessment. ' * 8) + '</p></article></body></html>'
        first = ingest_document(self.hf, self.db, lambda u: response(u, self.html))
        self.hf_id = first["document_id"]
        nist = {"url": registry["sources"]["nist"]["url"], "document_type": "standard", "source_name": "Synthetic NIST", "source_id": "fixture"}
        pdf = {"title": "Synthetic framework", "parts": [("PDF page 16", "GAI value chains include third-party components such as pre-trained models in this synthetic fixture. Evaluate supplier risk and monitor third-party model provenance. " * 8)], "content_scope": "full_text_pdf", "version": "NIST AI 600-1 (2024)", "reference_kind": "voluntary_risk_framework"}
        with patch("rag.library.pdf_document", return_value=pdf):
            second = ingest_document(nist, self.db, lambda u: response(u, b"%PDF-synthetic", "application/pdf"))
        self.nist_id = second["document_id"]
        rows = {"hf": detail(self.hf_id, self.db)["evidence"][0], "nist": detail(self.nist_id, self.db)["evidence"][0]}
        for fact in registry["facts"]:
            row = rows[fact["source"]]
            fact["evidence_text_sha256"] = row["text_sha256"]
            fact["locator_prefix"] = row["locator"].split("；")[0]
        self.path = Path(temp.name) / "registry.json"
        self.path.write_text(json.dumps(registry), encoding="utf-8")
        binding = patch("enrichment.relations.SUPPLY_REGISTRY", self.path); binding.start(); self.addCleanup(binding.stop)

    def proposals(self):
        return generate(topic="model_supply_chain", use_model=False, db_path=self.db)

    def approve(self, item, decision="approved"):
        return review(item["id"], decision=decision, facet="limitation", reviewer="Synthetic developer", note="Synthetic source binding and classification review only.", review_kind="developer_source_review", db_path=self.db)

    def test_supply_graph_and_three_paths_require_both_documents(self):
        graph = build_graph(topic="model_supply_chain", db_path=self.db)
        self.assertEqual(len(graph["facts"]), 8)
        self.assertFalse(any(e["predicate"] == "references" for e in graph["graph"]["edges"]))
        result = run("模型供应链的加载风险、防护建议及扫描局限", use_model=False, db_path=self.db)
        self.assertEqual(result["status"], "answered")
        self.assertEqual({a["id"] for a in result["analyses"]}, {"B1", "B2", "B3"})
        self.assertIn("不能保证文件安全", result["answer"])
        one = run("模型供应链如何防护", document_ids=[self.hf_id], use_model=False, db_path=self.db)
        self.assertEqual(one["status"], "insufficient_evidence")

    def test_pending_isolated_and_generation_deduplicated(self):
        first = self.proposals(); self.assertGreater(first["inserted"], 0)
        self.assertTrue(all(i["state"] == "pending" and not i["independent_review"] for i in first["items"]))
        self.assertFalse(reviewed_graph(topic="model_supply_chain", db_path=self.db)["facts"])
        self.assertEqual(self.proposals()["inserted"], 0)

    def test_reviewed_quotes_have_citations_but_do_not_add_analysis_premises(self):
        item = self.proposals()["items"][0]; self.approve(item)
        graph = reviewed_graph(topic="model_supply_chain", db_path=self.db)
        self.assertEqual(len(graph["facts"]), 1)
        self.assertEqual(graph["facts"][0]["facet"], "limitation")
        cited = {r["citation_id"] for r in graph["evidence"]}
        self.assertTrue(all(set(e["evidence_ids"]) <= cited for e in graph["graph"]["edges"]))
        result = run("模型供应链的加载风险", use_model=False, db_path=self.db)
        self.assertEqual(len(result["reviewed_quotes"]["facts"]), 1)
        self.assertTrue(all(item["id"] not in a["premises"] for a in result["analyses"]))
        filtered = reviewed_graph(topic="model_supply_chain", document_ids=["DOC-" + "0" * 16], db_path=self.db)
        self.assertFalse(filtered["facts"])

    def test_rejection_and_revocation_preserve_audit(self):
        items = self.proposals()["items"]
        self.approve(items[0], "rejected"); self.approve(items[1]); self.approve(items[1], "revoked")
        self.assertFalse(reviewed_graph(topic="model_supply_chain", db_path=self.db)["facts"])
        record = next(i for i in list_candidates(topic="model_supply_chain", db_path=self.db)["items"] if i["id"] == items[1]["id"])
        self.assertEqual([r["decision"] for r in record["reviews"]], ["approved", "revoked"])
        with self.assertRaises(ValueError): self.approve(items[0])

    def test_changed_snapshot_disables_approved_and_blocks_pending_approval(self):
        items = self.proposals()["items"]; self.approve(items[0])
        with _connection(self.db) as conn:
            conn.execute("UPDATE library_snapshots SET body=?", (b"tampered",))
        self.assertFalse(reviewed_graph(topic="model_supply_chain", db_path=self.db)["facts"])
        self.assertTrue(all(i["effective_state"] == "stale" for i in list_candidates(topic="model_supply_chain", db_path=self.db)["items"]))
        with self.assertRaises(ValueError): self.approve(items[1])
        self.approve(items[0], "revoked")

    def test_successful_source_update_requires_new_review(self):
        item = next(i for i in self.proposals()["items"] if i["document_id"] == self.hf_id); self.approve(item)
        updated = self.html.replace("synthetic fixture", "updated synthetic fixture")
        self.assertEqual(ingest_document(self.hf, self.db, lambda u: response(u, updated))["status"], "ok")
        self.assertFalse(reviewed_graph(topic="model_supply_chain", db_path=self.db)["facts"])
        self.assertGreater(self.proposals()["inserted"], 0)

    def test_model_selection_cannot_invent_quote_ids_or_extra_fields(self):
        option = {"Q1": {"quote": "fixed source text"}}
        for obj in [{"selections": [{"id": "Q9", "facet": "mechanism"}]},
                    {"selections": [{"id": "Q1", "facet": "mechanism", "quote": "invented"}]},
                    {"selections": [{"id": "Q1", "facet": []}]},
                    {"selections": [{"id": "Q1", "facet": "causes_attack"}]},
                    {"selections": [{"id": "Q1", "facet": "mechanism"}] * 2}]:
            with self.assertRaises(ValueError): validate_selections(json.dumps(obj), option)
        self.assertEqual(validate_selections('{"selections":[{"id":"Q1","facet":"mechanism"}]}', option)[0]["quote"], "fixed source text")

    def test_invalid_model_falls_back_to_pending_quotes(self):
        with patch("enrichment.relation_candidates.configured", return_value=True), patch("enrichment.relation_candidates.chat", return_value='{"selections":[{"id":"invented","facet":"mechanism"}]}'):
            result = generate(topic="model_supply_chain", db_path=self.db)
        self.assertTrue(result["model_attempted"]); self.assertFalse(result["used_model"])
        self.assertTrue(all(i["state"] == "pending" for i in result["items"]))

    def test_mixed_topics_and_unsupported_measurements_rejected_without_model(self):
        with patch("agents.relations_qa.chat") as model:
            for q in ["模型供应链和间接提示注入有什么因果关系", "模型供应链扫描成功率是多少", "模型供应链的后门如何防护"]:
                self.assertEqual(run(q, db_path=self.db)["status"], "unsupported_question")
        model.assert_not_called()

    def test_review_validation_and_unknown_topic(self):
        item = self.proposals()["items"][0]
        with self.assertRaises(ValueError): review(item["id"], decision="approved", facet="limitation", reviewer="", note="too short", db_path=self.db)
        with self.assertRaises(ValueError): generate(topic="invented", db_path=self.db)
        with self.assertRaises(ValueError): generate(topic="model_supply_chain", document_ids=["invalid"], db_path=self.db)
        with self.assertRaises(ValueError): self.approve(item, "revoked")

    def test_pending_quote_tampering_cannot_be_approved(self):
        item = self.proposals()["items"][0]
        from enrichment.relation_candidates import connection
        with connection(self.db) as conn:
            payload = dict(item, quote="This statement is absent from the original evidence.")
            conn.execute("UPDATE candidates SET payload=? WHERE id=?", (json.dumps(payload), item["id"]))
        with self.assertRaises(ValueError): self.approve(item)

    def test_api_routes_validate_topics_and_review_schema(self):
        from fastapi.testclient import TestClient
        from api.app import app
        with TestClient(app) as client:
            for route in ("graph", "candidates"):
                self.assertEqual(client.get("/api/library/relations/" + route + "?topic=unknown").status_code, 422)
            self.assertEqual(client.post("/api/library/relations/candidates", json={"topic": "unknown"}).status_code, 422)
            self.assertEqual(client.post("/api/library/relations/candidates/invalid/review", json={"decision": "approved", "facet": "mechanism", "reviewer": "Test", "note": "Source checked for synthetic fixture."}).status_code, 422)
            with patch("enrichment.relation_candidates.generate", return_value={"status": "ok"}) as model:
                self.assertEqual(client.post("/api/library/relations/candidates", json={"topic": "model_supply_chain", "use_model": False}).status_code, 200)
                model.assert_called_once_with(topic="model_supply_chain", document_ids=[], use_model=False)

    def test_model_can_only_select_existing_quotes(self):
        with patch("enrichment.relation_candidates.configured", return_value=True), patch("enrichment.relation_candidates.chat", return_value='{"selections":[{"id":"Q1","facet":"mechanism"}]}'):
            result = generate(topic="model_supply_chain", db_path=self.db)
        self.assertTrue(result["used_model"])
        self.assertEqual(result["selected"], 1)
        self.assertEqual(result["items"][0]["state"], "pending")

    def test_failed_refresh_retains_source_but_never_claims_fresh(self):
        item = next(i for i in self.proposals()["items"] if i["document_id"] == self.hf_id); self.approve(item)
        def unavailable(url): raise OSError("Synthetic source offline")
        failed = ingest_document(self.hf, self.db, unavailable)
        self.assertTrue(failed["retained_previous"])
        self.assertEqual(len(reviewed_graph(topic="model_supply_chain", db_path=self.db)["facts"]), 1)
        self.assertTrue(detail(self.hf_id, self.db)["retained_previous"])
        self.assertTrue(next(i for i in list_candidates(topic="model_supply_chain", db_path=self.db)["items"] if i["id"] == item["id"])["retained_previous"])


if __name__ == "__main__":
    unittest.main()
