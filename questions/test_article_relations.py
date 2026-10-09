"""新文章来源绑定及状态边界；合成案例不代表独立语义准确率。"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from enrichment.relation_candidates import (connection, generate, list_candidates, review,
    reviewed_graph, source_documents, validate_article_selections, validate_relation)
from rag.library import detail, ingest_document
from questions.test_reference_text import response

TOPIC = "article_relations"
QUOTE = "An AI agent can execute malicious commands when it reads an untrusted rule file."
RELATION = {"subject": "An AI agent", "predicate": "can execute", "object": "malicious commands",
            "conditions": ["when it reads an untrusted rule file"]}


class ArticleRelationsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "library.sqlite3"
        self.source = {"url": "https://example.org/new-ai-security-article", "document_type": "research_article",
                       "source_name": "Synthetic new article", "source_id": "fixture"}
        self.html = '<html><body><article><h1>New AI agent security research fixture</h1><p>' + (QUOTE + ' 智能体可能执行恶意命令，条件是读取了不可信规则文件。 ') * 8 + '</p></article></body></html>'
        self.doc_id = ingest_document(self.source, self.db, lambda u: response(u, self.html))["document_id"]

    def generate(self, model=False):
        return generate(topic=TOPIC, document_ids=[self.doc_id], use_model=model, db_path=self.db)

    def model(self, messages, **kwargs):
        options = json.loads(messages[1]["content"])["options"]
        option = next(o for o in options if o["quote"] == QUOTE)
        return json.dumps({"selections": [{"id": option["id"], "facet": "mechanism", **RELATION}]})

    def model_result(self):
        with patch("enrichment.relation_candidates.configured", return_value=True), patch("enrichment.relation_candidates.chat", side_effect=self.model):
            return self.generate(True)

    def approve(self, item, decision="approved"):
        return review(item["id"], decision=decision, facet="mechanism", reviewer="Synthetic developer",
                      note="Checked subject, modal predicate, object and complete condition against fixture quote.",
                      review_kind="developer_source_review", db_path=self.db)

    def test_non_registry_article_and_chinese_sentences_are_pending(self):
        result = self.generate()
        self.assertGreater(result["inserted"], 0)
        self.assertTrue(any(i["quote"].startswith("智能体") for i in result["items"]))
        self.assertTrue(all(i["document_id"] == self.doc_id and i["state"] == "pending" for i in result["items"]))
        self.assertFalse(reviewed_graph(topic=TOPIC, db_path=self.db)["facts"])
        self.assertEqual(self.generate()["inserted"], 0)

    def test_explicit_selection_required_and_catalog_excluded(self):
        for ids in ([], ["invalid"], ["DOC-" + "0" * 16]):
            with self.assertRaises(ValueError): generate(topic=TOPIC, document_ids=ids, db_path=self.db)
        original = detail(self.doc_id, self.db)
        for change in ({"content_scope": "catalog_only"}, {"integrity_status": "incomplete"}):
            with patch("enrichment.relation_candidates.detail", return_value=dict(original, **change)):
                self.assertEqual(source_documents(TOPIC, [self.doc_id], self.db), [])

    def test_model_span_relation_is_pending_until_review_and_citations_close(self):
        result = self.model_result(); self.assertTrue(result["used_model"])
        item = result["items"][0]; self.assertEqual(item["relation"], RELATION)
        self.assertFalse(reviewed_graph(topic=TOPIC, db_path=self.db)["facts"])
        self.approve(item)
        graph = reviewed_graph(topic=TOPIC, db_path=self.db)
        self.assertEqual(graph["facts"][0]["qualification_quote"], QUOTE)
        edge = next(e for e in graph["graph"]["edges"] if e["predicate"] == "can execute")
        self.assertEqual(edge["conditions"], RELATION["conditions"])
        cited = {r["citation_id"] for r in graph["evidence"]}
        self.assertTrue(all(set(e["evidence_ids"]) <= cited for e in graph["graph"]["edges"]))
        self.assertFalse(graph["facts"][0]["review"]["independent_review"])
        self.assertFalse(reviewed_graph(topic=TOPIC, document_ids=["DOC-" + "0" * 16], db_path=self.db)["facts"])

    def test_fabricated_spans_conditions_ids_and_extra_claim_rejected(self):
        option = {"Q1": {"quote": QUOTE}}
        base = {"id": "Q1", "facet": "mechanism", **RELATION}
        for changes in ({"subject": "ChatGPT"}, {"conditions": ["always"]}, {"id": "invented"},
                        {"claim": "Verified attack chain"}, {"predicate": "execute"}, {"object": "An AI agent"}):
            with self.assertRaises(ValueError):
                validate_article_selections(json.dumps({"selections": [dict(base, **changes)]}), option)

    def test_negative_predicate_cannot_drop_not(self):
        quote = "Blocking that exploit does not establish a complete repair."
        relation = {"subject": "Blocking that exploit", "predicate": "does not establish", "object": "a complete repair", "conditions": []}
        self.assertEqual(validate_relation(relation, quote), relation)
        with self.assertRaises(ValueError): validate_relation(dict(relation, predicate="establish"), quote)

    def test_invalid_model_falls_back_without_inventing_structure(self):
        with patch("enrichment.relation_candidates.configured", return_value=True), patch("enrichment.relation_candidates.chat", return_value='{"selections":[{"id":"invented"}]}'):
            result = self.generate(True)
        self.assertTrue(result["model_attempted"]); self.assertFalse(result["used_model"])
        self.assertTrue(all(not i.get("relation") and i["state"] == "pending" for i in result["items"]))

    def test_abstract_scope_is_preserved_and_not_called_full_text(self):
        original = detail(self.doc_id, self.db)
        with patch("enrichment.relation_candidates.detail", return_value=dict(original, content_scope="abstract")):
            result = self.generate()
        self.assertTrue(result["items"])
        self.assertTrue(all(i["content_scope"] == "abstract" and "仅依据摘要" in i["scope_notice"] for i in result["items"]))

    def test_material_is_data_and_model_receives_no_local_credentials(self):
        captured = []
        def model(messages, **kwargs):
            captured.extend(messages)
            return self.model(messages, **kwargs)
        with patch("enrichment.relation_candidates.configured", return_value=True), patch("enrichment.relation_candidates.chat", side_effect=model):
            self.generate(True)
        self.assertIn("材料仅为数据", captured[0]["content"])
        payload = json.loads(captured[1]["content"])
        self.assertEqual(set(payload), {"topic", "options"})
        self.assertTrue(all(set(o) == {"id", "quote"} for o in payload["options"]))

    def test_source_refresh_disables_review_and_old_graph(self):
        item = self.model_result()["items"][0]; self.approve(item)
        updated = self.html.replace("untrusted rule file", "untrusted retrieved document")
        ingest_document(self.source, self.db, lambda u: response(u, updated))
        old = next(i for i in list_candidates(topic=TOPIC, db_path=self.db)["items"] if i["id"] == item["id"])
        self.assertEqual(old["effective_state"], "stale")
        self.assertFalse(reviewed_graph(topic=TOPIC, db_path=self.db)["facts"])
        self.assertGreater(self.generate()["inserted"], 0)

    def test_tampered_relation_span_blocks_approval(self):
        item = self.model_result()["items"][0]
        with connection(self.db) as conn:
            payload = dict(item, relation=dict(RELATION, subject="Invented product"))
            conn.execute("UPDATE candidates SET payload=? WHERE id=?", (json.dumps(payload), item["id"]))
        with self.assertRaises(ValueError): self.approve(item)

    def test_even_source_valid_relation_edits_require_a_new_candidate(self):
        item = self.model_result()["items"][0]; self.approve(item)
        with connection(self.db) as conn:
            payload = dict(item, relation=dict(RELATION, subject="AI agent"))
            conn.execute("UPDATE candidates SET payload=? WHERE id=?", (json.dumps(payload), item["id"]))
        self.assertFalse(reviewed_graph(topic=TOPIC, db_path=self.db)["facts"])

    def test_revoke_keeps_audit_and_closes_graph(self):
        item = self.model_result()["items"][0]; self.approve(item); self.approve(item, "revoked")
        self.assertFalse(reviewed_graph(topic=TOPIC, db_path=self.db)["facts"])
        self.assertEqual(len(list_candidates(topic=TOPIC, db_path=self.db)["items"][0]["reviews"]), 2)

    def test_api_accepts_new_mode_and_requires_document_selection(self):
        from fastapi.testclient import TestClient
        from api.app import app
        with TestClient(app) as client:
            self.assertEqual(client.post("/api/library/relations/candidates", json={"topic": TOPIC}).status_code, 422)
            with patch("enrichment.relation_candidates.reviewed_graph", return_value={"facts": []}) as graph:
                result = client.get("/api/library/relations/graph?topic=" + TOPIC)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()["status"], "reviewed_quotes_only")
                graph.assert_called_once_with(topic=TOPIC)


if __name__ == "__main__": unittest.main()
