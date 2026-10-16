"""Source-backed persisted research links, including stale and forged caches."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from database import store
from enrichment.research_associations import refresh, current, KEY
from rag.library import ingest_document
from rag.evidence import _connection
from models import enriched_record


class ResearchAssociationsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.library = self.root / "library.sqlite3"
        self.evidence = self.root / "evidence.sqlite3"
        self.record = enriched_record({"cve_id": "CVE-2024-37032", "product": "ollama",
            "description": "Ollama path traversal vulnerability"})
        self.enterContext(patch("rag.library._dense", side_effect=RuntimeError("offline fixture")))
        self.candidate = {"url": "https://arxiv.org/abs/2401.12345", "source_id": "fixture",
                          "source_name": "Synthetic paper", "document_type": "academic_paper"}

    def ingest(self, text):
        body = ('<html><head><meta name="citation_title" content="Synthetic security research"></head><body>'
                '<blockquote class="abstract">Abstract: ' + text * 3 + '</blockquote></body></html>').encode()
        ingest_document(self.candidate, self.library, lambda url: {"url": url, "body": body, "content_type": "text/html"})

    def refresh(self):
        return refresh(self.record, library_db=self.library, evidence_db=self.evidence)

    def current(self):
        return current(self.record, library_db=self.library, evidence_db=self.evidence)

    def test_background_relation_is_persistable_but_not_a_direct_cve_paper(self):
        self.ingest("Ollama AI security path traversal research. ")
        before = store.source_revision(self.record)
        self.refresh()
        result = self.current()
        self.assertEqual(result["counts"]["paper"], 1)
        self.assertEqual(result["items"][0]["relation_type"], "related_research")
        self.assertEqual(self.record["papers"], [])
        self.assertEqual(store.source_revision(self.record), before)
        self.assertEqual(result["items"][0]["review_status"], "not_reviewed")

    def test_exact_mention_has_its_own_relation_type(self):
        self.ingest("Ollama AI security path traversal CVE-2024-37032. ")
        self.refresh()
        self.assertEqual(self.current()["items"][0]["relation_type"], "direct_mention")

    def test_same_product_without_security_mechanism_is_not_related(self):
        self.ingest("Ollama AI performance throughput measurement. ")
        self.refresh()
        self.assertEqual(self.current()["counts"]["paper"], 0)

    def test_source_revision_or_archived_bytes_change_hides_old_relations(self):
        self.ingest("Ollama AI security path traversal. ")
        self.refresh()
        original = copy.deepcopy(self.record)
        self.record["item"]["description"] += " revised"
        self.assertEqual(self.current()["status"], "stale")
        self.assertEqual(self.current()["items"], [])
        self.record = original
        with _connection(self.library) as conn:
            conn.execute("UPDATE library_snapshots SET body=?", (b"changed",))
        self.assertEqual(self.current()["items"], [])

    def test_forged_direct_flag_and_label_are_reconstructed_from_source(self):
        self.ingest("Ollama AI security path traversal. ")
        self.refresh()
        row = self.record["item"]["raw_data"][KEY]["items"][0]
        row.update(relation_type="direct_mention", explicit_cve_mention=True, title="forged", url="https://wrong.example/")
        row["evidence"][0]["text"] = "forged quote"
        actual = self.current()["items"][0]
        self.assertEqual(actual["relation_type"], "related_research")
        self.assertFalse(actual["explicit_cve_mention"])
        self.assertNotEqual(actual["title"], "forged")
        self.assertNotEqual(actual["evidence"][0]["text"], "forged quote")
        row["match_basis"].append({"kind": "explicit_cve_mention", "term": "CVE-2024-37032"})
        self.assertEqual(self.current()["items"], [])

    def api_client(self):
        from fastapi.testclient import TestClient
        from api.app import app
        from enrichment import research_associations
        changes = {name: self.root / filename for name, filename in {
            "DB_PATH": "main.sqlite3", "KB_PATH": "old.json", "RUNS_PATH": "runs.json",
            "CARDS_PATH": "cards.json", "CARDS_JS_PATH": "cards.js", "SEED_CARDS_PATH": "seed.json"}.items()}
        self.enterContext(patch.multiple(store, DATA=self.root, **changes))
        self.enterContext(patch.dict(os.environ, {"MAIN_KB_DB_PATH": str(changes["DB_PATH"]), "MAIN_IMPORT_DEMO_CARDS": "0"}))
        self.enterContext(patch.multiple(research_associations, LIBRARY_DB=self.library, DEFAULT_DB=self.evidence))
        self.ingest("Ollama AI security path traversal research. ")
        store.upsert([self.record])
        return TestClient(app)

    def test_refresh_and_read_api_roundtrip_uses_canonical_item_not_rag_view(self):
        client = self.api_client()
        with patch("api.app.get_record", side_effect=AssertionError("augmented display view must not be used")):
            response = client.post("/api/research-associations/CVE-2024-37032/refresh")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["counts"]["paper"], 1)
            response = client.get("/api/research-associations/CVE-2024-37032")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["counts"]["paper"], 1)
        saved = store.get_record("CVE-2024-37032")
        self.assertEqual(saved["item"]["raw_data"][KEY]["source_revision"], store.source_revision(saved))

    def test_item_detail_does_not_mark_research_stale_due_to_transient_poc_view(self):
        client = self.api_client()
        self.assertEqual(client.post("/api/research-associations/CVE-2024-37032/refresh").status_code, 200)
        view = store.get_record("CVE-2024-37032")
        view["item"]["raw_data"]["poc_code"] = {"status": "not_collected"}
        with patch("api.app.get_record", return_value=view), patch("rag.ingest.document_status", return_value={"status": "empty"}):
            response = client.get("/api/items/CVE-2024-37032")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["research_associations"]["counts"]["paper"], 1)

    def test_research_api_does_not_accept_library_only_records_for_persistence(self):
        client = self.api_client()
        with patch("api.app.get_record", return_value=self.record):
            for path in ("/api/research-associations/CVE-2099-99999",):
                self.assertEqual(client.get(path).status_code, 404)
                self.assertEqual(client.post(path + "/refresh").status_code, 404)
