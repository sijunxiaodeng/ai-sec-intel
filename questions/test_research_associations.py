"""Source-backed persisted research links, including stale and forged caches."""
import copy
import json
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
