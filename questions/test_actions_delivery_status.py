"""Serving a snapshot and consuming it are separate durable facts."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api.delivery_status import consumer_checkpoints, consumption_status

BASE = "http://b-api:8765"
EPOCH = "fixture-epoch"


class ConsumerDeliveryStatusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.knowledge = self.root / "knowledge.sqlite3"
        self.library = self.root / "library.sqlite3"
        with sqlite3.connect(self.knowledge) as connection:
            connection.execute("CREATE TABLE sync_cursors(source TEXT,cursor_json TEXT,updated_at TEXT)")
        with sqlite3.connect(self.library) as connection:
            connection.execute("CREATE TABLE team_sync_cursors(base_url TEXT,payload TEXT)")

    def save(self, cve=None, document=None):
        for path, table, values in ((self.knowledge, "sync_cursors", ("b_intelligence", cve, "2026-10-13")),
                                    (self.library, "team_sync_cursors", (BASE, document))):
            with sqlite3.connect(path) as connection:
                connection.execute("DELETE FROM " + table)
                if values[1] is not None:
                    connection.execute("INSERT INTO " + table + " VALUES (" + ",".join("?" for _ in values) + ")",
                                       tuple(json.dumps(value) if isinstance(value, dict) else value for value in values))

    def facts(self, through=10):
        return consumer_checkpoints(knowledge_db=self.knowledge, library_db=self.library, base_url=BASE,
                                     upstream={"epoch": EPOCH, "through": through})

    def test_no_checkpoint_does_not_claim_complete_even_for_empty_feed(self):
        facts = self.facts(through=0)
        self.assertFalse(facts["all_caught_up"])
        self.assertEqual(facts["cve"]["status"], "not_started")
        self.assertEqual(facts["document"]["status"], "not_started")

    def test_cve_done_document_partial_remains_pending_then_committed_page_catches_up(self):
        cve = {"epoch": EPOCH, "seq": 10, "base_url": BASE, "token": "fixture-never-export"}
        document = {"epoch": EPOCH, "seq": 4, "through": 10, "base_url": BASE}
        self.save(cve, document)
        facts = self.facts()
        self.assertEqual(facts["cve"]["status"], "caught_up")
        self.assertEqual(facts["document"]["status"], "lagging")
        self.assertEqual(facts["document"]["lag_events"], 6)
        self.assertFalse(facts["all_caught_up"])
        self.assertNotIn("fixture-never-export", json.dumps(facts))
        self.save(cve, {"epoch": EPOCH, "seq": 10, "base_url": BASE})
        self.assertTrue(self.facts()["all_caught_up"])
        self.assertFalse(self.facts()["processing_completion_verified"])

    def test_old_epoch_changed_source_or_cursor_ahead_requires_replay(self):
        for cursor, expected in (({"epoch": "old-epoch", "seq": 10, "base_url": BASE}, "reset_required"),
                                  ({"epoch": EPOCH, "seq": 11, "base_url": BASE}, "reset_required"),
                                  ({"epoch": EPOCH, "seq": 10, "base_url": "http://localhost:8765"}, "source_changed")):
            with self.subTest(expected=expected):
                self.save(cursor, {"epoch": EPOCH, "seq": 10, "base_url": BASE})
                self.assertEqual(self.facts()["cve"]["status"], expected)
                self.assertFalse(self.facts()["all_caught_up"])

    def test_status_is_read_only_and_missing_databases_are_not_initialized(self):
        before = (self.knowledge.read_bytes(), self.library.read_bytes())
        self.facts()
        self.assertEqual(before, (self.knowledge.read_bytes(), self.library.read_bytes()))
        absent = self.root / "absent"
        facts = consumer_checkpoints(knowledge_db=absent / "knowledge.sqlite3", library_db=absent / "library.sqlite3",
                                     base_url=BASE, upstream={"epoch": EPOCH, "through": 0})
        self.assertFalse(facts["all_caught_up"])
        self.assertFalse(absent.exists())

    def test_disabled_source_never_probes_upstream(self):
        with patch("collectors.intelligence.team_intel_disabled", return_value=True), patch("collectors.team_documents.TeamDocumentCollector") as collector:
            self.assertEqual(consumption_status()["status"], "disabled")
            collector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
