"""Persistent delivery cursors, backlog draining and failure-safe replays."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from collectors.intelligence import IncrementalIntelligenceCollector
from collectors.team_documents import TEAM_MEDIA, TeamDocumentCollector, team_id
from questions.test_team_documents import record
from rag.evidence import _connection
from rag.library import documents, search, sync_team, sync_team_drain


class ChangeDocumentFixture(TeamDocumentCollector):
    def __init__(self, count=251):
        super().__init__(max_documents=30, use_changefeed=True)
        self.events = [{"seq": index + 1, "entity_id": (row := record(number=index))["document_id"],
                        "operation": "upsert", "item": row} for index in range(count)]
        self.fail = False

    def get(self, path):
        if self.fail:
            raise TimeoutError("Fixture unavailable")
        query = parse_qs(urlsplit(path).query)
        cursor, limit = int(query["cursor"][0]), int(query["limit"][0])
        bound = int(query.get("through", [len(self.events)])[0])
        available = [event for event in self.events if cursor < event["seq"] <= bound]
        selected = available[:limit]
        more = len(available) > len(selected)
        page = {"epoch": "fixture", "reset": False, "cursor": cursor, "through": bound,
                "next_cursor": selected[-1]["seq"] if more else bound, "has_more": more, "changes": selected}
        return {"body": json.dumps(page).encode(), "url": self.base_url + path,
                "content_type": TEAM_MEDIA, "retrieved_at": "2026-10-10T01:00:00Z"}


class IncrementalSyncTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Path(directory.name) / "library.sqlite3"

    def state(self):
        with _connection(self.db) as connection:
            row = connection.execute("SELECT payload FROM team_sync_cursors").fetchone()
        return json.loads(row[0]) if row else None

    def test_more_than_200_documents_are_eventually_imported_across_restart(self):
        fixture = ChangeDocumentFixture()
        for _ in range(9):
            # A fresh client every round proves progress lives in the DB.
            result = sync_team(self.db, collector=ChangeDocumentFixture())
            self.assertTrue(result["source"]["cursor_committed"])
        self.assertEqual(len(documents(self.db)), 251)
        self.assertEqual(self.state()["seq"], 251)
        fixture.events[0]["item"]["description"] = "Corrected synthetic LLM supply chain security."
        fixture.events.append(dict(fixture.events[0], seq=252))
        result = sync_team(self.db, collector=fixture)
        self.assertEqual(result["changed"], 1)
        self.assertEqual(self.state()["seq"], 252)

    def test_network_or_bad_record_does_not_advance_cursor(self):
        fixture = ChangeDocumentFixture(count=1)
        fixture.fail = True
        self.assertEqual(sync_team(self.db, collector=fixture)["status"], "error")
        self.assertIsNone(self.state())
        fixture.fail = False
        fixture.events[0]["item"]["description"] = ""
        result = sync_team(self.db, collector=fixture)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["source"]["cursor_committed"])
        self.assertIsNone(self.state())
        fixture.events[0]["item"]["description"] = "Synthetic LLM prompt injection security."
        self.assertEqual(sync_team(self.db, collector=fixture)["status"], "ok")
        self.assertEqual(self.state()["seq"], 1)

    def test_index_failure_replays_the_same_page(self):
        fixture = ChangeDocumentFixture(count=1)
        with patch("rag.library.update_index", side_effect=RuntimeError("Fixture index failed")):
            with self.assertRaises(RuntimeError):
                sync_team(self.db, collector=fixture)
        self.assertIsNone(self.state())
        sync_team(self.db, collector=fixture)
        self.assertEqual(self.state()["seq"], 1)
        self.assertEqual(len(documents(self.db)), 1)

    def test_reported_index_error_does_not_commit_cursor(self):
        fixture = ChangeDocumentFixture(count=1)
        with patch("rag.library.update_index", return_value={"status": "error"}):
            result = sync_team(self.db, collector=fixture)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["source"]["cursor_committed"])
        self.assertIsNone(self.state())
        sync_team(self.db, collector=fixture)
        self.assertEqual(self.state()["seq"], 1)

    def test_drain_completes_backlog_or_resumes_after_budget(self):
        fixture = ChangeDocumentFixture(count=251)
        with patch("rag.library.time.monotonic", side_effect=[0, 61]):
            result = sync_team_drain(self.db, collector=fixture)
        self.assertTrue(result["has_more"])
        self.assertTrue(result["pending"])
        self.assertEqual(self.state()["seq"], 30)
        result = sync_team_drain(self.db, collector=fixture)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["has_more"])
        self.assertEqual(len(documents(self.db)), 251)

    def test_retraction_removes_evidence_but_keeps_historical_document(self):
        fixture = ChangeDocumentFixture(count=1)
        sync_team(self.db, collector=fixture)
        self.assertTrue(search("prompt injection", db_path=self.db)["evidence"])
        fixture.events.append({"seq": 2, "entity_id": fixture.events[0]["entity_id"], "operation": "retract", "item": None})
        sync_team(self.db, collector=fixture)
        self.assertFalse(search("prompt injection", db_path=self.db)["evidence"])
        self.assertEqual(documents(self.db)[0]["document_id"], team_id(fixture.events[0]["entity_id"]))
        self.assertEqual(documents(self.db)[0]["latest_attempt_status"], "withdrawn")

    def test_reclassification_after_retraction_restores_the_final_valid_state(self):
        fixture = ChangeDocumentFixture(count=1)
        first = fixture.events[0]
        fixture.events.extend([
            {"seq": 2, "entity_id": first["entity_id"], "operation": "retract", "item": None},
            dict(first, seq=3),
        ])
        result = sync_team(self.db, collector=fixture)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["source"]["retracted"], 0)
        self.assertTrue(search("prompt injection", db_path=self.db)["evidence"])
        self.assertEqual(documents(self.db)[0]["latest_attempt_status"], "ok")

    def test_known_retraction_is_applied_even_if_another_record_blocks_checkpoint(self):
        fixture = ChangeDocumentFixture(count=1)
        sync_team(self.db, collector=fixture)
        identity = fixture.events[0]["entity_id"]
        bad = record(number=900)
        bad["description"] = ""
        fixture.events.extend([
            {"seq": 2, "entity_id": identity, "operation": "retract", "item": None},
            {"seq": 3, "entity_id": bad["document_id"], "operation": "upsert", "item": bad},
        ])
        result = sync_team(self.db, collector=fixture)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(self.state()["seq"], 1)
        self.assertFalse(search("prompt injection", db_path=self.db)["evidence"])

    def test_environment_url_is_resolved_by_default_sync(self):
        with patch.dict("os.environ", {"TEAM_INTEL_BASE_URL": "http://b-api:8765"}), \
             patch.object(TeamDocumentCollector, "collect_changes", return_value={
                 "candidates": [], "errors": [], "retracted_ids": [], "selected": 0,
                 "total": None, "remaining": None, "has_more": False, "reset": False,
                 "cursor": {"epoch": "test", "seq": 0}, "coverage": "fixture"}) as called:
            result = sync_team(self.db)
        called.assert_called_once()
        self.assertEqual(result["source"]["url"], "http://b-api:8765/api/documents")

    def test_cve_pagination_failure_returns_no_partial_or_committed_cursor(self):
        collector = IncrementalIntelligenceCollector(cursor={}, max_pages=2)
        page = {"epoch": "fixture", "reset": False, "cursor": 0, "next_cursor": 1,
                "through": 2, "has_more": True, "changes": [{"seq": 1, "entity_id": "CVE-2026-10000",
                "operation": "upsert", "item": {"cve_id": "CVE-2026-10000"}}]}
        with patch.object(collector, "get", side_effect=[page, TimeoutError("Fixture interrupted")]):
            with self.assertRaises(TimeoutError):
                collector.collect()
        self.assertIsNone(collector.pending_cursor)
        with self.assertRaises(ValueError):
            collector.commit_cursor()


if __name__ == "__main__":
    unittest.main()
