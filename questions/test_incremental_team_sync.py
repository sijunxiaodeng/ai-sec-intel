"""Persistent delivery cursors, backlog draining and failure-safe replays."""
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from collectors.intelligence import IncrementalIntelligenceCollector
from collectors.team_documents import TEAM_MEDIA, TeamDocumentCollector, team_id
from questions.test_team_documents import record
from rag.evidence import _connection
from rag.library import documents, search, sync_team, sync_team_drain, _team_process_lock, _TEAM_SYNC_LOCK


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

    def test_monitor_honors_embedded_mode_without_http(self):
        from agents import monitor_agent
        page = {"epoch": "embedded", "reset": False, "cursor": 0, "through": 0,
                "next_cursor": 0, "has_more": False, "changes": []}
        with patch.dict(os.environ, {"TEAM_INTEL_MODE": "embed", "TEAM_ONLY_COLLECT": "1"}), \
             patch("database.store.get_sync_cursor", return_value={}), \
             patch("api.b_embed.list_changes_page", return_value=page) as local, \
             patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected HTTP")):
            result = monitor_agent.run()
        self.assertEqual(result["status"], "success")
        local.assert_called_once()

    def test_monitor_keywords_never_filter_changes_or_ack_before_persistence(self):
        from agents import monitor_agent
        page = {"epoch": "embedded", "reset": False, "cursor": 0, "through": 2,
                "next_cursor": 2, "has_more": False, "changes": [
                    {"seq": 1, "entity_id": "CVE-2026-55551", "operation": "upsert",
                     "item": {"cve_id": "CVE-2026-55551", "source": "NVD", "product": "torchserve",
                              "description": "Synthetic AI model serving vulnerability"}},
                    {"seq": 2, "entity_id": "CVE-2026-55552", "operation": "retract"},
                ]}
        with patch.dict(os.environ, {"TEAM_INTEL_MODE": "embed", "TEAM_ONLY_COLLECT": "1"}), \
             patch("database.store.get_sync_cursor", return_value={}), \
             patch("database.store.set_sync_cursor") as acknowledge, \
             patch("api.b_embed.list_changes_page", return_value=page) as local, \
             patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected HTTP")):
            result = monitor_agent.run("vllm")
        self.assertEqual([item["cve_id"] for item in result["items"]], ["CVE-2026-55551"])
        self.assertEqual(result["team_changes"]["retracted_ids"], ["CVE-2026-55552"])
        self.assertEqual(result["team_changes"]["cursor"]["seq"], 2)
        self.assertEqual((result["stats"]["hit"], result["stats"]["kept"]), (2, 1))
        acknowledge.assert_not_called()
        local.assert_called_once_with(kind="cve", cursor=0, through=None, epoch=None, limit=100)

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
        with patch.dict("os.environ", {"TEAM_INTEL_MODE": "sidecar", "TEAM_INTEL_BASE_URL": "http://b-api:8765"}), \
             patch.object(TeamDocumentCollector, "collect_changes", return_value={
                 "candidates": [], "errors": [], "retracted_ids": [], "selected": 0,
                 "total": None, "remaining": None, "has_more": False, "reset": False,
                 "cursor": {"epoch": "test", "seq": 0}, "coverage": "fixture"}) as called:
            result = sync_team(self.db)
        called.assert_called_once()
        self.assertEqual(result["source"]["url"], "http://b-api:8765/api/documents")

    def test_parallel_thread_cannot_import_an_old_document_page(self):
        fixture = ChangeDocumentFixture(count=1)
        with _TEAM_SYNC_LOCK:
            with self.assertRaisesRegex(ValueError, "正在运行"):
                sync_team(self.db, collector=fixture)
        self.assertFalse(self.db.exists())
        self.assertEqual(sync_team(self.db, collector=fixture)["status"], "ok")

    def test_parallel_process_cannot_read_a_cursor_until_current_page_commits(self):
        # A fresh interpreter has its own thread lock, exercising the OS lock.
        code = """
import sys
from questions.test_incremental_team_sync import ChangeDocumentFixture
from rag.library import sync_team
try:
    sync_team(sys.argv[1], collector=ChangeDocumentFixture(count=1))
except ValueError as exc:
    assert '其他进程' in str(exc), str(exc)
else:
    raise AssertionError('A concurrent process imported a page while locked')
"""
        with _team_process_lock(self.db):
            result = subprocess.run([sys.executable, "-c", code, str(self.db)],
                                    capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.db.exists())
        self.assertEqual(sync_team(self.db, collector=ChangeDocumentFixture(count=1))["status"], "ok")
        self.assertEqual(self.state()["seq"], 1)

    def test_cve_page_has_original_expected_cursor_even_after_endpoint_change(self):
        old = {"epoch": "previous", "seq": 9, "base_url": "http://b-api:8765"}
        collector = IncrementalIntelligenceCollector(base_url="http://localhost:8023", cursor=old)
        page = {"epoch": "new", "reset": False, "cursor": 0, "next_cursor": 0,
                "through": 0, "has_more": False, "changes": []}
        with patch.object(collector, "get", return_value=page):
            result = collector.collect()
        self.assertEqual(result["cursor"]["expected_cursor"], old)
        self.assertEqual(result["cursor"]["base_url"], "http://localhost:8023")
        self.assertEqual(old["seq"], 9)

    def test_feed_cannot_change_epoch_without_declaring_reset(self):
        page = {"epoch": "new", "reset": False, "cursor": 1, "next_cursor": 2,
                "through": 2, "has_more": False, "changes": []}
        cve = IncrementalIntelligenceCollector(cursor={"epoch": "old", "seq": 1})
        with patch.object(cve, "get", return_value=page), self.assertRaises(ValueError):
            cve.collect()
        document = ChangeDocumentFixture(count=1)
        response = {"body": json.dumps(page).encode()}
        with patch.object(document, "get", return_value=response), self.assertRaises(ValueError):
            document.collect_changes({"epoch": "old", "seq": 1})

    def test_embed_changefeed_supports_both_document_and_cve_consumers(self):
        document = record(number=12)
        pages = [
            {"epoch": "embed", "reset": False, "cursor": 0, "next_cursor": 1,
             "through": 1, "has_more": False, "changes": [{"seq": 1,
             "entity_id": "CVE-2026-10000", "operation": "upsert", "item": {"cve_id": "CVE-2026-10000"}}]},
            {"epoch": "embed", "reset": False, "cursor": 0, "next_cursor": 1,
             "through": 1, "has_more": False, "changes": [{"seq": 1,
             "entity_id": document["document_id"], "operation": "upsert", "item": document}]},
        ]
        with patch.dict("os.environ", {"TEAM_INTEL_MODE": "embed"}), \
             patch("api.b_embed.list_changes_page", side_effect=pages) as bridge:
            cve = IncrementalIntelligenceCollector(cursor={}).collect()
            docs = sync_team(self.db)
        self.assertEqual(cve["items"][0]["cve_id"], "CVE-2026-10000")
        self.assertEqual(cve["cursor"]["expected_cursor"], {})
        self.assertEqual(docs["ok"], 1)
        self.assertEqual(docs["source"]["url"], "inprocess://b-embed/api/documents")
        self.assertEqual([call.kwargs["kind"] for call in bridge.call_args_list], ["cve", "document"])

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
