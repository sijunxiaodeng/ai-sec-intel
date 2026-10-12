"""Offline durable pipeline regressions; upstream HTTP is substituted, persistence is real."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from automation import processing, schedule
from database import store
from models import enriched_record


class ProcessingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        changes = {name: self.root / filename for name, filename in {
            "DB_PATH": "main.sqlite3", "KB_PATH": "old.json", "RUNS_PATH": "runs.json",
            "CARDS_PATH": "cards.json", "CARDS_JS_PATH": "cards.js", "SEED_CARDS_PATH": "seed.json"}.items()}
        changes["DATA"] = self.root
        self.enterContext(patch.multiple(store, **changes))
        self.enterContext(patch.dict(os.environ, {"MAIN_KB_DB_PATH": str(changes["DB_PATH"]),
                                                  "MAIN_IMPORT_DEMO_CARDS": "0"}))
        self.record = enriched_record({"cve_id": "CVE-2026-34567", "title": "vLLM vulnerability",
            "description": "model serving RCE", "source": "NVD", "product": "vllm",
            "collected_at": "2026-10-10T01:00:00Z", "published_at": "2026-10-10T00:00:00Z"})

    def _providers(self, *, epss_error=None, document_error=False, index_error=False):
        def feeds(records):
            for record in records:
                record["epss"] = {"status": "ok", "score": "0.31"}
                record["kev"] = {"status": "not_listed"}
            return {"epss_error": epss_error, "kev_error": None}
        return (patch("enrichment.service.apply_public_feeds", side_effect=feeds),
                patch("enrichment.papers.fetch_papers", return_value=({}, None)),
                patch("rag.ingest.ingest", return_value={"attempted": 2, "ok": 1 if document_error else 2}),
                patch("rag.hybrid.update_index", return_value={"status": "error" if index_error else "deferred"}))

    def test_all_records_are_reconciled_once_after_restart(self):
        rows = []
        for number in range(251):
            row = copy.deepcopy(self.record)
            row["item"]["cve_id"] = "CVE-2026-%05d" % (40000 + number)
            rows.append(row)
        store.upsert(rows)  # Simulate a crash before the producer enqueues.
        self.assertEqual(processing.enqueue(store.load_kb()), 502)
        self.assertEqual(processing.enqueue(store.load_kb()), 0)
        with processing._connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM processing_jobs").fetchone()[0], 502)

    def test_successful_enrichment_does_not_create_another_revision(self):
        store.upsert([self.record])
        a, b, c, d = self._providers()
        with a, b, c, d:
            processing.run_batch()
        self.assertEqual(processing.state()["counts"], {"done": 3})
        self.assertEqual(processing.enqueue(store.load_kb()), 0)
        self.assertEqual(store.get_record(self.record["item"]["cve_id"])["epss"]["score"], "0.31")

    def test_partial_document_and_configured_index_failures_retry_and_recover(self):
        store.upsert([self.record])
        a, b, c, d = self._providers(document_error=True, index_error=True)
        with a, b, c, d:
            processing.run_batch()
        self.assertEqual(processing.state()["counts"], {"done": 1, "retry": 2})
        with processing._connection() as conn:
            conn.execute("UPDATE processing_jobs SET available_at=0 WHERE status='retry'")
        a, b, c, d = self._providers()
        with a, b, c, d:
            processing.run_batch()
        self.assertEqual(processing.state()["counts"], {"done": 3})

    def test_expired_worker_cannot_complete_reclaimed_task(self):
        store.upsert([self.record])
        processing.enqueue(store.load_kb())
        old = processing._claim("enrich", 1)[0]
        with processing._connection() as conn:
            conn.execute("UPDATE processing_jobs SET lease_until=0 WHERE id=?", (old["id"],))
        new = processing._claim("enrich", 1)[0]
        processing._finish(old)
        with processing._connection() as conn:
            row = conn.execute("SELECT status,lease_token FROM processing_jobs WHERE id=?", (new["id"],)).fetchone()
            self.assertEqual(tuple(row), ("running", new["lease_token"]))

    def test_new_index_request_invalidates_running_completion(self):
        job = {"cve_id": self.record["item"]["cve_id"], "revision": "r1"}
        processing._enqueue_index(job)
        old = processing._claim("index", 1)[0]
        processing._enqueue_index(job)
        processing._finish(old)
        new = processing._claim("index", 1)
        self.assertEqual(len(new), 1)
        self.assertNotEqual(new[0]["lease_token"], old["lease_token"])
        processing._finish(new[0])
        self.assertEqual(processing.state()["counts"], {"done": 1})

    def test_withdrawal_during_fetch_cannot_be_reactivated_by_worker(self):
        cve = self.record["item"]["cve_id"]
        store.upsert([self.record])
        def feeds(records):
            store.retract([cve])
            records[0]["epss"] = {"status": "ok", "score": "0.9"}
            return {}
        with patch("enrichment.service.apply_public_feeds", side_effect=feeds), \
             patch("enrichment.papers.fetch_papers", return_value=({}, None)), \
             patch("rag.ingest.ingest") as ingest:
            processing.run_batch()
        self.assertIsNone(store.get_record(cve))
        ingest.assert_not_called()
        self.assertEqual(processing.state()["counts"], {"skipped": 2})

    def test_evidence_commit_guard_rejects_upstream_change_and_scope_withdrawal(self):
        store.upsert([self.record])
        processing.enqueue(store.load_kb())
        job = processing._claim("documents", 1)[0]
        store.retract([job["cve_id"]])
        with self.assertRaises(processing.StaleWork):
            with processing._commit_guard(job):
                self.fail("A withdrawn record must not commit C evidence")

    def test_tombstone_filters_c_archive_even_without_main_record(self):
        from rag.retrieve import knowledge_records
        cve = self.record["item"]["cve_id"]
        store.retract([cve])
        with patch("rag.retrieve.load_records", return_value=[self.record]), \
             patch("enrichment.assessment.enrich_view", side_effect=lambda rows, db: rows):
            self.assertEqual(knowledge_records(self.root / "evidence.sqlite3"), [])

    def test_failed_monitor_does_not_report_old_knowledge_as_a_new_success(self):
        from agents.monitor_agent import run
        with patch("agents.monitor_agent.IncrementalIntelligenceCollector") as cls, \
             patch.dict(os.environ, {"TEAM_ONLY_COLLECT": "1"}):
            cls.return_value.collect.side_effect = ConnectionError("offline")
            with self.assertRaises(RuntimeError):
                run()

    def test_observation_start_is_preserved_and_sync_count_is_not_library_size(self):
        self.enterContext(patch.multiple(schedule, STATE_PATH=self.root / "monitor.json",
                                         LOG_PATH=self.root / "collect.log"))
        schedule._write_state({"started_at": "2026-10-09T12:05:16Z"})
        with patch("agents.orchestrator.run_collect", return_value={"records": [self.record] * 20,
                  "fetched": 3, "round_stats": {"inserted": 1, "merged": 2}, "status": "partial"}), \
             patch("rag.library.sync_team_drain", return_value={"status": "ok", "ok": 2}), \
             patch("rag.library.sync") as public:
            result = schedule.run_once()
        public.assert_not_called()
        self.assertEqual(result["last_count"], 1)
        self.assertEqual(result["last_received"], 3)
        self.assertEqual(result["last_status"], "partial")
        self.assertEqual(result["started_at"], "2026-10-09T12:05:16Z")


if __name__ == "__main__":
    unittest.main()
