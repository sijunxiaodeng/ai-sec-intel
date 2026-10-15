"""Manual research must progress independently of slow historical enrichment."""
import copy
import os
import threading
import unittest
from unittest.mock import patch

from automation import processing, investigation_queue as queue
from database import store
from questions import test_investigation_queue as fixtures


class InteractiveProcessingTest(unittest.TestCase):
    def setUp(self):
        fixtures.InvestigationQueueTest.setUp(self)

    result = fixtures.InvestigationQueueTest.result

    def explicit(self):
        return queue.reconcile([self.record], explicit=True, force=True, reason="user_research")

    def test_explicit_research_bypasses_pending_backlog_but_keeps_missing_evidence_visible(self):
        history = []
        for number in range(30):
            row = copy.deepcopy(self.record)
            row["item"]["cve_id"] = "CVE-2026-%05d" % (40000 + number)
            history.append(row)
        store.upsert(history)
        processing.enqueue(history)
        processing.enqueue([self.record])
        self.explicit()
        with patch("agents.investigation.run", side_effect=self.result) as agent:
            self.assertEqual(queue.run_pending(limit=1, explicit_only=True), 1)
        agent.assert_called_once()
        task = queue.tasks()["items"][0]
        self.assertEqual(task["status"], "done")
        self.assertIn("尚未完成", task["trace"]["evidence_notice"])
        self.assertEqual(task["trace"]["remaining_gaps"], ["cvss"])
        with processing._connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM processing_jobs WHERE status='pending'").fetchone()[0], 62)

    def test_pending_manual_task_reserves_its_cve_without_blocking_other_cves(self):
        other = copy.deepcopy(self.record)
        other["item"]["cve_id"] = "CVE-2026-12345"
        store.upsert([other])
        processing.enqueue([self.record, other])
        self.explicit()
        for stage in ("enrich", "documents"):
            jobs = processing._claim(stage, 10)
            self.assertEqual([job["cve_id"] for job in jobs], [other["item"]["cve_id"]])
        self.assertEqual(len(processing._claim("investigate", explicit_only=True)), 1)

    def test_manual_research_waits_for_same_cve_running_fetch_and_lease_excludes_duplicates(self):
        processing.enqueue([self.record])
        fetch = processing._claim("documents", 1)[0]
        self.explicit()
        self.assertEqual(processing._claim("investigate", explicit_only=True), [])
        processing._finish(fetch)
        barrier = threading.Barrier(2)
        claimed, errors = [], []
        def claim():
            try:
                barrier.wait(timeout=5)
                claimed.extend(processing._claim("investigate", 1, explicit_only=True))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(claimed), 1, "transactional claims must not execute the same task twice")
        self.assertEqual(processing._claim("enrich", 1), [], "a running investigation owns this CVE")
        old = claimed[0]
        with processing._connection() as conn:
            conn.execute("UPDATE processing_jobs SET lease_until=0 WHERE id=?", (old["id"],))
        replacement = processing._claim("investigate", 1, explicit_only=True)[0]
        processing._finish(old, trace={"committed": True})
        self.assertEqual(queue.tasks()["items"][0]["status"], "running")
        self.assertEqual(queue.history(old["id"]), [])
        processing._finish(replacement)
        self.assertEqual(queue.tasks()["items"][0]["status"], "done")

    def test_background_investigation_does_not_consume_explicit_lane(self):
        self.explicit()
        self.assertEqual(processing._claim("investigate", explicit_only=False), [])
        self.assertEqual(len(processing._claim("investigate", explicit_only=True)), 1)

    def test_interactive_worker_runs_while_bulk_worker_is_blocked_and_stops_after_current_job(self):
        processing.enqueue([self.record])
        self.explicit()
        stop = threading.Event()
        bulk_started, release_bulk, research_started, release_research = [threading.Event() for _ in range(4)]
        calls = []
        def slow_bulk(*args):
            bulk_started.set()
            if not release_bulk.wait(5):
                raise RuntimeError("Fixture bulk release timed out")
            return {}
        def research(record, **kwargs):
            calls.append(record["item"]["cve_id"])
            research_started.set()
            if not release_research.wait(5):
                raise RuntimeError("Fixture research release timed out")
            return self.result(record)
        with patch.object(processing, "_STOP", stop), patch.object(processing, "_THREAD", None), \
                patch.object(processing, "_INTERACTIVE_THREAD", None), \
                patch.dict(os.environ, {"AUTO_INGEST_ON_COLLECT": "1"}), \
                patch.object(processing, "run_batch", side_effect=slow_bulk), \
                patch("agents.investigation.run", side_effect=research):
            processing.start()
            try:
                self.assertTrue(bulk_started.wait(5))
                self.assertTrue(research_started.wait(5), "manual research must not wait for the bulk batch")
                bulk, interactive = processing._THREAD, processing._INTERACTIVE_THREAD
                processing.start()
                self.assertIs(processing._THREAD, bulk)
                self.assertIs(processing._INTERACTIVE_THREAD, interactive)
                processing.stop()
            finally:
                processing.stop()
                release_bulk.set()
                release_research.set()
                for worker in (processing._THREAD, processing._INTERACTIVE_THREAD):
                    if worker is not None:
                        worker.join(timeout=10)
            self.assertFalse(processing._THREAD.is_alive())
            self.assertFalse(processing._INTERACTIVE_THREAD.is_alive())
        self.assertEqual(calls, [self.record["item"]["cve_id"]])
        self.assertEqual(queue.tasks()["items"][0]["status"], "done")


if __name__ == "__main__":
    unittest.main()
