"""Expose execution state without starting providers or changing durable jobs."""
import os
import threading
import unittest
from unittest.mock import Mock, patch

from automation import processing, investigation_queue as queue
from enrichment import assets
from questions import test_investigation_queue as fixtures


class ProcessingStatusTest(unittest.TestCase):
    def setUp(self):
        fixtures.InvestigationQueueTest.setUp(self)
        self.stop = threading.Event()
        self.enterContext(patch.object(processing, "_STOP", self.stop))
        self.enterContext(patch.object(processing, "_THREAD", None))
        self.enterContext(patch.object(processing, "_INTERACTIVE_THREAD", None))
        self.enterContext(patch.object(processing, "_ACTIVITY", {
            name: {"last_started_at": None, "last_finished_at": None,
                   "last_error": None, "in_progress": False}
            for name in ("background", "explicit")}))
        self.enterContext(patch.dict(os.environ, {"AUTO_INGEST_ON_COLLECT": "1"}))

    def running(self):
        self.enterContext(patch.object(processing, "_THREAD", Mock(is_alive=Mock(return_value=True))))
        self.enterContext(patch.object(processing, "_INTERACTIVE_THREAD", Mock(is_alive=Mock(return_value=True))))

    def pending(self, explicit=False):
        if not explicit:
            assets.import_assets({"assets": [self.asset]})
        queue.reconcile([self.record], explicit=explicit)
        return queue.tasks()["items"][0]

    def test_configured_enable_does_not_claim_worker_is_alive(self):
        state = processing.worker_state()
        self.assertTrue(state["configured_enabled"])
        self.assertFalse(state["running"])
        self.assertEqual(state["status"], "not_started")
        self.assertTrue(state["restart_required"])
        self.assertEqual(self.pending()["wait_reason"]["code"], "worker_not_running")

    def test_disabled_switch_does_not_start_threads_or_claim_pending_jobs(self):
        with patch.dict(os.environ, {"AUTO_INGEST_ON_COLLECT": " false "}), \
                patch.object(processing.threading, "Thread") as thread:
            processing.start()
            task = self.pending()
            state = processing.worker_state()
        thread.assert_not_called()
        self.assertEqual(state["status"], "disabled")
        self.assertEqual(task["wait_reason"]["code"], "worker_disabled")
        self.assertEqual(task["attempts"], 0)
        self.assertEqual(task["status"], "pending")
        self.assertEqual(queue.history(task["id"]), [])

    def test_each_lane_and_stop_state_are_reported_independently(self):
        self.running()
        self.assertEqual(processing.worker_state()["status"], "running")
        with patch.object(processing, "_INTERACTIVE_THREAD", None):
            state = processing.worker_state()
            self.assertEqual(state["status"], "partial")
            self.assertTrue(state["background"]["running"])
            self.assertFalse(state["explicit"]["running"])
        processing.stop()
        state = processing.worker_state()
        self.assertEqual(state["status"], "stopping")
        self.assertFalse(state["running"])
        self.assertTrue(state["background"]["alive"])

    def test_config_changed_in_memory_does_not_hide_still_running_threads(self):
        self.running()
        with patch.dict(os.environ, {"AUTO_INGEST_ON_COLLECT": "0"}):
            state = processing.worker_state()
            self.assertFalse(state["configured_enabled"])
            self.assertTrue(state["running"])
            self.assertEqual(state["status"], "running")
            self.assertTrue(state["restart_required"])

    def test_pending_reason_matches_same_cve_prerequisite_claim_rules(self):
        self.running()
        assets.import_assets({"assets": [self.asset]})
        processing.enqueue([self.record])
        task = queue.tasks()["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "prerequisites")
        self.assertEqual({row["stage"] for row in task["wait_reason"]["prerequisites"]}, {"enrich", "documents"})
        self.assertEqual(processing._claim("investigate"), [])
        queue.reconcile([self.record], explicit=True, force=True)
        task = queue.tasks()["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "queued")
        job = processing._claim("investigate", explicit_only=True)[0]
        task = queue.tasks()["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "executing")
        self.assertEqual(task["attempts"], 1)
        processing._finish(job, "SyntheticProviderFailure")
        task = queue.tasks()["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "retry_wait")
        self.assertEqual(task["wait_reason"]["available_at"], task["available_at"])
        self.assertEqual(task["attempts"], 1)

    def test_explicit_waits_only_for_its_own_running_prerequisite(self):
        self.running()
        processing.enqueue([self.record])
        prerequisite = processing._claim("documents")[0]
        task = self.pending(explicit=True)
        self.assertEqual(task["wait_reason"]["code"], "prerequisites")
        self.assertEqual(task["wait_reason"]["prerequisites"], [{"stage": "documents", "status": "running", "attempts": 1}])
        processing._finish(prerequisite)
        self.assertEqual(queue.tasks()["items"][0]["wait_reason"]["code"], "queued")

    def test_expired_running_lease_is_visible_without_rewriting_it(self):
        self.pending(explicit=True)
        job = processing._claim("investigate")[0]
        with processing._connection() as conn:
            conn.execute("UPDATE processing_jobs SET lease_until=0 WHERE id=?", (job["id"],))
        task = queue.tasks()["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "lease_expired")
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["attempts"], 1)

    def test_disabled_restart_preserves_running_lease_without_claiming_execution(self):
        self.pending(explicit=True)
        job = processing._claim("investigate")[0]
        with processing._connection() as conn:
            before = tuple(conn.execute("SELECT status,attempts,lease_token,lease_until FROM processing_jobs WHERE id=?",
                                        (job["id"],)).fetchone())
        with patch.dict(os.environ, {"AUTO_INGEST_ON_COLLECT": "0"}):
            response = queue.tasks()
        self.assertEqual(response["worker"]["status"], "disabled")
        task = response["items"][0]
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["wait_reason"]["code"], "execution_unconfirmed")
        self.assertIn("当前对应线程未运行", task["wait_reason"]["label"])
        self.assertNotIn("正在执行", task["wait_reason"]["label"])
        self.assertEqual(task["wait_reason"]["lease_until"], before[3])
        with processing._connection() as conn:
            after = tuple(conn.execute("SELECT status,attempts,lease_token,lease_until FROM processing_jobs WHERE id=?",
                                       (job["id"],)).fetchone())
        self.assertEqual(after, before)
        self.assertEqual(queue.history(job["id"]), [])

    def test_only_the_running_jobs_own_lane_can_confirm_a_live_worker(self):
        self.pending(explicit=True)
        processing._claim("investigate")
        with patch.object(processing, "_THREAD", Mock(is_alive=Mock(return_value=True))):
            response = queue.tasks()
        self.assertEqual(response["worker"]["status"], "partial")
        self.assertEqual(response["items"][0]["wait_reason"]["code"], "execution_unconfirmed")

    def test_stopping_live_lane_does_not_infer_inflight_task_failure(self):
        self.running()
        self.pending(explicit=True)
        job = processing._claim("investigate")[0]
        processing.stop()
        response = queue.tasks()
        self.assertEqual(response["worker"]["status"], "stopping")
        task = response["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "execution_stopping")
        self.assertIn("可能仍有在途处理", task["wait_reason"]["label"])
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["attempts"], 1)
        self.assertEqual(task["error"], "")
        self.assertEqual(queue.history(job["id"]), [])

    def test_expired_prerequisite_does_not_claim_to_be_an_active_fetch(self):
        self.running()
        processing.enqueue([self.record])
        prerequisite = processing._claim("documents")[0]
        self.pending(explicit=True)
        with processing._connection() as conn:
            conn.execute("UPDATE processing_jobs SET lease_until=0 WHERE id=?", (prerequisite["id"],))
        self.assertEqual(queue.tasks()["items"][0]["wait_reason"]["code"], "queued")
        with processing._connection() as conn:
            self.assertEqual(conn.execute("SELECT status FROM processing_jobs WHERE id=?", (prerequisite["id"],)).fetchone()[0], "running")
        self.assertEqual(len(processing._claim("investigate", explicit_only=True)), 1)

    def test_completion_remains_visible_even_when_worker_is_disabled(self):
        self.pending(explicit=True)
        job = processing._claim("investigate")[0]
        processing._finish(job)
        with patch.dict(os.environ, {"AUTO_INGEST_ON_COLLECT": "0"}):
            task = queue.tasks()["items"][0]
        self.assertEqual(task["wait_reason"]["code"], "completed")
        self.assertEqual(task["attempts"], 1)

    def test_loop_error_observability_does_not_leak_provider_error_text(self):
        def fail(*args, **kwargs):
            self.assertTrue(processing.worker_state()["explicit"]["in_progress"])
            raise ValueError("private-token-at-private-host")
        with patch.object(queue, "run_pending", side_effect=fail), \
                patch.object(self.stop, "wait", side_effect=lambda seconds: self.stop.set()), \
                patch("logging.Logger.exception"):
            processing._interactive_loop()
        lane = processing.worker_state()["explicit"]
        self.assertEqual(lane["last_error"], "ValueError")
        self.assertIsNotNone(lane["last_started_at"])
        self.assertIsNotNone(lane["last_finished_at"])
        self.assertFalse(lane["in_progress"])
        self.assertNotIn("private-token", str(lane))


if __name__ == "__main__":
    unittest.main()
