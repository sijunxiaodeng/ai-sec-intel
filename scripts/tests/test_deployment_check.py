"""Desktop deployment proof must follow durable state, not startup or POST 200."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("desktop_check", Path(__file__).resolve().parents[1] / "deployment_check.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class DeploymentCheckTests(unittest.TestCase):
    def setUp(self):
        self.high = {"epoch": "fixture-epoch", "through": 10}
        self.delivery = {"status": "serving_verified_generation", "database_available": True,
            "generation": {"repository": "team/public-repo", "branch": "main", "workflow": "intelligence-collect.yml",
                           "run_id": 42, "run_number": 7, "collector_commit": "a" * 40},
            "compatibility": {"ready": True}, "changefeed": self.high, "poller_observation": "ready"}
        self.saved = {"cve": False, "document": False}
        self.posts = []
        self.elapsed = 0

    def reader(self, url):
        if url.endswith("/api/intelligence/delivery"):
            return copy.deepcopy(self.delivery)
        if url.endswith("/api/admin/actions-consumption"):
            consumers = {kind: {"status": "caught_up" if saved else "lagging", "checkpoint": {
                "epoch": self.high["epoch"], "seq": 10 if saved else 0}} for kind, saved in self.saved.items()}
            consumers["all_caught_up"] = all(self.saved.values())
            return {"status": "caught_up" if all(self.saved.values()) else "pending", "upstream": self.high, "consumers": consumers}
        return {**self.high, "cursor": 0, "next_cursor": 10, "has_more": False, "reset": False, "changes": []}

    def poster(self, url, body):
        self.posts.append((url, body))
        self.saved["cve" if url.endswith("/api/collect") else "document"] = True
        return True

    def sleep(self, seconds):
        self.elapsed += seconds

    def check(self, **overrides):
        options = dict(b_base="http://127.0.0.1:8023", main_base="http://127.0.0.1:8023", run_id=42,
                       collector_commit="a" * 40, wait_seconds=5, reader=self.reader, poster=self.poster,
                       clock=lambda: self.elapsed, sleeper=self.sleep)
        options.update(overrides)
        return CHECK.check(**options)

    def test_readonly_never_starts_import_and_pending_state_is_not_complete(self):
        proof = self.check()
        self.assertTrue(proof["snapshot_serving_verified"])
        self.assertFalse(proof["deployment_import_loop_verified"])
        self.assertEqual(self.posts, [])

    def test_explicit_sync_rechecks_both_real_persisted_consumers(self):
        proof = self.check(synchronize=True)
        self.assertTrue(proof["deployment_import_loop_verified"])
        self.assertTrue(proof["pull_verified"])
        self.assertFalse(proof["processing_verified"])
        self.assertEqual([url.rsplit("/", 1)[-1] for url, _ in self.posts], ["collect", "team-sync"])
        self.assertEqual(self.posts[1][1], {"max_documents": 200})

    def test_successful_posts_do_not_prove_saved_data(self):
        proof = self.check(synchronize=True, poster=lambda url, body: True)
        self.assertFalse(proof["consumption_verified"])
        self.assertFalse(proof["deployment_import_loop_verified"])

    def test_finished_consumer_is_not_repeated_while_another_catches_up(self):
        self.saved["cve"] = True
        proof = self.check(synchronize=True)
        self.assertTrue(proof["deployment_import_loop_verified"])
        self.assertEqual(len(self.posts), 1)
        self.assertTrue(self.posts[0][0].endswith("/api/library/team-sync"))

    def test_wrong_generation_never_receives_import_writes(self):
        self.delivery["generation"]["run_id"] = 41
        proof = self.check(synchronize=True)
        self.assertFalse(proof["deployment_import_loop_verified"])
        self.assertEqual(self.posts, [])

    def test_merely_reachable_html_or_generic_success_is_not_ready(self):
        proof = self.check(synchronize=True, reader=lambda url: {"ok": True})
        self.assertFalse(proof["snapshot_serving_verified"])
        self.assertEqual(self.posts, [])

    def test_saved_import_without_recent_mirror_pull_is_not_a_pull_loop(self):
        self.saved = {"cve": True, "document": True}
        self.delivery["poller_observation"] = "stale"
        proof = self.check()
        self.assertTrue(proof["consumption_verified"])
        self.assertFalse(proof["pull_verified"])
        self.assertEqual(proof["reason_category"], "import_verified_recent_pull_unverified")

    def test_sync_failures_remain_incomplete_and_report_no_request_body(self):
        proof = self.check(synchronize=True, poster=lambda url, body: False)
        self.assertTrue(proof["synchronization_request_failed"])
        self.assertFalse(proof["deployment_import_loop_verified"])
        self.assertNotIn("max_documents", str(proof))

    def test_invalid_wait_or_credentials_are_rejected_before_requests(self):
        for options in ({"wait_seconds": True}, {"wait_seconds": 4}, {"run_id": 0},
                        {"main_base": "https://user:secret@example.test"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.check(synchronize=True, **options)
        self.assertEqual(self.posts, [])


if __name__ == "__main__":
    unittest.main()
