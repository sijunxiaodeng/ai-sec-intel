"""Desktop deployment proof must follow durable state, not startup or POST 200."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

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

    def test_wait_progress_is_immediate_periodic_and_does_not_start_imports(self):
        updates = []
        proof = self.check(wait_seconds=25, progress=updates.append)
        self.assertEqual([item["phase"] for item in updates],
                         ["verification_started", "waiting", "waiting", "waiting", "wait_expired"])
        self.assertEqual([item["elapsed_seconds"] for item in updates], [0, 0, 10, 20, 25])
        self.assertTrue(updates[1]["snapshot_serving_verified"])
        self.assertEqual(updates[1]["reason_category"], "consumer_import_pending")
        self.assertFalse(proof["deployment_import_loop_verified"])
        self.assertEqual(self.posts, [])

    def test_sync_progress_precedes_blocking_posts_and_requires_saved_recheck(self):
        updates = []

        def delayed_poster(url, body):
            kind = "cve" if url.endswith("/api/collect") else "document"
            self.assertEqual(updates[-1]["phase"], kind + "_import_started")
            self.assertFalse(updates[-1][kind + "_caught_up"])
            self.elapsed += 3
            return self.poster(url, body)

        proof = self.check(synchronize=True, wait_seconds=20, poster=delayed_poster, progress=updates.append)
        self.assertTrue(proof["deployment_import_loop_verified"])
        self.assertEqual([item["phase"] for item in updates], [
            "verification_started", "waiting", "cve_import_started", "cve_import_returned",
            "document_import_started", "document_import_returned", "verified"])
        self.assertFalse(updates[-2]["document_caught_up"])
        self.assertTrue(updates[-1]["cve_caught_up"])
        self.assertTrue(updates[-1]["document_caught_up"])
        self.assertEqual(updates[-1]["reason_category"], "actions_pull_and_durable_import_verified")

    def test_arbitrary_endpoint_errors_and_metadata_never_enter_progress(self):
        secret = "fixture-private-token"
        updates = []

        def failed_reader(url):
            raise CHECK.DELIVERY.VerificationError("https://example.test/private?token=" + secret)

        self.check(reader=failed_reader, progress=updates.append)
        safe = CHECK.progress_summary({
            "reason_category": "error " + secret, "poller_observation": secret,
            "generation": {"repository": secret}, "url": "https://example.test/" + secret,
            "consumers": {"cve": {"caught_up": secret}, "document": {"caught_up": True}},
        }, phase="waiting", elapsed_seconds=3)
        self.assertEqual(safe["reason_category"], "unverified")
        self.assertEqual(safe["poller_observation"], "unverified")
        self.assertFalse(safe["cve_caught_up"])
        self.assertTrue(safe["document_caught_up"])
        self.assertNotIn(secret, json.dumps(updates + [safe]))
        self.assertNotIn("https://", json.dumps(updates + [safe]))

    def test_cli_keeps_default_stdout_json_and_progress_is_explicit(self):
        proof = self.check(synchronize=True)
        argv = ["--run-id", "42", "--collector-commit", "a" * 40]
        for enabled in (False, True):
            with self.subTest(progress=enabled):
                output = io.StringIO()

                def run_check(**options):
                    if options["progress"] is not None:
                        options["progress"](CHECK.progress_summary({}, phase="verification_started", elapsed_seconds=0))
                    return proof

                with patch.object(CHECK, "check", side_effect=run_check), redirect_stdout(output):
                    self.assertEqual(CHECK.main(argv + (["--progress"] if enabled else [])), 0)
                body = output.getvalue()
                if enabled:
                    self.assertTrue(body.startswith("[deployment-check] "))
                    body = body.split("\n", 1)[1]
                self.assertEqual(json.loads(body), proof)

    def test_progress_print_flushes_stdout(self):
        with patch("builtins.print") as printer:
            CHECK.print_progress(CHECK.progress_summary({}, phase="verification_started", elapsed_seconds=0))
        self.assertTrue(printer.call_args.kwargs["flush"])


if __name__ == "__main__":
    unittest.main()
