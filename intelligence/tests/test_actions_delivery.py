"""A successful HTTP exchange alone must never become delivery evidence."""
import io
import json
import os
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from deployment import actions_sync as sync
from deployment.actions_state import StateError

REPOSITORY = "team/public-repo"
TOKEN = "fixture-only-deployment-token"
MANIFEST = {"repository": REPOSITORY, "branch": "main", "run_id": 42,
            "run_number": 7, "collector_commit": "a" * 40,
            "workflow": "intelligence-collect.yml"}


class ActionsDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.archive = self.directory / "snapshot.zip"
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("manifest.json", json.dumps(MANIFEST))
        self.status = self.directory / "delivery_status.json"

    def push(self, body, **kwargs):
        opener = Mock()
        opener.open.return_value = io.BytesIO(body)
        with patch.object(sync.urllib.request, "build_opener", return_value=opener):
            result = sync.push_snapshot(url=kwargs.pop("url", "https://deploy.example"),
                                        token=TOKEN, repository=REPOSITORY, branch="main",
                                        run_id=42, archive=self.archive, **kwargs)
        return result, opener.open.call_args.args[0]

    def test_installed_receipt_must_match_every_outgoing_generation_field(self):
        installed = {**MANIFEST, "changed": True}
        result, request = self.push(json.dumps({"ok": True, "installed": installed,
                                               "server_secret": TOKEN}).encode())
        self.assertEqual(result["installed"], MANIFEST)
        self.assertFalse(result["consumer_verified"])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(request.full_url, "https://deploy.example/api/admin/actions-sync")
        self.assertEqual(request.headers["Authorization"], "Bearer " + TOKEN)
        for field, wrong in (("run_id", 41), ("run_number", 6), ("collector_commit", "b" * 40),
                             ("repository", "wrong/repository"), ("branch", "feature"),
                             ("workflow", "other.yml"), ("changed", 1)):
            with self.subTest(field=field), self.assertRaises(StateError):
                self.push(json.dumps({"ok": True, "installed": {**installed, field: wrong}}).encode())

    def test_http_200_error_html_and_generic_ok_never_count_as_verified_delivery(self):
        for body in (b"<html>sign in</html>", b'{"ok":true}', b'{"ok":false}',
                     b"[]", b"\xff", b" " * (sync.MAX_RESPONSE_BYTES + 1)):
            with self.subTest(body=body[:30]), self.assertRaises(StateError):
                self.push(body)

    def test_untrusted_error_body_and_token_bearing_url_are_never_exposed(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError(
            "https://deploy.example", 502, TOKEN, {}, io.BytesIO(TOKEN.encode()))
        with patch.object(sync.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(StateError, r"^Deploy ingest failed: HTTP 502$"):
                sync.push_snapshot(url="https://deploy.example", token=TOKEN, repository=REPOSITORY,
                                   branch="main", run_id=42, archive=self.archive)
        for url in ("http://deploy.example", "https://user:password@deploy.example",
                    "https://deploy.example?token=" + TOKEN, "https://deploy.example/#secret"):
            with self.subTest(url=url), self.assertRaises(StateError):
                self.push(b"{}", url=url)
        self.assertIsNone(sync._NoRedirect().redirect_request(None, None, 302, "Found", {},
                                                              "https://another.example"))
        with self.assertRaises(StateError), patch.object(sync.urllib.request, "build_opener") as build:
            sync.push_snapshot(url="https://deploy.example", token=TOKEN + "\r\nInjected: secret",
                               repository=REPOSITORY, branch="main", run_id=42, archive=self.archive)
        build.assert_not_called()

    def test_push_disabled_and_pull_unverified_are_recorded_separately(self):
        facts = sync.delivery_status(self.status, run_id=42, configured=False,
                                     push_outcome="skipped", upload_outcome="success")
        self.assertEqual((facts["status"], facts["pull_status"], facts["consumer_status"]),
                         ("disabled", "unverified", "unverified"))
        facts = sync.delivery_status(self.status, run_id=42, configured=True,
                                     push_outcome="skipped", upload_outcome="failure")
        self.assertEqual(facts["status"], "blocked")

    def test_only_same_run_verified_receipt_with_successful_step_counts(self):
        receipt = {"installed": MANIFEST, "changed": True}
        sync.record_delivery(self.status, run_id=41, status="verified",
                             reason_category="installed_receipt_verified", receipt=receipt)
        facts = sync.delivery_status(self.status, run_id=42, configured=True,
                                     push_outcome="success", upload_outcome="success")
        self.assertEqual(facts["status"], "unknown")
        sync.record_delivery(self.status, run_id=42, status="verified",
                             reason_category="installed_receipt_verified", receipt=receipt)
        facts = sync.delivery_status(self.status, run_id=42, configured=True,
                                     push_outcome="failure", upload_outcome="success")
        self.assertEqual(facts["status"], "failed")
        sync.record_delivery(self.status, run_id=42, status="verified",
                             reason_category="installed_receipt_verified", receipt=receipt)
        facts = sync.delivery_status(self.status, run_id=42, configured=True,
                                     push_outcome="success", upload_outcome="success")
        self.assertEqual(facts["status"], "verified")

    def test_cli_failed_push_writes_safe_current_run_status(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(sync, "push_snapshot", side_effect=StateError("safe failure")):
            self.assertEqual(sync.main(["push", "--run-id", "42", "--archive", str(self.archive),
                                        "--url", "https://deploy.example", "--ingest-token", TOKEN,
                                        "--status-file", str(self.status)]), 2)
        self.assertEqual(json.loads(self.status.read_text())["status"], "failed")
        self.assertNotIn(TOKEN, self.status.read_text())

    def test_workflow_failed_migration_or_compatibility_cannot_publish_or_push(self):
        source = (Path(__file__).resolve().parents[2] / ".github/workflows/intelligence-collect.yml").read_text()
        def step(name):
            return source.split("      - name: " + name, 1)[1].split("      - name:", 1)[0]
        self.assertLess(source.index("run_migrate_state.py"), source.index("run_monitor.py"))
        migration = step("Migrate restored state for current collector and consumers")
        self.assertIn("steps.restore.outputs.initial_deployment", migration)
        self.assertIn('if [ "$INITIAL_DEPLOYMENT" = "true" ]', migration)
        self.assertEqual(migration.count("--allow-new"), 1)
        for name in ("Collect public intelligence", "Review ambiguous intelligence with DeepSeek",
                     "Record disabled or unavailable model review", "Prepare consistent SQLite snapshot"):
            self.assertIn("steps.migrate.outcome == 'success'", step(name))
        self.assertIn("steps.compatibility.outcome == 'success'", step("Persist public collection state"))
        self.assertIn("steps.upload.outcome == 'success'", step("Push snapshot to deploy ingest API (optional)"))
        self.assertIn("env.DEPLOY_INGEST_CONFIGURED == 'true'", step("Push snapshot to deploy ingest API (optional)"))
        self.assertIn("actions_sync.py push", step("Push snapshot to deploy ingest API (optional)"))
        self.assertIn("always()", step("Record delivery evidence or missing configuration"))

    def test_push_receiver_uses_same_mirror_volume_as_api_and_can_bootstrap_empty_mirror(self):
        root = Path(__file__).resolve().parents[2]
        compose = (root / "docker-compose.actions.yml").read_text()
        main = compose.split("  main-app:", 1)[1].split("\nvolumes:", 1)[0]
        self.assertIn("b-actions-mirror-data:/app/actions-mirror", main)
        self.assertIn("ACTIONS_SYNC_DIRECTORY: /app/actions-mirror", main)
        self.assertIn("INTELLIGENCE_DB_PATH: /app/actions-mirror/current/intelligence.db", main)
        self.assertIn("ACTIONS_INGEST_TOKEN: ${ACTIONS_INGEST_TOKEN:-}", main)
        self.assertIn("condition: service_started", main)
        self.assertNotIn("condition: service_healthy", main)
        mirror = compose.split("  b-mirror:", 1)[1].split("  b-api:", 1)[0]
        self.assertIn("GITHUB_TOKEN: ${GITHUB_TOKEN:-}", mirror)
        self.assertNotIn("ACTIONS_INGEST_TOKEN", mirror)


if __name__ == "__main__":
    unittest.main()
