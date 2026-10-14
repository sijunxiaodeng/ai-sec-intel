"""Exercise the actual metadata reader embedded in the Windows entry point."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "production-check.ps1"
CODE = re.search(r"\$MetadataCode = @'\n(.*?)\n'@", SCRIPT.read_text(), re.S).group(1)


class StateError(RuntimeError):
    pass


class MetadataDiagnosticsTests(unittest.TestCase):
    def read(self, *, error=None, run=None):
        mirror = types.ModuleType("deployment.actions_mirror")
        state = types.ModuleType("deployment.actions_state")
        state.StateError = StateError
        state.GitHubClient = lambda token, repository: object()

        def latest_snapshot(client):
            if error is not None:
                raise error
            return run or {"id": 42, "head_sha": "a" * 40}, {"id": 7}

        mirror.latest_snapshot = latest_snapshot
        output = io.StringIO()
        exit_code = 0
        with patch.dict("sys.modules", {"deployment.actions_mirror": mirror, "deployment.actions_state": state}), redirect_stdout(output):
            try:
                exec(compile(CODE, str(SCRIPT), "exec"), {})
            except SystemExit as exc:
                exit_code = exc.code
        return exit_code, json.loads(output.getvalue())

    def test_success_emits_only_expected_generation(self):
        code, result = self.read()
        self.assertEqual(code, 0)
        self.assertEqual(result, {"run_id": 42, "collector_commit": "a" * 40})

    def test_network_failure_is_visible_without_exception_details(self):
        code, result = self.read(error=StateError("GitHub state API unavailable; no collection was started"))
        self.assertEqual(code, 1)
        self.assertEqual(result, {"error_category": "github_network_unavailable", "http_status": None})

    def test_http_categories_keep_403_ambiguous(self):
        categories = {401: "github_authentication_failed", 403: "github_access_denied_or_rate_limited",
                      429: "github_rate_limited", 503: "github_http_unavailable", 404: "github_resource_unavailable"}
        for status, category in categories.items():
            with self.subTest(status=status):
                code, result = self.read(error=StateError(f"GitHub state API failed: HTTP {status}; no collection was started"))
                self.assertEqual(code, 1)
                self.assertEqual(result, {"error_category": category, "http_status": status})

    def test_arbitrary_state_error_and_header_exception_do_not_expose_secrets(self):
        for error in (StateError("https://private.example/?token=fixture-secret"), ValueError("Invalid header fixture-secret")):
            with self.subTest(error_type=type(error).__name__):
                code, result = self.read(error=error)
                self.assertEqual(code, 1)
                self.assertNotIn("fixture-secret", json.dumps(result))
                self.assertNotIn("https://", json.dumps(result))

    def test_invalid_generation_never_emits_a_success(self):
        code, result = self.read(run={"id": True, "head_sha": "fixture-secret"})
        self.assertEqual(code, 1)
        self.assertEqual(result, {"error_category": "unexpected_metadata_failure"})


if __name__ == "__main__":
    unittest.main()
