"""The offline runner resolves shared helpers without shadowing B packages."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class OfflineRunnerTests(unittest.TestCase):
    def test_b_imports_and_socket_guard_work_without_pythonpath_override(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Path(directory)
            (suite / "test_runner_fixture.py").write_text('''
from pathlib import Path
import socket
import unittest
import collectors
from team_change_protocol import validate_page

class RunnerFixture(unittest.TestCase):
    def test_package_precedence(self):
        self.assertEqual(Path(collectors.__file__).resolve().parent,
                         Path.cwd() / "collectors")
        page = {"epoch": "fixture", "cursor": 0, "next_cursor": 0,
                "through": 0, "reset": False, "has_more": False, "changes": []}
        self.assertEqual(validate_page(page, 0), page)

    def test_loopback_allowed_public_connections_blocked(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname(), timeout=1):
                client, _ = listener.accept()
                client.close()
        with socket.socket() as client:
            with self.assertRaisesRegex(OSError, "Offline tests prohibit"):
                client.connect(("203.0.113.1", 443))
''', encoding="utf-8")
            runner_env = dict(os.environ)
            runner_env.pop("PYTHONPATH", None)
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/run_offline_tests.py"),
                 "--start-directory", str(suite)],
                cwd=ROOT / "intelligence", env=runner_env,
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Ran 2 tests", result.stderr)
