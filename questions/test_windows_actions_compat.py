"""Native Windows/Linux imports, status and publication-lock contracts; no network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
INTELLIGENCE = ROOT / "intelligence"
# Match the application's import strategy without shadowing main collectors.*.
if str(INTELLIGENCE) not in sys.path:
    sys.path.append(str(INTELLIGENCE))

from deployment import actions_mirror, state_role
from deployment.actions_state import StateError
from monitoring.lock import AlreadyRunning, ProcessFileLock


class NativeActionsCompatibilityTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_direct_scripts_import_without_unix_fcntl_or_cwd_dependency(self):
        for script in ("actions_sync.py", "actions_mirror.py", "state_role.py"):
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, str(INTELLIGENCE / "deployment" / script), "--help"],
                                        cwd=self.root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_actual_sync_status_reads_marker_on_native_python(self):
        from api.actions_ingest import actions_sync_status
        directory = self.root / "mirror"
        directory.mkdir()
        with patch.dict(os.environ, {"ACTIONS_SYNC_DIRECTORY": str(directory), "ACTIONS_INGEST_TOKEN": ""}):
            empty = actions_sync_status()
            self.assertFalse(empty["synced"])
            self.assertFalse(empty["enabled"])
            # Reading status must not require symlink privilege; publication is
            # separately tested and still requires a managed directory symlink.
            (directory / "current").mkdir()
            (directory / "current/manifest.json").write_text(json.dumps({"run_id": 42, "status": "installed"}), encoding="utf-8")
            current = actions_sync_status()
        self.assertTrue(current["synced"])
        self.assertEqual(current["last_sync"]["run_id"], 42)

    def test_role_claim_retains_writer_separation(self):
        directory = self.root / "state"
        state_role.claim_role(directory, "collector")
        state_role.claim_role(directory, "collector")
        with self.assertRaisesRegex(RuntimeError, "different writer"):
            state_role.claim_role(directory, "actions-mirror")
        self.assertEqual((directory / ".writer-mode").read_text().strip(), "collector")

    def holder(self, delay):
        path = self.root / "shared.lock"
        code = ("import sys,time; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                "from monitoring.lock import ProcessFileLock\n"
                "with ProcessFileLock(Path(sys.argv[2])):\n"
                " print('locked',flush=True)\n"
                " time.sleep(float(sys.argv[3]))\n")
        process = subprocess.Popen([sys.executable, "-c", code, str(INTELLIGENCE), str(path), str(delay)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        def finish():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        self.addCleanup(finish)
        self.assertEqual(process.stdout.readline().strip(), "locked")
        return path, process

    def test_publication_waits_for_other_process_then_acquires(self):
        path, process = self.holder(0.15)
        with ProcessFileLock(path, timeout=2):
            self.assertEqual(process.wait(timeout=2), 0)
        with ProcessFileLock(path):
            pass

    def test_nonblocking_and_bounded_timeout_still_reject_contention(self):
        path, _ = self.holder(3)
        with self.assertRaises(AlreadyRunning):
            with ProcessFileLock(path):
                self.fail("Conflicting lock acquired")
        with self.assertRaises(AlreadyRunning):
            with ProcessFileLock(path, timeout=0.05):
                self.fail("Timed-out lock acquired")

    def test_symlink_denied_is_explicit_state_error_before_generation_move(self):
        directory = self.root / "mirror"
        manifest = {"workflow": "intelligence-collect.yml", "collector_commit": "a" * 40,
                    "run_number": 1, "run_id": 42, "repository": "synthetic/repo", "branch": "main"}
        def restore(payload, staged, **kwargs):
            staged.mkdir()
            (staged / "intelligence.db").write_bytes(b"synthetic validated fixture")
            return manifest
        with patch.object(actions_mirror, "restore_archive", side_effect=restore), \
                patch.object(actions_mirror, "validate_deployment_state"), \
                patch.object(Path, "symlink_to", side_effect=PermissionError("Synthetic Windows privilege denial")):
            with self.assertRaisesRegex(StateError, "symlink permission"):
                actions_mirror.install_snapshot(b"fixture", directory, repository="synthetic/repo",
                                                branch="main", run_id=42)
        self.assertFalse((directory / "current").exists())
        self.assertFalse((directory / "snapshots/42").exists())
        self.assertFalse((directory / ".current-next").exists())
        self.assertEqual(list(directory.glob(".incoming-*")), [])


if __name__ == "__main__":
    unittest.main()
