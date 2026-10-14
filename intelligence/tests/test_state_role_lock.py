"""claim_role / deployment locks must not require Unix-only fcntl at import time."""
from __future__ import annotations

import ast
import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


INTEL = Path(__file__).resolve().parents[1]


class StateRolePortableLockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = str(INTEL)
        if root not in sys.path:
            sys.path.insert(0, root)

    def _purge(self):
        for key in list(sys.modules):
            if key in {"deployment.file_lock", "deployment.state_role", "file_lock", "state_role"}:
                sys.modules.pop(key, None)

    def _load_state_role(self):
        self._purge()
        return importlib.import_module("deployment.state_role")

    def test_source_has_no_top_level_fcntl_import(self):
        """Static guard: Windows hosts fail at import if fcntl is top-level."""
        for relative in ("deployment/file_lock.py", "deployment/state_role.py", "deployment/actions_mirror.py"):
            tree = ast.parse((INTEL / relative).read_text(encoding="utf-8"), filename=relative)
            for node in tree.body:
                if isinstance(node, ast.Import):
                    names = {alias.name for alias in node.names}
                    self.assertNotIn("fcntl", names, relative)
                if isinstance(node, ast.ImportFrom) and node.module == "fcntl":
                    self.fail("%s imports fcntl at module level" % relative)

    def test_import_does_not_require_fcntl_module(self):
        """Top-level import must succeed even when Unix fcntl is absent (Windows)."""
        real_import = __import__
        attempted = []

        def blocked(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "fcntl":
                attempted.append(name)
                raise ModuleNotFoundError("No module named 'fcntl'")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", blocked):
            module = self._load_state_role()
            self.assertTrue(callable(module.claim_role))
        self.assertEqual(attempted, [], "importing state_role must not import fcntl")

    def test_claim_role_writes_collector_marker(self):
        state_role = self._load_state_role()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            state_role.claim_role(directory, "collector")
            self.assertEqual((directory / ".writer-mode").read_text().strip(), "collector")
            self.assertTrue((directory / ".runtime-role.lock").is_file())

    def test_claim_role_uses_msvcrt_when_windows_branch(self):
        """Windows lock path must call msvcrt and never import fcntl."""
        state_role = self._load_state_role()
        file_lock = importlib.import_module("deployment.file_lock")
        calls = []
        fake_msvcrt = types.SimpleNamespace(
            LK_LOCK=1, LK_NBLCK=2, LK_UNLCK=3,
            locking=lambda fd, mode, n: calls.append((mode, n)),
        )
        real_import = __import__

        def guarded(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "fcntl":
                raise AssertionError("fcntl must not be imported on Windows")
            return real_import(name, globals, locals, fromlist, level)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(file_lock, "_is_windows", return_value=True), \
                 patch.dict(sys.modules, {"msvcrt": fake_msvcrt}), \
                 patch("builtins.__import__", guarded):
                state_role.claim_role(directory, "collector")
            self.assertEqual((directory / ".writer-mode").read_text().strip(), "collector")
        self.assertTrue(calls)
        # claim_role uses timeout=30 → non-blocking acquire with retry (LK_NBLCK).
        self.assertEqual(calls[0][0], fake_msvcrt.LK_NBLCK)
        self.assertEqual(calls[-1][0], fake_msvcrt.LK_UNLCK)

    def test_conflicting_writer_mode_rejected(self):
        state_role = self._load_state_role()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            state_role.claim_role(directory, "collector")
            with self.assertRaises(RuntimeError):
                state_role.claim_role(directory, "actions-mirror")


if __name__ == "__main__":
    unittest.main()
