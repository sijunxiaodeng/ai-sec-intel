"""Offline tests for Actions → deploy DB install (no GitHub network)."""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEL = ROOT / "intelligence"


def _load_sync():
    # Append (do not prepend) so root collectors.* stay ahead of intelligence/.
    if str(INTEL) not in sys.path:
        sys.path.append(str(INTEL))
    from deployment.actions_state import save_state
    from deployment import actions_sync

    return save_state, actions_sync


class ActionsSyncInstallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db = INTEL / "data" / "intelligence.db"
        if not db.is_file():
            import os
            import subprocess

            subprocess.check_call(
                [sys.executable, "seed_demo_db.py", "--force"],
                cwd=str(INTEL),
                env={**os.environ, "PYTHONPATH": str(INTEL)},
            )

    def test_install_replaces_db_keeps_unrelated_files(self):
        save_state, actions_sync = _load_sync()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            snap = temporary / "snap"
            snap.mkdir()
            save_state(
                INTEL / "data",
                snap,
                repository="sijunxiaodeng/ai-sec-intel",
                branch="main",
                run_id=9001,
            )
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as archive:
                for path in snap.iterdir():
                    archive.write(path, arcname=path.name)
            dest = temporary / "dest"
            dest.mkdir()
            (dest / "keep-me.log").write_text("noise", encoding="utf-8")
            (dest / "intelligence.db").write_bytes(b"stale")
            marker = actions_sync.install_archive(
                buf.getvalue(),
                dest,
                repository="sijunxiaodeng/ai-sec-intel",
                branch="main",
                run_id=9001,
                source="unittest",
            )
            self.assertEqual(marker["run_id"], 9001)
            self.assertGreater((dest / "intelligence.db").stat().st_size, 100)
            self.assertEqual((dest / "keep-me.log").read_text(encoding="utf-8"), "noise")
            self.assertTrue((dest / "actions_sync.json").is_file())
            self.assertTrue((dest / "monitoring_baseline.json").is_file())

    def test_bad_run_id_rejected(self):
        save_state, actions_sync = _load_sync()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            snap = temporary / "snap"
            snap.mkdir()
            save_state(
                INTEL / "data",
                snap,
                repository="sijunxiaodeng/ai-sec-intel",
                branch="main",
                run_id=11,
            )
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as archive:
                for path in snap.iterdir():
                    archive.write(path, arcname=path.name)
            with self.assertRaises(Exception):
                actions_sync.install_archive(
                    buf.getvalue(),
                    temporary / "dest2",
                    repository="sijunxiaodeng/ai-sec-intel",
                    branch="main",
                    run_id=99,
                    source="unittest",
                )

    def test_ingest_disabled_without_token(self):
        import os
        from importlib import reload

        os.environ.pop("ACTIONS_INGEST_TOKEN", None)
        import api.actions_ingest as ingest

        reload(ingest)
        self.assertFalse(ingest.ingest_enabled())


if __name__ == "__main__":
    unittest.main()
