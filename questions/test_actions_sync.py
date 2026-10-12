"""Offline tests for Actions → deploy DB install (no GitHub network)."""
from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
from contextlib import closing
from unittest.mock import patch
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


BASELINE = "2026-10-07T00:00:00+00:00"
FIXTURE_CVE = "CVE-2099-99999"


def _complete_state(directory):
    """Build real B schema/history privately; never use the worktree's data."""
    directory.mkdir()
    code = """
import json,sys
from pathlib import Path
from collectors.base import IntelligenceItem
from monitoring.multisource import ensure_source_baseline
from monitoring.source_registry import get_source
from storage.sqlite_store import SQLiteIntelligenceStore
root = Path(sys.argv[1])
store = SQLiteIntelligenceStore(root / 'intelligence.db')
cve = sys.argv[3]
item = IntelligenceItem(
    source='NVD', source_id=cve, cve_id=cve,
    title='Synthetic snapshot fixture', description='Offline fixture, not a real vulnerability',
    url='https://example.org/snapshot-fixture', published_at='2026-10-08T01:00:00Z',
    modified_at='2026-10-08T01:00:00Z', severity=None,
    raw_data={'id':cve,'demo_fixture':True},
)
store.ingest_batch('NVD', [item])
ensure_source_baseline(store, get_source('NVD'))
with store._connect() as con:
    con.execute('UPDATE source_observation_baselines SET started_at=?', (sys.argv[2],))
(root / 'monitoring_baseline.json').write_text(json.dumps({'started_at':sys.argv[2]}), encoding='utf-8')
"""
    # B's collectors live only in this child process, preserving A imports.
    subprocess.run([sys.executable, "-c", code, str(directory), BASELINE, FIXTURE_CVE],
                   cwd=INTEL, env={**os.environ, "PYTHONPATH": str(INTEL),
                                  "PYTHONDONTWRITEBYTECODE":"1"},
                   check=True, capture_output=True, timeout=30)
    return directory


class ActionsSyncInstallTest(unittest.TestCase):
    def test_install_replaces_db_keeps_unrelated_files(self):
        save_state, actions_sync = _load_sync()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            source = _complete_state(temporary / "source")
            snap = temporary / "snap"
            snap.mkdir()
            save_state(
                source,
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
            self.assertEqual(json.loads((dest / "monitoring_baseline.json").read_text(encoding="utf-8"))["started_at"], BASELINE)
            with closing(sqlite3.connect(dest / "intelligence.db")) as con:
                self.assertEqual(con.execute("SELECT cve_id FROM unified_vulnerabilities").fetchone()[0], FIXTURE_CVE)
                self.assertEqual(con.execute("SELECT source,started_at FROM source_observation_baselines").fetchone(), ("NVD", BASELINE))

    def test_bad_run_id_rejected(self):
        save_state, actions_sync = _load_sync()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            source = _complete_state(temporary / "source")
            snap = temporary / "snap"
            snap.mkdir()
            save_state(
                source,
                snap,
                repository="sijunxiaodeng/ai-sec-intel",
                branch="main",
                run_id=11,
            )
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as archive:
                for path in snap.iterdir():
                    archive.write(path, arcname=path.name)
            with self.assertRaisesRegex(actions_sync.StateError, "provenance"):
                actions_sync.install_archive(
                    buf.getvalue(),
                    temporary / "dest2",
                    repository="sijunxiaodeng/ai-sec-intel",
                    branch="main",
                    run_id=99,
                    source="unittest",
                )

    def test_ingest_disabled_without_token(self):
        import api.actions_ingest as ingest
        with patch.dict(os.environ, {"ACTIONS_INGEST_TOKEN":""}):
            self.assertFalse(ingest.ingest_enabled())


if __name__ == "__main__":
    unittest.main()
