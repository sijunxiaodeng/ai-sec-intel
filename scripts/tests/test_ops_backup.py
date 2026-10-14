import importlib.util
import json
import os
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "backup_state.py"
SPEC = importlib.util.spec_from_file_location("ops_backup_under_test", SCRIPT)
OPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OPS)


class StateBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.backup_path = self.root / "backup"
        self.restored = self.root / "restored"
        for name in OPS.DATABASES:
            with closing(sqlite3.connect(self.data / name)) as connection, connection:
                connection.execute("CREATE TABLE evidence (id TEXT PRIMARY KEY, text TEXT)")
                connection.execute("INSERT INTO evidence VALUES ('id',?)", (name,))
        (self.data / "monitor.json").write_text('{"last_run":"original"}')
        (self.data / "model-settings.json").write_text('{"api_key":"private-test-key"}')

    def test_roundtrip_preserves_main_and_c_data_without_secret_settings(self):
        manifest = OPS.backup(self.data, self.backup_path, quiesced=True)
        self.assertFalse(manifest["secrets_included"])
        self.assertNotIn("model-settings.json", manifest["files"])
        OPS.verify(self.backup_path)
        OPS.restore(self.backup_path, self.restored)
        for name in OPS.DATABASES:
            with closing(sqlite3.connect(self.restored / name)) as connection, connection:
                self.assertEqual(connection.execute("SELECT text FROM evidence").fetchone()[0], name)
        self.assertEqual((self.restored / "monitor.json").read_text(), '{"last_run":"original"}')
        self.assertFalse((self.restored / "model-settings.json").exists())

    def test_committed_wal_pages_are_folded_into_backup(self):
        live = sqlite3.connect(self.data / "knowledge.sqlite3")
        self.addCleanup(live.close)
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("INSERT INTO evidence VALUES ('wal','committed')")
        live.commit()
        self.assertTrue((self.data / "knowledge.sqlite3-wal").exists())
        OPS.backup(self.data, self.backup_path, quiesced=True)
        self.assertFalse((self.backup_path / "knowledge.sqlite3-wal").exists())
        with closing(sqlite3.connect(self.backup_path / "knowledge.sqlite3")) as connection, connection:
            self.assertEqual(connection.execute("SELECT text FROM evidence WHERE id='wal'").fetchone()[0], "committed")

    def test_cross_database_backup_requires_stopped_writer_declaration(self):
        with self.assertRaises(OPS.BackupError):
            OPS.backup(self.data, self.backup_path)
        self.assertFalse(self.backup_path.exists())

    def test_settings_are_explicit_and_not_disclosed_in_manifest(self):
        manifest = OPS.backup(self.data, self.backup_path, quiesced=True, include_settings=True)
        self.assertTrue(manifest["secrets_included"])
        self.assertNotIn("private-test-key", json.dumps(manifest))

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits do not represent Windows ACL permissions")
    def test_settings_file_mode_is_private_on_posix(self):
        OPS.backup(self.data, self.backup_path, quiesced=True, include_settings=True)
        self.assertEqual((self.backup_path / "model-settings.json").stat().st_mode & 0o777, 0o600)

    def test_corrupt_backup_refuses_restore_without_partial_destination(self):
        OPS.backup(self.data, self.backup_path, quiesced=True)
        (self.backup_path / "task_c.sqlite3").write_bytes(b"broken")
        with self.assertRaises(OPS.BackupError):
            OPS.restore(self.backup_path, self.restored)
        self.assertFalse(self.restored.exists())

    def test_existing_destination_is_never_overwritten(self):
        OPS.backup(self.data, self.backup_path, quiesced=True)
        self.restored.mkdir()
        (self.restored / "user-data").write_text("preserved")
        with self.assertRaises(OPS.BackupError):
            OPS.restore(self.backup_path, self.restored)
        self.assertEqual((self.restored / "user-data").read_text(), "preserved")

    def test_extra_file_invalidates_inventory(self):
        OPS.backup(self.data, self.backup_path, quiesced=True)
        (self.backup_path / "unexpected").write_text("new")
        with self.assertRaises(OPS.BackupError):
            OPS.verify(self.backup_path)

    def symlink_or_skip(self, path, target):
        try:
            path.symlink_to(target)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows account lacks symbolic-link privilege (WinError 1314)")
            raise

    def test_symlink_invalidates_inventory(self):
        OPS.backup(self.data, self.backup_path, quiesced=True)
        (self.backup_path / "monitor.json").unlink()
        self.symlink_or_skip(self.backup_path / "monitor.json", self.data / "monitor.json")
        with self.assertRaises(OPS.BackupError):
            OPS.verify(self.backup_path)

    def test_missing_source_is_not_bootstrapped(self):
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(OPS.BackupError):
            OPS.backup(empty, self.backup_path, quiesced=True)
        self.assertEqual(list(empty.iterdir()), [])

    def test_dangling_state_or_destination_symlink_is_rejected(self):
        (self.data / "library.sqlite3").unlink()
        self.symlink_or_skip(self.data / "library.sqlite3", self.root / "missing-database")
        with self.assertRaises(OPS.BackupError):
            OPS.backup(self.data, self.backup_path, quiesced=True)
        self.assertFalse(self.backup_path.exists())
        self.symlink_or_skip(self.backup_path, self.root / "missing-destination")
        with self.assertRaises(OPS.BackupError):
            OPS.backup(self.data, self.backup_path, quiesced=True)
        self.assertTrue(self.backup_path.is_symlink())

    def test_target_appearing_after_validation_is_not_replaced(self):
        OPS.backup(self.data, self.backup_path, quiesced=True)
        publish = OPS.publish_directory
        def competing_target(staged, destination):
            destination.mkdir()
            identity = destination.stat().st_ino
            try:
                return publish(staged, destination)
            finally:
                self.assertEqual(destination.stat().st_ino, identity)
        with patch.object(OPS, "publish_directory", side_effect=competing_target):
            with self.assertRaises((OPS.BackupError, OSError)):
                OPS.restore(self.backup_path, self.restored)
        self.assertEqual(list(self.restored.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
