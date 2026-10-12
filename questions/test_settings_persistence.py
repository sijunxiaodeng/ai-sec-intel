"""Fresh application processes must share the explicitly persisted settings path."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent


class SettingsPersistenceTests(unittest.TestCase):
    def test_failed_publication_retains_the_previous_settings(self):
        from config import settings
        with tempfile.TemporaryDirectory() as directory, patch.object(settings, 'LOCAL', Path(directory) / 'settings.json'):
            settings.save_settings({'api_key': 'fixture-state-value', 'model': 'previous'})
            before = settings.LOCAL.read_bytes()
            with patch.object(settings.os, 'replace', side_effect=OSError('fixture disk failure')):
                with self.assertRaises(OSError):
                    settings.save_settings({'model': 'new'})
            self.assertEqual(settings.LOCAL.read_bytes(), before)
            self.assertEqual(list(settings.LOCAL.parent.glob('*.tmp')), [])

    def test_saved_configuration_survives_a_fresh_process_without_exposing_the_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state' / 'settings.json'
            env = dict(os.environ, APP_SETTINGS_PATH=str(path), PYTHONUTF8='1')
            subprocess.run([sys.executable, '-c',
                "from config.settings import save_settings; save_settings({'model':'offline-fixture','api_key':'fixture-state-value'})"],
                cwd=ROOT, env=env, check=True, capture_output=True)
            result = subprocess.run([sys.executable, '-c',
                "import json; from config.settings import LOCAL,public_settings; print(json.dumps({'path':str(LOCAL),'public':public_settings()}))"],
                cwd=ROOT, env=env, check=True, capture_output=True, text=True, encoding='utf-8')
            public = json.loads(result.stdout)
            self.assertEqual(Path(public['path']), path)
            self.assertEqual(public['public']['model'], 'offline-fixture')
            self.assertTrue(public['public']['has_key'])
            self.assertNotIn('fixture-state-value', result.stdout)


if __name__ == '__main__':
    unittest.main()
