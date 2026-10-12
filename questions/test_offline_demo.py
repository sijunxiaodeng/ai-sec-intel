"""Fresh demo bootstrap works without external sockets and reuses its own data."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OfflineDemoTests(unittest.TestCase):
    def test_fresh_seed_repeat_import_and_offline_query(self):
        with tempfile.TemporaryDirectory() as directory:
            code = '''
import json,sys,socket
from scripts.offline_demo import prepare
first=prepare(sys.argv[1])
from database.store import load_kb
seen={r['item']['cve_id']:r['item']['collected_at'] for r in load_kb()}
second=prepare(sys.argv[1])
assert seen=={r['item']['cve_id']:r['item']['collected_at'] for r in load_kb()}
assert first==second and first['vulnerabilities']==4 and first['documents']==4
try: socket.getaddrinfo('example.org',443)
except OSError: pass
else: raise AssertionError('External DNS allowed')
from fastapi.testclient import TestClient
from api.app import app
with TestClient(app) as client:
    assert client.get('/api/overview').json()['offline_demo'] is True
    from config.settings import LOCAL, load_settings
    from pathlib import Path
    assert LOCAL.is_relative_to(Path(sys.argv[1]))
    assert not load_settings()['api_key']
    saved=client.put('/api/settings',json={'model':'offline-fixture','api_key':'synthetic-unused'}).json()
    assert saved['model']=='offline-fixture' and LOCAL.is_file()
    assert client.get('/api/overview').json()['llm_ready'] is False
    answer=client.post('/api/library/ask',json={'question':'提示注入风险是什么？'}).json()
    assert answer['answer'] and not answer['used_model']
print(json.dumps(first))
'''
            result = subprocess.run([sys.executable, "-c", code, directory], cwd=ROOT,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr[-4000:])
            self.assertIn('"external_network": false', result.stdout)

    def test_existing_unowned_data_directory_is_never_reseeded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "intelligence.db"
            path.write_bytes(b"existing production data")
            result = subprocess.run([sys.executable, "scripts/offline_demo.py", "--data-directory", directory,
                                     "--prepare-only"], cwd=ROOT, capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_bytes(), b"existing production data")
