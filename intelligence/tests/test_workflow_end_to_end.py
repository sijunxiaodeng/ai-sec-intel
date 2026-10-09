"""Actual CLI and HTTP smoke test with explicit synthetic offline input."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from collectors.base import IntelligenceItem
from storage.sqlite_store import SQLiteIntelligenceStore


class WorkflowSmokeTest(unittest.TestCase):
    def test_fusion_rule_classification_api_and_team_collector(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'intelligence.db'
            store = SQLiteIntelligenceStore(db)
            raw = {
                'id': 'CVE-2026-10001',
                'configurations': [{'nodes': [{'cpeMatch': [{
                    'vulnerable': True, 'criteria': 'cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*',
                    'versionEndExcluding': '0.1.34',
                }]}]}],
                'metrics': {'cvssMetricV31': [{'type': 'Primary', 'source': 'nvd@nist.gov',
                    'cvssData': {'version': '3.1', 'baseScore': 9.8,
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}}]},
            }
            store.ingest_batch('NVD', [IntelligenceItem(
                source='NVD', source_id=raw['id'], cve_id=raw['id'],
                title='Synthetic offline fixture', description='Synthetic Ollama regression input.',
                url=None, published_at='2026-10-08T01:00:00Z',
                modified_at='2026-10-08T02:00:00Z', severity=None, raw_data=raw,
            )])
            rebuilt = subprocess.run(
                [sys.executable, str(root / 'run_rebuild_unified.py'), '--db', str(db)],
                cwd=root.parent, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
            classified = subprocess.run(
                [sys.executable, str(root / 'run_ai_classification_v5.py'), '--db', str(db),
                 '--max-items', '10', '--max-llm-calls', '0'],
                cwd=root.parent, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(classified.returncode, 0, classified.stderr)
            status = json.loads((db.parent / 'classification_status.json').read_text(encoding='utf-8'))
            self.assertEqual(status['stats']['positive'], 1)
            self.assertEqual(status['stats']['semantic_calls'], 0)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            env = os.environ.copy()
            env['INTELLIGENCE_DB_PATH'] = str(db)
            with tempfile.TemporaryFile(mode='w+') as log:
                proc = subprocess.Popen(
                    [sys.executable, str(root / 'run_intelligence_api_v6.py'), '--port', str(port)],
                    cwd=root.parent, env=env, stdout=log, stderr=log, text=True,
                )
                try:
                    base = f'http://127.0.0.1:{port}'
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            with urllib.request.urlopen(base + '/api/intelligence/health', timeout=1) as response:
                                health = json.load(response)
                            break
                        except OSError:
                            if proc.poll() is not None or time.monotonic() >= deadline:
                                log.seek(0)
                                self.fail('API failed to start: ' + log.read())
                            time.sleep(0.1)
                    self.assertTrue(health['database_available'])
                    self.assertEqual(health['classification']['summary']['positive'], 1)
                    with urllib.request.urlopen(base + '/api/intelligence/ai', timeout=2) as response:
                        self.assertEqual(json.load(response)['total'], 1)
                    code = (
                        'import json; from collectors.intelligence import IntelligenceCollector; '
                        'from models import enriched_record; from rag.retrieve import _blob; '
                        'from agents.qa_agent import _evidence_text, _extractive; '
                        f'rows=IntelligenceCollector("ollama", base_url={base!r}).collect(); '
                        'records=[enriched_record(row) for row in rows]; '
                        'assert "ollama" in _blob(records[0]); '
                        'assert "9.8" in _evidence_text(records); '
                        'assert "受影响" in _extractive(records); '
                        'print(json.dumps(rows))'
                    )
                    team = subprocess.run([sys.executable, '-c', code], cwd=root.parent,
                                          text=True, capture_output=True, timeout=10)
                    self.assertEqual(team.returncode, 0, team.stderr)
                    rows = json.loads(team.stdout)
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]['cve_id'], raw['id'])
                    self.assertEqual(rows[0]['raw_data']['cvss_score'], 9.8)
                    self.assertEqual(rows[0]['raw_data']['cvss_version'], '3.1')
                    self.assertIn('ollama', rows[0]['affected'][0])
                    self.assertEqual(rows[0]['raw_data']['affected_packages'][0]['product'], 'ollama')
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
