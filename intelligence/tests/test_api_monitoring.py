import importlib.util
import io
import json
import os
from contextlib import closing
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from ai_pipeline.store import ClassificationStore
from api_v6.app import _public_status, create_app
from api_v6.repository import IntelligenceRepository
from collectors.base import IntelligenceItem
from monitoring.metrics import latency_report
from monitoring.service import parse_source_results, run_once
from run_monitor_once import main as monitor_main
from storage.sqlite_store import SQLiteIntelligenceStore


def item(cve='CVE-2026-10001', description='A vulnerability in Ollama'):
    return IntelligenceItem(
        source='NVD', source_id=cve, cve_id=cve, title=cve,
        description=description, url=f'https://nvd.nist.gov/vuln/detail/{cve}',
        published_at='2026-10-08T00:00:00.000', modified_at='2026-10-08T01:00:00.000',
        severity=None, raw_data={'id': cve},
    )


class APIReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'data' / 'intelligence.db'
        self.store = SQLiteIntelligenceStore(self.db)
        self.store.ingest_batch('NVD', [item()])
        self.version_patch = patch('api_v6.repository.current_classifier_version', return_value='test-version')
        self.version_patch.start()
        self.addCleanup(self.version_patch.stop)
        self.client = TestClient(create_app(self.root, self.db))
        self.addCleanup(self.client.close)

    def test_collected_but_never_classified_is_readable_without_schema_writes(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            before = con.execute('SELECT name, sql FROM sqlite_master ORDER BY name').fetchall()
        listing = self.client.get('/api/intelligence')
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()['total'], 1)
        self.assertEqual(listing.json()['items'][0]['classification_state'], 'unclassified_or_stale')
        self.assertIsNone(listing.json()['items'][0]['is_ai_related'])
        self.assertEqual(self.client.get('/api/intelligence/CVE-2026-10001').status_code, 200)
        self.assertEqual(self.client.get('/api/intelligence/stats').json()['classified_ai_positive'], 0)
        self.assertEqual(self.client.get('/api/intelligence/ai').json()['total'], 0)
        self.assertEqual(self.client.get('/api/intelligence/health').json()['database_available'], True)
        self.assertEqual(self.client.get('/api/intelligence/metrics').json()['continuous_monitoring']['samples'], 0)
        with closing(sqlite3.connect(self.db)) as con, con:
            after = con.execute('SELECT name, sql FROM sqlite_master ORDER BY name').fetchall()
        self.assertEqual(before, after)

    def _classify(self, state='classified'):
        classification = ClassificationStore(self.db)
        row = classification.fresh('test-version', 1)[0]
        result = SimpleNamespace(
            is_ai_related=True, category='ai_infrastructure', confidence=0.9,
            reason='Ollama is the vulnerable product', evidence=['Ollama'],
            decision_source='rule', needs_review=(state == 'review'), rule_score=0.9,
        )
        self.assertTrue(classification.record(row, 'test-version', state, result=result))

    def test_current_vs_stale_classification_and_literal_search(self):
        self._classify()
        self.assertEqual(self.client.get('/api/intelligence/ai').json()['total'], 1)
        self.assertEqual(self.client.get('/api/intelligence', params={'q': '%'}).json()['total'], 0)
        self.assertEqual(self.client.get('/api/intelligence', params={'q': "' OR 1=1 --"}).json()['total'], 0)
        self.store.ingest_batch('NVD', [item(description='A corrected description for Ollama')])
        self.assertEqual(self.client.get('/api/intelligence/ai').json()['total'], 0)
        self.assertIsNone(self.client.get('/api/intelligence/CVE-2026-10001').json()['classification'])

    def test_team_schema_retains_evidence_and_review_is_opt_in(self):
        self._classify(state='review')
        self.assertEqual(self.client.get('/api/intelligence/team').json()['total'], 0)
        self.assertEqual(self.client.get('/api/intelligence/ai').json()['total'], 0)
        stats = self.client.get('/api/intelligence/stats').json()
        self.assertEqual((stats['classified_ai_positive'], stats['review_ai_positive']), (0, 1))
        data = self.client.get('/api/intelligence/team', params={'include_review': True}).json()['items'][0]
        self.assertEqual(data['id'], 'CVE-2026-10001')
        self.assertTrue(data['raw_data']['classification']['needs_review'])
        self.assertEqual(data['raw_data']['raw_by_source']['NVD']['id'], data['id'])
        # Load the teammate's unchanged normalizer without mixing collector packages.
        model_path = Path(__file__).resolve().parents[2] / 'models.py'
        spec = importlib.util.spec_from_file_location('team_contract_models', model_path)
        models = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(models)
        normalized = models.intelligence_item(data)
        self.assertEqual(normalized['cve_id'], data['cve_id'])
        self.assertEqual(normalized['raw_data'], data['raw_data'])

    def test_missing_database_validation_and_corrupt_status(self):
        other = TestClient(create_app(self.root, self.root / 'missing.db'))
        self.addCleanup(other.close)
        self.assertEqual(other.get('/api/intelligence').status_code, 503)
        self.assertEqual(other.get('/api/intelligence/health').json()['database_available'], False)
        self.assertEqual(self.client.get('/api/intelligence/not-a-cve').status_code, 422)
        status = self.root / 'broken_status.json'
        status.write_text(json.dumps({'sources': ['wrong shape']}), encoding='utf-8')
        self.assertEqual(_public_status(status, 'monitoring')['status'], 'invalid_status_file')


class LatencyTests(unittest.TestCase):
    def test_historical_precise_new_samples_and_bad_times_are_separate(self):
        con = sqlite3.connect(':memory:')
        self.addCleanup(con.close)
        con.row_factory = sqlite3.Row
        con.execute('CREATE TABLE unified_vulnerabilities(payload_json TEXT, first_seen_at TEXT)')
        cases = [
            ('2026-10-08T01:00:00Z', '2026-10-08T03:00:00Z', 'NVD'),
            ('2020-01-01T01:00:00Z', '2026-10-08T03:00:00Z', 'NVD'),
            ('2026-10-08', '2026-10-08T03:00:00Z', 'NVD'),
            ('2026-10-08T04:00:00Z', '2026-10-08T03:00:00Z', 'NVD'),
            ('2026-10-08T01:00:00Z', '2026-10-08T03:00:00Z', 'CISA_KEV'),
        ]
        for published, seen, source in cases:
            con.execute('INSERT INTO unified_vulnerabilities VALUES (?,?)',
                        (json.dumps({'published_at': published, 'publication_source': source}), seen))
        result = latency_report(con, '2026-10-08T00:00:00Z')
        self.assertEqual(result['continuous_monitoring']['samples'], 1)
        self.assertEqual(result['continuous_monitoring']['p95_hours'], 2)
        self.assertEqual(result['all_observed_including_backfill']['samples'], 2)
        self.assertEqual(result['excluded'], {'missing_or_imprecise_time': 2, 'negative_delay': 1})
        self.assertEqual(latency_report(con, None)['continuous_monitoring']['samples'], 0)


class MonitoringTests(unittest.TestCase):
    SUMMARY = """print('>>> 开始增量采集 NVD')
print('增量采集结果:', {'fetched': 0, 'pending': False})
print('>>> 开始增量采集 GITHUB_ADVISORY')
print('增量采集结果:', {'fetched': 0, 'pending': False})
print('>>> 同步 CISA KEV 全量目录快照')
print('CISA 快照去重结果:', {'fetched': 0})
print('>>> 成功来源 3，失败来源 0')
"""

    def test_successful_monitor_baseline_survives_next_run_and_timeout_fails(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'AUTO_CLASSIFY_V4': '0', 'AUTO_CLASSIFY_V5': '0'}), redirect_stdout(io.StringIO()):
            root = Path(directory)
            (root / 'fixture.py').write_text(self.SUMMARY, encoding='utf-8')
            first = run_once(root, script_name='fixture.py')
            second = run_once(root, script_name='fixture.py')
            self.assertEqual(first['status'], 'success')
            self.assertEqual(first['monitoring_started_at'], second['monitoring_started_at'])
            (root / 'slow.py').write_text('import time\ntime.sleep(30)\n', encoding='utf-8')
            with patch.dict(os.environ, {'MONITOR_TIMEOUT_SECONDS': '1'}):
                failed = run_once(root, script_name='slow.py')
            self.assertEqual(failed['status'], 'failed')
            self.assertIsNotNone(failed['error'])
            self.assertNotEqual(failed['return_code'], 0)

    def test_forged_summary_or_missing_source_does_not_pass(self):
        _, valid, _ = parse_source_results('>>> 成功来源 3，失败来源 0')
        self.assertFalse(valid)
        text = "ERROR NVD: failed\n>>> 成功来源 3，失败来源 0"
        self.assertFalse(parse_source_results(text)[1])

    def test_periodic_monitor_retries_failed_run_and_treats_backlog_as_partial(self):
        calls, waits = [], []
        def runner(root):
            calls.append(root)
            return {'status': 'failed' if len(calls) == 1 else 'partial'}
        with redirect_stdout(io.StringIO()):
            code = monitor_main(['--interval-minutes', '60', '--max-runs', '2'], runner=runner, wait=waits.append)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 3590)


if __name__ == '__main__':
    unittest.main()
