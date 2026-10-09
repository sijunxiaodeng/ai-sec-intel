import io
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from ai_pipeline.store import ClassificationStore
from api_v6.app import create_app
from api_v6.repository import current_classifier_version
from collectors.base import IntelligenceItem
from collectors.documents import CollectionResult, KnowledgeDocument, make_document_id
from incremental.cursors import CursorStore
from monitoring.multisource import _run_child, collect_source, ensure_source_baseline, run_cycle
from monitoring.source_registry import SourceSpec, get_sources
from run_monitor import main as monitor_main
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

ROOT = Path(__file__).resolve().parents[1]


def document(spec, identity='one', published='2026-10-08T01:00:00Z'):
    return KnowledgeDocument(make_document_id(spec.name, identity), spec.name, spec.category,
                             spec.content_type or 'article', 'AI security fixture', 'Prompt injection fixture',
                             'https://example.com/' + identity, published, None, ['CVE-2026-10001'],
                             {'fixture': True})


class MultisourceTests(unittest.TestCase):
    def test_recent_phase_commits_before_failing_backfill_and_cursor_stays_put(self):
        spec = get_sources()[0]
        now = datetime.now(timezone.utc)
        cve = IntelligenceItem('NVD', 'CVE-2026-10001', 'CVE-2026-10001', 'Offline CVE',
                              'Ollama fixture', None, (now - timedelta(minutes=2)).isoformat(),
                              now.isoformat(), None, raw_data={'id': 'CVE-2026-10001'})
        calls = []
        class Collector:
            max_pages = 4
            def collect_window(self, start, end):
                calls.append((start, end))
                if len(calls) == 1:
                    return [cve]
                raise RuntimeError('incomplete old window')
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            db = Path(directory) / 'intel.db'
            result = collect_source(spec, db, now=now, collector=Collector())
            self.assertEqual(result['status'], 'partial')
            self.assertTrue(result['recent_success'])
            self.assertEqual(SQLiteIntelligenceStore(db).stats()['unified_cves'], 1)
            self.assertIsNone(CursorStore(db).get('NVD'))
            self.assertLess(calls[1][0], calls[0][0])

    def test_conditional_poll_keeps_documents_and_original_source_baseline(self):
        spec = get_sources()[3]
        row = document(spec)
        class Collector:
            def __init__(self):
                self.calls = []
            def collect(self, **kwargs):
                self.calls.append(kwargs)
                return (CollectionResult([row], etag='v1', fetched_count=1) if len(self.calls) == 1
                        else CollectionResult([], status='not_modified'))
        collector = Collector()
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'intel.db'
            self.assertEqual(collect_source(spec, db, collector=collector)['status'], 'success')
            with sqlite3.connect(db) as con:
                anchor = con.execute('SELECT started_at FROM source_observation_baselines').fetchone()[0]
            self.assertEqual(collect_source(spec, db, collector=collector)['status'], 'success')
            documents = SQLiteDocumentStore(db)
            self.assertEqual(documents.stats()['documents'], 1)
            self.assertEqual(documents.get_http_state(spec.name)['etag'], 'v1')
            self.assertEqual(collector.calls[1]['etag'], 'v1')
            with sqlite3.connect(db) as con:
                self.assertEqual(con.execute('SELECT started_at FROM source_observation_baselines').fetchone()[0], anchor)

    def test_one_failed_source_does_not_block_other_categories(self):
        calls = []
        def worker(root, spec, db, config, timeout):
            calls.append(spec.name)
            return {'source': spec.name, 'category': spec.category,
                    'status': 'failed' if spec.name == 'NVD' else 'success'}
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            db = Path(directory) / 'intel.db'
            result = run_cycle(ROOT, db_path=db, child_runner=worker)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['failed_sources'], 1)
            self.assertEqual(len(calls), 11)
            self.assertEqual(len({v['category'] for v in result['sources'].values()}), 8)
            with sqlite3.connect(db) as con:
                self.assertEqual(con.execute('SELECT COUNT(*) FROM source_observation_baselines').fetchone()[0], 11)
            self.assertEqual(json.loads((db.parent / 'monitoring_status.json').read_text())['status'], 'partial')

    def test_timeout_records_failure_without_advancing_http_state(self):
        spec = get_sources()[3]
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'intel.db'
            documents = SQLiteDocumentStore(db)
            documents.ingest(spec.name, spec.category, [document(spec)])
            documents.save_http_state(spec.name, etag='old')
            with patch('monitoring.multisource.subprocess.run', side_effect=subprocess.TimeoutExpired('worker', 1)):
                result = _run_child(ROOT, spec, db, None, 1)
            self.assertEqual(result['status'], 'failed')
            self.assertIn('TimeoutError', result['error'])
            self.assertEqual(documents.get_http_state(spec.name)['etag'], 'old')
            self.assertEqual(documents.stats()['latest_runs'][0]['status'], 'failed')

    def test_default_daemon_polls_15_minutes_and_retries_failed_round(self):
        calls, waits = [], []
        def runner(*args, **kwargs):
            calls.append(kwargs)
            return {'status': 'failed' if len(calls) == 1 else 'success'}
        with patch.dict(os.environ, {'MONITOR_INTERVAL_MINUTES': '15'}), redirect_stdout(io.StringIO()):
            self.assertEqual(monitor_main(['--max-runs', '2'], runner=runner, wait=waits.append), 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]['timeout_seconds'], 120)
        self.assertGreater(waits[0], 890)
        self.assertLessEqual(waits[0], 900)

    def test_unbounded_cycle_or_6_hour_interval_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_cycle(ROOT, db_path=Path(directory) / 'intel.db', workers=1, timeout_seconds=3000)
        with redirect_stdout(io.StringIO()), patch('sys.stderr', io.StringIO()):
            with self.assertRaises(SystemExit):
                monitor_main(['--interval-minutes', '360'])
            with self.assertRaises(SystemExit):
                monitor_main(['--interval-minutes', '359'])

    def test_relative_environment_catalog_is_forwarded_to_source_workers_as_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            catalog = Path(directory) / 'sources.json'
            catalog.write_text(json.dumps([{'name': 'BLOG', 'category': 'security_blog', 'kind': 'feed',
                                          'url': 'https://example.com/feed', 'options': {'ai_only': True}}]))
            observed = []
            def runner(root, spec, db, config, timeout):
                observed.append(config)
                return {'source': spec.name, 'status': 'success'}
            with patch.dict(os.environ, {'INTELLIGENCE_SOURCE_CONFIG': os.path.relpath(catalog)}):
                run_cycle(ROOT, db_path=Path(directory) / 'intel.db', child_runner=runner)
            self.assertEqual(observed, [catalog.resolve()])


class KnowledgeAPITests(unittest.TestCase):
    def test_seven_categories_persist_query_and_exact_cve_link_without_claiming_live_sla(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'intel.db'
            store = SQLiteIntelligenceStore(db)
            cve = IntelligenceItem('NVD', 'CVE-2026-10001', 'CVE-2026-10001', 'Offline CVE',
                                  'Ollama fixture', None, '2026-10-08T01:00:00Z', None, None,
                                  raw_data={'id': 'CVE-2026-10001'})
            store.ingest_batch('NVD', [cve])
            version = current_classifier_version(ROOT)
            classifier = ClassificationStore(db)
            row = classifier.fresh(version, 1)[0]
            classifier.record(row, version, 'classified', result=SimpleNamespace(
                is_ai_related=True, category='ai_infrastructure', confidence=.9, reason='fixture',
                evidence=['Ollama'], decision_source='rule', needs_review=False, rule_score=.9))
            documents = SQLiteDocumentStore(db)
            selected = {}
            for spec in get_sources():
                if spec.kind not in {'nvd', 'github', 'cisa'} and spec.category not in selected:
                    selected[spec.category] = spec
                    documents.ingest(spec.name, spec.category, [document(spec)])
            with TestClient(create_app(ROOT, db)) as client:
                data = client.get('/api/documents').json()
                self.assertEqual(data['total'], 6)
                self.assertNotIn('raw_data', data['items'][0])
                self.assertEqual(client.get('/api/documents', params={'category': 'policy_regulation'}).json()['total'], 1)
                self.assertEqual(client.get('/api/documents', params={'cve_id': 'CVE-2026-10001'}).json()['total'], 6)
                self.assertEqual(client.get('/api/documents', params={'cve_id': 'CVE-2026-100010'}).json()['total'], 0)
                self.assertEqual(client.get('/api/documents/stats').json()['total_documents'], 6)
                detail = client.get('/api/intelligence/CVE-2026-10001').json()
                self.assertEqual(len(detail['related_documents']), 6)
                coverage = client.get('/api/intelligence/coverage').json()
                self.assertEqual(coverage['configured_category_count'], 8)
                self.assertEqual(coverage['observed_ai_category_count'], 7)
                self.assertTrue(coverage['required_categories_observed'])
                self.assertEqual(coverage['sla_evidence'], 'insufficient_samples')
                first = data['items'][0]['document_id']
                self.assertIn('raw_data', client.get('/api/documents/' + first, params={'include_raw': True}).json())


if __name__ == '__main__':
    unittest.main()
