"""Published gaps survive outages independently of modified-time catch-up."""
import io
import os
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from collectors.base import IntelligenceItem
from incremental.cursors import CursorStore
from incremental.limits import WindowPageLimitExceeded
from monitoring.multisource import collect_source
from monitoring.source_registry import get_sources
from storage.sqlite_store import SQLiteIntelligenceStore


NOW = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)


class Collector:
    max_pages = 4
    page_size = 100

    def __init__(self, items=(), publication_error=None, modified_error=None):
        self.items = items
        self.calls = []
        self.publication_error = publication_error
        self.modified_error = modified_error

    def collect_published_window(self, start, end):
        self.calls.append(('published', start, end, self.request_budget.deadline))
        self.request_budget.acquire()
        if self.publication_error:
            raise self.publication_error
        return [item for item in self.items if start <= datetime.fromisoformat(item.published_at) <= end]

    def collect_window(self, start, end):
        self.calls.append(('modified', start, end, self.request_budget.deadline))
        self.request_budget.acquire()
        if self.modified_error:
            raise self.modified_error
        return []


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.context = ExitStack()
        self.addCleanup(self.context.close)
        directory = self.context.enter_context(tempfile.TemporaryDirectory())
        self.context.enter_context(redirect_stdout(io.StringIO()))
        self.context.enter_context(patch.dict(os.environ, {
            'VULNERABILITY_BOOTSTRAP_DAYS': '7', 'PUBLICATION_RECOVERY_MAX_WINDOWS': '4',
            'PUBLICATION_RECOVERY_WINDOW_HOURS': '6', 'PUBLICATION_RECOVERY_MAX_REQUESTS': '6',
            'PUBLICATION_RECOVERY_MAX_ATTEMPTS': '8', 'PUBLICATION_RECOVERY_BUDGET_SECONDS': '25',
            'BACKFILL_MAX_REQUESTS': '12', 'INCREMENTAL_SETTLE_MINUTES': '5',
            'INTELLIGENCE_CHILD_TIMEOUT_SECONDS': '120',
        }))
        self.db = Path(directory) / 'intelligence.db'
        self.store = SQLiteIntelligenceStore(self.db)
        self.cursors = CursorStore(self.db)
        self.spec = next(spec for spec in get_sources() if spec.name == 'NVD')

    def item(self, number, hours):
        stamp = (NOW - timedelta(hours=hours)).isoformat()
        return IntelligenceItem('NVD', f'CVE-2026-{number}', f'CVE-2026-{number}',
                                'Ollama fixture', 'Public fixture', None, stamp, stamp, None)

    def first_seen(self, cve_id):
        with self.store._connect() as connection:
            return connection.execute('SELECT first_seen_at FROM unified_vulnerabilities WHERE cve_id=?',
                                      (cve_id,)).fetchone()[0]

    def test_53_hour_gap_recovers_with_recent_priority_even_when_modified_fails(self):
        old, recent = self.item(10001, 46), self.item(10002, 1)
        self.cursors.advance('NVD:published', NOW - timedelta(hours=53))
        self.cursors.advance('NVD', NOW - timedelta(days=4))
        collector = Collector([old, recent], modified_error=RuntimeError('offline modified failure'))
        result = collect_source(self.spec, self.db, now=NOW, collector=collector)
        self.assertEqual(collector.calls[0][1], NOW - timedelta(hours=12))
        self.assertEqual(result['inserted'], 1)
        self.assertEqual(result['publication_recovery']['inserted'], 1)
        self.assertTrue(result['publication_recovery']['pending'])
        self.assertEqual(self.cursors.get('NVD:published'), NOW - timedelta(hours=29))
        self.assertEqual(self.cursors.get('NVD'), NOW - timedelta(days=4))
        first_seen = self.first_seen(old.cve_id)
        collector.calls.clear()
        later = NOW + timedelta(minutes=15)
        result = collect_source(self.spec, self.db, now=later, collector=collector)
        self.assertEqual(collector.calls[0][1], later - timedelta(hours=12))
        self.assertFalse(result['publication_recovery']['pending'])
        self.assertEqual(self.cursors.get('NVD:published'), later - timedelta(minutes=5))
        self.assertEqual(self.first_seen(old.cve_id), first_seen)

    def test_failed_first_cycle_keeps_bootstrap_anchor_without_claiming_coverage(self):
        collector = Collector(publication_error=RuntimeError('publication failure'))
        result = collect_source(self.spec, self.db, now=NOW, collector=collector)
        anchor = NOW - timedelta(minutes=5, days=7)
        self.assertIsNone(self.cursors.get('NVD:published'))
        self.assertEqual(result['publication_recovery']['bootstrap_start_at'], anchor.isoformat())
        self.assertTrue(result['publication_recovery']['pending'])
        result = collect_source(self.spec, self.db, now=NOW + timedelta(days=2), collector=collector)
        self.assertEqual(result['publication_recovery']['bootstrap_start_at'], anchor.isoformat())
        self.assertIsNone(self.cursors.get('NVD:published'))
        self.assertEqual(self.cursors.get('NVD'), NOW + timedelta(days=2, minutes=-5))

    def test_recent_success_does_not_jump_over_failed_old_publication_window(self):
        class FailOld(Collector):
            def collect_published_window(self, start, end):
                rows = super().collect_published_window(start, end)
                if start < NOW - timedelta(hours=12):
                    raise RuntimeError('old publication unavailable')
                return rows
        self.cursors.advance('NVD:published', NOW - timedelta(hours=53))
        result = collect_source(self.spec, self.db, now=NOW, collector=FailOld([self.item(10001, 1)]))
        self.assertTrue(result['recent_success'])
        self.assertEqual(result['inserted'], 1)
        self.assertEqual(self.cursors.get('NVD:published'), NOW - timedelta(hours=53))
        self.assertEqual(result['publication_recovery']['pending_reason'], 'source_failure')

    def test_request_budget_advances_only_complete_slices_and_leaves_modified_time(self):
        self.cursors.advance('NVD:published', NOW - timedelta(hours=53))
        self.cursors.advance('NVD', NOW - timedelta(hours=1))
        collector = Collector()
        with patch.dict(os.environ, {'PUBLICATION_RECOVERY_MAX_REQUESTS': '1'}), \
                patch('monitoring.multisource.time.monotonic', return_value=1000):
            result = collect_source(self.spec, self.db, now=NOW, collector=collector)
        self.assertEqual(self.cursors.get('NVD:published'), NOW - timedelta(hours=47))
        self.assertEqual(result['publication_recovery']['requests'], 1)
        self.assertEqual(result['publication_recovery']['pending_reason'], 'request_or_time_budget')
        publication_deadline = collector.calls[1][3]
        modified_deadline = next(call[3] for call in collector.calls if call[0] == 'modified')
        self.assertLessEqual(publication_deadline, 1025)
        self.assertEqual(modified_deadline, 1085)
        self.assertEqual(self.cursors.get('NVD'), NOW - timedelta(minutes=5))

    def test_dense_published_windows_split_without_advancing_on_incomplete_pages(self):
        class Dense(Collector):
            def collect_published_window(self, start, end):
                rows = super().collect_published_window(start, end)
                if start < NOW - timedelta(hours=12) and end - start > timedelta(hours=3):
                    raise WindowPageLimitExceeded('dense window')
                return rows
        initial = NOW - timedelta(hours=20)
        self.cursors.advance('NVD:published', initial)
        result = collect_source(self.spec, self.db, now=NOW, collector=Dense())
        self.assertGreater(result['publication_recovery']['split_windows'], 0)
        self.assertFalse(result['publication_recovery']['pending'])
        self.assertEqual(self.cursors.get('NVD:published'), NOW - timedelta(minutes=5))


if __name__ == '__main__':
    unittest.main()
