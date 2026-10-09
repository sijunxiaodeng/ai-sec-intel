"""Offline regression checks: no third-party calls or credentials required."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
from collectors.cisa_kev import CISAKEVCollector
from collectors.github_advisory import GitHubAdvisoryCollector
from collectors.http import _get
from collectors.nvd import NVDCollector
from incremental.api_collectors import (
    GithubModifiedCollector, NVDModifiedCollector, _api_timestamp, _iso_timestamp,
    from_nvd,
)
from incremental.cursors import CursorStore
from incremental.engine import ingest_incremental_source


class Response:
    def __init__(self, document, status=200, headers=None, next_url=None):
        self.document = document
        self.status_code = status
        self.headers = headers or {}
        self.links = {'next': {'url': next_url}} if next_url else {}
        self.closed = False

    def json(self):
        return self.document

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'HTTP {self.status_code}')

    def close(self):
        self.closed = True


def session_for(*responses):
    return Mock(get=Mock(side_effect=responses))


def nvd_document(index, total, *identifiers):
    return {'startIndex': index, 'resultsPerPage': len(identifiers), 'totalResults': total,
            'vulnerabilities': [{'cve': {'id': value}} for value in identifiers]}


class IncrementalCollectorTests(unittest.TestCase):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)

    def nvd(self, *responses, max_pages=30):
        collector = NVDModifiedCollector(session=session_for(*responses), api_key='', max_pages=max_pages)
        collector._rate_limit = Mock()
        return collector

    def test_nvd_reads_all_pages_and_uses_actual_offsets(self):
        collector = self.nvd(Response(nvd_document(0, 3, 'CVE-2026-1001', 'CVE-2026-1002')),
                             Response(nvd_document(2, 3, 'CVE-2026-1003')))
        items = collector.collect_window(self.start, self.end)
        self.assertEqual(3, len(items))
        self.assertEqual(2, collector.session.get.call_args_list[1].kwargs['params']['startIndex'])

    def test_publication_fast_lane_is_independent_of_modified_time_backfill(self):
        nvd = self.nvd(Response(nvd_document(0, 1, 'CVE-2026-1001')))
        nvd.collect_published_window(self.start, self.end)
        params = nvd.session.get.call_args.kwargs['params']
        self.assertIn('pubStartDate', params)
        self.assertNotIn('lastModStartDate', params)
        self.assertEqual(params['resultsPerPage'], 500)
        github = GithubModifiedCollector(session=session_for(Response([])), token='')
        github.collect_published_window(self.start, self.end)
        self.assertIn('published', github.session.get.call_args.kwargs['params'])
        self.assertNotIn('modified', github.session.get.call_args.kwargs['params'])

    def test_nvd_missing_total_is_not_successful_empty_window(self):
        collector = self.nvd(Response({'vulnerabilities': []}))
        with self.assertRaises(ValueError):
            collector.collect_window(self.start, self.end)

    def test_nvd_rejects_wrong_offset_changed_total_and_duplicate_ids(self):
        for second in [nvd_document(0, 2, 'CVE-2026-1002'),
                       nvd_document(1, 3, 'CVE-2026-1002'),
                       nvd_document(1, 2, 'CVE-2026-1001')]:
            with self.subTest(second=second):
                collector = self.nvd(Response(nvd_document(0, 2, 'CVE-2026-1001')),
                                     Response(second))
                with self.assertRaises(RuntimeError):
                    collector.collect_window(self.start, self.end)

    def test_nvd_rejects_incomplete_empty_page(self):
        collector = self.nvd(Response(nvd_document(0, 1)))
        with self.assertRaises(RuntimeError):
            collector.collect_window(self.start, self.end)

    def test_nvd_page_budget_does_not_return_partial_success(self):
        collector = self.nvd(Response(nvd_document(0, 2, 'CVE-2026-1001')), max_pages=1)
        with self.assertRaisesRegex(RuntimeError, 'max_pages'):
            collector.collect_window(self.start, self.end)

    def test_github_preserves_advisory_without_cve_and_raw_evidence(self):
        raw = {'ghsa_id': 'GHSA-aaaa-bbbb-cccc', 'cve_id': None, 'summary': 'Prompt injection',
               'references': ['https://example.org/source']}
        collector = GithubModifiedCollector(session=session_for(Response([raw])), token='')
        item = collector.collect_window(self.start, self.end)[0]
        self.assertIsNone(item.cve_id)
        self.assertEqual(raw, item.raw_data)
        self.assertIn('modified', collector.session.get.call_args.kwargs['params'])

    def test_github_refuses_insecure_or_unrelated_next_links(self):
        for url in ['http://api.github.com/advisories?page=2',
                    'https://attacker.example/advisories', 'https://api.github.com/users']:
            with self.subTest(url=url):
                session = session_for(Response([{'ghsa_id': 'GHSA-aaaa-bbbb-cccc'}], next_url=url))
                collector = GithubModifiedCollector(session=session, token='test-placeholder')
                with self.assertRaisesRegex(RuntimeError, 'pagination URL'):
                    collector.collect_window(self.start, self.end)
                self.assertEqual(1, session.get.call_count)

    def test_github_does_not_resend_params_on_following_link(self):
        next_url = 'https://api.github.com/advisories?page=2'
        session = session_for(Response([{'ghsa_id': 'GHSA-aaaa-bbbb-cccc'}], next_url=next_url),
                              Response([{'ghsa_id': 'GHSA-dddd-eeee-ffff'}]))
        self.assertEqual(2, len(GithubModifiedCollector(session=session, token='').collect_window(self.start, self.end)))
        self.assertIsNone(session.get.call_args.kwargs['params'])

    def test_github_rejects_repeated_ids_and_empty_nonfinal_page(self):
        next_url = 'https://api.github.com/advisories?page=2'
        for first, second in [([], []), ([{'ghsa_id': 'same'}], [{'ghsa_id': 'same'}])]:
            with self.subTest(first=first):
                collector = GithubModifiedCollector(session=session_for(
                    Response(first, next_url=next_url), Response(second)), token='')
                with self.assertRaises(RuntimeError):
                    collector.collect_window(self.start, self.end)

    def test_source_timestamps_keep_fractional_precision(self):
        timestamp = self.start.replace(microsecond=123456)
        self.assertTrue(_api_timestamp(timestamp).endswith('.123Z'))
        self.assertTrue(_iso_timestamp(timestamp).endswith('.123456Z'))
        with self.assertRaises(ValueError):
            _api_timestamp(timestamp.replace(tzinfo=None))

    def test_github_queries_use_supported_seconds_and_cover_fractional_boundaries(self):
        collector = GithubModifiedCollector(session=session_for(Response([])), token='')
        collector.collect_window(self.start.replace(microsecond=123456),
                                 self.end.replace(microsecond=654321))
        query = collector.session.get.call_args.kwargs['params']['modified']
        self.assertEqual(query, '2026-01-01T00:00:00Z..2026-01-02T00:00:01Z')

    def test_cvss_v4_and_v2_fallback(self):
        self.assertEqual('CRITICAL', from_nvd({'id': 'CVE-2026-1001', 'metrics': {
            'cvssMetricV40': [{'cvssData': {'baseSeverity': 'CRITICAL'}}],
        }}).severity)
        self.assertEqual('HIGH', from_nvd({'id': 'CVE-2026-1001', 'metrics': {
            'cvssMetricV2': [{'baseSeverity': 'HIGH', 'cvssData': {}}],
        }}).severity)


class RequestRetryTests(unittest.TestCase):
    @patch('collectors.http.time.sleep')
    def test_transient_retry_honors_retry_after_and_rates_every_attempt(self, sleep):
        limited = Response({}, status=429, headers={'Retry-After': '7'})
        successful = Response({})
        session = session_for(limited, successful)
        before = Mock()
        self.assertIs(successful, _get(session, 'https://example.org', before_request=before))
        sleep.assert_called_once_with(7.0)
        self.assertTrue(limited.closed)
        self.assertEqual(2, before.call_count)
        self.assertNotIn('verify', session.get.call_args.kwargs)

    @patch('collectors.http.time.sleep')
    @patch('collectors.http.time.time', return_value=100)
    def test_github_limit_reset_is_honored(self, clock, sleep):
        limited = Response({}, status=403, headers={
            'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '145'})
        _get(session_for(limited, Response({})), 'https://api.github.com/advisories')
        sleep.assert_called_once_with(45.0)

    @patch('collectors.http.time.sleep')
    def test_authentication_failure_is_not_retried(self, sleep):
        session = session_for(Response({}, status=401))
        with self.assertRaises(requests.HTTPError):
            _get(session, 'https://example.org')
        self.assertEqual(1, session.get.call_count)
        sleep.assert_not_called()

    @patch('collectors.http.time.sleep')
    def test_network_retries_are_bounded(self, sleep):
        session = session_for(requests.Timeout(), requests.Timeout())
        with self.assertRaises(requests.Timeout):
            _get(session, 'https://example.org', retries=2)
        self.assertEqual(2, session.get.call_count)


class LegacyCollectorTests(unittest.TestCase):
    def test_github_collect_limit_over_100_is_paginated(self):
        first = [{'ghsa_id': f'GHSA-first-{i}'} for i in range(100)]
        second = [{'ghsa_id': f'GHSA-second-{i}'} for i in range(10)]
        collector = GitHubAdvisoryCollector(token='', session=session_for(
            Response(first, next_url='https://api.github.com/advisories?page=2'), Response(second)))
        self.assertEqual(105, len(collector.collect(limit=105)))
        self.assertEqual(2, collector.session.get.call_count)

    def test_kev_addition_is_not_cve_publication_and_raw_row_is_preserved(self):
        raw = {'cveID': 'CVE-2026-1001', 'dateAdded': '2026-02-03',
               'vendorProject': 'Example', 'requiredAction': 'Upgrade'}
        collector = CISAKEVCollector(session=session_for(Response({'count': 1, 'vulnerabilities': [raw]})))
        item = collector.collect()[0]
        self.assertIsNone(item.published_at)
        self.assertEqual(raw, item.raw_data)

    def test_kev_count_mismatch_is_not_success(self):
        collector = CISAKEVCollector(session=session_for(Response({'count': 1, 'vulnerabilities': []})))
        with self.assertRaises(ValueError):
            collector.collect()

    def test_kev_uses_cisa_owned_mirror_on_request_failure_and_preserves_original_row(self):
        raw = {'cveID': 'CVE-2026-1001', 'dateAdded': '2026-02-03'}
        session = session_for(Response({}, status=403), Response({'count': 1, 'vulnerabilities': [raw]}))
        collector = CISAKEVCollector(session=session)
        item = collector.collect()[0]
        self.assertEqual(session.get.call_args.args[0], collector.MIRROR_URL)
        self.assertEqual(collector.endpoint_used, collector.MIRROR_URL)
        self.assertEqual(item.raw_data, raw)
        self.assertIsNone(item.published_at)

    def test_kev_invalid_success_response_does_not_silently_use_mirror(self):
        session = session_for(Response({'count': 2, 'vulnerabilities': []}))
        with self.assertRaises(ValueError):
            CISAKEVCollector(session=session).collect()
        self.assertEqual(session.get.call_count, 1)

    def test_empty_limits_do_not_use_network(self):
        for collector in [NVDCollector(session=Mock()),
                          GitHubAdvisoryCollector(token='', session=Mock()),
                          CISAKEVCollector(session=Mock())]:
            self.assertEqual([], collector.collect(limit=0))
            collector.session.get.assert_not_called()


class WindowAndCursorTests(unittest.TestCase):
    def ingest(self, *, cursor=None, **options):
        collector, store, cursors = Mock(), Mock(), Mock()
        collector.collect_window.return_value = []
        store.ingest_batch.return_value = {'fetched': 0, 'inserted': 0, 'updated': 0, 'unchanged': 0}
        cursors.get.return_value = cursor
        arguments = dict(name='NVD', collector=collector, store=store, cursors=cursors,
                         now=datetime(2026, 1, 10, tzinfo=timezone.utc),
                         settle_minutes=0, log=lambda _: None)
        arguments.update(options)
        return arguments, collector, store, cursors

    def test_large_overlap_with_one_window_still_advances_checkpoint(self):
        cursor = datetime(2026, 1, 5, tzinfo=timezone.utc)
        args, collector, _, cursors = self.ingest(cursor=cursor, overlap_minutes=2 * 1440,
                                                   window_days=1, max_windows=1)
        outcome = ingest_incremental_source(**args)
        collector.collect_window.assert_called_once_with(cursor - timedelta(days=2), cursor + timedelta(days=1))
        cursors.advance.assert_called_once_with('NVD', cursor + timedelta(days=1))
        self.assertTrue(outcome['pending'])

    def test_overlap_plus_window_respects_nvd_query_limit(self):
        cursor = datetime(2026, 1, 5, tzinfo=timezone.utc)
        args, collector, _, _ = self.ingest(cursor=cursor, overlap_minutes=1440,
                                           window_days=119, max_windows=1,
                                           now=datetime(2026, 12, 1, tzinfo=timezone.utc))
        ingest_incremental_source(**args)
        start, end = collector.collect_window.call_args.args
        self.assertEqual(timedelta(days=119), end - start)
        self.assertGreater(end, cursor)

    def test_hour_backfill_makes_progress_without_a_week_sized_request(self):
        cursor = datetime(2026, 1, 5, tzinfo=timezone.utc)
        args, collector, _, cursors = self.ingest(cursor=cursor, window_hours=1, max_windows=1)
        result = ingest_incremental_source(**args)
        start, end = collector.collect_window.call_args.args
        self.assertEqual(end, cursor + timedelta(hours=1))
        self.assertEqual(start, cursor - timedelta(minutes=30))
        cursors.advance.assert_called_once_with('NVD', end)
        self.assertTrue(result['pending'])

    def test_network_or_ingest_failure_never_advances(self):
        for failing_stage in ('network', 'database'):
            with self.subTest(stage=failing_stage):
                args, collector, store, cursors = self.ingest()
                if failing_stage == 'network':
                    collector.collect_window.side_effect = requests.Timeout()
                else:
                    store.ingest_batch.side_effect = sqlite3.OperationalError('disk full')
                with self.assertRaises(Exception):
                    ingest_incremental_source(**args)
                cursors.advance.assert_not_called()

    def test_cursor_does_not_move_backwards_with_legacy_timezone_or_fraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cursor.db'
            cursors = CursorStore(path)
            with sqlite3.connect(path) as connection:
                connection.execute('INSERT INTO incremental_cursors VALUES(?,?,?)',
                                   ('NVD', '2026-01-01T08:00:00.500000+08:00', 'legacy'))
            older = datetime(2026, 1, 1, 0, 0, 0, 400000, tzinfo=timezone.utc)
            cursors.advance('NVD', older)
            self.assertEqual(500000, cursors.get('NVD').microsecond)
            newer = older.replace(microsecond=600000)
            cursors.advance('NVD', newer)
            self.assertEqual(newer, cursors.get('NVD'))


if __name__ == '__main__':
    unittest.main()
