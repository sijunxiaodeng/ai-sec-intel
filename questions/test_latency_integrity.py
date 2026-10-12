"""Hourly monitoring evidence must use real, precise, timezone-aware timestamps."""
import json
import sqlite3
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from automation import schedule
from intelligence.monitoring.metrics import latency_report


NOW = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


class LatencyIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(':memory:')
        self.con.row_factory = sqlite3.Row
        self.con.execute('CREATE TABLE unified_vulnerabilities(payload_json TEXT, first_seen_at TEXT)')
        self.addCleanup(self.con.close)

    def row(self, published, seen, source='NVD'):
        self.con.execute('INSERT INTO unified_vulnerabilities VALUES (?, ?)',
                         (json.dumps({'published_at': published, 'publication_source': source}), seen))

    def test_future_publication_or_ingestion_never_improves_latency(self):
        self.row('2099-01-01T00:00:00Z', '2099-01-01T01:00:00Z')
        self.row('2026-10-12T10:00:00Z', '2099-01-01T01:00:00Z')
        self.row('2026-10-12T10:00:00Z', '2026-10-12T11:00:00Z')
        report = latency_report(self.con, '2026-10-12T00:00:00Z', now=NOW)
        self.assertEqual(report['continuous_monitoring']['samples'], 1)
        self.assertEqual(report['excluded']['future_timestamp'], 2)
        self.assertEqual(report['continuous_monitoring']['p50_hours'], 1)

    def test_bad_json_and_date_only_are_excluded_not_success_or_server_errors(self):
        for payload in ('{invalid', 'null', '[]'):
            self.con.execute('INSERT INTO unified_vulnerabilities VALUES (?,?)', (payload, '2026-10-12T11:00:00Z'))
        self.row('2026-10-12', '2026-10-12T11:00:00Z')
        report = latency_report(self.con, None, now=NOW)
        self.assertEqual(report['all_observed_including_backfill']['samples'], 0)
        self.assertEqual(report['excluded']['invalid_payload'], 3)
        self.assertEqual(report['excluded']['missing_or_imprecise_time'], 1)

    def test_offset_equivalent_times_and_inclusive_competition_boundary(self):
        self.row('2026-10-12T09:00:00+08:00', '2026-10-12T07:00:00Z')
        report = latency_report(self.con, '2026-10-12T00:00:00Z', now=NOW)
        self.assertEqual(report['continuous_monitoring']['within_6h'], 1)
        self.assertEqual(report['continuous_monitoring']['p50_hours'], 6)

    def test_root_compatibility_count_rejects_imprecise_and_future_samples(self):
        def record(published, seen):
            return {'item': {'published_at': published, 'collected_at': seen, 'sources': ['NVD']}}
        rows = [record('2026-10-12', '2026-10-12T11:00:00Z'),
                record('2099-01-01T00:00:00Z', '2099-01-01T01:00:00Z'),
                record('2026-10-12T09:00:00+08:00', '2026-10-12T03:00:00Z')]
        with patch.object(schedule, 'ensure_state', return_value={'started_at': '2026-10-12T00:00:00Z'}), \
             patch.object(schedule, 'datetime', FrozenDateTime):
            self.assertEqual(schedule.countable_latency(rows), 1)

    def test_next_run_keeps_the_fifteen_minute_interval(self):
        self.assertEqual(schedule.next_run_iso({'last_run': '2026-10-12T10:00:00Z',
                                                'interval_hours': 0.25, 'interval_minutes': 15}),
                         '2026-10-12T10:15:00Z')

    def test_loop_waits_fifteen_minutes_instead_of_clamping_to_an_hour(self):
        class StopLoop(BaseException):
            pass
        waits = []
        class Event:
            def wait(self, seconds):
                waits.append(seconds)
                if len(waits) == 2:
                    raise StopLoop()
        with patch.object(schedule.threading, 'Event', Event), \
             patch.object(schedule, 'AUTO_ENABLED', True), \
             patch.object(schedule, 'AUTO_ON_START', False), \
             patch.object(schedule, 'INTERVAL_MINUTES', 15), \
             patch.object(schedule, 'log_line'):
            with self.assertRaises(StopLoop):
                schedule._loop()
        self.assertEqual(waits, [2.0, 900])

    def test_disabled_scheduler_starts_no_thread_or_timer_and_has_no_next_run(self):
        with patch.object(schedule, 'AUTO_ENABLED', False), \
             patch.object(schedule, '_STARTED', False), \
             patch.object(schedule, 'ensure_state', return_value={}), \
             patch.object(schedule.threading, 'Thread') as thread, \
             patch.object(schedule.threading, 'Event') as event, \
             patch.object(schedule, 'run_once') as run:
            schedule.start()
            schedule._loop()
            thread.assert_not_called()
            event.assert_not_called()
            run.assert_not_called()
        self.assertEqual(schedule.next_run_iso({'auto_enabled': False, 'last_run': '2026-10-12T10:00:00Z',
                                                'interval_minutes': 15}), '')


if __name__ == '__main__':
    unittest.main()
