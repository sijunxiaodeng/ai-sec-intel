import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from automation import schedule


class DeadlineTests(unittest.TestCase):
    def test_restarted_worker_uses_actual_deadline_not_old_last_completion(self):
        before = datetime.now(timezone.utc)
        with patch.object(schedule, '_STARTED', True), patch.object(schedule, '_NEXT_RUN_AT', ''), patch.object(schedule, 'INTERVAL_MINUTES', 15):
            self.assertEqual(schedule.next_run_iso({'auto_enabled': True, 'last_run': '2000-01-01T00:00:00Z'}), '')
            schedule._schedule_next()
            displayed = datetime.fromisoformat(schedule.next_run_iso({'auto_enabled': True, 'last_run': '2000-01-01T00:00:00Z'}).replace('Z', '+00:00'))
            self.assertGreaterEqual(displayed, before + timedelta(seconds=899))
            self.assertLessEqual(displayed, datetime.now(timezone.utc) + timedelta(seconds=900))
            self.assertEqual(schedule.next_run_iso({'auto_enabled': False}), '')

    def test_long_round_waits_full_interval_instead_of_immediate_catchup(self):
        elapsed, waits, runs = [0], [], []

        class Stop:
            def is_set(self):
                return False

            def wait(self, seconds):
                waits.append(seconds)
                if len(waits) == 3:
                    return True
                elapsed[0] += seconds
                return False

        def run(_):
            runs.append(elapsed[0])
            elapsed[0] += 1200  # Slower than the configured fifteen-minute interval.

        with patch.object(schedule, 'AUTO_ENABLED', True), patch.object(schedule, 'AUTO_ON_START', False), patch.object(schedule, 'INTERVAL_MINUTES', 15), patch.object(schedule, '_NEXT_RUN_AT', ''), patch.object(schedule, '_STOP', Stop()), patch.object(schedule, 'ensure_state', return_value={}), patch.object(schedule, 'log_line'), patch.object(schedule, 'run_once', side_effect=run), patch.object(schedule.time, 'monotonic', side_effect=lambda: elapsed[0]):
            schedule._loop()
        self.assertEqual(waits, [2, 900, 900])
        self.assertEqual(runs, [902])

    def test_startup_round_schedules_from_completion_even_if_it_fails(self):
        elapsed, waits = [0], []

        class Stop:
            def is_set(self):
                return False

            def wait(self, seconds):
                waits.append(seconds)
                elapsed[0] += seconds
                return len(waits) == 2

        def failed(_):
            elapsed[0] += 120
            raise RuntimeError('controlled failure')

        with patch.object(schedule, 'AUTO_ENABLED', True), patch.object(schedule, 'AUTO_ON_START', True), patch.object(schedule, 'INTERVAL_MINUTES', 15), patch.object(schedule, '_NEXT_RUN_AT', ''), patch.object(schedule, '_STOP', Stop()), patch.object(schedule, 'ensure_state', return_value={}), patch.object(schedule, 'log_line'), patch.object(schedule, 'run_once', side_effect=failed), patch.object(schedule.time, 'monotonic', side_effect=lambda: elapsed[0]):
            schedule._loop()
        self.assertEqual(waits, [2, 900])


if __name__ == '__main__':
    unittest.main()
