"""Progress polling must retain collector state and never see a partial file."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from automation import schedule


class MonitorStateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'monitor.json'
        self.addCleanup(patch.stopall)
        patch.object(schedule, 'STATE_PATH', self.path).start()

    def test_polling_does_not_rewrite_initialized_progress(self):
        state = schedule.ensure_state()
        state.update(running=True, run_phase='collecting', last_error='previous source outage')
        schedule._write_state(state)
        before = (self.path.read_bytes(), self.path.stat().st_mtime_ns)
        for _ in range(100):
            polled = schedule.state()
            self.assertTrue(polled['running'])
            self.assertEqual(polled['run_phase'], 'collecting')
            self.assertEqual(polled['last_error'], 'previous source outage')
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_failed_state_replace_retains_complete_previous_progress(self):
        previous = schedule.ensure_state()
        previous['run_phase'] = 'previous'
        schedule._write_state(previous)
        incoming = dict(previous, run_phase='new')
        with patch.object(schedule.os, 'replace', side_effect=OSError('disk write failure')):
            with self.assertRaises(OSError):
                schedule._write_state(incoming)
        self.assertEqual(json.loads(self.path.read_text(encoding='utf-8')), previous)
        self.assertEqual(list(self.path.parent.glob('*.tmp')), [])

    def test_readers_keep_complete_state_during_repeated_publication(self):
        state = schedule.ensure_state()
        state.update(running=True, run_phase='0')
        schedule._write_state(state)
        done, errors = threading.Event(), []

        def writer():
            try:
                for number in range(1, 81):
                    schedule._write_state(dict(state, run_phase=str(number)))
            except Exception as exc:
                errors.append(exc)
            finally:
                done.set()

        def reader():
            try:
                while not done.is_set():
                    observed = schedule.ensure_state()
                    if not observed['running'] or not observed['run_phase'].isdigit():
                        raise AssertionError('poller saw empty or partial progress')
            except Exception as exc:
                errors.append(exc)

        readers = [threading.Thread(target=reader) for _ in range(2)]
        for thread in readers:
            thread.start()
        producer = threading.Thread(target=writer)
        producer.start()
        producer.join(10)
        self.assertFalse(producer.is_alive())
        done.set()
        for thread in readers:
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(schedule.state()['run_phase'], '80')


if __name__ == '__main__':
    unittest.main()
