"""Evaluation harness integrity checks; these do not emulate a real model."""
import json
from pathlib import Path
import tempfile
import unittest
import sqlite3

from scripts.evaluate_investigation_ab import FrozenHTTP, quality_hash, scenarios, sqlite_file_path


class EvaluationIntegrityTest(unittest.TestCase):
    def test_sqlite_uri_resolves_to_same_isolated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '中文 evidence.sqlite3'
            self.assertEqual(sqlite_file_path(path), sqlite_file_path(path.as_uri() + '?mode=ro'))
            self.assertRaises(RuntimeError, sqlite_file_path, 'file://external-host/production.sqlite3')

    def test_replay_uses_captured_bytes_and_blocks_unknown_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = FrozenHTTP(Path(directory))
            url = 'https://example.org/fixture'
            first = cache.response('test', url, lambda: {'body': b'real transport fixture'})
            cache.recording = False
            replay = cache.response('test', url, lambda: self.fail('Replay performed network work'))
            self.assertEqual(first['body'], replay['body'])
            self.assertRaises(RuntimeError, cache.response, 'test', url + '/unknown', lambda: {})
            body = next(Path(directory).glob('*.body'))
            body.write_bytes(b'changed')
            self.assertRaisesRegex(RuntimeError, 'hash mismatch', cache.response, 'test', url, lambda: {})

    def test_provider_failure_is_not_converted_into_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = FrozenHTTP(Path(directory))
            def unavailable():
                raise TimeoutError('fixture transport timeout')
            self.assertRaises(RuntimeError, cache.response, 'test', 'https://example.org', unavailable)
            cache.recording = False
            self.assertRaisesRegex(RuntimeError, 'TimeoutError', cache.response, 'test', 'https://example.org', lambda: {})
            self.assertEqual(cache.manifest()[0]['status'], 'error')

    def test_scenarios_are_fixed_and_paired_budgets_are_explicit(self):
        rows = scenarios()
        self.assertEqual(len(rows), 7)
        self.assertEqual(len({r['cve_id'] for r in rows}), 3)
        self.assertEqual([r['tool_budget'] for r in rows[:6]], [1, 4, 1, 4, 1, 4])
        self.assertTrue(all(r['model_budget'] == 2 and r['seconds'] == 90 for r in rows))

    def test_quality_hash_excludes_live_observations_but_detects_new_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'acceptance.sqlite3'
            conn = sqlite3.connect(path)
            try:
                for table in ('quality_runs', 'quality_cases', 'quality_reviews', 'quality_datasets', 'observations'):
                    conn.execute('CREATE TABLE "' + table + '" (id TEXT,payload TEXT)')
                conn.commit()
                baseline = quality_hash(path)
                conn.execute("INSERT INTO observations VALUES ('tick','new snapshot')")
                conn.commit()
                self.assertEqual(quality_hash(path), baseline)
                conn.execute("INSERT INTO quality_reviews VALUES ('review','human checked')")
                conn.commit()
                self.assertNotEqual(quality_hash(path), baseline)
            finally:
                conn.close()


if __name__ == '__main__':
    unittest.main()
