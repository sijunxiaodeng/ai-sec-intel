"""The legacy collect response must not conceal failed source outcomes."""
from contextlib import nullcontext
import importlib
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


class CollectResponseTests(unittest.TestCase):
    def test_failed_empty_round_exposes_failure_and_round_counts(self):
        appmod = importlib.import_module('api.app')
        result = {'records': [], 'steps': [], 'status': 'failed', 'error': 'all sources unavailable',
                  'source_outcomes': {'osv': 'failed', 'aggregate': 'failed', 'nvd': 'skipped'},
                  'warnings': ['all sources unavailable'], 'round_stats': {'inserted': 0}}
        with patch.object(appmod, 'run_collect', return_value=result), \
             patch('database.store.collection_lock', side_effect=lambda **kw: nullcontext()):
            response = TestClient(appmod.app).post('/api/collect', json={'keyword': 'ollama'})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['status'], 'failed')
        self.assertEqual(body['error'], result['error'])
        self.assertEqual(body['source_outcomes'], result['source_outcomes'])
        self.assertEqual(body['round_stats']['inserted'], 0)


if __name__ == '__main__':
    unittest.main()
