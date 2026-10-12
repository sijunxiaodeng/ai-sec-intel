"""Exercise the real ASGI import/preview flow using synthetic exports and a temporary DB."""
from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


class AssetObservationsApiTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / 'observations.sqlite3'
        self.module = importlib.import_module('enrichment.asset_observations')
        self.client = TestClient(importlib.import_module('api.app').app)
        self.patch = patch.object(self.module, 'DEFAULT_OBSERVATION_DB', self.db)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.banner = {'ip_str': '203.0.113.10', 'port': 11434, 'product': 'Ollama',
                       'version': '0.1.33', 'timestamp': datetime.now(timezone.utc).isoformat(),
                       'data': 'Synthetic provider record, no target was contacted.'}
        self.body = {'provider': 'shodan', 'content': json.dumps({'matches': [self.banner]}),
                     'fields': [], 'is_demo': True}
        self.assessment = {'cve_id': 'CVE-2024-37032', 'status': 'partial', 'affected_ranges': [{
            'criteria': 'cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*',
            'versionEndExcluding': '0.1.34', 'display': 'ollama < 0.1.34',
            'pointer': 'configurations/0', 'evidence_ids': ['CVE-2024-37032/SYNTHETIC-RANGE']}],
            'evidence': [{'citation_id': 'CVE-2024-37032/SYNTHETIC-RANGE', 'text': 'Synthetic version range'}]}
        self.network = patch('socket.create_connection', side_effect=AssertionError('network disabled'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def test_preview_does_not_save_and_optional_cve_calls_real_matcher(self):
        response = self.client.post('/api/asset-observations/preview', json=self.body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['count'], 1)
        self.assertNotIn('impact', response.json())
        self.assertFalse(self.db.exists())
        with patch('api.app._asset_assessment', return_value=self.assessment):
            response = self.client.post('/api/asset-observations/preview',
                                        json=dict(self.body, cve_id='CVE-2024-37032'))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()['impact']['preview'])
        self.assertEqual(response.json()['impact']['asset_count'], 1)
        self.assertFalse(self.db.exists())

    def test_import_and_saved_impact_keep_demo_and_original_hash(self):
        response = self.client.post('/api/asset-observations/import', json=self.body)
        self.assertEqual(response.status_code, 200, response.text)
        response = self.client.get('/api/asset-observations')
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['demo_count'], 1)
        self.assertEqual(len(result['items'][0]['source_response_sha256']), 64)
        with patch('api.app._asset_assessment', return_value=self.assessment):
            response = self.client.get('/api/asset-observation-impact/CVE-2024-37032')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['demo_count'], 1)
        self.assertFalse(response.json()['preview'])

    def test_invalid_body_or_export_is_rejected_before_storage(self):
        for change in ({'provider': 'internet_scan'}, {'is_demo': 'false'}, {'content': 42},
                       {'content': '{malformed'}, {'fields': [123]}, {'api_key': 'synthetic-key'},
                       {'content': 'x' * (1024 * 1024 + 1)}):
            with self.subTest(change_keys=list(change)):
                response = self.client.post('/api/asset-observations/import', json=dict(self.body, **change))
                self.assertEqual(response.status_code, 422, response.text)
                self.assertFalse(self.db.exists())

    def test_bad_cve_and_absent_cve_have_explicit_http_errors(self):
        self.assertEqual(self.client.post('/api/asset-observations/preview',
            json=dict(self.body, cve_id='../CVE')).status_code, 422)
        with patch('api.app.get_record', return_value=None):
            self.assertEqual(self.client.post('/api/asset-observations/preview',
                json=dict(self.body, cve_id='CVE-2099-99999')).status_code, 404)
        self.assertFalse(self.db.exists())

    def test_fofa_arrays_require_explicit_columns(self):
        body = {'provider': 'fofa', 'content': json.dumps({'results': [['203.0.113.11', '11434', 'Ollama']]}),
                'is_demo': True}
        self.assertEqual(self.client.post('/api/asset-observations/preview', json=body).status_code, 422)
        response = self.client.post('/api/asset-observations/preview',
                                    json=dict(body, fields=['ip', 'port', 'product']))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['count'], 1)
        self.assertFalse(self.db.exists())

    def test_demo_payload_is_marked_and_provider_load_failures_do_not_return_success(self):
        response = self.client.get('/api/asset-observations/demo')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()['is_demo'])
        self.assertIsInstance(response.json()['content'], str)
        with patch.object(self.module, 'load_observations', side_effect=ValueError('snapshot integrity failed')):
            self.assertEqual(self.client.get('/api/asset-observations').status_code, 409)
            with patch('api.app._asset_assessment', return_value=self.assessment):
                self.assertEqual(self.client.get('/api/asset-observation-impact/CVE-2024-37032').status_code, 409)


if __name__ == '__main__':
    unittest.main()
