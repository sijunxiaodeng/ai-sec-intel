import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from api_v6.team_adapter import to_team_item


TEAM_ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('team_source_collector', TEAM_ROOT / 'collectors' / 'intelligence.py')
collector_module = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(TEAM_ROOT))
try:
    spec.loader.exec_module(collector_module)
finally:
    sys.path.remove(str(TEAM_ROOT))


class TeamCollectorTests(unittest.TestCase):
    def test_paginated_rows_are_normalized_and_query_encoded(self):
        rows = [{'cve_id': f'CVE-2026-{10000 + i}', 'raw_data': {}} for i in range(101)]
        responses = [io.StringIO(json.dumps({'items': rows[:100], 'total': 101})),
                     io.StringIO(json.dumps({'items': rows[100:], 'total': 101}))]
        with patch.object(collector_module.urllib.request, 'urlopen', side_effect=responses) as opened:
            items = collector_module.IntelligenceCollector(keyword='Ollama & 中文').collect()
        self.assertEqual(len(items), 101)
        self.assertEqual(items[0]['id'], rows[0]['cve_id'])
        first_url = opened.call_args_list[0].args[0].full_url
        second_url = opened.call_args_list[1].args[0].full_url
        self.assertIn('q=Ollama+%26+', first_url)
        self.assertIn('offset=100', second_url)

    def test_truncated_response_or_page_limit_raises_instead_of_partial_success(self):
        with patch.object(collector_module.urllib.request, 'urlopen', return_value=io.StringIO(json.dumps({'items': [], 'total': 1}))):
            with self.assertRaises(ValueError):
                collector_module.IntelligenceCollector().collect()
        with patch.object(collector_module.urllib.request, 'urlopen', return_value=io.StringIO(json.dumps({'items': [{'cve_id': 'CVE-2026-10001'}], 'total': 2}))):
            with self.assertRaises(RuntimeError):
                collector_module.IntelligenceCollector(max_pages=1).collect()

    def test_team_affected_strings_and_source_marked_exploits_preserve_evidence(self):
        data = to_team_item({'cve_id': 'CVE-2026-10001', 'first_seen_at': '2026-10-08T03:00:00Z',
            'item': {'sources': ['NVD'], 'affected_packages': [{
                'ecosystem': 'pip', 'name': 'ollama', 'vulnerable_version_range': '<0.1.34',
                'first_patched_version': '0.1.34'}],
                'raw_by_source': {'NVD': {'references': [
                    {'url': 'https://example.com/poc', 'tags': ['Exploit']},
                    {'url': 'https://example.com/article', 'tags': ['Technical Description']},
                ]}}}})
        self.assertIsInstance(data['affected'][0], str)
        self.assertIn('<0.1.34', data['affected'][0])
        self.assertIn('修复版本 0.1.34', data['affected'][0])
        self.assertEqual(data['raw_data']['affected_packages'][0]['name'], 'ollama')
        self.assertEqual(data['raw_data']['exploit_refs'], ['https://example.com/poc'])


if __name__ == '__main__':
    unittest.main()
