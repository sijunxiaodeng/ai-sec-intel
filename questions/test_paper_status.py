"""Expose bounded lookup coverage separately from public-source outages."""
import unittest
from unittest.mock import patch

from agents import orchestrator


class PaperStatusTests(unittest.TestCase):
    def test_rotation_budget_is_not_reported_as_public_source_disconnection(self):
        class Papers(dict):
            metadata = {'status': 'partial', 'requested_cve_ids': ['CVE-2024-37032', 'CVE-2025-0312'],
                        'queried_cve_ids': ['CVE-2024-37032'], 'deferred_cve_ids': ['CVE-2025-0312']}
        papers = Papers()
        with patch.object(orchestrator, 'load_kb', return_value=[]), \
             patch.object(orchestrator, 'apply_public_feeds', return_value={'epss_error': None, 'kev_error': None}), \
             patch.object(orchestrator, 'fetch_papers', return_value=(papers, '预算内未查询的编号延后')), \
             patch.object(orchestrator, 'upsert', return_value=[]), \
             patch.object(orchestrator, '_documents_step', return_value=([], [])), \
             patch.object(orchestrator, 'append_run'):
            result = orchestrator.run_enrich()
        self.assertEqual(result['feed']['papers'], papers.metadata)
        self.assertEqual(result['feed']['paper_error'], '预算内未查询的编号延后')
        self.assertIn('覆盖 1/2', result['steps'][0]['detail'])
        self.assertNotIn('公开源没有连通', result['steps'][0]['detail'])


if __name__ == '__main__':
    unittest.main()
