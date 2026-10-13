"""Embedded B owns NVD polling; legacy direct polling is an explicit fallback."""
import os
import unittest
from unittest.mock import Mock, patch

from agents import monitor_agent, orchestrator
from collectors.intelligence import IntelligenceCollector


class MonitorAuthorityTests(unittest.TestCase):
    def run_monitor(self, overrides, *, nvd_error=False, osv_error=False):
        nvd = Mock()
        nvd.collect.return_value = []
        if nvd_error:
            nvd.collect.side_effect = ConnectionError('Synthetic NVD outage')
        nvd.last_stats = {'fetched': 0, 'kept': 0, 'external_fetches': 1}
        osv = Mock()
        osv.collect.return_value = []
        if osv_error:
            osv.collect.side_effect = ConnectionError('Synthetic OSV outage')
        osv.last_stats = {'fetched': 0, 'kept': 0, 'external_fetches': 1}
        team = Mock()
        team.collect.return_value = [{'cve_id': 'CVE-2026-41234'}]
        environment = dict(os.environ)
        environment.pop('ROOT_NVD_ENABLED', None)
        environment.pop('TEAM_ONLY_COLLECT', None)
        environment.update(overrides)
        changes = Mock()
        changes.collect.return_value = {
            'source': 'b_intelligence', 'items': team.collect.return_value,
            'retracted_ids': [], 'cursor': {'epoch': 'fixture', 'seq': 1},
        }
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(monitor_agent, 'NVDCollector', return_value=nvd) as nvd_class, \
             patch.object(monitor_agent, 'OSVCollector', return_value=osv), \
             patch.object(monitor_agent, 'IntelligenceCollector', return_value=team) as legacy_class, \
             patch.object(monitor_agent, 'IncrementalIntelligenceCollector', return_value=changes) as change_class, \
             patch('urllib.request.urlopen', side_effect=AssertionError('Unexpected live network')):
            result = monitor_agent.run('llm')
        team_class = change_class if overrides.get('TEAM_INTEL_MODE') in {'embed', 'sidecar'} and not (
            overrides.get('ROOT_NVD_ENABLED') == '1' or overrides.get('TEAM_ONLY_COLLECT') == '0') else legacy_class
        if team_class is change_class:
            legacy_class.assert_not_called()
        else:
            change_class.assert_not_called()
        return result, nvd_class, team_class

    def test_embed_does_not_repeat_nvd_polling(self):
        result, constructor, team = self.run_monitor({'TEAM_INTEL_MODE': 'embed'})
        constructor.assert_not_called()
        team.assert_called_once()
        self.assertTrue(result['stats']['nvd_disabled_duplicate'])
        self.assertIsNone(result['collectors']['nvd'])
        self.assertEqual(result['items'][0]['cve_id'], 'CVE-2026-41234')
        self.assertEqual(result['team_changes']['cursor']['seq'], 1)
        self.assertTrue(result['stats']['osv_disabled_duplicate'])

    def test_standalone_mode_keeps_the_direct_collector(self):
        result, constructor, team = self.run_monitor({'TEAM_INTEL_MODE': 'off'})
        # Broad llm expands to multiple NVD product keywords (capped).
        self.assertGreaterEqual(constructor.call_count, 2)
        team.assert_not_called()
        self.assertFalse(result['stats']['nvd_disabled_duplicate'])
        self.assertIn('open webui', result['keywords']['nvd'])

    def test_explicit_fallback_can_poll_when_the_team_mode_is_enabled(self):
        result, constructor, team = self.run_monitor({'TEAM_INTEL_MODE': 'embed', 'ROOT_NVD_ENABLED': '1'})
        self.assertGreaterEqual(constructor.call_count, 2)
        team.assert_called_once()
        self.assertFalse(result['stats']['nvd_disabled_duplicate'])

    def test_explicit_legacy_route_uses_nonincremental_collector(self):
        result, nvd, team = self.run_monitor({'TEAM_INTEL_MODE': 'embed', 'TEAM_ONLY_COLLECT': '0'})
        nvd.assert_not_called()
        team.assert_called_once()
        self.assertNotIn('team_changes', result)
        self.assertFalse(result['stats'].get('osv_disabled_duplicate', False))

    def test_disabled_team_aliases_neither_query_nor_degrade_healthy_empty_poll(self):
        for mode in ('off', 'disabled', '0', 'false', 'no'):
            with self.subTest(mode=mode):
                result, nvd, team = self.run_monitor({'TEAM_INTEL_MODE': mode})
                self.assertGreaterEqual(nvd.call_count, 2)
                team.assert_not_called()
                self.assertTrue(result['stats']['aggregate_disabled'])
                self.assertFalse(result['stats']['aggregate_ok'])
                # Multi-keyword NVD + one OSV round.
                self.assertGreaterEqual(result['stats']['external_fetches'], 3)
                self.assertIn('跳过', result['steps'][-1]['action'])
                outcome = orchestrator._monitor_outcome(result)
                self.assertEqual(outcome['status'], 'success')
                self.assertEqual(outcome['source_outcomes']['aggregate'], 'skipped')

    def test_disabled_team_does_not_rescue_two_failed_external_sources(self):
        result, nvd, team = self.run_monitor({'TEAM_INTEL_MODE': 'off'}, nvd_error=True, osv_error=True)
        self.assertGreaterEqual(nvd.call_count, 2)
        team.assert_not_called()
        outcome = orchestrator._monitor_outcome(result)
        self.assertEqual(outcome['status'], 'failed')
        self.assertEqual(outcome['source_outcomes'], {'nvd': 'failed', 'osv': 'failed', 'aggregate': 'skipped'})

    def test_explicit_nvd_disable_is_retained_in_standalone_mode(self):
        result, nvd, team = self.run_monitor({'TEAM_INTEL_MODE': 'off', 'ROOT_NVD_ENABLED': '0'})
        nvd.assert_not_called()
        team.assert_not_called()
        outcome = orchestrator._monitor_outcome(result)
        self.assertEqual(outcome['status'], 'success')
        self.assertEqual(outcome['source_outcomes'], {'nvd': 'skipped', 'osv': 'success', 'aggregate': 'skipped'})

    def test_sidecar_keeps_team_queries_without_duplicate_root_nvd(self):
        result, nvd, team = self.run_monitor({'TEAM_INTEL_MODE': 'sidecar'})
        nvd.assert_not_called()
        team.assert_called_once()
        self.assertFalse(result['stats']['aggregate_disabled'])
        self.assertEqual(result['items'][0]['cve_id'], 'CVE-2026-41234')

    def test_collector_disabled_modes_never_access_embed_or_http(self):
        for mode in ('off', 'disabled', '0', 'false', 'no'):
            with self.subTest(mode=mode), patch.dict(os.environ, {'TEAM_INTEL_MODE': mode}), \
                    patch.object(IntelligenceCollector, '_collect_embed') as embed, \
                    patch.object(IntelligenceCollector, '_collect_http') as http:
                self.assertEqual(IntelligenceCollector('llm').collect(), [])
                embed.assert_not_called()
                http.assert_not_called()

    def test_collector_enabled_modes_retain_their_adapters(self):
        for mode, method in (('embed', '_collect_embed'), ('sidecar', '_collect_http')):
            with self.subTest(mode=mode), patch.dict(os.environ, {'TEAM_INTEL_MODE': mode}), \
                    patch.object(IntelligenceCollector, method, return_value=[{'cve_id': 'CVE-2026-41234'}]) as collect:
                self.assertEqual(IntelligenceCollector('llm').collect()[0]['cve_id'], 'CVE-2026-41234')
                collect.assert_called_once()


if __name__ == '__main__':
    unittest.main()
