"""OSV monitor step must report package-batch hits, not fake keyword=llm zero."""
import os
import unittest
from unittest.mock import patch

from agents import monitor_agent
from collectors.osv import _known_package_entries


class TestOSVMonitorStep(unittest.TestCase):
    def test_osv_step_detail_lists_packages_not_keyword_llm(self):
        calls = []

        def fake_post(eco, name, page_token=""):
            calls.append((eco, name))
            return {
                "vulns": [{
                    "id": "CVE-2099-%05d" % (abs(hash(name)) % 90000 + 10000),
                    "summary": "%s issue" % name.split("/")[-1],
                    "published": "2026-01-15T00:00:00Z",
                    "affected": [{"package": {"name": name}}],
                    "references": [],
                }],
            }

        with patch.dict(os.environ, {"TEAM_INTEL_MODE": "off", "ROOT_NVD_ENABLED": "0"}, clear=False), \
             patch("collectors.osv._post", side_effect=fake_post), \
             patch("collectors.nvd.NVDCollector.collect", return_value=[]), \
             patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
            result = monitor_agent.run("llm,vllm,transformers,langchain")

        osv_steps = [s for s in result["steps"] if s.get("action") == "调用 OSV"]
        self.assertEqual(len(osv_steps), 1)
        detail = osv_steps[0]["detail"]
        self.assertIn("AI 组件包", detail)
        self.assertIn("命中", detail)
        self.assertIn("保留", detail)
        self.assertNotIn("关键词 llm", detail)
        self.assertIn("vllm", detail)
        self.assertGreater(result["stats"]["osv"].get("fetched") or 0, 0)
        self.assertEqual(set(calls), set(_known_package_entries()))
        self.assertTrue(result["stats"]["osv"].get("expanded_broad"))


if __name__ == "__main__":
    unittest.main()
