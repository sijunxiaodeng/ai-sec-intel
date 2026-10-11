"""Offline OSV keyword → package resolution (no network)."""
import unittest
from unittest.mock import patch

from collectors.osv import PACKAGES, OSVCollector, resolve_packages, _known_package_entries


class TestOSVPackages(unittest.TestCase):
    def test_known_keyword_stays_narrow(self):
        self.assertEqual(resolve_packages("ollama"), list(PACKAGES["ollama"]))

    def test_broad_llm_expands_known_set(self):
        resolved = resolve_packages("llm")
        self.assertEqual(set(resolved), set(_known_package_entries()))
        self.assertNotIn(("GIT", "github.com/llm/llm"), resolved)

    def test_collect_llm_queries_all_known_packages(self):
        calls = []

        def fake_post(eco, name):
            calls.append((eco, name))
            return {"vulns": []}

        with patch("collectors.osv._post", side_effect=fake_post):
            items = OSVCollector(keyword="llm").collect()
        self.assertEqual(items, [])
        self.assertEqual(set(calls), set(_known_package_entries()))
        self.assertNotIn(("GIT", "github.com/llm/llm"), calls)

    def test_one_package_failure_does_not_abort(self):
        def flaky(eco, name):
            if name == "vllm":
                raise TimeoutError("skip")
            return {"vulns": []}

        with patch("collectors.osv._post", side_effect=flaky):
            items = OSVCollector(keyword="llm").collect()
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
