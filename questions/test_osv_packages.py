"""Offline OSV keyword → package resolution and diversity caps (no network)."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from collectors import cursors
from collectors.osv import (
    PACKAGES,
    PER_PACKAGE_LIMIT,
    OSVCollector,
    resolve_packages,
    _known_package_entries,
    _round_robin_merge,
)


class TestOSVPackages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cursor = patch.object(cursors, "CURSOR_PATH", Path(self.tmp.name) / "cursors.json")
        self.cursor.start()
        self.addCleanup(self.cursor.stop)

    def test_known_keyword_stays_narrow(self):
        self.assertEqual(resolve_packages("ollama"), list(PACKAGES["ollama"]))

    def test_broad_llm_expands_known_set(self):
        resolved = resolve_packages("llm")
        self.assertEqual(set(resolved), set(_known_package_entries()))
        self.assertNotIn(("GIT", "github.com/llm/llm"), resolved)
        # Stack coverage beyond the historical ollama-only path.
        names = {name for _, name in resolved}
        self.assertIn("vllm", names)
        self.assertIn("transformers", names)
        self.assertIn("langchain", names)
        self.assertIn("github.com/ollama/ollama", names)

    def test_auto_monitor_csv_expands_not_fake_slash_package(self):
        # Safety net: full AUTO_MONITOR string must not become github.com/llm,vllm/...
        csv = "llm,vllm,transformers,langchain,llama-index,huggingface,openai,ollama"
        resolved = resolve_packages(csv)
        self.assertEqual(set(resolved), set(_known_package_entries()))
        self.assertTrue(all("/" not in eco for eco, _ in resolved))
        joined = ",".join(name for _, name in resolved)
        self.assertNotIn("llm,vllm", joined)

    def test_narrow_csv_unions_named_packages(self):
        resolved = resolve_packages("vllm,langchain")
        self.assertEqual(set(resolved), set(PACKAGES["vllm"] + PACKAGES["langchain"]))

    def test_collect_llm_queries_all_known_packages(self):
        calls = []

        def fake_post(eco, name):
            calls.append((eco, name))
            return {"vulns": []}

        with patch("collectors.osv._post", side_effect=fake_post):
            coll = OSVCollector(keyword="llm")
            items = coll.collect()
        self.assertEqual(items, [])
        self.assertEqual(set(calls), set(_known_package_entries()))
        self.assertNotIn(("GIT", "github.com/llm/llm"), calls)
        self.assertTrue(coll.last_stats.get("expanded_broad"))
        self.assertIn("vllm", coll.last_stats.get("package_labels") or [])
        self.assertGreaterEqual(coll.last_stats.get("packages_planned") or 0, 8)

    def test_one_package_failure_does_not_abort(self):
        def flaky(eco, name):
            if name == "vllm":
                raise TimeoutError("skip")
            return {"vulns": []}

        with patch("collectors.osv._post", side_effect=flaky):
            items = OSVCollector(keyword="llm").collect()
        self.assertEqual(items, [])

    def test_per_package_cap_and_product_label(self):
        def flood(eco, name):
            product = name.split("/")[-1]
            vulns = []
            for i in range(20):
                vulns.append({
                    "id": "CVE-2099-%05d" % (hash((eco, name, i)) % 90000 + 10000),
                    "summary": "%s issue %d" % (product, i),
                    "published": "2026-01-%02dT00:00:00Z" % ((i % 28) + 1),
                    "affected": [{"package": {"name": name}}],
                    "references": [],
                })
            return {"vulns": vulns}

        with patch("collectors.osv._post", side_effect=flood):
            items = OSVCollector(keyword="llm", per_package_limit=3).collect()
        by_product = {}
        for item in items:
            prod = item.get("product") or ""
            by_product[prod] = by_product.get(prod, 0) + 1
            self.assertNotEqual(prod, "llm")
        self.assertTrue(by_product)
        self.assertLessEqual(max(by_product.values()), 3)
        # Multiple AI packages should appear, not only ollama.
        self.assertGreaterEqual(len(by_product), 3)
        self.assertLessEqual(PER_PACKAGE_LIMIT, 10)

    def test_round_robin_merge_interleaves(self):
        a = [{"cve_id": "CVE-A1"}, {"cve_id": "CVE-A2"}]
        b = [{"cve_id": "CVE-B1"}, {"cve_id": "CVE-B2"}]
        merged = _round_robin_merge([a, b])
        self.assertEqual([x["cve_id"] for x in merged], ["CVE-A1", "CVE-B1", "CVE-A2", "CVE-B2"])


if __name__ == "__main__":
    unittest.main()
