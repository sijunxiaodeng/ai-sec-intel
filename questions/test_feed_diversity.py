"""Offline monitor feed mix helpers (no network / no FastAPI)."""
import unittest

from api.feed_mix import (
    diversify_cves_by_product,
    diversify_documents,
    feed_composition,
    interleave_feed,
)


class TestFeedDiversity(unittest.TestCase):
    def test_diversify_documents_round_robins_categories(self):
        rows = (
            [{"title": "blog-%d" % i, "category": "security_blog", "url": "u-b-%d" % i} for i in range(5)]
            + [{"title": "paper-%d" % i, "category": "academic_paper", "url": "u-p-%d" % i} for i in range(5)]
            + [{"title": "vendor-%d" % i, "category": "vendor_advisory", "url": "u-v-%d" % i} for i in range(5)]
        )
        out = diversify_documents(rows, limit=6)
        cats = [r["category"] for r in out]
        self.assertEqual(len(out), 6)
        self.assertEqual(cats.count("security_blog"), 2)
        self.assertEqual(cats.count("academic_paper"), 2)
        self.assertEqual(cats.count("vendor_advisory"), 2)

    def test_interleave_feed_inserts_documents(self):
        cves = [{"kind": "cve", "cve_id": "CVE-%d" % i, "published_at": "2026-10-%02dT00:00:00Z" % (10 - i)} for i in range(4)]
        docs = [{"kind": "document", "title": "D%d" % i, "published_at": "2026-10-%02dT00:00:00Z" % (9 - i)} for i in range(2)]
        mixed = interleave_feed(cves, docs)
        kinds = [r["kind"] for r in mixed]
        self.assertIn("document", kinds)
        # First window should not be four CVEs in a row when docs exist.
        self.assertNotEqual(kinds[:4], ["cve", "cve", "cve", "cve"])

    def test_composition_tracks_ollama_share(self):
        items = [
            {"kind": "cve", "product": "vllm", "title": "vLLM issue"},
            {"kind": "cve", "product": "ollama", "title": "Ollama issue"},
            {"kind": "document", "category": "security_blog", "title": "blog", "description": ""},
        ]
        comp = feed_composition(items)
        self.assertEqual(comp["by_kind"]["cve"], 2)
        self.assertEqual(comp["by_kind"]["document"], 1)
        self.assertEqual(comp["by_category"]["security_blog"], 1)
        self.assertEqual(comp["ollama_mentions"], 1)

    def test_diversify_cves_caps_single_product(self):
        rows = (
            [{"kind": "cve", "product": "ollama", "cve_id": "CVE-O-%d" % i, "published_at": "2026-10-01"} for i in range(20)]
            + [{"kind": "cve", "product": "vllm", "cve_id": "CVE-V-%d" % i, "published_at": "2026-10-02"} for i in range(5)]
            + [{"kind": "cve", "product": "langchain", "cve_id": "CVE-L-%d" % i, "published_at": "2026-10-03"} for i in range(5)]
        )
        out = diversify_cves_by_product(rows, per_product_limit=3, limit=12)
        products = [r["product"] for r in out]
        self.assertLessEqual(products.count("ollama"), 3)
        self.assertIn("vllm", products)
        self.assertIn("langchain", products)


if __name__ == "__main__":
    unittest.main()
