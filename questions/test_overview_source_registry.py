"""Homepage source_count must reflect SourceSpec registry, not CVE card tags alone."""
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


class OverviewSourceRegistryTests(unittest.TestCase):
    def setUp(self):
        import api.app as app_module
        self.app = app_module
        self.client = TestClient(app_module.app)

    def test_source_count_uses_registry_not_four_card_tags(self):
        # Knowledge cards historically only carried NVD/OSV/GitHub/CISA — that
        # subset must not become the homepage「登记来源」count.
        card_only = ["NVD", "OSV", "GITHUB_ADVISORY", "CISA_KEV"]
        records = [
            {"item": {"sources": card_only[:2], "raw_data": {}}},
            {"item": {"sources": card_only[2:], "raw_data": {}}},
        ]
        with patch("api.app.knowledge_records", return_value=records), \
                patch("api.app._team_intel_snapshot", return_value={"reachable": False}), \
                patch("rag.library.overview", return_value={
                    "documents": 0, "chunks": 0, "source_categories": []}), \
                patch("api.app.configured", return_value=False), \
                patch("api.app.last_steps", return_value=[]), \
                patch("api.app.monitor_state", return_value={}):
            data = self.client.get("/api/overview").json()
        self.assertEqual(data["source_basis"], "source_registry")
        self.assertGreaterEqual(data["source_count"], 13)
        self.assertEqual(data["observed_source_count"], 4)
        self.assertEqual(sorted(data["observed_sources"]), sorted(card_only))
        for required in ("NVD", "OSV", "GITHUB_ADVISORY", "ARXIV_AI_SECURITY",
                         "TRAIL_OF_BITS_BLOG", "FEDERAL_REGISTER_AI_POLICY"):
            self.assertIn(required, data["sources"])
        # Must not shrink to the four card tags.
        self.assertNotEqual(sorted(data["sources"]), sorted(card_only))

    def test_visibility_exposes_registry_alongside_observed_tags(self):
        records = [{"item": {"sources": ["NVD", "OSV"], "raw_data": {}}}]
        with patch("api.app.knowledge_records", return_value=records), \
                patch("api.app._team_intel_snapshot", return_value={"reachable": False}), \
                patch("rag.library.overview", return_value={
                    "documents": 0, "chunks": 0, "source_categories": []}), \
                patch("api.app.configured", return_value=False), \
                patch("api.app.monitor_state", return_value={}), \
                patch("enrichment.assets.load_assets", return_value=[]):
            board = self.client.get("/api/visibility").json()
        registry = board["source_registry"]
        self.assertEqual(registry["source_basis"], "source_registry")
        self.assertGreaterEqual(registry["source_count"], 13)
        self.assertEqual(registry["observed_source_count"], 2)
        self.assertEqual(sorted(registry["observed_sources"]), ["NVD", "OSV"])


if __name__ == "__main__":
    unittest.main()
