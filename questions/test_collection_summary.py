"""A non-AI raw insertion and an incomplete poll must remain distinguishable."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automation.collection_summary import summarize_collection
from automation import schedule


class CollectionSummaryTest(unittest.TestCase):
    def test_all_committed_phases_are_counted_separately_from_unique_cves(self):
        result = summarize_collection({"status": "partial", "configured_sources": 3, "sources": {
            "NVD": {"status": "partial", "inserted": 38, "updated": 2, "fetched": 177,
                    "backfill": {"inserted": 2, "updated": 3, "fetched": 10, "lag_seconds": 3600},
                    "publication_recovery": {"inserted": 5, "updated": 0, "fetched": 5}},
            "OSV": {"status": "success", "inserted": 0, "updated": 0, "fetched": 2,
                    "documents": {"inserted": 1, "updated": 0, "fetched": 1}},
            "GITHUB": {"status": "failed", "error": "CollectionRateLimited: HTTP 403"}}})
        self.assertEqual(result["raw_inserted"], 46)
        self.assertEqual(result["raw_fetched"], 195)
        self.assertEqual(result["source_success"], 1)
        self.assertEqual(result["source_partial"], 1)
        self.assertEqual(result["source_failed"], 1)
        self.assertFalse(result["counts_complete"])

    def test_overall_timeout_cannot_masquerade_as_successful_zero(self):
        result = summarize_collection({"status": "timeout"})
        self.assertIsNone(result["raw_inserted"])
        self.assertIsNone(result["source_total"])
        self.assertIsNone(result["source_failed"])
        self.assertFalse(result["counts_complete"])

    def test_absent_individual_metrics_remain_unknown(self):
        result = summarize_collection({"status": "success", "sources": {
            "NVD": {"status": "success", "inserted": 0}}})
        self.assertEqual(result["raw_inserted"], 0)
        self.assertIsNone(result["raw_updated"])
        self.assertIsNone(result["raw_fetched"])
        self.assertFalse(result["counts_complete"])

    def test_complete_empty_source_is_legitimate_zero(self):
        result = summarize_collection({"status": "success", "configured_sources": 1, "sources": {
            "NVD": {"status": "success", "inserted": 0, "updated": 0, "fetched": 0}}})
        self.assertEqual(result["raw_inserted"], 0)
        self.assertTrue(result["counts_complete"])

    def test_new_cycle_without_source_refresh_clears_prior_collection_summary(self):
        with tempfile.TemporaryDirectory() as root, patch.object(schedule, 'STATE_PATH', Path(root) / 'monitor.json'):
            summary = summarize_collection({"status": "partial"})
            schedule.mark_run(count=0, status="partial", collection_summary=summary)
            self.assertEqual(schedule.state()["collection_summary"], summary)
            schedule.mark_run(count=0)
            self.assertIsNone(schedule.state()["collection_summary"])


if __name__ == '__main__':
    unittest.main()
