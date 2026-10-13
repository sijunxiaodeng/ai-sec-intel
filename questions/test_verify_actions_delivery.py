"""The proof command must reject wrong generations and merely reachable APIs."""
import copy
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("delivery_verifier", Path(__file__).resolve().parents[1] / "scripts/verify-actions-delivery.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

GENERATION = {"repository": "team/public-repo", "branch": "main", "workflow": "intelligence-collect.yml",
              "run_id": 42, "run_number": 7, "collector_commit": "a" * 40}
HIGH = {"epoch": "fixture-epoch", "through": 10}


class VerifyActionsDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.delivery = {"status": "serving_verified_generation", "database_available": True,
                         "generation": GENERATION, "compatibility": {"ready": True},
                         "changefeed": HIGH, "poller_observation": "ready"}
        self.consumption = {"status": "caught_up", "upstream": HIGH,
                            "consumers": {"all_caught_up": True, "processing_completion_verified": False,
                                "cve": {"status": "caught_up", "checkpoint": {"epoch": HIGH["epoch"], "seq": 10}},
                                "document": {"status": "caught_up", "checkpoint": {"epoch": HIGH["epoch"], "seq": 10}}}}

    def reader(self, url):
        if url.endswith("/api/intelligence/delivery"):
            return copy.deepcopy(self.delivery)
        if url.endswith("/api/admin/actions-consumption"):
            return copy.deepcopy(self.consumption)
        return {**HIGH, "cursor": 0, "next_cursor": 10, "has_more": False, "reset": False, "changes": []}

    def verify(self, reader=None):
        return verifier.verify(b_base="http://127.0.0.1:8765", main_base="http://127.0.0.1:8023",
                               run_id=42, collector_commit="a" * 40, reader=reader or self.reader)

    def test_expected_generation_and_both_committed_consumers_prove_import_only(self):
        facts = self.verify()
        self.assertTrue(facts["snapshot_serving_verified"])
        self.assertTrue(facts["consumption_verified"])
        self.assertFalse(facts["processing_verified"])

    def test_http_200_or_generic_success_does_not_prove_serving(self):
        facts = self.verify(reader=lambda url: {"ok": True})
        self.assertFalse(facts["snapshot_serving_verified"])
        self.assertFalse(facts["consumption_verified"])

    def test_claimed_done_must_match_actual_persisted_document_checkpoint(self):
        self.consumption["consumers"]["document"]["checkpoint"]["seq"] = 9
        facts = self.verify()
        self.assertTrue(facts["snapshot_serving_verified"])
        self.assertFalse(facts["consumption_verified"])
        self.consumption["upstream"] = {"epoch": "other-generation", "through": 10}
        self.assertEqual(self.verify()["reason_category"], "consumer_upstream_generation_unverified")

    def test_atomic_switch_during_requests_invalidates_previous_proof(self):
        calls = 0
        def changing(url):
            nonlocal calls
            result = self.reader(url)
            if url.endswith("/api/intelligence/delivery"):
                calls += 1
                if calls == 3:
                    result["changefeed"] = {"epoch": HIGH["epoch"], "through": 11}
            return result
        facts = self.verify(reader=changing)
        self.assertFalse(facts["snapshot_serving_verified"])
        self.assertFalse(facts["consumption_verified"])
        self.assertEqual(facts["reason_category"], "generation_changed_during_verification")

    def test_verifier_rejects_remote_cleartext_and_embedded_url_credentials(self):
        for base in ("http://remote.example", "https://user:secret@example.org", "https://example.org?token=secret"):
            with self.subTest(base=base), self.assertRaises(verifier.VerificationError):
                verifier.validate_base(base)


if __name__ == "__main__":
    unittest.main()
