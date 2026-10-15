"""Source-tagged patch leads remain visible without claiming a verified fix."""
import copy
import unittest

from agents.qa_agent import _assessment_lines, _local_notes
from enrichment.assessment import assess
from questions import test_assessment as fixtures
from rag.ingest import ingest


class PatchCandidateTest(unittest.TestCase):
    setUp = fixtures.AssessmentTest.setUp
    fetch = fixtures.AssessmentTest.fetch

    def prepare(self):
        # Only NVD is stored; the referenced patch page is never fetched.
        ingest(self.record, self.db, max_sources=1, fetcher=self.fetch)
        return assess(self.cve, self.db)

    def test_patch_tag_is_a_cited_candidate_without_a_fetched_fix_record(self):
        report = self.prepare()
        self.assertEqual(report["fix_records"], [])
        self.assertEqual(len(report["patch_candidates"]), 1)
        candidate = report["patch_candidates"][0]
        self.assertEqual(candidate["url"], self.fix)
        self.assertEqual(candidate["validation"], "not_verified")
        self.assertNotIn("fixed_version", candidate)
        evidence = {row["citation_id"]: row for row in report["evidence"]}
        for identifier in candidate["evidence_ids"]:
            self.assertIn('"Patch"', evidence[identifier]["text"])
            self.assertEqual(evidence[identifier]["source_response_sha256"], report["source"]["sha256"])
        record = copy.deepcopy(self.record)
        record["item"]["raw_data"]["automatic_assessment"] = report
        answer = "\n".join(_assessment_lines(record, "应该怎么修复？") + _local_notes(record, "应该怎么修复？"))
        self.assertIn("NVD 标为 Patch 的修复候选参考", answer)
        self.assertIn(self.fix, answer)
        self.assertIn("尚未据此确认修复效果或修复版本", answer)

    def test_exploit_and_patch_tags_share_source_evidence_without_merging_status(self):
        self.nvd["references"] = [{"url": self.fix, "tags": ["Patch", "Exploit"]}] * 2
        report = self.prepare()
        self.assertEqual(len(report["patch_candidates"]), 1)
        self.assertEqual(len(report["poc_candidates"]), 1)
        self.assertEqual(report["patch_candidates"][0]["evidence_ids"], report["poc_candidates"][0]["evidence_ids"])
        self.assertEqual(report["poc_candidates"][0]["validation"], "not_run")

    def test_untagged_reference_is_not_promoted_to_a_patch(self):
        self.nvd["references"] = [{"url": self.fix, "tags": ["Third Party Advisory"]}]
        self.assertEqual(self.prepare()["patch_candidates"], [])


if __name__ == "__main__":
    unittest.main()
