import json
from pathlib import Path
import tempfile
import unittest
from questions.evaluate import DATASET, check_case, summarize_review


class EvaluationTest(unittest.TestCase):
    def test_topic_list_has_unique_questions_and_manual_source_preconditions(self):
        data = json.loads(DATASET.read_text(encoding="utf-8"))
        self.assertEqual(len(data["cases"]), 36)
        self.assertEqual(len({c["id"] for c in data["cases"]}), 36)
        self.assertEqual(len(data["sources"]), 3)
        self.assertTrue(all(c["review_checklist"] for c in data["cases"]))

    def test_keyword_alone_does_not_pass_without_expected_source_citation(self):
        case = {"expected_cves": ["CVE-2024-37032"], "required_patterns": ["8.8"],
                "required_evidence": [{"cve_id": "CVE-2024-37032", "locator_contains": "metrics/", "url_prefix": "https://nvd.nist.gov/"}]}
        payload = {"answer": "8.8", "evidence": [{"cve_id": "CVE-2024-37032"}], "verdict": {"passed": True}}
        self.assertTrue(check_case(case, payload))

    def test_unreviewed_cases_cannot_be_counted_as_manual_accuracy(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            data = {"summary": {}, "cases": [{"manual_review": {"correct": None, "citations_supported": None}, "response": {"evidence": [1]}}]}
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                summarize_review(path)
            data["cases"][0]["manual_review"] = {"correct": False, "citations_supported": True}
            path.write_text(json.dumps(data), encoding="utf-8")
            result = summarize_review(path)
            self.assertEqual(result["manual_accuracy"], 0)
            self.assertEqual(result["manual_citation_support_rate"], 1)
