"""Snapshot boundaries and one genuine isolated HTTP/SQLite business chain."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.acceptance_snapshot import capture, validate_base

ROOT = Path(__file__).resolve().parents[2]


class AcceptanceSnapshotTest(unittest.TestCase):
    def test_default_never_requests_model_or_work_and_unknown_stays_waiting(self):
        calls = []
        def empty(base, route, body):
            calls.append((route, body))
            return {"items": [], "total": 0}
        result = capture("http://127.0.0.1:8023", "CVE-2099-90099", requester=empty)
        self.assertTrue(all(body is None for _, body in calls))
        self.assertFalse(result["summary"]["chain_bindings_verified"])
        self.assertIn("qa_same_evidence", result["summary"]["waiting"])
        self.assertIsNone(result["monitor"]["raw_inserted"])
        self.assertIsNone(result["monitor"]["source_failed"])
        self.assertIsNone(result["summary"]["semantic_accuracy"])
        self.assertFalse(result["commit_verified_by_server"])

    def test_request_errors_are_visible_without_exporting_exception_secrets(self):
        def failed(*args):
            raise RuntimeError("private-key-do-not-export")
        result = capture("http://localhost:8023", "CVE-2099-90099", requester=failed)
        self.assertTrue(result["summary"]["errors"])
        self.assertNotIn("private-key", json.dumps(result))

    def test_nonlocal_or_credential_urls_rejected(self):
        for base in ("https://example.com", "http://user:password@localhost", "http://localhost/path",
                     "http://localhost?secret=value", "http://localhost/#fragment"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                validate_base(base)

    def test_real_offline_http_chain_and_risk_transitions(self):
        with tempfile.TemporaryDirectory(prefix="acceptance-fixture-") as directory:
            result = subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("acceptance_chain_fixture.py")), directory],
                                    cwd=ROOT, text=True, encoding="utf-8", errors="replace",
                                    capture_output=True, timeout=70)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((Path(directory) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["evidence_kind"], "offline_fixture")
            self.assertTrue(report["summary"]["chain_bindings_verified"])
            self.assertFalse(report["scope"]["external_network"])
            self.assertEqual(report["scope"]["transport"], "localhost_http")
            self.assertIsNone(report["summary"]["enrichment_accuracy"])
            self.assertTrue(all(report["fixture_checks"].values()))


if __name__ == "__main__":
    unittest.main()
