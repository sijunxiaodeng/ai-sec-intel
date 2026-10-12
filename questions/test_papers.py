"""Legacy arXiv contract/coverage regressions, all responses injected offline."""
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
from xml.sax.saxutils import escape

from enrichment.papers import MAX_BYTES, fetch_papers, _fetch

A = "CVE-2024-37032"


def feed(entries=()):
    text = '<feed xmlns="http://www.w3.org/2005/Atom">'
    for title, summary, url in entries:
        text += '<entry><title>' + escape(title) + '</title><summary>' + escape(summary) + '</summary><link rel="alternate" href="' + escape(url) + '"/></entry>'
    return (text + '</feed>').encode()


class PapersTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.cursor = Path(temp.name) / "paper_queries.sqlite3"
        self.urls = []
        self.payload = feed()

    def fetch(self, url):
        self.urls.append(url)
        return self.payload

    def query(self, ids, **kwargs):
        return fetch_papers(ids, cursor_path=self.cursor, fetcher=self.fetch, **kwargs)

    def queried_ids(self):
        return [urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["search_query"][0].split(" OR ") for url in self.urls]

    def test_contract_and_complete_identifier_boundaries(self):
        entries = [("AI security " + value, "Reference only.", "https://arxiv.org/abs/2401.%05d" % (n + 1))
                   for n, value in enumerate([A, A + "1", "X" + A, A + "_suffix", A + "-extra"])]
        self.payload = feed(entries)
        result, error = self.query([A.lower(), A, None, "not-a-cve"])
        self.assertIsNone(error)
        self.assertIsInstance(result, dict)
        self.assertEqual(list(result), [A])
        self.assertEqual(len(result[A]), 1)
        self.assertEqual(result[A][0]["association"], "explicit_cve_mention")
        self.assertEqual(result[A][0]["content_scope"], "title_and_abstract")
        self.assertEqual(len(result[A][0]["feed_response_sha256"]), 64)

    def test_more_than_twelve_ids_use_all_bounded_batches(self):
        ids = ["CVE-2025-%04d" % n for n in range(1000, 1029)]
        result, error = self.query(ids)
        self.assertIsNone(error)
        self.assertEqual(len(self.urls), 3)
        self.assertEqual({v.removeprefix("all:") for batch in self.queried_ids() for v in batch}, set(ids))
        self.assertTrue(all(len(batch) <= 12 for batch in self.queried_ids()))
        self.assertEqual(result.metadata["deferred_cve_ids"], [])
        self.assertTrue(all(url.startswith("https://export.arxiv.org/") for url in self.urls))

    def test_over_budget_ids_rotate_durably_and_are_not_called_empty_results(self):
        ids = ["CVE-2025-%04d" % n for n in range(1000, 1073)]
        attempted = set()
        for _ in range(4):
            self.urls = []
            result, error = self.query(ids, max_batches=2)
            self.assertEqual(len(self.urls), 2)
            self.assertIn("延后", error)
            self.assertEqual(len(result.metadata["queried_cve_ids"]), 24)
            attempted.update(result.metadata["queried_cve_ids"])
        self.assertEqual(attempted, set(ids))

    def test_new_ids_do_not_reset_rotation_to_the_first_batch(self):
        ids = ["CVE-2025-%04d" % n for n in range(1000, 1030)]
        first, _ = self.query(ids, max_batches=1)
        second, _ = self.query(["CVE-2024-9999"] + ids, max_batches=1)
        self.assertEqual(second.metadata["queried_cve_ids"][0], "CVE-2025-1012")
        self.assertTrue(set(first.metadata["queried_cve_ids"]).isdisjoint(second.metadata["queried_cve_ids"]))

    def test_partial_failure_keeps_successful_batches_and_describes_failed_ids(self):
        ids = ["CVE-2025-%04d" % n for n in range(1000, 1025)]
        def fetch(url):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["search_query"][0]
            if "CVE-2025-1012" in query:
                raise TimeoutError("fixture timeout")
            target = query.split(" OR ")[0].removeprefix("all:")
            return feed([("AI security " + target, "Reference only.", "https://arxiv.org/abs/2401.12345")])
        result, error = fetch_papers(ids, cursor_path=self.cursor, fetcher=fetch)
        self.assertIn("批次 2", error)
        self.assertTrue(result[ids[0]])
        self.assertTrue(result[ids[24]])
        self.assertEqual([row["status"] for row in result.metadata["batches"]], ["ok", "error", "ok"])

    def test_bad_atom_api_error_and_entities_are_failed_queries(self):
        for payload in [b"<html/>", b"broken XML", b'<!DOCTYPE feed [<!ENTITY x "huge">]><feed/>',
                        b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>http://arxiv.org/api/errors#x</id></entry></feed>']:
            with self.subTest(payload=payload):
                self.payload = payload
                result, error = self.query([A])
                self.assertTrue(error)
                self.assertEqual(result.metadata["batches"][0]["status"], "error")
                self.assertEqual(result[A], [])

    def test_only_arxiv_abstract_urls_are_accepted(self):
        self.payload = feed([("AI security " + A, "Reference.", value) for value in
                             ["javascript:alert(1)", "https://evil.example/abs/2401.12345", "https://arxiv.org/abs/2401.12345?redirect=x", "http://arxiv.org/abs/2401.12345"]])
        result, error = self.query([A])
        self.assertIsNone(error)
        self.assertEqual([row["url"] for row in result[A]], ["https://arxiv.org/abs/2401.12345"])

    def test_response_and_results_are_bounded(self):
        self.payload = b"x" * (MAX_BYTES + 1)
        self.assertTrue(self.query([A])[1])
        self.payload = feed([("AI security " + A, "Reference.", "https://arxiv.org/abs/2401.%05d" % (n + 1)) for n in range(30)])
        self.assertEqual(len(self.query([A])[0][A]), 8)
        with patch("urllib.request.urlopen", return_value=BytesIO(b"x" * (MAX_BYTES + 1))):
            with self.assertRaises(ValueError):
                _fetch("https://export.arxiv.org/api/query")

    def test_no_ids_makes_no_query_and_bad_budget_is_rejected(self):
        result, error = self.query([])
        self.assertEqual(result, {})
        self.assertIsNone(error)
        self.assertEqual(self.urls, [])
        for kwargs in [{"max_batches": 0}, {"max_batches": 9}, {"batch_size": 13}, {"batch_size": True}]:
            with self.assertRaises(ValueError):
                self.query([A], **kwargs)

    def test_rotation_connection_is_closed_and_corrupt_state_is_preserved(self):
        self.query([A])
        original = self.cursor.read_bytes()
        self.cursor.write_bytes(b"corrupt SQLite state")
        self.urls = []
        _, error = self.query([A])
        self.assertIn("状态不可用", error)
        self.assertEqual(self.urls, [])
        self.assertEqual(self.cursor.read_bytes(), b"corrupt SQLite state")
        self.assertTrue(original)


if __name__ == "__main__":
    unittest.main()
