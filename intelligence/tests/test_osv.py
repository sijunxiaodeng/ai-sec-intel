import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from collectors.osv import OSVCollector
from fusion.merger import merge_by_cve
from monitoring.multisource import collect_source
from monitoring.source_registry import get_source
from storage.sqlite_store import SQLiteIntelligenceStore
from storage.document_store import SQLiteDocumentStore
from ai_pipeline.documents import run_document_batch
from api_v6.change_repository import ChangeRepository
from api_v6.repository import IntelligenceRepository, current_classifier_version


def advisory(identifier="GHSA-fixture", aliases=None):
    return {"id": identifier, "aliases": aliases or ["CVE-2099-10001"],
            "summary": "vLLM prompt injection fixture", "details": "Synthetic LLM security issue",
            "published": "2026-10-10T01:00:00Z", "modified": "2026-10-10T02:00:00Z",
            "affected": [{"package": {"name": "vllm", "ecosystem": "PyPI"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}],
            "references": [{"url": "https://example.org/advisory"}]}


class OSVTests(unittest.TestCase):
    def collector(self, pages, **kwargs):
        session = Mock()
        session.post.side_effect = [Mock(json=Mock(return_value=p)) if not isinstance(p, Exception) else p for p in pages]
        return OSVCollector(session=session, packages=["vllm"], **kwargs)

    def test_all_pages_and_aliases_preserve_package_facts(self):
        row = advisory(aliases=["CVE-2099-10001", "CVE-2099-10002"])
        c = self.collector([{"vulns": [row], "next_page_token": "next"}, {"vulns": [row]}])
        result = c.collect()
        self.assertEqual({r.cve_id for r in result}, {"CVE-2099-10001", "CVE-2099-10002"})
        self.assertEqual(c.session.post.call_args.kwargs["json"]["page_token"], "next")
        merged = merge_by_cve(result)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0].affected_packages[0]["ranges"], row["affected"][0]["ranges"])
        self.assertIn("https://example.org/advisory", merged[0].references)

    def test_failed_or_incomplete_source_does_not_commit_partial_rows(self):
        for ending in [TimeoutError(), {"next_page_token": "next"}]:
            with self.subTest(ending=ending), tempfile.TemporaryDirectory() as directory:
                c = self.collector([{"vulns": [advisory()], "next_page_token": "next"}, ending])
                db = Path(directory) / "b.db"
                result = collect_source(get_source("OSV"), db, collector=c)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(SQLiteIntelligenceStore(db).stats()["unified_cves"], 0)

    def test_page_limit_and_bad_schema_fail_instead_of_truncating(self):
        for c in [self.collector([{"vulns": [advisory()], "next_page_token": "n"}], max_pages=1),
                  self.collector([{"vulns": {}}])]:
            with self.assertRaises((RuntimeError, ValueError)):
                c.collect()

    def test_explicit_empty_success_and_withdrawn_response(self):
        self.assertEqual(self.collector([{}]).collect(), [])
        row = dict(advisory(), withdrawn="2026-10-10T03:00:00Z")
        with self.assertRaises(ValueError):
            self.collector([{"vulns": [row]}]).collect()

    def test_success_uses_b_store(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "b.db"
            c = self.collector([{"vulns": [advisory()]}])
            self.assertEqual(collect_source(get_source("OSV"), db, collector=c)["status"], "success")
            self.assertEqual(SQLiteIntelligenceStore(db).stats()["unified_cves"], 1)

    def test_non_cve_advisory_classifies_and_enters_document_changefeed(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'b.db'
            row = advisory()
            row['aliases'] = []
            collector = self.collector([{'vulns': [row]}])
            result = collect_source(get_source('OSV'), db, collector=collector)
            self.assertEqual(result['status'], 'success')
            self.assertEqual(SQLiteIntelligenceStore(db).stats()['unified_cves'], 0)
            self.assertEqual(SQLiteDocumentStore(db).stats()['documents'], 1)
            root = Path(__file__).resolve().parents[1]
            version = current_classifier_version(root)
            self.assertEqual(run_document_batch(db, version)['positive'], 1)
            page = ChangeRepository(IntelligenceRepository(db, root=root)).page(kind='document')
            active = [c['item'] for c in page['changes'] if c['operation'] == 'upsert']
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0]['cve_ids'], [])
            self.assertEqual(active[0]['source'], 'OSV')
