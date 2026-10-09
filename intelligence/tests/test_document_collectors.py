"""Offline protocol fixtures for complete, source-backed document ingestion."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collectors.documents import (
    ArxivCollector, FeedCollector, GitHubVendorAdvisoryCollector,
    document_id, is_ai_security_related, source_timestamp,
)


class Response:
    def __init__(self, body=b"", *, status=200, headers=None, next_url=None):
        self.content = body.encode() if isinstance(body, str) else body
        self.status_code = status
        self.headers = headers or {}
        self.links = {"next": {"url": next_url}} if next_url else {}
        self.closed = False

    def iter_content(self, chunk_size):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start:start + chunk_size]

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("fixture HTTP failure")

    def close(self):
        self.closed = True


class Session:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected external request")
        return self.responses.pop(0)


def rss(entries):
    return '<rss version="2.0"><channel><title>Source feed</title>' + ''.join(entries) + '</channel></rss>'


def item(identity="post-1", *, title="AI security and prompt injection", description="A source analysis.",
         link="https://source.test/post-1", dates='<pubDate>Thu, 08 Oct 2026 08:30:00 +0800</pubDate>'):
    return f'<item><guid>{identity}</guid><title>{title}</title><link>{link}</link><description>{description}</description>{dates}</item>'


def atom_entry(identity="paper-1", title="LLM security research", link="https://arxiv.org/abs/2610.00001"):
    return f'''<entry><id>{identity}</id><title>{title}</title>
        <summary>Research on prompt injection and CVE-2026-12345.</summary>
        <link href="{link}" rel="alternate" type="text/html"/>
        <published>2026-10-08T00:30:00Z</published><updated>2026-10-08T01:00:00Z</updated>
    </entry>'''


def atom(entries, *, total=None, start=0, size=100):
    paging = '' if total is None else f'''<op:totalResults>{total}</op:totalResults>
        <op:startIndex>{start}</op:startIndex><op:itemsPerPage>{size}</op:itemsPerPage>'''
    return f'''<feed xmlns="http://www.w3.org/2005/Atom" xmlns:op="http://a9.com/-/spec/opensearch/1.1/">
        <title>AI security papers</title>{paging}{''.join(entries)}</feed>'''


class FeedTests(unittest.TestCase):
    def collector(self, response, **kwargs):
        return FeedCollector("SECURITY_BLOG_TEST", "security_blog", "blog", "https://source.test/feed.xml",
                             session=Session(response), **kwargs)

    def test_rss_preserves_source_text_dates_and_real_cves(self):
        raw = rss([item(description='&lt;p&gt;LLM vulnerability cve-2026-12345, CVE-2026-12345.&lt;/p&gt;')])
        response = Response(raw, headers={"ETag": '"version-1"', "Set-Cookie": "DO_NOT_PERSIST"})
        result = self.collector(response).collect()
        self.assertEqual(result.status, "success")
        self.assertEqual(result.fetched_count, 1)
        doc = result.items[0]
        self.assertEqual(doc.source_category, "security_blog")
        self.assertEqual(doc.published_at, "2026-10-08T00:30:00Z")
        self.assertIsNone(doc.modified_at)
        self.assertEqual(doc.cve_ids, ["CVE-2026-12345"])
        self.assertIn("cve-2026-12345", doc.raw_data["entry_xml"])
        self.assertEqual(result.etag, '"version-1"')
        self.assertNotIn("set-cookie", result.response_headers)
        self.assertTrue(response.closed)

    def test_identity_remains_stable_when_source_title_changes(self):
        first = self.collector(Response(rss([item(title="AI security first")]))).collect().items[0]
        later = self.collector(Response(rss([item(title="AI security revised")]))).collect().items[0]
        self.assertEqual(first.document_id, later.document_id)
        self.assertNotEqual(document_id("SOURCE_A", "same"), document_id("SOURCE_B", "same"))

    def test_no_cve_document_is_not_dropped_or_fabricated(self):
        doc = self.collector(Response(rss([item()]))).collect().items[0]
        self.assertEqual(doc.cve_ids, [])

    def test_missing_and_updated_only_publication_dates_stay_unknown(self):
        for dates in ('', '<updated>2026-10-08T01:00:00Z</updated>'):
            with self.subTest(dates=dates):
                doc = self.collector(Response(rss([item(dates=dates)]))).collect().items[0]
                self.assertIsNone(doc.published_at)
        self.assertEqual(source_timestamp("2026-10-08"), "2026-10-08")
        self.assertIsNone(source_timestamp("2026-10-08T01:00:00"))
        with self.assertRaises(ValueError):
            source_timestamp("not a date")

    def test_atom_uses_distinct_published_and_updated_dates(self):
        doc = self.collector(Response(atom([atom_entry()]))).collect().items[0]
        self.assertEqual(doc.published_at, "2026-10-08T00:30:00Z")
        self.assertEqual(doc.modified_at, "2026-10-08T01:00:00Z")
        self.assertIn("entry_xml", doc.raw_data)

    def test_ai_filter_requires_actual_ai_and_security_terms(self):
        entries = [item("1"), item("2", title="Ordinary router security", description="A firmware patch"),
                   item("3", title="AI image feature", description="A colorful image"),
                   item("4", title="Arrays are available", description="Firmware vulnerability")]
        result = self.collector(Response(rss(entries)), ai_only=True).collect()
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.filtered_count, 3)
        self.assertEqual(result.fetched_count, 4)
        self.assertTrue(is_ai_security_related("基于人工智能的隐私风险评估"))
        self.assertFalse(is_ai_security_related("available firmware security"))
        self.assertFalse(is_ai_security_related("Power transformers firmware security vulnerability"))

    def test_query_scoped_feed_can_keep_relevant_standard_with_no_generic_keyword(self):
        result = self.collector(Response(rss([item(title="Trustworthy systems", description="A technical publication")])) ,
                                ai_only=True, query_scoped=True).collect()
        self.assertEqual(len(result.items), 1)

    def test_standard_filters_exclude_news_even_when_ai_security_related(self):
        entries = [item("1", link="https://source.test/pubs/ai-security-standard"),
                   item("2", link="https://source.test/news/ai-security-workshop")]
        result = self.collector(Response(rss(entries)), allowed_url_patterns=[r"/pubs/"],
                                content_terms=["security"]).collect()
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.filtered_count, 1)

    def test_conditional_get_returns_not_modified_without_parsing_a_body(self):
        response = Response(status=304, headers={"ETag": '"v2"'})
        collector = self.collector(response)
        result = collector.collect(etag='"v1"', last_modified="Thu, 08 Oct 2026 00:00:00 GMT")
        headers = collector.session.calls[0][1]["headers"]
        self.assertEqual(headers["If-None-Match"], '"v1"')
        self.assertIn("If-Modified-Since", headers)
        self.assertEqual(result.status, "not_modified")
        self.assertEqual(result.items, [])
        self.assertTrue(response.closed)

    def test_relative_links_resolve_only_against_known_https_source_hosts(self):
        doc = self.collector(Response(rss([item(link="/post-1")]))).collect().items[0]
        self.assertEqual(doc.url, "https://source.test/post-1")
        for url in ("javascript:alert(1)", "//unknown.test/post", "http://unknown.test/post", "https://user:password@source.test/post"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.collector(Response(rss([item(link=url)]))).collect()

    def test_malformed_empty_and_nonfeed_responses_cannot_report_success(self):
        for body in (b"", b"<html>error</html>", b"<rss><channel>", b"<rss/>", b"<feed/>"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.collector(Response(body)).collect()

    def test_dtd_and_entity_expansion_are_rejected_even_in_utf16(self):
        xml = '<!DOCTYPE rss [<!ENTITY unsafe "AI security">]>' + rss([item(title="&unsafe;")])
        for body in (xml.encode(), xml.encode("utf-16")):
            with self.subTest(encoding=body[:2]), self.assertRaises(ValueError):
                self.collector(Response(body)).collect()

    def test_caps_fail_instead_of_silently_dropping_source_documents(self):
        for response, limits in ((Response(rss([item()])), {"max_bytes": 20}),
                                 (Response(rss([item("1"), item("2")])), {"max_items": 1})):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.collector(response, **limits).collect()
            self.assertTrue(response.closed)

    def test_unhandled_opensearch_pagination_is_not_a_success(self):
        with self.assertRaises(ValueError):
            self.collector(Response(atom([atom_entry()], total=2, start=0, size=1))).collect()


class ArxivTests(unittest.TestCase):
    def setUp(self):
        sleeper = patch("collectors.documents.time.sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)

    url = "https://export.arxiv.org/api/query?search_query=all:LLM+AND+all:security&max_results=1"

    def collector(self, *responses, **kwargs):
        return ArxivCollector("ARXIV_AI_SECURITY", "academic_paper", "paper", self.url,
                              session=Session(*responses), **kwargs)

    def test_collects_and_verifies_all_pages_without_inventing_publication_time(self):
        first = Response(atom([atom_entry("paper-1")], total=2, start=0, size=1))
        last = Response(atom([atom_entry("paper-2", link="http://arxiv.org/abs/2610.00002")], total=2, start=1, size=1))
        collector = self.collector(first, last)
        result = collector.collect()
        self.assertEqual(len(result.items), 2)
        self.assertEqual(result.fetched_count, 2)
        self.assertEqual([parse_qs(urlsplit(url).query)["start"][0] for url, _ in collector.session.calls], ["0", "1"])
        self.assertEqual(result.items[1].url, "https://arxiv.org/abs/2610.00002")
        self.assertIsNone(result.etag)
        self.assertTrue(first.closed and last.closed)

    def test_missing_or_changing_metadata_and_incomplete_pages_fail(self):
        scenarios = [
            [Response(atom([atom_entry()]))],
            [Response(atom([atom_entry()], total=2, start=1, size=1))],
            [Response(atom([], total=2, start=0, size=1))],
            [Response(atom([atom_entry()], total=2, start=0, size=1)), Response(atom([atom_entry("2")], total=3, start=1, size=1))],
            [Response(atom([atom_entry()], total=2, start=0, size=1)), Response(atom([atom_entry()], total=2, start=1, size=1))],
        ]
        for responses in scenarios:
            with self.subTest(pages=len(responses)), self.assertRaises(ValueError):
                self.collector(*responses).collect()

    def test_item_and_page_caps_do_not_produce_a_partial_success(self):
        with self.assertRaises(ValueError):
            self.collector(Response(atom([atom_entry()], total=2, start=0, size=1)), max_items=1).collect()
        with self.assertRaises(ValueError):
            self.collector(Response(atom([atom_entry()], total=2, start=0, size=1)), max_pages=1).collect()


class VendorTests(unittest.TestCase):
    url = "https://api.github.com/repos/example/ai-project/security-advisories"

    def advisory(self, ghsa="GHSA-aaaa-bbbb-cccc"):
        return {"ghsa_id": ghsa, "summary": "LLM vulnerability", "description": "Model loader security issue",
                "html_url": "https://github.com/example/ai-project/security/advisories/" + ghsa,
                "published_at": "2026-10-08T00:30:00Z", "updated_at": "2026-10-08T01:00:00Z",
                "cve_id": "CVE-2026-12345"}

    def collector(self, *responses, **kwargs):
        return GitHubVendorAdvisoryCollector("AI_VENDOR_TEST", "vendor_advisory", "advisory", self.url,
                                             session=Session(*responses), **kwargs)

    def test_vendor_advisory_has_distinct_source_category_and_raw_record(self):
        raw = self.advisory()
        result = self.collector(Response(json.dumps([raw]), headers={"ETag": '"vendor-v1"'})).collect()
        self.assertEqual(result.items[0].source_category, "vendor_advisory")
        self.assertEqual(result.items[0].cve_ids, ["CVE-2026-12345"])
        self.assertEqual(result.items[0].raw_data["advisory"], raw)
        self.assertEqual(result.etag, '"vendor-v1"')

    def test_vendor_pagination_collects_every_page_and_does_not_cache_only_page_one(self):
        result = self.collector(
            Response(json.dumps([self.advisory()]), next_url=self.url + "?page=2&per_page=100", headers={"ETag": '"page-1"'}),
            Response(json.dumps([self.advisory("GHSA-dddd-eeee-ffff")])),
        ).collect()
        self.assertEqual(result.fetched_count, 2)
        self.assertEqual(len(result.items), 2)
        self.assertIsNone(result.etag)

    def test_vendor_never_forwards_authentication_to_foreign_pagination_url(self):
        collector = self.collector(Response(json.dumps([self.advisory()]), next_url="https://unknown.test/advisories"),
                                   token="TEST_TOKEN")
        with self.assertRaises(ValueError):
            collector.collect()
        self.assertEqual(len(collector.session.calls), 1)

    def test_vendor_malformed_or_incomplete_payloads_cannot_succeed(self):
        for response in (Response('{"message":"rate limited"}'), Response('['), Response('[{}]'),
                         Response('[]', next_url=self.url + "?page=2")):
            with self.subTest(response=response.content), self.assertRaises(ValueError):
                self.collector(response).collect()


if __name__ == "__main__":
    unittest.main()
