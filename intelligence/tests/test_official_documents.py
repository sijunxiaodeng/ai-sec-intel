"""Official source format checks; fixtures do not claim live endpoint availability."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collectors.official_documents import FederalRegisterPolicyCollector, NISTStandardCollector


class Response:
    def __init__(self, document=None, *, text='', headers=None, status=200, url=None):
        self.document = document
        self.text = text
        self.headers = headers or {}
        self.status_code = status
        self.url = url

    def json(self):
        return self.document

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'HTTP {self.status_code}')

    def close(self):
        pass


def session_for(*responses):
    return Mock(get=Mock(side_effect=responses))


def policy(identifier='2026-10001', **overrides):
    return {'document_number': identifier,
            'title': 'Safe and Trustworthy Artificial Intelligence',
            'abstract': 'Requirements for artificial intelligence governance and risk assessment.',
            'publication_date': '2026-10-01',
            'html_url': f'https://www.federalregister.gov/documents/2026/10/01/{identifier}/ai',
            'type': 'Presidential Document', **overrides}


def policy_page(rows, *, count=None, total_pages=1, next_url=None):
    return Response({'count': len(rows) if count is None else count,
                     'total_pages': total_pages, 'results': rows, 'next_page_url': next_url})


INDEX = 'https://csrc.nist.gov/projects/artificial-intelligence'
FORMAL = 'https://csrc.nist.gov/pubs/ai/100/1/final'
FORMAL2 = 'https://csrc.nist.gov/pubs/sp/800/218/a/final'


def index(*urls, extra=''):
    return Response(text='<main>' + ''.join(f'<a href="{url}">Publication</a>' for url in urls)
                    + extra + '</main>')


def detail(*, date='August 14, 2025', metadata='', title='Artificial Intelligence Risk Management Framework',
           abstract='Trustworthy AI guidance for managing model safety and security risks.', extra='', url=None):
    return Response(text=f'<html><head>{metadata}</head><body><main><h1>{title}</h1>'
                    f'<div id="pubs-abstract"><h4>Abstract</h4><p>{abstract}</p></div>'
                    f'<h4>Publication Date:</h4><p>{date}</p>{extra}</main></body></html>', url=url)


class FederalRegisterTests(unittest.TestCase):
    def test_official_extensionless_json_next_page_is_accepted_but_html_is_rejected(self):
        url = 'https://www.federalregister.gov/api/v1/documents?format=json&page=2'
        session = session_for(policy_page([policy()], count=2, total_pages=2, next_url=url),
                              policy_page([policy('2026-10002')], count=2, total_pages=2))
        self.assertEqual(len(FederalRegisterPolicyCollector(session=session).collect().items), 2)
        self.assertEqual(session.get.call_args.args[0], url)
        with self.assertRaisesRegex(RuntimeError, 'official source URL'):
            FederalRegisterPolicyCollector(session=session_for(policy_page(
                [policy()], count=2, total_pages=2,
                next_url='https://www.federalregister.gov/api/v1/documents?page=2'))).collect()

    def test_policy_preserves_day_only_date_original_json_and_no_cve(self):
        original = policy()
        result = FederalRegisterPolicyCollector(session=session_for(policy_page([original]))).collect()
        self.assertEqual('success', result.status)
        self.assertEqual(1, result.fetched_count)
        item = result.items[0]
        self.assertEqual('policy_regulation', item.source_category)
        self.assertEqual('2026-10-01', item.published_at)
        self.assertEqual([], item.cve_ids)
        self.assertEqual(original['html_url'], item.url)
        self.assertEqual(original, item.raw_data['document'])
        self.assertEqual('day', item.raw_data['publication_precision'])
        self.assertIsNone(item.modified_at)

    def test_reads_all_pages_preserves_first_headers_and_drops_next_page_params(self):
        next_url = 'https://www.federalregister.gov/api/v1/documents.json?page=2'
        first = policy_page([policy()], count=2, total_pages=2, next_url=next_url)
        first.headers = {'ETag': 'page-one', 'Last-Modified': 'Wed, 01 Oct 2026 00:00:00 GMT'}
        second = policy_page([policy('2026-10002')], count=2, total_pages=2)
        session = session_for(first, second)
        result = FederalRegisterPolicyCollector(session=session).collect(etag='old', last_modified='previous')
        self.assertEqual(2, len(result.items))
        self.assertEqual('page-one', result.etag)
        first_call, second_call = session.get.call_args_list
        self.assertEqual('artificial intelligence', first_call.kwargs['params']['conditions[term]'])
        self.assertEqual('old', first_call.kwargs['headers']['If-None-Match'])
        self.assertEqual(next_url, second_call.args[0])
        self.assertIsNone(second_call.kwargs['params'])
        self.assertNotIn('If-None-Match', second_call.kwargs['headers'])

    def test_not_modified_is_explicit_and_retains_response_headers(self):
        session = session_for(Response(status=304, headers={'ETag': 'unchanged'}))
        result = FederalRegisterPolicyCollector(session=session).collect(etag='unchanged')
        self.assertEqual('not_modified', result.status)
        self.assertEqual([], result.items)
        self.assertEqual('unchanged', result.etag)

    def test_generic_ai_funding_is_filtered_but_ai_privacy_policy_is_collected(self):
        generic = policy('2026-10002', title='Artificial Intelligence Research Grants',
                         abstract='Funding for artificial intelligence research and development.')
        private = policy('2026-10003', title='Machine Learning and Consumer Privacy',
                         abstract='Privacy safeguards and AI transparency requirements.')
        result = FederalRegisterPolicyCollector(session=session_for(policy_page([generic, private]))).collect()
        self.assertEqual(2, result.fetched_count)
        self.assertEqual(1, result.filtered_count)
        self.assertEqual([private['html_url']], [item.url for item in result.items])

    def test_unsafe_next_urls_are_not_requested(self):
        for next_url in ['http://www.federalregister.gov/api/v1/documents.json?page=2',
                         'https://evil.example/api/v1/documents.json?page=2',
                         'https://www.federalregister.gov/other?page=2',
                         'https://www.federalregister.gov/api/v1/documents.json?page=2#fragment']:
            with self.subTest(url=next_url):
                session = session_for(policy_page([policy()], count=2, total_pages=2, next_url=next_url))
                with self.assertRaisesRegex(RuntimeError, 'official source URL'):
                    FederalRegisterPolicyCollector(session=session).collect()
                self.assertEqual(1, session.get.call_count)

    def test_max_pages_does_not_succeed_with_partial_documents(self):
        session = session_for(policy_page([policy()], count=2, total_pages=2,
                                         next_url=FederalRegisterPolicyCollector.BASE_URL + '?page=2'))
        with self.assertRaisesRegex(RuntimeError, 'max_pages'):
            FederalRegisterPolicyCollector(session=session, max_pages=1).collect()

    def test_missing_page_and_changing_total_fail_completeness(self):
        with self.assertRaisesRegex(RuntimeError, 'before all documents'):
            FederalRegisterPolicyCollector(session=session_for(
                policy_page([policy()], count=2, total_pages=2))).collect()
        with self.assertRaisesRegex(RuntimeError, 'count changed'):
            FederalRegisterPolicyCollector(session=session_for(
                policy_page([policy()], count=2, total_pages=2,
                            next_url=FederalRegisterPolicyCollector.BASE_URL + '?page=2'),
                policy_page([policy('2026-10002')], count=3, total_pages=2))).collect()

    def test_duplicate_document_numbers_fail_instead_of_hiding_incomplete_pages(self):
        with self.assertRaisesRegex(RuntimeError, 'repeated a document'):
            FederalRegisterPolicyCollector(session=session_for(policy_page([policy(), policy()]))).collect()

    def test_invalid_publication_date_is_not_replaced_with_response_date(self):
        for value in ['2026-02-30', 'October 2026', None, '2026-10-01T01:00:00Z']:
            with self.subTest(date=value), self.assertRaisesRegex(ValueError, 'publication_date'):
                FederalRegisterPolicyCollector(session=session_for(
                    policy_page([policy(publication_date=value)]))).collect()

    def test_missing_pagination_and_empty_intermediate_pages_fail(self):
        with self.assertRaisesRegex(ValueError, 'pagination count'):
            FederalRegisterPolicyCollector(session=session_for(Response({'results': []}))).collect()
        with self.assertRaisesRegex(RuntimeError, 'empty page'):
            FederalRegisterPolicyCollector(session=session_for(policy_page(
                [], count=2, total_pages=2,
                next_url=FederalRegisterPolicyCollector.BASE_URL + '?page=2'))).collect()

    def test_api_redirect_outside_official_origin_is_rejected(self):
        response = policy_page([policy()])
        response.url = 'https://evil.example/api/v1/documents.json'
        with self.assertRaisesRegex(RuntimeError, 'official source URL'):
            FederalRegisterPolicyCollector(session=session_for(response)).collect()


class NISTStandardTests(unittest.TestCase):
    def collector(self, *responses, **kwargs):
        return NISTStandardCollector(url=INDEX, session=session_for(*responses), **kwargs)

    def test_discovers_actual_formal_standards_and_preserves_original_html(self):
        publication = detail()
        result = self.collector(index(FORMAL, 'https://csrc.nist.gov/news/2026/ai-risks'), publication).collect()
        self.assertEqual(1, len(result.items))
        self.assertEqual(1, result.fetched_count)
        item = result.items[0]
        self.assertEqual('technical_standard', item.source_category)
        self.assertEqual(FORMAL, item.url)
        self.assertEqual('2025-08-14', item.published_at)
        self.assertEqual([], item.cve_ids)
        self.assertEqual(publication.text, item.raw_data['html'])
        self.assertEqual('day', item.raw_data['publication_precision'])
        self.assertEqual(INDEX, item.raw_data['discovery']['index_url'])

    def test_month_only_dates_and_modified_metadata_do_not_invent_publication(self):
        result = self.collector(index(FORMAL), detail(date='August 2025', metadata=(
            '<meta name="dcterms.modified" content="2026-10-01">'
            '<meta name="dateModified" content="2026-10-02T01:00:00Z">'))).collect()
        item = result.items[0]
        self.assertIsNone(item.published_at)
        self.assertIsNone(item.modified_at)
        self.assertEqual('month', item.raw_data['publication_precision'])
        self.assertEqual('August 2025', item.raw_data['publication_date_evidence']['value'])

    def test_exact_published_metadata_has_precedence_and_keeps_timezone(self):
        result = self.collector(index(FORMAL), detail(date='August 2025', metadata=(
            '<meta name="citation_publication_date" content="2025-08-14T09:25:00-04:00">'
            '<meta name="dcterms.modified" content="2026-10-01T01:00:00Z">'))).collect()
        item = result.items[0]
        self.assertEqual('2025-08-14T09:25:00-04:00', item.published_at)
        self.assertEqual('timestamp', item.raw_data['publication_precision'])

    def test_unknown_or_naive_dates_remain_unknown(self):
        for metadata in ['<meta name="Last-Modified" content="2026-10-01T01:00:00Z">',
                         '<meta name="citation_publication_date" content="2026-10-01T01:00:00">']:
            with self.subTest(metadata=metadata):
                response = Response(text='<head>' + metadata + '</head><main>'
                    '<h1>AI risk management</h1><p>Last Modified: October 1, 2026</p></main>')
                item = self.collector(index(FORMAL), response).collect().items[0]
                self.assertIsNone(item.published_at)

    def test_h1_identifier_and_publication_subtitle_are_combined(self):
        response = Response(text='<main><h1 id="pub-title">NIST SP 800-218A</h1>'
            '<h2 id="pub-subtitle">Secure Software Development Practices for Generative AI</h2>'
            '<div id="pubs-abstract">AI security risk management guidance.</div>'
            '<h4>Publication Date:</h4><p>July 26, 2024</p></main>')
        item = self.collector(index(FORMAL2), response).collect().items[0]
        self.assertIn('NIST SP 800-218A:', item.title)
        self.assertIn('Generative AI', item.title)
        self.assertEqual('2024-07-26', item.published_at)

    def test_generic_non_ai_standard_is_not_counted_by_navigation_words(self):
        publication = detail(title='General System Controls', abstract='Cybersecurity system controls.',
            extra='<nav>Artificial Intelligence</nav>')
        result = self.collector(index(FORMAL), publication).collect()
        self.assertEqual([], result.items)
        self.assertEqual(1, result.filtered_count)

    def test_duplicate_discovery_links_are_fetched_once(self):
        collector = self.collector(index(FORMAL, FORMAL + '#abstract', FORMAL + '/'), detail())
        result = collector.collect()
        self.assertEqual(1, len(result.items))
        self.assertEqual(2, collector.session.get.call_count)

    def test_formal_types_allow_guidelines_and_exclude_external_and_pdf_links(self):
        allowed = ['https://csrc.nist.gov/pubs/sp/800/218/a/final',
                   'https://csrc.nist.gov/pubs/ir/8269/final',
                   'https://csrc.nist.gov/pubs/fips/204/final',
                   'https://csrc.nist.gov/pubs/cswp/29/final', FORMAL]
        excluded = ['https://csrc.nist.gov/news/2025/ai-framework',
                    'https://evil.example/pubs/ai/100/1/final',
                    'http://csrc.nist.gov/pubs/ai/100/1/final',
                    'https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf',
                    FORMAL + '?format=pdf']
        collector = self.collector(index(*(allowed + excluded)), *[detail() for _ in allowed])
        result = collector.collect()
        self.assertEqual(5, len(result.items))
        self.assertEqual(6, collector.session.get.call_count)

    def test_index_next_page_is_followed_and_budget_exhaustion_fails(self):
        next_url = INDEX + '?page=2'
        first = index(FORMAL, extra=f'<a href="{next_url}" aria-label="Next page">Next</a>')
        collector = self.collector(first, index(FORMAL2), detail(), detail())
        self.assertEqual(2, len(collector.collect().items))
        self.assertEqual(next_url, collector.session.get.call_args_list[1].args[0])
        with self.assertRaisesRegex(RuntimeError, 'max_pages'):
            self.collector(first, max_pages=1).collect()

    def test_next_links_in_navigation_or_html_head_are_not_silently_dropped(self):
        next_url = INDEX + '?page=2'
        for pagination in [f'<nav><a href="{next_url}">Next</a></nav>',
                           f'<link rel="next" href="{next_url}">']:
            with self.subTest(pagination=pagination):
                collector = self.collector(index(FORMAL, extra=pagination), index(FORMAL2), detail(), detail())
                self.assertEqual(2, len(collector.collect().items))
                self.assertEqual(next_url, collector.session.get.call_args_list[1].args[0])

    def test_legacy_abstract_heading_and_slash_date_metadata_are_supported(self):
        response = Response(text='<head><meta name="citation_publication_date" content="2025/08/14"></head>'
            '<main><h1>Artificial Intelligence Framework</h1><h4>Abstract</h4>'
            '<p>Security risk management for machine learning models.</p><h4>Keywords</h4>'
            '<p>model guidelines</p></main>')
        item = self.collector(index(FORMAL), response).collect().items[0]
        self.assertEqual('2025-08-14', item.published_at)
        self.assertEqual('Security risk management for machine learning models.', item.description)

    def test_link_budget_exhaustion_does_not_return_a_subset(self):
        collector = self.collector(index(FORMAL, FORMAL2), max_links=1)
        with self.assertRaisesRegex(RuntimeError, 'max_links'):
            collector.collect()
        self.assertEqual(1, collector.session.get.call_count)

    def test_unsafe_discovery_next_url_and_detail_redirect_are_rejected(self):
        for next_url in ['https://evil.example/?page=2', INDEX.replace('https:', 'http:') + '?page=2',
                         'https://csrc.nist.gov/news?page=2']:
            with self.subTest(next_url=next_url), self.assertRaisesRegex(RuntimeError, 'official source URL'):
                self.collector(index(extra=f'<a rel="next" href="{next_url}">Next</a>')).collect()
        with self.assertRaisesRegex(RuntimeError, 'redirected outside'):
            self.collector(index(FORMAL), detail(url='https://evil.example/pubs/ai/100/1/final')).collect()

    def test_no_conditional_validators_for_multi_page_publication_discovery(self):
        collector = self.collector(index(FORMAL), detail())
        result = collector.collect(etag='index-only', last_modified='old-index')
        self.assertIsNone(result.etag)
        self.assertIsNone(result.last_modified)
        for call in collector.session.get.call_args_list:
            self.assertNotIn('If-None-Match', call.kwargs['headers'])
            self.assertNotIn('If-Modified-Since', call.kwargs['headers'])


if __name__ == '__main__':
    unittest.main()
