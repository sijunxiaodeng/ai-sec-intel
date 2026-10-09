"""Source catalog validation and independent category regression tests."""
import json
import os
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from monitoring.source_registry import (
    SOURCE_CATEGORIES, SourceSpec, get_source, get_sources, source_domains,
)


class SourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {'INTELLIGENCE_SOURCE_CONFIG': ''})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def config(self, payload):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'sources.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def source(self, **overrides):
        payload = {'name': 'CUSTOM_BLOG', 'category': 'security_blog', 'kind': 'feed',
                   'url': 'https://example.org/feed', 'content_type': 'blog_post'}
        payload.update(overrides)
        return payload

    def test_default_catalog_has_all_eight_categories_with_independent_community(self):
        sources = get_sources()
        self.assertEqual(11, len(sources))
        self.assertEqual(SOURCE_CATEGORIES, {source.category for source in sources})
        self.assertEqual('vulnerability_database', get_source('GITHUB_ADVISORY').category)
        community = get_source('HF_SECURITY_COMMUNITY')
        self.assertEqual('discuss.huggingface.co', urlsplit(community.url).hostname)
        self.assertTrue(community.options['query_scoped'])
        self.assertIn('vulnerability', community.options['content_terms'])

    def test_vendor_targets_are_official_repository_advisories(self):
        for name, path in [
                ('VLLM_VENDOR', '/repos/vllm-project/vllm/security-advisories'),
                ('OLLAMA_VENDOR', '/repos/ollama/ollama/security-advisories'),
                ('LANGCHAIN_VENDOR', '/repos/langchain-ai/langchain/security-advisories')]:
            source = get_source(name)
            self.assertEqual('vendor_advisory', source.category)
            self.assertEqual('api.github.com', urlsplit(source.url).hostname)
            self.assertEqual(path, urlsplit(source.url).path)

    def test_arxiv_query_is_security_scoped_with_bounded_page_size(self):
        source = get_source('ARXIV_AI_SECURITY')
        query = parse_qs(urlsplit(source.url).query)
        self.assertIn('prompt injection', query['search_query'][0])
        self.assertIn('large language model', query['search_query'][0])
        self.assertEqual(['submittedDate'], query['sortBy'])
        self.assertEqual(['100'], query['max_results'])

    def test_config_replaces_defaults_and_allows_fewer_than_seven_categories(self):
        path = self.config([self.source()])
        sources = get_sources(path)
        self.assertEqual(['CUSTOM_BLOG'], [source.name for source in sources])
        self.assertEqual({'security_blog'}, {source.category for source in sources})

    def test_environment_config_and_disabled_sources(self):
        path = self.config({'sources': [self.source(), self.source(name='DISABLED', enabled=False)]})
        with patch.dict(os.environ, {'INTELLIGENCE_SOURCE_CONFIG': str(path)}):
            self.assertEqual(['CUSTOM_BLOG'], [source.name for source in get_sources()])
            with self.assertRaises(ValueError):
                get_source('DISABLED')

    def test_empty_custom_catalog_is_not_silently_replaced(self):
        self.assertEqual([], get_sources(self.config([])))

    def test_duplicate_ids_are_rejected_even_when_disabled(self):
        path = self.config([self.source(), self.source(name='custom_blog', enabled=False)])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            get_sources(path)

    def test_unsafe_urls_and_invalid_options_are_rejected(self):
        for overrides in [
            {'url': 'http://example.org/feed'},
            {'url': 'https://user:password@example.org/feed'},
            {'url': 'https://example.org/feed#fragment'},
            {'url': 'https://example.org:invalid/feed'},
            {'url': 'https://example.org/a b'},
            {'options': []}, {'options': {'ai_only': 'true'}},
            {'options': {'content_terms': 'security'}},
            {'options': {'allowed_url_patterns': ['[bad']}},
        ]:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    get_sources(self.config([self.source(**overrides)]))

    def test_unknown_kind_category_name_or_field_is_rejected(self):
        for overrides in [{'kind': 'unknown'}, {'category': 'github'}, {'name': '../source'},
                          {'enabled': 'false'}, {'extra_field': True}]:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    get_sources(self.config([self.source(**overrides)]))

    def test_spec_is_frozen_and_default_options_are_not_shared_between_loads(self):
        source = get_source('HF_SECURITY_COMMUNITY')
        with self.assertRaises(FrozenInstanceError):
            source.category = 'vendor_advisory'
        source.options['content_terms'].clear()
        self.assertIn('security', get_source('HF_SECURITY_COMMUNITY').options['content_terms'])

    def test_domains_are_exact_sorted_unique_and_include_explicit_nist_urls(self):
        sources = [
            SourceSpec('FIRST', 'security_blog', 'feed', 'https://example.org/feed'),
            SourceSpec('SECOND', 'security_blog', 'feed', 'https://example.org/other'),
            SourceSpec('DISABLED', 'security_blog', 'feed', 'https://disabled.example/feed', enabled=False),
            SourceSpec('CUSTOM_NIST', 'technical_standard', 'nist', options={
                'source_urls': ['https://csrc.nist.gov/pubs/ai/100/2/final',
                                'https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2.pdf'],
            }),
        ]
        self.assertEqual(['csrc.nist.gov', 'example.org', 'nvlpubs.nist.gov'], source_domains(sources))
        self.assertNotIn('*', ''.join(source_domains(get_sources())))

    def test_core_default_url_is_used_for_domain_metadata(self):
        self.assertEqual(['api.github.com'], source_domains([
            SourceSpec('CUSTOM_GH', 'vulnerability_database', 'github')]))


if __name__ == '__main__':
    unittest.main()
