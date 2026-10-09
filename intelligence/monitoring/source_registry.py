"""Configured source types, independent of observed coverage or live validation.

An endpoint in this catalog is a collection target, not evidence that its
category was collected. Runtime coverage must use persisted source documents.
"""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlencode, urlsplit


SOURCE_CATEGORIES = frozenset({
    'vulnerability_database', 'security_community', 'vendor_advisory',
    'security_blog', 'academic_paper', 'technical_standard',
    'policy_regulation', 'government_alert',
})
SUPPORTED_KINDS = frozenset({
    'nvd', 'github', 'cisa', 'feed', 'arxiv', 'github_vendor',
    'nist', 'federal_register',
})
_SOURCE_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}')


def _https_host(value: str) -> str:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ValueError('Source URL must be a nonempty HTTPS URL')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        parsed.port  # Reject invalid ports rather than deferring to requests.
    except ValueError as error:
        raise ValueError('Source URL has an invalid host or port') from error
    if (parsed.scheme != 'https' or not host or parsed.username is not None
            or parsed.password is not None or '#' in value):
        raise ValueError('Source URL must use HTTPS without credentials or fragments')
    return host.lower()


@dataclass(frozen=True)
class SourceSpec:
    name: str
    category: str
    kind: str
    url: str | None = None
    content_type: str | None = None
    options: dict = field(default_factory=dict)
    enabled: bool = True

    def __post_init__(self):
        if not isinstance(self.name, str) or not _SOURCE_NAME.fullmatch(self.name):
            raise ValueError('Source name must be 1-64 ASCII letters, digits, underscores or hyphens, starting with a letter')
        if not isinstance(self.category, str) or self.category not in SOURCE_CATEGORIES:
            raise ValueError('Unsupported source category')
        if not isinstance(self.kind, str) or self.kind not in SUPPORTED_KINDS:
            raise ValueError('Unsupported source adapter kind')
        if self.url is not None:
            _https_host(self.url)
        if self.content_type is not None and (
                not isinstance(self.content_type, str) or not self.content_type.strip()):
            raise ValueError('content_type must be a nonempty string or None')
        if not isinstance(self.options, dict):
            raise ValueError('Source options must be a dictionary')
        if not isinstance(self.enabled, bool):
            raise ValueError('Source enabled must be a boolean')
        if self.kind in {'feed', 'arxiv', 'github_vendor', 'federal_register'} and self.url is None:
            raise ValueError('This source adapter requires a URL')
        source_urls = self.options.get('source_urls')
        if source_urls is not None:
            if not isinstance(source_urls, list) or not source_urls:
                raise ValueError('source_urls must be a nonempty list of HTTPS URLs')
            for endpoint in source_urls:
                _https_host(endpoint)
        if self.kind == 'nist' and self.url is not None and source_urls is not None:
            raise ValueError('NIST sources accept either url or source_urls')
        for key in ('ai_only', 'query_scoped'):
            if key in self.options and not isinstance(self.options[key], bool):
                raise ValueError(f'{key} must be a boolean')
        for key in ('content_terms', 'allowed_url_patterns', 'allowed_link_hosts'):
            if key in self.options and (
                    not isinstance(self.options[key], list)
                    or any(not isinstance(value, str) or not value.strip()
                           for value in self.options[key])):
                raise ValueError(f'{key} must be a list of nonempty strings')
        for pattern in self.options.get('allowed_url_patterns', []):
            try:
                re.compile(pattern)
            except re.error as error:
                raise ValueError('Invalid allowed_url_patterns regular expression') from error


_ARXIV_QUERY = (
    'all:"prompt injection" OR '
    '((all:"large language model" OR all:"LLM" OR all:"artificial intelligence" '
    'OR all:"machine learning" OR all:"AI agent") AND '
    '(all:"security" OR all:"adversarial" OR all:"jailbreak" OR all:"poisoning"))'
)
_SECURITY_TERMS = [
    'security', 'vulnerability', 'vulnerabilities', 'CVE', 'exploit', 'RCE',
    'prompt injection', 'jailbreak', 'poisoning', 'backdoor', 'malicious',
    'data leakage', 'prompt leakage', 'privacy',
]
_DEFAULT_SOURCES = (
    SourceSpec('NVD', 'vulnerability_database', 'nvd',
               'https://services.nvd.nist.gov/rest/json/cves/2.0', 'vulnerability'),
    # The global advisory database is not an independent community/vendor source.
    SourceSpec('GITHUB_ADVISORY', 'vulnerability_database', 'github',
               'https://api.github.com/advisories', 'vulnerability'),
    SourceSpec('CISA_KEV', 'government_alert', 'cisa',
               'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
               'government_alert'),
    SourceSpec('HF_SECURITY_COMMUNITY', 'security_community', 'feed',
               'https://discuss.huggingface.co/latest.rss', 'community_post', options={
                   'ai_only': True, 'query_scoped': True,
                   'content_terms': _SECURITY_TERMS,
                   'allowed_url_patterns': [r'^https://discuss\.huggingface\.co/t/'],
                   'allowed_link_hosts': ['discuss.huggingface.co'],
               }),
    SourceSpec('VLLM_VENDOR', 'vendor_advisory', 'github_vendor',
               'https://api.github.com/repos/vllm-project/vllm/security-advisories',
               'advisory', options={'query_scoped': True}),
    SourceSpec('OLLAMA_VENDOR', 'vendor_advisory', 'github_vendor',
               'https://api.github.com/repos/ollama/ollama/security-advisories',
               'advisory', options={'query_scoped': True}),
    SourceSpec('LANGCHAIN_VENDOR', 'vendor_advisory', 'github_vendor',
               'https://api.github.com/repos/langchain-ai/langchain/security-advisories',
               'advisory', options={'query_scoped': True}),
    SourceSpec('TRAIL_OF_BITS_BLOG', 'security_blog', 'feed',
               'https://blog.trailofbits.com/feed/', 'blog_post', options={
                   'ai_only': True,
                   'allowed_url_patterns': [r'^https://blog\.trailofbits\.com/'],
                   'allowed_link_hosts': ['blog.trailofbits.com', 'trailofbits.com'],
               }),
    SourceSpec('ARXIV_AI_SECURITY', 'academic_paper', 'arxiv',
               'https://export.arxiv.org/api/query?' + urlencode({
                   'search_query': _ARXIV_QUERY, 'sortBy': 'submittedDate',
                   'sortOrder': 'descending', 'start': 0, 'max_results': 100,
               }), 'paper', options={'query_scoped': True}),
    # AI-scoped discovery of formal publications. No guessed RSS endpoint.
    SourceSpec('NIST_CSRC_AI_STANDARDS', 'technical_standard', 'nist',
               'https://csrc.nist.gov/publications/search?keywords=artificial%20intelligence',
               'standard', options={'max_pages': 10, 'max_links': 100}),
    SourceSpec('FEDERAL_REGISTER_AI_POLICY', 'policy_regulation', 'federal_register',
               'https://www.federalregister.gov/api/v1/documents.json',
               'policy', options={'max_pages': 20, 'per_page': 100}),
)


def get_sources(config_path: str | Path | None = None) -> list[SourceSpec]:
    """Return enabled sources, replacing defaults when a JSON config is supplied.

    Custom catalogs may intentionally have fewer categories. Do not convert
    configured categories into a claim of observed seven-category coverage.
    """
    if config_path is None:
        configured = os.getenv('INTELLIGENCE_SOURCE_CONFIG', '').strip()
        config_path = configured or None
    if config_path is None:
        return copy.deepcopy([source for source in _DEFAULT_SOURCES if source.enabled])
    path = Path(config_path)
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except OSError as error:
        raise ValueError(f'Cannot read intelligence source configuration: {path}') from error
    except (ValueError, UnicodeError) as error:
        raise ValueError('Intelligence source configuration is not valid UTF-8 JSON') from error
    if isinstance(payload, dict) and set(payload) == {'sources'}:
        payload = payload['sources']
    if not isinstance(payload, list):
        raise ValueError('Intelligence source configuration must contain a list of source specs')
    sources, seen = [], set()
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError('Each configured source must be an object')
        try:
            source = SourceSpec(**entry)
        except TypeError as error:
            raise ValueError('Configured source is missing required fields or has unknown fields') from error
        identity = source.name.casefold()
        if identity in seen:
            raise ValueError(f'Duplicate configured source name: {source.name}')
        seen.add(identity)
        if source.enabled:
            sources.append(source)
    return sources


def get_source(name: str, config_path: str | Path | None = None) -> SourceSpec:
    for source in get_sources(config_path):
        if source.name == name:
            return source
    raise ValueError(f'Unknown or disabled intelligence source: {name}')


def source_domains(sources: Iterable[SourceSpec]) -> list[str]:
    """Exact endpoint hosts needed for egress configuration; no wildcards."""
    domains = set()
    default_urls = {source.kind: source.url for source in _DEFAULT_SOURCES
                    if source.kind in {'nvd', 'github', 'cisa', 'nist'}}
    for source in sources:
        if not source.enabled:
            continue
        explicit_urls = source.options.get('source_urls') or []
        url = source.url or (default_urls.get(source.kind) if not explicit_urls else None)
        if url:
            domains.add(_https_host(url))
        if source.kind == 'cisa':
            domains.add('raw.githubusercontent.com')
        for endpoint in explicit_urls:
            domains.add(_https_host(endpoint))
    return sorted(domains)
