"""Official AI policy and formal NIST publication collectors.

Discovery and publication dates are separate evidence: an HTTP Last-Modified
header or a web page's modification date never becomes a publication date.
These endpoints require live validation in a network-enabled deployment.
"""
from __future__ import annotations

import re
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

import requests

from collectors.documents import CollectionResult, KnowledgeDocument, make_document_id
from collectors.http import _get


_AI = re.compile(
    r"\b(?:artificial intelligence|machine learning|deep learning|generative ai|"
    r"large language models?|foundation models?|neural networks?|llms?|ai)\b", re.I
)
_SECURITY = re.compile(
    r"\b(?:security|cybersecurity|safety|safe|risk|risks|governance|privacy|"
    r"trustworthy|responsible|adversarial|robustness|accountability|transparency|"
    r"bias|discrimination|rights|model evaluation|model testing)\b", re.I
)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_HEADERS = {'User-Agent': 'AI-Security-Intelligence-System/official-documents',
            'Accept': 'application/json, text/html;q=0.9'}
_FORMAL_PATH = re.compile(r'^/pubs/(?:sp|ir|fips|cswp|ai)/[a-zA-Z0-9/_\-.]+/?$')


def _positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f'{name} must be a positive integer')
    return value


def _date_evidence(value):
    """Return a truthful ISO date/timestamp and precision; leave month dates unknown."""
    if not isinstance(value, str) or not value.strip():
        return None, 'unknown'
    value = value.strip()
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        try:
            return datetime.strptime(value, '%Y-%m-%d').date().isoformat(), 'day'
        except ValueError:
            return None, 'unknown'
    if re.match(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', value):
        try:
            stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if stamp.tzinfo is not None and stamp.utcoffset() is not None:
                return stamp.isoformat(), 'timestamp'
        except ValueError:
            pass
        return None, 'unknown'
    # An explicitly named day is precise enough; never assign the first of a month.
    for pattern in ('%B %d, %Y', '%b %d, %Y', '%B %d %Y', '%b %d %Y', '%Y/%m/%d'):
        try:
            return datetime.strptime(value, pattern).date().isoformat(), 'day'
        except ValueError:
            pass
    if re.fullmatch(r'[A-Za-z]+ \d{4}', value):
        return None, 'month'
    return None, 'unknown'


def _relevant(text):
    return bool(_AI.search(text) and _SECURITY.search(text))


def _https_origin_url(url, host, path=None):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != host or parsed.fragment
            or (path is not None and parsed.path != path)):
        raise RuntimeError(f'Unexpected official source URL for {host}')
    return url


def _conditional_headers(etag, last_modified):
    headers = dict(_HEADERS)
    if etag:
        headers['If-None-Match'] = etag
    if last_modified:
        headers['If-Modified-Since'] = last_modified
    return headers


def _federal_register_api_url(url):
    """The official next-page link uses /documents?format=json, without .json."""
    _https_origin_url(url, 'www.federalregister.gov')
    parsed = urlsplit(url)
    if (parsed.path not in {'/api/v1/documents.json', '/api/v1/documents'}
            or (parsed.path == '/api/v1/documents'
                and parse_qs(parsed.query).get('format') != ['json'])):
        raise RuntimeError('Unexpected official source URL for www.federalregister.gov')
    return url


def _result(items, response=None, *, fetched_count=0, filtered_count=0, status='success'):
    headers = dict(response.headers) if response is not None else {}
    return CollectionResult(items=items, status=status, etag=headers.get('ETag'),
                            last_modified=headers.get('Last-Modified'),
                            response_headers=headers, fetched_count=fetched_count,
                            filtered_count=filtered_count)


class FederalRegisterPolicyCollector:
    """Paginate the official Federal Register's AI policy search, without CVE assumptions."""
    BASE_URL = 'https://www.federalregister.gov/api/v1/documents.json'
    source_category = 'policy_regulation'

    def __init__(self, *, source=None, url=None, session=None, max_pages=30, per_page=100):
        self.source = source or 'FEDERAL_REGISTER_AI_POLICY'
        self.url = url or self.BASE_URL
        _https_origin_url(self.url, 'www.federalregister.gov', '/api/v1/documents.json')
        self.session = session or requests.Session()
        self.max_pages = _positive_integer(max_pages, 'max_pages')
        self.per_page = _positive_integer(per_page, 'per_page')
        if self.per_page > 1000:
            raise ValueError('per_page exceeds the Federal Register maximum of 1000')

    def collect(self, etag=None, last_modified=None):
        url, params = self.url, {'conditions[term]': 'artificial intelligence',
                                 'order': 'newest', 'per_page': self.per_page}
        items, seen_urls, seen_ids = [], set(), set()
        expected_count = expected_pages = None
        fetched = filtered = 0
        first_response = None
        for page in range(self.max_pages):
            if url in seen_urls:
                raise RuntimeError('Federal Register pagination loop; incomplete collection')
            seen_urls.add(url)
            response = _get(self.session, url, headers=(
                _conditional_headers(etag, last_modified) if page == 0 else dict(_HEADERS)
            ), params=params)
            _federal_register_api_url(getattr(response, 'url', None) or url)
            if page == 0:
                first_response = response
            if response.status_code == 304:
                if page != 0:
                    raise RuntimeError('Unexpected 304 during Federal Register pagination')
                return _result([], response, status='not_modified')
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get('results'), list):
                raise ValueError('Federal Register did not return a results list')
            count, total_pages = payload.get('count'), payload.get('total_pages')
            for name, value in [('count', count), ('total_pages', total_pages)]:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f'Federal Register pagination {name} is missing or invalid')
            if count and not total_pages:
                raise RuntimeError('Federal Register positive count has zero total_pages')
            if page == 0:
                expected_count, expected_pages = count, total_pages
            elif count != expected_count or total_pages != expected_pages:
                raise RuntimeError('Federal Register result count changed; retry complete collection')
            for row in payload['results']:
                if not isinstance(row, dict):
                    raise ValueError('Invalid Federal Register document payload')
                identifier = row.get('document_number')
                if not isinstance(identifier, str) or not identifier:
                    raise ValueError('Federal Register document_number is missing')
                if identifier in seen_ids:
                    raise RuntimeError('Federal Register repeated a document; pagination may be incomplete')
                seen_ids.add(identifier)
                fetched += 1
                title, abstract = row.get('title'), row.get('abstract') or ''
                if not isinstance(title, str) or not title.strip() or not isinstance(abstract, str):
                    raise ValueError('Federal Register title or abstract is invalid')
                if not _relevant(title + ' ' + abstract):
                    filtered += 1
                    continue
                canonical = row.get('html_url')
                if not isinstance(canonical, str):
                    raise ValueError('Federal Register html_url is missing')
                _https_origin_url(canonical, 'www.federalregister.gov')
                publication, precision = _date_evidence(row.get('publication_date'))
                if not publication or precision != 'day':
                    raise ValueError('Federal Register publication_date is missing or invalid')
                items.append(KnowledgeDocument(
                    document_id=make_document_id(self.source, identifier), source=self.source,
                    source_category=self.source_category, content_type=self.source_category,
                    title=title.strip(), description=abstract.strip(), url=canonical,
                    published_at=publication, modified_at=None,
                    cve_ids=sorted(set(match.upper() for match in _CVE.findall(title + ' ' + abstract))),
                    raw_data={'document': row, 'publication_date_source': 'publication_date',
                              'publication_precision': precision, 'discovery_url': self.url},
                ))
            if fetched > expected_count:
                raise RuntimeError('Federal Register returned more documents than count')
            next_url = payload.get('next_page_url')
            if not next_url:
                if fetched != expected_count or (expected_pages and page + 1 != expected_pages):
                    raise RuntimeError('Federal Register pagination ended before all documents were read')
                return _result(items, first_response, fetched_count=fetched, filtered_count=filtered)
            if not payload['results']:
                raise RuntimeError('Federal Register returned an empty page before completion')
            if page + 1 >= expected_pages or fetched >= expected_count:
                raise RuntimeError('Federal Register pagination metadata contradicts next page')
            if not isinstance(next_url, str):
                raise ValueError('Invalid Federal Register next_page_url')
            url = _federal_register_api_url(next_url)
            params = None
        raise RuntimeError(f'Federal Register reached max_pages={self.max_pages}; collection is incomplete')


class _OfficialHTML(HTMLParser):
    """Extract links, explicit publication metadata and visible evidence without executing HTML."""
    _BLOCK = {'script', 'style', 'nav', 'header', 'footer'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.meta, self.text_lines = [], {}, []
        self.title, self.h1, self.subtitle, self.abstract = [], [], [], []
        self.canonical = None
        self._stack, self._anchor = [], None
        self._buffer = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self._stack.append((tag, attrs))
        if tag == 'meta':
            name = (attrs.get('name') or attrs.get('property') or '').lower()
            if name and attrs.get('content'):
                self.meta.setdefault(name, attrs['content'])
        if tag == 'link' and 'canonical' in attrs.get('rel', '').lower().split():
            self.canonical = attrs.get('href')
        if tag == 'link' and 'next' in attrs.get('rel', '').lower().split():
            self.links.append({'href': attrs.get('href'), 'attrs': attrs, 'text': ''})
        if tag == 'a':
            self._anchor = {'href': attrs.get('href'), 'attrs': attrs, 'text': []}
        if tag in {'p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'dt', 'dd', 'br', 'li'}:
            self._flush()
        # HTML void elements never enclose later content.
        if tag in {'meta', 'link', 'br', 'img', 'input', 'hr', 'source', 'wbr'}:
            self._stack.pop()

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in {'meta', 'link', 'br', 'img', 'input', 'hr', 'source', 'wbr'}:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == 'a' and self._anchor is not None:
            self._anchor['text'] = ' '.join(self._anchor['text']).strip()
            self.links.append(self._anchor)
            self._anchor = None
        if tag in {'p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'dt', 'dd', 'li'}:
            self._flush()
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                del self._stack[index:]
                break

    def handle_data(self, data):
        data = ' '.join(data.split())
        if not data:
            return
        # Pagination is often inside <nav>; retain link labels while excluding
        # navigation prose from publication titles, abstracts and date evidence.
        if self._anchor is not None:
            self._anchor['text'].append(data)
        if any(tag in self._BLOCK for tag, _ in self._stack):
            return
        self._buffer.append(data)
        if any(tag == 'h1' for tag, _ in self._stack):
            self.h1.append(data)
        if any(tag in {'h2', 'h3'} and 'pub-subtitle' in attrs.get('id', '')
               for tag, attrs in self._stack):
            self.subtitle.append(data)
        if any(tag == 'title' for tag, _ in self._stack):
            self.title.append(data)
        if any('abstract' in ((attrs.get('id', '') + ' ' + attrs.get('class', '')).lower())
               for _, attrs in self._stack):
            self.abstract.append(data)

    def _flush(self):
        if self._buffer:
            self.text_lines.append(' '.join(self._buffer))
            self._buffer = []

    def close(self):
        super().close()
        self._flush()


def _parse_html(text):
    if not isinstance(text, str):
        raise ValueError('Official publication did not return HTML text')
    parser = _OfficialHTML()
    parser.feed(text)
    parser.close()
    return parser


def _formal_url(href, base):
    if not href:
        return None
    parsed = urlsplit(urljoin(base, href))
    if (parsed.scheme != 'https' or parsed.netloc != 'csrc.nist.gov'
            or not _FORMAL_PATH.fullmatch(parsed.path) or parsed.query):
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), '', ''))


def _publication_date(parsed):
    # Deliberately exclude dateModified, Last-Modified, dcterms.modified and generic date.
    for key in ('citation_publication_date', 'dc.date.issued', 'dcterms.issued',
                'article:published_time', 'datepublished', 'publication_date', 'pubdate'):
        value = parsed.meta.get(key)
        if value:
            normalized, precision = _date_evidence(value)
            return normalized, {'field': key, 'value': value, 'precision': precision}
    for index, line in enumerate(parsed.text_lines):
        match = re.match(r'^(?:Publication Date|Published(?: Date)?|Date Published)\s*:\s*(.*)$', line, re.I)
        if not match:
            continue
        value = match.group(1).strip()
        if not value and index + 1 < len(parsed.text_lines):
            value = parsed.text_lines[index + 1].strip()
        normalized, precision = _date_evidence(value)
        return normalized, {'field': 'visible_publication_label', 'value': value, 'precision': precision}
    return None, {'field': None, 'value': None, 'precision': 'unknown'}


def _description(parsed):
    explicit = ' '.join(parsed.abstract).strip()
    if explicit:
        return explicit
    # Older CSRC layouts use a heading and following paragraphs without an abstract ID.
    for index, line in enumerate(parsed.text_lines):
        if line.strip().lower().rstrip(':') != 'abstract':
            continue
        paragraphs = []
        for paragraph in parsed.text_lines[index + 1:]:
            if re.match(r'^(?:Keywords|Authors?|Publication Date|Published|Citation|'
                        r'Document Type|Download|Related Publications|Supplemental Material)\b',
                        paragraph, re.I):
                break
            paragraphs.append(paragraph)
        if paragraphs:
            return ' '.join(paragraphs)
    return parsed.meta.get('description') or parsed.meta.get('dc.description') or ''


class NISTStandardCollector:
    """Discover actual formal AI standards/guidelines from official CSRC indexes."""
    DEFAULT_URLS = (
        'https://csrc.nist.gov/publications/search?keywords=artificial%20intelligence',
    )
    source_category = 'technical_standard'

    def __init__(self, *, source=None, url=None, source_urls=None, session=None,
                 max_pages=10, max_links=100):
        if url is not None and source_urls is not None:
            raise ValueError('Specify url or source_urls, not both')
        self.source = source or 'NIST_CSRC_AI_STANDARDS'
        self.source_urls = tuple(source_urls if source_urls is not None else (
            (url,) if url is not None else self.DEFAULT_URLS))
        if not self.source_urls:
            raise ValueError('NIST requires at least one discovery URL')
        for entry in self.source_urls:
            _https_origin_url(entry, 'csrc.nist.gov')
        self.session = session or requests.Session()
        self.max_pages = _positive_integer(max_pages, 'max_pages')
        self.max_links = _positive_integer(max_links, 'max_links')

    def collect(self, etag=None, last_modified=None):
        # Index validators cannot prove publication detail pages are unchanged.
        queue, visited, publications = list(self.source_urls), set(), {}
        while queue:
            page_url = queue.pop(0)
            if page_url in visited:
                continue
            if len(visited) >= self.max_pages:
                raise RuntimeError(f'NIST reached max_pages={self.max_pages}; discovery is incomplete')
            visited.add(page_url)
            response = _get(self.session, page_url, headers=dict(_HEADERS))
            if response.status_code == 304:
                raise RuntimeError('Unexpected NIST 304 without complete publication evidence')
            effective_url = getattr(response, 'url', None) or page_url
            _https_origin_url(effective_url, 'csrc.nist.gov')
            parsed = _parse_html(response.text)
            for link in parsed.links:
                candidate = _formal_url(link['href'], effective_url)
                if candidate:
                    publications.setdefault(candidate, {'index_url': page_url, 'link_text': link['text']})
                    if len(publications) > self.max_links:
                        raise RuntimeError(f'NIST exceeded max_links={self.max_links}; discovery is incomplete')
                attrs = link['attrs']
                labels = [link['text'], attrs.get('aria-label', ''), attrs.get('title', '')]
                next_link = 'next' in attrs.get('rel', '').lower().split() or bool(
                    any(re.fullmatch(r'(?:next(?: page)?\s*[›»>]*|[›»])', label.strip(), re.I)
                        for label in labels)
                )
                if next_link and link['href']:
                    next_url = urljoin(effective_url, link['href'])
                    _https_origin_url(next_url, 'csrc.nist.gov', urlsplit(effective_url).path)
                    if next_url in visited:
                        raise RuntimeError('NIST discovery pagination loop; collection is incomplete')
                    if next_url not in queue:
                        queue.append(next_url)
        items, filtered, seen_canonicals = [], 0, set()
        for publication_url, discovery in publications.items():
            response = _get(self.session, publication_url, headers=dict(_HEADERS))
            if response.status_code == 304:
                raise RuntimeError('Unexpected NIST detail 304 without publication evidence')
            effective_url = getattr(response, 'url', None) or publication_url
            canonical = _formal_url(effective_url, publication_url)
            if canonical is None:
                raise RuntimeError('NIST detail redirected outside formal official publications')
            parsed = _parse_html(response.text)
            if parsed.canonical:
                canonical = _formal_url(parsed.canonical, effective_url)
                if canonical is None:
                    raise RuntimeError('Unexpected NIST publication canonical URL')
            if canonical in seen_canonicals:
                continue
            seen_canonicals.add(canonical)
            title = ' '.join(parsed.h1 or parsed.title).strip()
            if parsed.h1 and parsed.subtitle:
                title += ': ' + ' '.join(parsed.subtitle)
            if not title:
                raise ValueError('NIST formal publication has no title')
            description = _description(parsed)
            evidence = title + ' ' + description + ' ' + discovery['link_text']
            if not _relevant(evidence):
                filtered += 1
                continue
            publication, date_evidence = _publication_date(parsed)
            items.append(KnowledgeDocument(
                document_id=make_document_id(self.source, canonical), source=self.source,
                source_category=self.source_category, content_type=self.source_category,
                title=title, description=description, url=canonical, published_at=publication,
                modified_at=None, cve_ids=sorted(set(match.upper() for match in _CVE.findall(evidence))),
                raw_data={'html': response.text, 'discovery': discovery,
                          'publication_date_evidence': date_evidence,
                          'publication_precision': date_evidence['precision'],
                          'metadata': parsed.meta, 'visible_text': '\n'.join(parsed.text_lines)},
            ))
        return _result(items, fetched_count=len(publications), filtered_count=filtered)
