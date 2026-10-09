"""Source-preserving RSS/Atom and vendor advisory knowledge collectors.

These adapters never invent CVEs, publication times, or model labels. Collection
is deliberately separate from persistence and scheduling. Incomplete pages raise
an error so a caller cannot advance a source checkpoint or freshness deadline.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from collectors.http import _get


@dataclass
class KnowledgeDocument:
    document_id: str
    source: str
    source_category: str
    content_type: str
    title: str
    description: str
    url: str
    published_at: str | None
    modified_at: str | None
    cve_ids: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionResult:
    items: list[KnowledgeDocument]
    status: str = "success"
    etag: str | None = None
    last_modified: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    fetched_count: int = 0
    filtered_count: int = 0


def document_id(source: str, source_id: str) -> str:
    """Namespaced stable identity; text edits do not create another document."""
    if not source.strip() or not source_id.strip():
        raise ValueError("Document source and source identity are required")
    return "doc-" + hashlib.sha256((source + "\0" + source_id).encode("utf-8")).hexdigest()


make_document_id = document_id


def source_timestamp(value: str | None) -> str | None:
    """Preserve day precision; never substitute collection time for publication."""
    if value is None or not str(value).strip():
        return None
    value = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        datetime.strptime(value, "%Y-%m-%d")
        return value
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            stamp = parsedate_to_datetime(value)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("Source supplied an invalid publication timestamp") from exc
    if stamp.tzinfo is None:
        # No timezone means precision is insufficient for a six-hour SLA.
        return None
    return stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class _PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        elif tag in {"p", "div", "br", "li"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1
        elif tag in {"p", "div", "li"}:
            self.parts.append(" ")

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def _plain(value: str) -> str:
    parser = _PlainText()
    parser.feed(value or "")
    parser.close()
    return " ".join(html.unescape(" ".join(parser.parts)).split())


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element, *names):
    return [child for child in element if _local(child.tag) in names]


def _text(element, *names):
    matches = _children(element, *names)
    return "".join(matches[0].itertext()).strip() if matches else ""


class _NoDTD(ET.TreeBuilder):
    def doctype(self, name, pubid, system):
        raise ValueError("DTD declarations are forbidden in source feeds")


class _StreamingSession:
    """Let the shared verified/retrying HTTP helper retain a bounded body."""
    def __init__(self, session):
        self.session = session

    def get(self, url, **kwargs):
        return self.session.get(url, stream=True, **kwargs)


def _read_body(response, max_bytes: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length:
        try:
            reported_size = int(length)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid source Content-Length") from exc
        if reported_size < 0:
            raise ValueError("Invalid source Content-Length")
        if reported_size > max_bytes:
            raise ValueError("Source response exceeds the configured byte limit")
    chunks, size = [], 0
    iterator = getattr(response, "iter_content", None)
    parts = iterator(chunk_size=65536) if callable(iterator) else [response.content]
    for chunk in parts:
        if not chunk:
            continue
        size += len(chunk)
        if size > max_bytes:
            raise ValueError("Source response exceeds the configured byte limit")
        chunks.append(chunk)
    body = b"".join(chunks)
    if not body.strip():
        raise ValueError("Source returned an empty response body")
    return body


def _cache_headers(response) -> dict[str, str]:
    # Do not persist cookies, authentication, or arbitrary provider headers.
    allowed = {"etag", "last-modified", "content-type", "date"}
    return {str(key).lower(): str(value) for key, value in response.headers.items()
            if str(key).lower() in allowed}


def _result(items, response, *, count=0, filtered=0, status="success"):
    headers = _cache_headers(response)
    return CollectionResult(items, status, headers.get("etag"),
                            headers.get("last-modified"), headers, count, filtered)


def _condition_headers(etag=None, last_modified=None) -> dict[str, str]:
    headers = {"User-Agent": "ai-sec-intel/1.0"}
    for key, value in (("If-None-Match", etag), ("If-Modified-Since", last_modified)):
        if value is not None:
            if not isinstance(value, str) or "\r" in value or "\n" in value or len(value) > 4096:
                raise ValueError("Invalid HTTP cache validator")
            headers[key] = value
    return headers


AI_TERMS = (
    "artificial intelligence", "machine learning", "deep learning", "large language model",
    "llm", "generative ai", "genai", "ai", "chatbot", "ai agent", "prompt injection",
    "model poisoning", "data poisoning", "ollama", "langchain", "pytorch", "tensorflow",
    "huggingface", "hugging face", "vllm", "litellm", "model context protocol",
    "人工智能", "大模型", "机器学习", "智能体", "生成式", "提示注入", "数据投毒",
)
SECURITY_TERMS = (
    "security", "cybersecurity", "vulnerability", "vulnerabilities", "advisory", "attack",
    "threat", "exploit", "poisoning", "injection", "privacy", "risk", "robustness",
    "safety", "jailbreak", "安全", "漏洞", "攻击", "威胁", "风险", "隐私", "投毒", "越狱",
)


def _has_term(text, term):
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(term) + r"(?![A-Za-z0-9_])"
    return bool(re.search(pattern, text, flags=re.IGNORECASE))


def is_ai_security_related(text: str) -> bool:
    return any(_has_term(text, term) for term in AI_TERMS) and any(
        _has_term(text, term) for term in SECURITY_TERMS
    )


class FeedCollector:
    def __init__(self, source: str, source_category: str, content_type: str, url: str, *,
                 ai_only: bool = False, query_scoped: bool = False, session=None,
                 max_bytes: int = 2 * 1024 * 1024, max_items: int = 2000,
                 content_terms=None, allowed_url_patterns=None, allowed_link_hosts=None,
                 timeout: int = 35):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Source endpoint must be an HTTPS URL without embedded credentials")
        if min(max_bytes, max_items, timeout) <= 0:
            raise ValueError("Source limits and timeout must be positive")
        if not source.strip() or not source_category.strip() or not content_type.strip():
            raise ValueError("Source identity, category, and content type are required")
        self.source, self.source_category, self.content_type, self.url = (
            source, source_category, content_type, url
        )
        self.ai_only, self.query_scoped = ai_only, query_scoped
        self.session = session if session is not None else requests.Session()
        self.max_bytes, self.max_items, self.timeout = max_bytes, max_items, timeout
        self.content_terms = tuple(content_terms or ())
        self.allowed_url_patterns = [re.compile(pattern) for pattern in (allowed_url_patterns or ())]
        self.allowed_link_hosts = {parsed.hostname.lower(), *(str(host).lower() for host in (allowed_link_hosts or ()))}

    def _url(self, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Feed entry is missing its source URL")
        value = value.strip()
        original = urlsplit(value)
        resolved = urlsplit(urljoin(self.url, value))
        if (not resolved.hostname or resolved.username or resolved.password
                or resolved.port not in {None, 443, 80}):
            raise ValueError("Feed entry has an unsafe source URL")
        if not original.scheme and resolved.hostname.lower() not in self.allowed_link_hosts:
            raise ValueError("Relative feed links must remain on a known source host")
        scheme = resolved.scheme
        if scheme == "http" and resolved.hostname.lower() in self.allowed_link_hosts:
            scheme = "https"
        if scheme != "https":
            raise ValueError("Feed entry must link to an HTTPS source")
        netloc = resolved.hostname.lower()
        if resolved.port not in {None, 80, 443}:
            netloc += ":" + str(resolved.port)
        return urlunsplit((scheme, netloc, resolved.path or "/", resolved.query, ""))

    def _keep(self, document: KnowledgeDocument) -> bool:
        text = document.title + "\n" + document.description
        if self.ai_only and not self.query_scoped and not is_ai_security_related(text):
            return False
        if self.content_terms and not any(_has_term(text, term) for term in self.content_terms):
            return False
        if self.allowed_url_patterns and not any(pattern.search(document.url) for pattern in self.allowed_url_patterns):
            return False
        return True

    def _document(self, *, identity, title, description, url, published, modified, raw):
        title, description = _plain(title), _plain(description)
        if not title:
            raise ValueError("Source entry has no usable title")
        url = self._url(url)
        return KnowledgeDocument(
            document_id(self.source, identity or url), self.source, self.source_category,
            self.content_type, title, description, url, source_timestamp(published),
            source_timestamp(modified), sorted({value.upper() for value in re.findall(
                r"\bCVE-\d{4}-\d{4,}\b", title + "\n" + description, flags=re.IGNORECASE
            )}), raw,
        )

    def _parse(self, body: bytes):
        if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", body, flags=re.IGNORECASE):
            raise ValueError("DTD and entity declarations are forbidden in source feeds")
        try:
            root = ET.fromstring(body, parser=ET.XMLParser(target=_NoDTD()))
        except ET.ParseError as exc:
            raise ValueError("Source returned malformed RSS/Atom XML") from exc
        name = _local(root.tag)
        if name == "rss":
            channels = _children(root, "channel")
            if len(channels) != 1:
                raise ValueError("RSS feed must contain one channel")
            container, entry_type = channels[0], "item"
        elif name in {"feed", "RDF"}:
            container, entry_type = root, "entry" if name == "feed" else "item"
        else:
            raise ValueError("Source response is not an RSS/Atom feed")
        entries = _children(container, entry_type)
        if not entries and not _text(container, "title"):
            raise ValueError("Source feed has neither entries nor identifying feed metadata")
        if len(entries) > self.max_items:
            raise ValueError("Feed exceeds configured item limit; collection is incomplete")
        metadata = {}
        for key in ("totalResults", "startIndex", "itemsPerPage"):
            value = _text(root, key)
            if value:
                if not re.fullmatch(r"[0-9]+", value):
                    raise ValueError("Invalid feed pagination metadata")
                metadata[key] = int(value)
        items, filtered, identities = [], 0, set()
        for entry in entries:
            links = _children(entry, "link")
            if entry_type == "entry":
                link = next((node.get("href", "") for node in links
                             if node.get("rel", "alternate") == "alternate"
                             and node.get("type", "text/html") in {"text/html", "application/xhtml+xml"}), "")
                identity = _text(entry, "id")
                published, modified = _text(entry, "published"), _text(entry, "updated")
                content = _children(entry, "content") or _children(entry, "summary")
            else:
                link = _text(entry, "link")
                identity = _text(entry, "guid") or entry.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about", "")
                if not link and identity.startswith(("https://", "http://")):
                    link = identity
                published = _text(entry, "pubDate", "date")
                modified = _text(entry, "updated", "modified")
                content = _children(entry, "encoded") or _children(entry, "description")
            description = "".join(content[0].itertext()).strip() if content else ""
            raw = {
                "feed_url": self.url, "entry_id": identity,
                "entry_xml": ET.tostring(entry, encoding="unicode"),
                "description_source": description,
            }
            doc = self._document(identity=identity, title=_text(entry, "title"), description=description,
                                 url=link, published=published, modified=modified, raw=raw)
            doc.cve_ids = [value.upper() for value in doc.cve_ids]
            if doc.document_id in identities:
                raise ValueError("Feed contains duplicate source document identities")
            identities.add(doc.document_id)
            if self._keep(doc):
                items.append(doc)
            else:
                filtered += 1
        metadata["document_ids"] = identities
        return items, len(entries), filtered, metadata

    def _fetch(self, url, *, etag=None, last_modified=None, accept=None, extra_headers=None,
               before_request=None):
        headers = _condition_headers(etag, last_modified)
        headers["Accept"] = accept or "application/atom+xml, application/rss+xml, application/xml"
        headers.update(extra_headers or {})
        return _get(_StreamingSession(self.session), url, headers=headers, timeout=self.timeout,
                    before_request=before_request)

    def collect(self, etag=None, last_modified=None) -> CollectionResult:
        response = self._fetch(self.url, etag=etag, last_modified=last_modified)
        try:
            if response.status_code == 304:
                return _result([], response, status="not_modified")
            items, count, filtered, metadata = self._parse(_read_body(response, self.max_bytes))
            if metadata.get("startIndex", 0) != 0 or metadata.get("totalResults", count) > count:
                raise ValueError("Feed is paginated or truncated; use its supported pagination adapter")
            return _result(items, response, count=count, filtered=filtered)
        finally:
            response.close()


class ArxivCollector(FeedCollector):
    """Collect an entire query, verifying every OpenSearch page before success."""
    def __init__(self, *args, max_pages=20, **kwargs):
        kwargs.setdefault("query_scoped", True)
        kwargs.setdefault("allowed_link_hosts", ("arxiv.org", "www.arxiv.org", "export.arxiv.org"))
        super().__init__(*args, **kwargs)
        parsed = urlsplit(self.url)
        if parsed.hostname not in {"arxiv.org", "export.arxiv.org"} or parsed.path != "/api/query":
            raise ValueError("ArxivCollector requires the official arXiv API endpoint")
        if max_pages < 1:
            raise ValueError("max_pages must be positive")
        self.max_pages = max_pages
        self._last_call = None

    def _rate_limit(self):
        # arXiv requests should be separated by at least three seconds.
        if self._last_call is not None:
            pause = 3 - (time.monotonic() - self._last_call)
            if pause > 0:
                time.sleep(pause)
        self._last_call = time.monotonic()

    def collect(self, etag=None, last_modified=None) -> CollectionResult:
        parsed = urlsplit(self.url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if int(query.get("start", "0")) != 0:
            raise ValueError("A complete arXiv query must start at zero")
        page_size = int(query.get("max_results", "100"))
        if page_size < 1 or page_size > 2000:
            raise ValueError("arXiv max_results must be between 1 and 2000")
        all_items, total, start, count, filtered, first_headers = [], None, 0, 0, 0, {}
        seen = set()
        for page in range(self.max_pages):
            query.update(start=str(start), max_results=str(page_size))
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
            response = self._fetch(url, before_request=self._rate_limit)
            try:
                items, fetched, skipped, metadata = self._parse(_read_body(response, self.max_bytes))
                if page == 0:
                    first_headers = _cache_headers(response)
                if not all(key in metadata for key in ("totalResults", "startIndex", "itemsPerPage")):
                    raise ValueError("arXiv response is missing pagination metadata")
                if metadata["startIndex"] != start or fetched > metadata["itemsPerPage"]:
                    raise ValueError("arXiv returned an unexpected page offset or count")
                if total is not None and total != metadata["totalResults"]:
                    raise ValueError("arXiv result count changed during pagination; retry the query")
                total = metadata["totalResults"]
                if total > self.max_items or start + fetched > total:
                    raise ValueError("arXiv query exceeds item limit or pagination counts are inconsistent")
                if not fetched and start < total:
                    raise ValueError("arXiv returned an incomplete empty page")
                page_ids = metadata["document_ids"]
                if seen.intersection(page_ids):
                    raise ValueError("arXiv repeated a document across pages")
                seen.update(page_ids)
                all_items.extend(items)
                count, filtered = count + fetched, filtered + skipped
                start += fetched
                if start >= total:
                    # Conditional validators for one page cannot prove later pages unchanged.
                    return CollectionResult(all_items, "success", response_headers=first_headers,
                                            fetched_count=count, filtered_count=filtered)
            finally:
                response.close()
        raise ValueError("arXiv reached its page limit before completing the query")


class GitHubVendorAdvisoryCollector(FeedCollector):
    """Public repository security advisories, distinct from community advisories."""
    def __init__(self, *args, token=None, max_pages=20, **kwargs):
        super().__init__(*args, **kwargs)
        parsed = urlsplit(self.url)
        if (parsed.hostname != "api.github.com" or not re.fullmatch(
            r"/repos/[^/]+/[^/]+/security-advisories", parsed.path
        ) or parsed.query or parsed.fragment):
            raise ValueError("Vendor advisories require an official GitHub repository API endpoint")
        if max_pages < 1:
            raise ValueError("max_pages must be positive")
        self.token, self.max_pages = token, max_pages

    def collect(self, etag=None, last_modified=None) -> CollectionResult:
        headers = {"X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        first_url = self.url + "?per_page=100"
        url, items, count, filtered, seen, first_headers = first_url, [], 0, 0, set(), {}
        for page in range(self.max_pages):
            response = self._fetch(url, etag=etag if page == 0 else None,
                                   last_modified=last_modified if page == 0 else None,
                                   accept="application/vnd.github+json", extra_headers=headers)
            try:
                if response.status_code == 304:
                    if page:
                        raise ValueError("Unexpected conditional response on a vendor pagination page")
                    return _result([], response, status="not_modified")
                if not page:
                    first_headers = _cache_headers(response)
                try:
                    payload = json.loads(_read_body(response, self.max_bytes))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ValueError("Vendor source returned malformed JSON") from exc
                if not isinstance(payload, list):
                    raise ValueError("Vendor API must return a repository advisory list")
                count += len(payload)
                if count > self.max_items:
                    raise ValueError("Vendor advisories exceed item limit; collection is incomplete")
                for raw in payload:
                    if not isinstance(raw, dict) or not isinstance(raw.get("ghsa_id"), str) or not raw["ghsa_id"]:
                        raise ValueError("Vendor advisory is missing its stable GHSA identity")
                    if raw["ghsa_id"] in seen:
                        raise ValueError("Vendor API repeated an advisory across pages")
                    seen.add(raw["ghsa_id"])
                    doc = self._document(
                        identity=raw["ghsa_id"], title=raw.get("summary") or raw["ghsa_id"],
                        description=raw.get("description") or "", url=raw.get("html_url") or "",
                        published=raw.get("published_at"), modified=raw.get("updated_at"),
                        raw={"api_url": self.url, "advisory": raw},
                    )
                    cve = raw.get("cve_id")
                    if isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.IGNORECASE):
                        doc.cve_ids = sorted(set([*doc.cve_ids, cve.upper()]))
                    if self._keep(doc):
                        items.append(doc)
                    else:
                        filtered += 1
                next_url = getattr(response, "links", {}).get("next", {}).get("url")
                if not next_url:
                    return CollectionResult(
                        items, "success", first_headers.get("etag") if page == 0 else None,
                        first_headers.get("last-modified") if page == 0 else None,
                        first_headers, count, filtered,
                    )
                target, initial = urlsplit(next_url), urlsplit(self.url)
                if (target.scheme != "https" or target.netloc != initial.netloc
                        or target.path != initial.path or target.fragment):
                    raise ValueError("Vendor pagination escaped the original HTTPS API endpoint")
                if not payload:
                    raise ValueError("Vendor source returned an incomplete empty page")
                url = next_url
            finally:
                response.close()
        raise ValueError("Vendor API reached page limit before completing collection")
