"""NVD modified-time and GitHub modified-time incremental collectors.

Uses the existing IntelligenceItem dataclass and merger raw_data shapes.
No changes are made to the user's existing collector implementations.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import requests
from collectors.base import IntelligenceItem


NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
GITHUB_URL = 'https://api.github.com/advisories'


def _api_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError('Timezone-aware datetime required')
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def _iso_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError('Timezone-aware datetime required')
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _get(session, url, *, headers=None, params=None, timeout=35, retries=4):
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=timeout)
        except requests.RequestException:
            if attempt == retries - 1:
                raise
            time.sleep(min(2 ** (attempt + 1), 25))
            continue
        status = response.status_code
        if status in {429, 500, 502, 503, 504} or (
            status == 403 and response.headers.get('X-RateLimit-Remaining') == '0'
        ):
            if attempt == retries - 1:
                response.raise_for_status()
            delay = min(2 ** (attempt + 1), 30)
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    delay = min(max(float(retry_after), 0), 120)
                except ValueError:
                    try:
                        delay = min(max((parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds(), 0), 120)
                    except Exception:
                        pass
            time.sleep(delay)
            continue
        response.raise_for_status()
        return response
    raise RuntimeError('Unreachable HTTP retry state')


def _nvd_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get('descriptions') or []
    if not isinstance(descriptions, list):
        return ''
    for d in descriptions:
        if isinstance(d, dict) and d.get('lang') == 'en':
            return str(d.get('value') or '')
    return str(descriptions[0].get('value') or '') if descriptions and isinstance(descriptions[0], dict) else ''


def _nvd_severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get('metrics') or {}
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        for metric in metrics.get(key) or []:
            data = metric.get('cvssData') or {}
            severity = data.get('baseSeverity') or metric.get('baseSeverity')
            if severity:
                return str(severity).upper()
    return None


def from_nvd(raw: dict[str, Any]) -> IntelligenceItem:
    cve_id = str(raw['id']).upper()
    return IntelligenceItem(
        source='NVD', source_id=cve_id, cve_id=cve_id,
        title=cve_id, description=_nvd_description(raw),
        url=f'https://nvd.nist.gov/vuln/detail/{cve_id}',
        published_at=raw.get('published'), modified_at=raw.get('lastModified'),
        severity=_nvd_severity(raw), ai_relevance_hint=0.0,
        tags=[], raw_data=raw,
    )


def from_github(raw: dict[str, Any]) -> IntelligenceItem:
    ghsa = str(raw['ghsa_id'])
    cve = str(raw.get('cve_id') or '').upper() or None
    return IntelligenceItem(
        source='GITHUB_ADVISORY', source_id=ghsa, cve_id=cve,
        title=str(raw.get('summary') or ghsa),
        description=str(raw.get('description') or ''),
        url=str(raw.get('html_url') or raw.get('url') or ''),
        published_at=raw.get('published_at'),
        modified_at=raw.get('updated_at'),
        severity=str(raw.get('severity') or '').upper() or None,
        ai_relevance_hint=0.0,
        tags=[], raw_data=raw,
    )


class NVDModifiedCollector:
    def __init__(self, session=None, api_key=None, max_pages=30):
        self.session = session or requests.Session()
        self.api_key = api_key if api_key is not None else os.getenv('NVD_API_KEY', '')
        self.max_pages = max_pages
        self._last_call = None

    def _rate_limit(self):
        # NVD without a key: default 5 requests/30 seconds (space by 6.5s).
        interval = 0.8 if self.api_key else 6.5
        if self._last_call is not None:
            pause = interval - (time.monotonic() - self._last_call)
            if pause > 0:
                time.sleep(pause)
        self._last_call = time.monotonic()

    def collect_window(self, start: datetime, end: datetime):
        if not start < end:
            return []
        if (end - start).total_seconds() > 119 * 86400:
            raise ValueError('NVD single query window must be < 120 days')
        headers = {'User-Agent': 'AI-Security-Intel-B/1.0'}
        if self.api_key:
            headers['apiKey'] = self.api_key
        page = 0
        start_index = 0
        output = []
        total = None
        while True:
            if page >= self.max_pages:
                raise RuntimeError(f'NVD reached max_pages={self.max_pages}; cursor will NOT advance')
            self._rate_limit()
            r = _get(self.session, NVD_URL, headers=headers, params={
                'lastModStartDate': _api_timestamp(start),
                'lastModEndDate': _api_timestamp(end),
                'resultsPerPage': 2000,
                'startIndex': start_index,
            })
            doc = r.json()
            vulnerabilities = doc.get('vulnerabilities')
            if not isinstance(vulnerabilities, list):
                raise ValueError('NVD did not return vulnerabilities list')
            if total is None:
                total = int(doc.get('totalResults', 0))
            elif total != int(doc.get('totalResults', 0)):
                # Avoid checkpoint advancement if upstream pagination moved underneath us.
                raise RuntimeError('NVD totalResults changed during pagination; retry later')
            if len(vulnerabilities) == 0 and start_index < total:
                raise RuntimeError('NVD returned incomplete page before reaching totalResults')
            for row in vulnerabilities:
                raw = row.get('cve') if isinstance(row, dict) else None
                if not isinstance(raw, dict) or not raw.get('id'):
                    raise ValueError('Invalid NVD CVE payload')
                output.append(from_nvd(raw))
            start_index += len(vulnerabilities)
            page += 1
            if start_index >= total:
                break
        if start_index != total:
            raise RuntimeError('NVD result count mismatch, refusing cursor advancement')
        return output


class GithubModifiedCollector:
    def __init__(self, session=None, token=None, max_pages=30):
        self.session = session or requests.Session()
        self.token = token if token is not None else os.getenv('GITHUB_TOKEN', '')
        self.max_pages = max_pages

    def collect_window(self, start: datetime, end: datetime):
        if not start < end:
            return []
        # "modified" includes advisories published OR updated in the window.
        params = {
            'type': 'reviewed',
            'modified': f'{_iso_timestamp(start)}..{_iso_timestamp(end)}',
            'sort': 'updated',
            'direction': 'desc',
            'per_page': 100,
        }
        headers = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'AI-Security-Intel-B/1.0',
        }
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        url = GITHUB_URL
        seen_urls = set()
        output = []
        pages = 0
        while url:
            if pages >= self.max_pages:
                raise RuntimeError(f'GitHub reached max_pages={self.max_pages}; cursor will NOT advance')
            if url in seen_urls:
                raise RuntimeError('GitHub pagination loop, refusing checkpoint')
            seen_urls.add(url)
            r = _get(self.session, url, headers=headers, params=params)
            docs = r.json()
            if not isinstance(docs, list):
                raise ValueError('GitHub advisories API did not return a list')
            for raw in docs:
                if not isinstance(raw, dict) or not raw.get('ghsa_id'):
                    raise ValueError('Invalid GitHub advisory payload')
                # GHSA without CVE remains in source_items for future non-CVE support,
                # but the existing merger only creates unified CVE records.
                output.append(from_github(raw))
            pages += 1
            nxt = r.links.get('next', {}).get('url')
            if nxt and urlparse(nxt).netloc != 'api.github.com':
                raise RuntimeError('Unexpected GitHub pagination host')
            url = nxt
            params = None  # next URL already contains its own cursor params
        return output
