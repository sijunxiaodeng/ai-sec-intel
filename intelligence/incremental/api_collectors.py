"""NVD modified-time and GitHub modified-time incremental collectors.

Uses the existing IntelligenceItem dataclass and preserves source raw_data.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from collectors.base import IntelligenceItem
from collectors.http import _get, github_next_url, nvd_page


NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
GITHUB_URL = 'https://api.github.com/advisories'


def _api_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError('Timezone-aware datetime required')
    return dt.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _iso_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError('Timezone-aware datetime required')
    precision = 'microseconds' if dt.microsecond else 'seconds'
    return dt.astimezone(timezone.utc).isoformat(timespec=precision).replace('+00:00', 'Z')


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
    if not isinstance(metrics, dict):
        raise ValueError('Invalid NVD metrics payload')
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        for metric in metrics.get(key) or []:
            if not isinstance(metric, dict):
                raise ValueError('Invalid NVD metric payload')
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
    def __init__(self, session=None, api_key=None, max_pages=30, page_size=500):
        self.session = session or requests.Session()
        self.api_key = api_key if api_key is not None else os.getenv('NVD_API_KEY', '')
        self.max_pages = max_pages
        self.page_size = page_size
        if max_pages <= 0:
            raise ValueError('max_pages must be positive')
        if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 2000:
            raise ValueError('NVD page_size must be 1..2000')
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
        return self._collect_window(start, end, 'lastMod')

    def collect_published_window(self, start: datetime, end: datetime):
        return self._collect_window(start, end, 'pub')

    def _collect_window(self, start: datetime, end: datetime, field: str):
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError('Timezone-aware window boundaries required')
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
        seen_ids = set()
        total = None
        while True:
            if page >= self.max_pages:
                raise RuntimeError(f'NVD reached max_pages={self.max_pages}; cursor will NOT advance')
            r = _get(self.session, NVD_URL, headers=headers, params={
                f'{field}StartDate': _api_timestamp(start),
                f'{field}EndDate': _api_timestamp(end),
                'resultsPerPage': self.page_size,
                'startIndex': start_index,
            }, before_request=self._rate_limit)
            vulnerabilities, total = nvd_page(r.json(), start_index, total)
            for row in vulnerabilities:
                raw = row.get('cve') if isinstance(row, dict) else None
                if not isinstance(raw, dict) or not raw.get('id'):
                    raise ValueError('Invalid NVD CVE payload')
                if raw['id'] in seen_ids:
                    raise RuntimeError('NVD repeated CVE during pagination; retry later')
                seen_ids.add(raw['id'])
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
        self.token = token if token is not None else (os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN', ''))
        self.max_pages = max_pages
        if max_pages <= 0:
            raise ValueError('max_pages must be positive')

    def collect_window(self, start: datetime, end: datetime):
        return self._collect_window(start, end, 'modified')

    def collect_published_window(self, start: datetime, end: datetime):
        return self._collect_window(start, end, 'published')

    def _collect_window(self, start: datetime, end: datetime, field: str):
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError('Timezone-aware window boundaries required')
        if not start < end:
            return []
        # "modified" includes advisories published OR updated in the window.
        params = {
            'type': 'reviewed',
            # GitHub rejects fractional seconds (422). Widen the query by at
            # most a second so precise local cursor boundaries cannot omit rows.
            field: f'{_iso_timestamp(start.replace(microsecond=0))}..'
                   f'{_iso_timestamp((end + timedelta(seconds=1 if end.microsecond else 0)).replace(microsecond=0))}',
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
        seen_ids = set()
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
                if raw['ghsa_id'] in seen_ids:
                    raise RuntimeError('GitHub repeated advisory during pagination; retry later')
                seen_ids.add(raw['ghsa_id'])
                # GHSA without CVE remains in source_items for future non-CVE support,
                # but the existing merger only creates unified CVE records.
                output.append(from_github(raw))
            pages += 1
            url = github_next_url(r)
            if url and not docs:
                raise RuntimeError('GitHub returned empty page before final page')
            params = None  # next URL already contains its own cursor params
        return output
