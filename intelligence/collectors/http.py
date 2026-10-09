"""Bounded, TLS-verified HTTP requests shared by intelligence collectors."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests


def _retry_delay(response, attempt):
    delay = min(2 ** (attempt + 1), 30)
    retry_after = response.headers.get('Retry-After')
    if retry_after:
        try:
            return min(max(float(retry_after), 0), 120)
        except ValueError:
            try:
                stamp = parsedate_to_datetime(retry_after)
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                return min(max((stamp - datetime.now(timezone.utc)).total_seconds(), 0), 120)
            except (ValueError, TypeError, OverflowError):
                pass
    reset = response.headers.get('X-RateLimit-Reset')
    if response.headers.get('X-RateLimit-Remaining') == '0' and reset:
        try:
            return min(max(float(reset) - time.time(), 0), 120)
        except ValueError:
            pass
    return delay


def _get(session, url, *, headers=None, params=None, timeout=35, retries=4,
         before_request=None):
    """Retry transient failures only; never disable TLS or expose headers."""
    if retries < 1:
        raise ValueError('retries must be positive')
    for attempt in range(retries):
        if before_request:
            before_request()
        try:
            response = session.get(url, headers=headers, params=params, timeout=timeout)
        except requests.RequestException:
            if attempt == retries - 1:
                raise
            time.sleep(min(2 ** (attempt + 1), 25))
            continue
        retryable = response.status_code in {429, 500, 502, 503, 504} or (
            response.status_code == 403 and (
                response.headers.get('X-RateLimit-Remaining') == '0'
                or bool(response.headers.get('Retry-After'))
            )
        )
        if retryable and attempt < retries - 1:
            delay = _retry_delay(response, attempt)
            response.close()
            time.sleep(delay)
            continue
        response.raise_for_status()
        return response
    raise RuntimeError('Unreachable HTTP retry state')


def github_next_url(response):
    """Do not send a GitHub bearer token to a downgraded/unrelated next URL."""
    link = response.links.get('next', {}).get('url')
    if not link:
        return None
    parsed = urlparse(link)
    if (parsed.scheme != 'https' or parsed.netloc != 'api.github.com'
            or parsed.path != '/advisories' or parsed.fragment):
        raise RuntimeError('Unexpected GitHub pagination URL')
    return link


def nvd_page(document, start_index, expected_total=None):
    """Validate completeness before a caller may advance its watermark."""
    if not isinstance(document, dict):
        raise ValueError('NVD API did not return an object')
    rows = document.get('vulnerabilities')
    if not isinstance(rows, list):
        raise ValueError('NVD did not return vulnerabilities list')
    for key in ('totalResults', 'startIndex', 'resultsPerPage'):
        value = document.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f'NVD pagination field {key} is missing or invalid')
    total = document['totalResults']
    if document['startIndex'] != start_index:
        raise RuntimeError('NVD returned an unexpected pagination offset')
    if expected_total is not None and total != expected_total:
        raise RuntimeError('NVD totalResults changed during pagination; retry later')
    if len(rows) > document['resultsPerPage'] or start_index + len(rows) > total:
        raise RuntimeError('NVD result count mismatch, refusing cursor advancement')
    if not rows and start_index < total:
        raise RuntimeError('NVD returned incomplete page before reaching totalResults')
    return rows, total
