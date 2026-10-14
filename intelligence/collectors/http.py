"""Bounded, TLS-verified HTTP requests shared by intelligence collectors."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests


class CollectionBudgetExceeded(RuntimeError):
    """A bounded collection may resume its uncommitted window next cycle."""


class CollectionRateLimited(CollectionBudgetExceeded):
    """Retain a provider's quota failure when its wait cannot fit the budget."""

    def __init__(self, response):
        super().__init__('Provider rate limit exceeds remaining collection budget')
        self.response = response


class RequestBudget:
    """Count every HTTP attempt and stop before exceeding a source deadline."""

    def __init__(self, *, max_requests, deadline):
        if max_requests <= 0:
            raise ValueError('max_requests must be positive')
        self.max_requests = max_requests
        self.deadline = deadline
        self.requests = 0

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CollectionBudgetExceeded('Collection time budget exhausted')
        return remaining

    def check(self):
        self.remaining()
        if self.requests >= self.max_requests:
            raise CollectionBudgetExceeded('Collection request budget exhausted')

    def acquire(self):
        self.check()
        self.requests += 1

    def sleep(self, seconds):
        if seconds >= self.remaining():
            raise CollectionBudgetExceeded('Collection wait exceeds remaining time budget')
        time.sleep(seconds)


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
         before_request=None, budget=None):
    """Retry transient failures only; never disable TLS or expose headers."""
    if retries < 1:
        raise ValueError('retries must be positive')
    for attempt in range(retries):
        if budget:
            budget.check()
        if before_request:
            before_request()
        request_timeout = timeout
        if budget:
            budget.acquire()
            request_timeout = min(timeout, budget.remaining())
        try:
            response = session.get(url, headers=headers, params=params, timeout=request_timeout)
        except requests.RequestException:
            if attempt == retries - 1:
                raise
            delay = min(2 ** (attempt + 1), 25)
            budget.sleep(delay) if budget else time.sleep(delay)
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
            try:
                budget.sleep(delay) if budget else time.sleep(delay)
            except CollectionBudgetExceeded:
                if response.status_code in {403, 429}:
                    raise CollectionRateLimited(response) from None
                raise
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
