# NVD 关键词采集。B 以后在 collectors 里加别的来源，返回值仍用 models.normalize。
# Recency: prefer lastMod window (30d → 90d → unrestricted) so keyword hits are not
# dominated by ancient CVE-* year labels that happen to match "llm".

import json
import math
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from models import normalize


def fetch_nvd(keyword, limit=10, last_mod_days=None, *, start_index=0, start=None, end=None):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": int(limit),
        "startIndex": int(start_index),
    }
    if last_mod_days:
        if start is not None or end is not None:
            raise ValueError("Use either a fixed window or last_mod_days")
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=int(last_mod_days))
    if start is not None or end is not None:
        if start is None or end is None or start.tzinfo is None or end.tzinfo is None or not start < end:
            raise ValueError("NVD needs an ordered, timezone-aware pair of boundaries")
        if end - start > timedelta(days=119):
            raise ValueError("NVD window must not exceed 119 days")
        params["lastModStartDate"] = start.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        params["lastModEndDate"] = end.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student"})
    with urllib.request.urlopen(request, timeout=90) as response:
        body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise ValueError("NVD response exceeds the size limit")
        return json.loads(body.decode("utf-8"))


def cvss_detail(cve):
    metrics = cve.get("metrics") or {}
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        rows = metrics.get(key) or []
        if not rows:
            continue
        data = rows[0].get("cvssData") or {}
        if data.get("baseScore") is None:
            continue
        return {
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity"),
            "version": version,
            "vector": data.get("vectorString"),
        }
    return None


def cvss_score(cve):
    detail = cvss_detail(cve)
    if not detail:
        return None
    return detail.get("score")


def split_references(cve):
    links = []
    exploits = []
    for ref in (cve.get("references") or [])[:8]:
        url = ref.get("url")
        if not url:
            continue
        if url not in links:
            links.append(url)
        tags = [str(tag).lower() for tag in (ref.get("tags") or [])]
        if "exploit" in tags and url not in exploits:
            exploits.append(url)
    return links[:5], exploits


def affected_products(cve):
    names = []
    for block in cve.get("configurations") or []:
        for node in block.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) >= 6 and parts[4] and parts[4] != "*":
                    version = parts[5] if parts[5] and parts[5] != "*" else "见原文"
                    names.append("%s %s" % (parts[4], version))
    unique = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return unique[:5]


def describe(cve):
    for row in cve.get("descriptions") or []:
        if row.get("lang") == "en":
            return row.get("value") or ""
    return ""


def to_card(item, keyword, collected_at):
    cve = item.get("cve") or {}
    links, exploits = split_references(cve)
    detail = cvss_detail(cve) or {}
    cve_id = cve.get("id") or ""
    card = normalize({
        "id": cve_id,
        "cve_id": cve_id,
        "title": cve_id,
        "description": describe(cve),
        "source": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id if cve_id else "",
        "published_at": cve.get("published") or "",
        "collected_at": collected_at,
        "product": keyword,
        "affected": affected_products(cve),
        "cvss": detail.get("score"),
        "references": links,
    })
    card["raw_data"] = {
        "cvss_score": detail.get("score"),
        "cvss_severity": detail.get("severity"),
        "cvss_version": detail.get("version"),
        "cvss_vector": detail.get("vector"),
        "exploit_refs": exploits,
    }
    return card


def _nvd_time(value):
    """Only NVD source timestamps may omit the documented UTC offset."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)


def query_cursor_key(keyword):
    from collectors.cursors import scoped_key
    return scoped_key("nvd", (keyword or "llm").strip().lower() or "llm")


class NVDCollector(object):
    """collect() 返回 IntelligenceItem 列表。

    Fixed, fully paginated modified-time windows use a keyword-scoped position.
    Untrusted legacy global positions trigger a complete bounded-page replay.
    Reaching the request/page budget raises, never acknowledging a partial page.
    """

    def __init__(self, keyword="llm", limit=100, use_cursor=True, max_pages=20,
                 max_windows=8, overlap_minutes=30, settle_minutes=5, request_interval=6.5):
        if type(limit) is not int or not 1 <= limit <= 2000:
            raise ValueError("NVD page size must be 1..2000")
        if type(max_pages) is not int or type(max_windows) is not int or min(max_pages, max_windows) <= 0:
            raise ValueError("NVD page and window limits must be positive integers")
        if not 0 <= overlap_minutes < 119 * 24 * 60 or not 0 <= settle_minutes < 6 * 60:
            raise ValueError("NVD overlap or settlement is invalid")
        if not math.isfinite(request_interval) or request_interval < 0:
            raise ValueError("NVD request interval cannot be negative")
        self.keyword = (keyword or "llm").strip().lower() or "llm"
        self.limit = limit
        self.use_cursor = bool(use_cursor)
        self.max_pages, self.max_windows = max_pages, max_windows
        self.overlap_minutes, self.settle_minutes = overlap_minutes, settle_minutes
        self.request_interval = request_interval
        self.last_stats = {}
        self._pending_states = {}
        self._requests = 0
        self._last_request = None

    def _collect_pages(self, start=None, end=None):
        offset, expected_total, output, identities = 0, None, [], set()
        while True:
            if self._requests >= self.max_pages:
                raise RuntimeError("NVD exceeded max_pages; no position will advance")
            if self._last_request is not None:
                delay = self.request_interval - (time.monotonic() - self._last_request)
                if delay > 0:
                    time.sleep(delay)
            self._last_request = time.monotonic()
            self._requests += 1
            payload = fetch_nvd(self.keyword, self.limit, start_index=offset, start=start, end=end)
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise ValueError("NVD response lacks its vulnerabilities list")
            for name in ("totalResults", "startIndex", "resultsPerPage"):
                value = payload.get(name)
                if type(value) is not int or value < 0:
                    raise ValueError("NVD pagination field is invalid: " + name)
            total, rows = payload["totalResults"], payload["vulnerabilities"]
            if payload["startIndex"] != offset or (expected_total is not None and total != expected_total):
                raise RuntimeError("NVD pagination offset/total changed; retry the whole window")
            if len(rows) > payload["resultsPerPage"] or offset + len(rows) > total or (not rows and offset < total):
                raise RuntimeError("NVD incomplete or inconsistent page; no position will advance")
            expected_total = total
            for row in rows:
                cve = row.get("cve") if isinstance(row, dict) else None
                if not isinstance(cve, dict) or not isinstance(cve.get("id"), str) or not cve["id"]:
                    raise ValueError("NVD record lacks its source identity")
                if cve["id"] in identities:
                    raise RuntimeError("NVD repeated an identity during pagination")
                if start is not None:
                    modified = _nvd_time(cve.get("lastModified"))
                    if modified is None or not start <= modified <= end:
                        raise ValueError("NVD returned an item outside the fixed modified-time window")
                identities.add(cve["id"])
                output.append(row)
            offset += len(rows)
            if offset == total:
                return output

    def collect(self):
        from collectors.cursors import get_cursor, get_state, parse_utc
        from models import intelligence_item

        self.last_stats, self._pending_states = {}, {}
        self._requests, self._last_request = 0, None
        key = query_cursor_key(self.keyword)
        state = get_state(key) if self.use_cursor else {}
        meta = state.get("meta")
        protocol = meta.get("protocol") if isinstance(meta, dict) else None
        watermark = parse_utc(state.get("window_end_at")) if protocol == "nvd_query_windows_v2" else None
        legacy = get_cursor("nvd") if self.use_cursor else ""
        end = (datetime.now(timezone.utc) - timedelta(minutes=self.settle_minutes)).replace(microsecond=0)
        rows, windows, used_days, query_start, completed_end = [], 0, None, None, end
        if watermark:
            if watermark > end:
                raise ValueError("NVD scoped cursor is ahead of the settled clock")
            position = watermark
            # A very recent repeat still replays the overlap, without regressing.
            while windows < self.max_windows:
                start = position - timedelta(minutes=self.overlap_minutes) if windows == 0 else position
                next_end = min(end, start + timedelta(days=119))
                if not start < next_end:
                    break
                query_start = query_start or start
                rows.extend(self._collect_pages(start, next_end))
                windows += 1
                position = completed_end = next_end
                if position >= end:
                    break
        else:
            # The old global cursor may have skipped old first pages or another
            # keyword; replay it instead of importing an unsafe position.
            for days in ([None] if legacy or state else [30, 90, None]):
                start = end - timedelta(days=days) if days else None
                rows = self._collect_pages(start, end if start else None)
                windows += 1
                used_days, query_start = days, start
                if rows or days is None:
                    break
        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        by_id = {}
        for vuln in rows:
            card = to_card(vuln, self.keyword, collected_at)
            if card.get("cve_id"):
                by_id[card["cve_id"]] = intelligence_item(card)
        items = list(by_id.values())
        # Newest published first within this batch (CVE year ≠ freshness).
        items.sort(key=lambda row: str((row.get("published_at") if isinstance(row, dict) else "") or ""), reverse=True)
        self.last_stats = {
            "source": "NVD",
            "fetched": len(items),
            "kept": len(items),
            "last_mod_days": used_days,
            "watermark_before": watermark.isoformat() if watermark else "",
            "watermark_candidate": completed_end.isoformat(),
            "incremental": bool(watermark),
            "legacy_global_replayed": bool(legacy) and not watermark,
            "cursor_scope": "keyword",
            "window_start_at": query_start.isoformat() if query_start else None,
            "window_end_at": completed_end.isoformat(),
            "pending_windows": completed_end < end,
            "completed_windows": windows,
            "external_fetches": self._requests,
        }
        if self.use_cursor:
            self._pending_states = {key: {
                "window_end_at": completed_end.isoformat(),
                "meta": {"protocol": "nvd_query_windows_v2", "keyword": self.keyword},
            }}
        return items

    def commit_cursor(self):
        from collectors.cursors import commit_states
        commit_states(self._pending_states)
        self._pending_states = {}
