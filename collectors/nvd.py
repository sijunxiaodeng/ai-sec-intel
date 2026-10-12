# NVD 关键词采集。B 以后在 collectors 里加别的来源，返回值仍用 models.normalize。
# Recency: prefer lastMod window (30d → 90d → unrestricted) so keyword hits are not
# dominated by ancient CVE-* year labels that happen to match "llm".

import json
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from models import normalize


def fetch_nvd(keyword, limit=10, last_mod_days=None):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": int(limit),
    }
    if last_mod_days:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=int(last_mod_days))
        # NVD 2.0 expects local-like ISO without offset; use explicit Z-less form with ms.
        params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


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


def _days_since(iso_stamp):
    """How many whole days from watermark to now (UTC); None if unparsable."""
    if not iso_stamp:
        return None
    text = str(iso_stamp).replace("Z", "+00:00")
    try:
        start = datetime.fromisoformat(text)
    except ValueError:
        try:
            start = datetime.strptime(str(iso_stamp)[:19], "%Y-%m-%dT%H:%M:%S")
            start = start.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - start.astimezone(timezone.utc)
    return max(1, int(delta.total_seconds() // 86400) + 1)


class NVDCollector(object):
    """collect() 返回 IntelligenceItem 列表。

    With a stored watermark, prefer a lastMod window starting near that stamp
    (plus a small overlap via ceil days) so re-runs resume instead of looking empty.
    """

    def __init__(self, keyword="llm", limit=20, use_cursor=True):
        self.keyword = keyword
        self.limit = limit
        self.use_cursor = bool(use_cursor)
        self.last_stats = {}

    def collect(self):
        from collectors.cursors import get_cursor
        from models import intelligence_item

        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        watermark = get_cursor("nvd") if self.use_cursor else ""
        # Prefer recently modified matches; widen if the short window is empty.
        # When a watermark exists, start from ~that age (capped) then widen.
        window_plan = [30, 90, None]
        if watermark:
            since = _days_since(watermark)
            if since is not None:
                # Overlap: look back at least 2 days before watermark age.
                first = min(max(since + 2, 2), 120)
                window_plan = [first, 90, None] if first < 90 else [first, None]
        payload = {"vulnerabilities": []}
        used_days = None
        fetches = 0
        for days in window_plan:
            try:
                payload = fetch_nvd(self.keyword, self.limit, last_mod_days=days)
                fetches += 1
                used_days = days
            except Exception:
                if days is None:
                    raise
                continue
            if payload.get("vulnerabilities") or days is None:
                break
        items = []
        for vuln in payload.get("vulnerabilities") or []:
            card = to_card(vuln, self.keyword, collected_at)
            if card.get("cve_id"):
                items.append(intelligence_item(card))
        # Newest published first within this batch (CVE year ≠ freshness).
        items.sort(key=lambda row: str((row.get("published_at") if isinstance(row, dict) else "") or ""), reverse=True)
        self.last_stats = {
            "source": "NVD",
            "fetched": len(items),
            "kept": len(items),
            "last_mod_days": used_days,
            "watermark_before": watermark,
            "watermark_candidate": collected_at,
            "incremental": bool(watermark),
            "external_fetches": fetches,
        }
        return items

    def commit_cursor(self):
        from collectors.cursors import set_cursor

        candidate = (self.last_stats or {}).get("watermark_candidate")
        if not candidate:
            return
        set_cursor(
            "nvd",
            candidate,
            meta={
                "fetched": (self.last_stats or {}).get("fetched"),
                "keyword": self.keyword,
                "last_mod_days": (self.last_stats or {}).get("last_mod_days"),
            },
        )
