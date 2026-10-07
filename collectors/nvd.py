# NVD 关键词采集。B 以后在 collectors 里加别的来源，返回值仍用 models.normalize。

import json
import urllib.request

from models import normalize


def fetch_nvd(keyword, limit=10):
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        "?keywordSearch=%s&resultsPerPage=%s"
        % (urllib.request.quote(keyword), int(limit))
    )
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


class NVDCollector(object):
    """B 的采集接口：collect() 返回 IntelligenceItem 列表。"""

    def __init__(self, keyword="ollama", limit=10):
        self.keyword = keyword
        self.limit = limit

    def collect(self):
        from datetime import datetime, timezone

        from models import intelligence_item

        payload = fetch_nvd(self.keyword, self.limit)
        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        items = []
        for vuln in payload.get("vulnerabilities") or []:
            card = to_card(vuln, self.keyword, collected_at)
            if card.get("cve_id"):
                items.append(intelligence_item(card))
        return items
