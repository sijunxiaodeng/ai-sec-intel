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


def cvss_score(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData") or {}
            score = data.get("baseScore")
            if score is not None:
                return score
    return None


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


def to_card(item, keyword, collected_at):
    cve = item.get("cve") or {}
    description = ""
    for row in cve.get("descriptions") or []:
        if row.get("lang") == "en":
            description = row.get("value") or ""
            break
    links = []
    for ref in (cve.get("references") or [])[:5]:
        url = ref.get("url")
        if url:
            links.append(url)
    cve_id = cve.get("id") or ""
    return normalize({
        "id": cve_id,
        "cve_id": cve_id,
        "title": cve_id,
        "description": description,
        "source": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id if cve_id else "",
        "published_at": cve.get("published") or "",
        "collected_at": collected_at,
        "product": keyword,
        "affected": affected_products(cve),
        "cvss": cvss_score(cve),
        "references": links,
    })
