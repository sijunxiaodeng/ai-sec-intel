# OSV 是与 NVD 不同的公开来源。同一 CVE 编号在入库时合并。

import json
import urllib.request
from datetime import datetime, timezone

from models import intelligence_item

QUERY_URL = "https://api.osv.dev/v1/query"
PACKAGES = {
    "ollama": [("GIT", "github.com/ollama/ollama")],
    "vllm": [("PyPI", "vllm"), ("GIT", "github.com/vllm-project/vllm")],
    "transformers": [("PyPI", "transformers")],
    "langchain": [("PyPI", "langchain")],
}


def _post(ecosystem, name):
    body = json.dumps({"package": {"ecosystem": ecosystem, "name": name}}).encode("utf-8")
    request = urllib.request.Request(
        QUERY_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "ai-sec-intel-student"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _cve_id(vuln):
    own = vuln.get("id") or ""
    if own.startswith("CVE-"):
        return own
    for alias in vuln.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return alias
    return own


def _affected(vuln, keyword):
    names = []
    for block in vuln.get("affected") or []:
        package = ((block.get("package") or {}).get("name") or keyword).split("/")[-1]
        events = []
        for chunk in block.get("ranges") or []:
            extra = (chunk.get("database_specific") or {}).get("extracted_events") or []
            events.extend(extra or [])
        for event in events:
            fixed = event.get("fixed") or ""
            last = event.get("last_affected") or ""
            if fixed and len(fixed) < 24:
                names.append("%s，修复于 %s" % (package, fixed))
            elif last and len(last) < 24:
                names.append("%s，受影响至 %s" % (package, last))
    unique = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return unique[:5]


def _vector(vuln):
    for row in vuln.get("severity") or []:
        score = row.get("score") or ""
        if score.startswith("CVSS:"):
            return score
    return ""


def to_item(vuln, keyword, collected_at):
    cve_id = _cve_id(vuln)
    links = []
    page = "https://osv.dev/vulnerability/%s" % (vuln.get("id") or cve_id)
    links.append(page)
    for ref in vuln.get("references") or []:
        url = ref.get("url")
        if url and url not in links:
            links.append(url)
    return intelligence_item({
        "id": cve_id,
        "cve_id": cve_id,
        "title": vuln.get("summary") or cve_id,
        "description": vuln.get("details") or vuln.get("summary") or "",
        "source": "OSV",
        "sources": ["OSV"],
        "url": page,
        "published_at": vuln.get("published") or "",
        "collected_at": collected_at,
        "product": keyword,
        "affected": _affected(vuln, keyword),
        "references": links[:8],
        "raw_data": {
            "osv_id": vuln.get("id") or "",
            "cvss_vector": _vector(vuln),
        },
    })


class OSVCollector(object):
    """collect() 返回 IntelligenceItem 列表。查不到包时返回空列表，不编造记录。"""

    def __init__(self, keyword="ollama"):
        self.keyword = keyword or "ollama"

    def collect(self):
        packages = PACKAGES.get(self.keyword.lower())
        if not packages:
            packages = [("GIT", "github.com/%s/%s" % (self.keyword, self.keyword))]
        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        items = []
        seen = set()
        for ecosystem, name in packages:
            payload = _post(ecosystem, name)
            for vuln in payload.get("vulns") or []:
                item = to_item(vuln, self.keyword, collected_at)
                if not item.get("cve_id") or item["cve_id"] in seen:
                    continue
                seen.add(item["cve_id"])
                items.append(item)
        return items
