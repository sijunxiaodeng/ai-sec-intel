# OSV 是与 NVD 不同的公开来源。同一 CVE 编号在入库时合并。
# 默认按已知 AI 组件包集合查询，并限制单包条数，避免某一组件（如 ollama）独占列表。

import json
import urllib.request
from datetime import datetime, timezone

from models import intelligence_item

QUERY_URL = "https://api.osv.dev/v1/query"

# Known AI-stack packages we can maintain. Order is round-robin preference for
# interleaving results — not a severity ranking.
PACKAGES = {
    "vllm": [("PyPI", "vllm"), ("GIT", "github.com/vllm-project/vllm")],
    "transformers": [("PyPI", "transformers")],
    "langchain": [("PyPI", "langchain")],
    "langgraph": [("PyPI", "langgraph")],
    "llama-index": [("PyPI", "llama-index")],
    "huggingface_hub": [("PyPI", "huggingface_hub")],
    "ollama": [("GIT", "github.com/ollama/ollama")],
    "openai": [("PyPI", "openai")],
}

# Cap per package so one ecosystem (historically ollama) cannot flood the feed.
PER_PACKAGE_LIMIT = 6

# Broad AI-security keywords used by AUTO_MONITOR / monitor_agent primary.
# These are not OSV package names — expanding to PACKAGES avoids empty
# github.com/<keyword>/<keyword> queries (e.g. keyword "llm").
BROAD_KEYWORDS = {
    "llm",
    "ai",
    "adversarial",
    "jailbreak",
    "prompt injection",
    "prompt-injection",
    "huggingface",
    "openai",
    "genai",
    "generative",
}


def _known_package_entries():
    seen = set()
    out = []
    for entries in PACKAGES.values():
        for entry in entries:
            if entry in seen:
                continue
            seen.add(entry)
            out.append(entry)
    return out


def resolve_packages(keyword):
    """Map a monitor keyword to OSV (ecosystem, name) pairs."""
    key = (keyword or "").strip().lower()
    if key in PACKAGES:
        return list(PACKAGES[key])
    if key in BROAD_KEYWORDS or not key:
        return _known_package_entries()
    # Unknown single token: keep legacy guess (may return empty).
    return [("GIT", "github.com/%s/%s" % (key, key))]


def _product_label(ecosystem, name):
    """Human product slug from OSV package identity (not the search keyword)."""
    if not name:
        return "unknown"
    short = name.split("/")[-1]
    return short or name


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


def _affected(vuln, product):
    names = []
    for block in vuln.get("affected") or []:
        package = ((block.get("package") or {}).get("name") or product).split("/")[-1]
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


def to_item(vuln, product, collected_at):
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
        "product": product,
        "affected": _affected(vuln, product),
        "references": links[:8],
        "raw_data": {
            "osv_id": vuln.get("id") or "",
            "cvss_vector": _vector(vuln),
            "osv_package": product,
        },
    })


def _round_robin_merge(buckets):
    """Interleave per-package lists so one package cannot occupy the whole head."""
    out = []
    seen = set()
    active = [list(bucket) for bucket in buckets if bucket]
    while active:
        next_round = []
        for bucket in active:
            item = bucket.pop(0)
            cve = item.get("cve_id") if isinstance(item, dict) else None
            if cve and cve not in seen:
                seen.add(cve)
                out.append(item)
            if bucket:
                next_round.append(bucket)
        active = next_round
    return out


class OSVCollector(object):
    """collect() 返回 IntelligenceItem 列表。查不到包时返回空列表，不编造记录。"""

    def __init__(self, keyword="llm", per_package_limit=PER_PACKAGE_LIMIT):
        self.keyword = keyword or "llm"
        self.per_package_limit = max(1, int(per_package_limit or PER_PACKAGE_LIMIT))

    def collect(self):
        packages = resolve_packages(self.keyword)
        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Merge ecosystem variants (PyPI + GIT) per product before capping.
        by_product = {}
        for ecosystem, name in packages:
            product = _product_label(ecosystem, name)
            try:
                payload = _post(ecosystem, name)
            except Exception:
                # One package failure must not drop the rest of the AI set.
                continue
            bucket = by_product.setdefault(product, [])
            seen_ids = {item.get("cve_id") for item in bucket}
            for vuln in payload.get("vulns") or []:
                item = to_item(vuln, product, collected_at)
                cve = item.get("cve_id")
                if not cve or cve in seen_ids:
                    continue
                seen_ids.add(cve)
                bucket.append(item)
        buckets = []
        for product, bucket in by_product.items():
            bucket.sort(
                key=lambda row: str((row.get("published_at") if isinstance(row, dict) else "") or ""),
                reverse=True,
            )
            buckets.append(bucket[: self.per_package_limit])
        items = _round_robin_merge(buckets)
        # Cap already enforces package diversity; newest published first overall.
        items.sort(
            key=lambda row: str((row.get("published_at") if isinstance(row, dict) else "") or ""),
            reverse=True,
        )
        return items
