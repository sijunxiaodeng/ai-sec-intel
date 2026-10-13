"""OSV package queries for the platform KB funnel.

Canonical location: intelligence/platform_bridge/osv.py
Root collectors/osv.py is a thin facade (stable import for tests / monitor_agent).

OSV is not part of intelligence/collectors multisource writers; it feeds the
main knowledge.json merge alongside local-DB CVE reads. Same CVE ids merge
on upsert. Cap per package; unsaved revisions stay for later rounds.
"""

import hashlib
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
    # OSV canonical id: pkg:pypi/open-webui (GHSA/PYSEC aliases map to CVE).
    "open-webui": [("PyPI", "open-webui"), ("GIT", "github.com/open-webui/open-webui")],
}

# Per-product batch cap; deferred source identities remain unacknowledged.
# Env OSV_PER_PACKAGE_LIMIT can raise/lower within 1..20 (honest drip, no invented CVEs).
def _per_package_limit_default():
    import os
    try:
        raw = int(os.environ.get("OSV_PER_PACKAGE_LIMIT", "10") or "10")
    except ValueError:
        raw = 10
    return max(1, min(20, raw))


PER_PACKAGE_LIMIT = _per_package_limit_default()

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


def _post(ecosystem, name, page_token=""):
    query = {"package": {"ecosystem": ecosystem, "name": name}}
    if page_token:
        query["page_token"] = page_token
    body = json.dumps(query).encode("utf-8")
    request = urllib.request.Request(
        QUERY_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "ai-sec-intel-student"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise ValueError("OSV response exceeds the size limit")
        return json.loads(body.decode("utf-8"))


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


def package_cursor_key(ecosystem, name):
    from collectors.cursors import scoped_key
    return scoped_key("osv", ecosystem, name)


def _revision(vuln):
    text = json.dumps(vuln, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class OSVCollector(object):
    """collect() 返回 IntelligenceItem 列表。查不到包时返回空列表，不编造记录。

    Each (ecosystem, package) remembers only revisions actually emitted and then
    successfully upserted. A capped/failed package cannot be skipped by another
    package's timestamp. Legacy global watermarks are retained but not trusted.
    """

    def __init__(self, keyword="llm", per_package_limit=PER_PACKAGE_LIMIT, use_cursor=True, max_pages=5):
        self.keyword = keyword or "llm"
        self.per_package_limit = max(1, int(per_package_limit or PER_PACKAGE_LIMIT))
        self.use_cursor = bool(use_cursor)
        if type(max_pages) is not int or max_pages <= 0:
            raise ValueError("OSV max_pages must be a positive integer")
        self.max_pages = max_pages
        self.last_stats = {}
        self._pending_states = {}

    def collect(self):
        from collectors.cursors import get_cursor, get_state

        packages = resolve_packages(self.keyword)
        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.last_stats = {}
        self._pending_states = {}
        legacy = get_cursor("osv") if self.use_cursor else ""
        fetched = 0
        package_ok = 0
        package_fail = 0
        calls = 0
        watermarks = []
        incremental = False
        pending_states = {}
        # Merge ecosystem variants (PyPI + GIT) per product before capping.
        by_product = {}
        for ecosystem, name in packages:
            product = _product_label(ecosystem, name)
            key = package_cursor_key(ecosystem, name)
            state = get_state(key) if self.use_cursor else {}
            meta = state.get("meta")
            if not isinstance(meta, dict) or meta.get("protocol") != "osv_package_revisions_v2":
                state = {}  # Replay untrusted global / older scoped state.
            saved = state.get("record_revisions") or {}
            saved = saved if isinstance(saved, dict) else {}
            incremental |= bool(state)
            if state.get("window_end_at"):
                watermarks.append(state["window_end_at"])
            try:
                token, tokens, ids, rows = "", set(), set(), []
                for page in range(self.max_pages):
                    calls += 1
                    payload = _post(ecosystem, name, page_token=token) if token else _post(ecosystem, name)
                    if not isinstance(payload, dict) or not isinstance(payload.get("vulns", []), list):
                        raise ValueError("OSV package response is invalid")
                    for vuln in payload.get("vulns", []):
                        fetched += 1
                        if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"]:
                            raise ValueError("OSV record lacks its source identity")
                        if vuln["id"] in ids:
                            raise ValueError("OSV repeated an identity during pagination")
                        ids.add(vuln["id"])
                        revision = _revision(vuln)
                        if saved.get(vuln["id"]) != revision:
                            rows.append({"key": key, "osv_id": vuln["id"], "revision": revision,
                                         "item": to_item(vuln, product, collected_at)})
                    following = payload.get("next_page_token", "")
                    if following is None:
                        following = ""
                    if not isinstance(following, str) or following in tokens:
                        raise ValueError("OSV pagination token is invalid or repeated")
                    if not following:
                        break
                    tokens.add(following)
                    token = following
                else:
                    raise RuntimeError("OSV exceeded max_pages; package state will not advance")
                package_ok += 1
            except Exception:
                # Discard partial pages. Other independently scoped packages continue.
                package_fail += 1
                continue
            by_product.setdefault(product, []).extend(rows)
            pending_states[key] = {
                "window_end_at": collected_at, "record_revisions": {},
                "meta": {"protocol": "osv_package_revisions_v2", "ecosystem": ecosystem, "package": name},
            }
        if packages and not package_ok:
            raise RuntimeError("No OSV package completed successfully; positions were not advanced")
        buckets, candidates = [], []
        for product, bucket in by_product.items():
            bucket.sort(key=lambda row: (row["item"].get("published_at") or "", row["osv_id"]), reverse=True)
            candidates.extend(bucket)
            # Duplicate CVEs across package variants are deferred, not acknowledged.
            unique, seen = [], set()
            for row in bucket:
                cve = row["item"].get("cve_id")
                if cve and cve not in seen:
                    unique.append(row)
                    seen.add(cve)
            buckets.append(unique[:self.per_package_limit])
        selected, seen = [], set()
        for index in range(self.per_package_limit):
            for bucket in buckets:
                if index < len(bucket):
                    row = bucket[index]
                    cve = row["item"]["cve_id"]
                    if cve not in seen:
                        selected.append(row)
                        seen.add(cve)
                        pending_states[row["key"]]["record_revisions"][row["osv_id"]] = row["revision"]
        items = [row["item"] for row in selected]
        self._pending_states = pending_states if self.use_cursor else {}
        self.last_stats = {
            "source": "OSV",
            "fetched": fetched,
            "kept": len(items),
            "packages_queried": package_ok,
            "packages_failed": package_fail,
            "packages_planned": len(packages),
            "watermark_before": max(watermarks) if watermarks else "",
            "watermark_candidate": collected_at,
            "incremental": incremental,
            "legacy_global_replayed": bool(legacy) and not incremental,
            "cursor_scope": "package_record_revisions",
            "deferred_records": len(candidates) - len(selected),
            "external_fetches": calls,
        }
        return items

    def commit_cursor(self):
        """Acknowledge only emitted revisions after the caller's successful upsert."""
        from collectors.cursors import commit_states
        commit_states(self._pending_states)
        self._pending_states = {}
