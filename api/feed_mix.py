"""Monitor feed mix helpers — keep CVE + non-CVE composition honest and diverse.

No FastAPI import: safe for offline unit tests.
"""


def doc_category_key(row):
    return (row.get("category") or row.get("content_type") or row.get("category_label") or "other").strip() or "other"


def diversify_documents(rows, limit=72):
    """Round-robin across document categories so one type cannot fill the feed."""
    buckets = {}
    for row in rows:
        key = doc_category_key(row)
        buckets.setdefault(key, []).append(row)
    preferred = (
        "security_blog", "research_article", "research", "academic_paper", "academic",
        "vendor_advisory", "vendor", "vendor_guidance", "security_community",
        "technical_standard", "standard", "policy_regulation", "policy",
        "government_alert",
    )
    order = [k for k in preferred if k in buckets] + sorted(k for k in buckets if k not in preferred)
    out = []
    seen = set()
    while len(out) < limit and order:
        next_order = []
        for key in order:
            bucket = buckets.get(key) or []
            if not bucket:
                continue
            row = bucket.pop(0)
            mark = (row.get("url") or "") + "|" + (row.get("title") or "")
            if mark not in seen:
                seen.add(mark)
                out.append(row)
            if bucket:
                next_order.append(key)
        order = next_order
    return out


def _pub_ts(row):
    raw = (row.get("published_at") or "").strip()
    if not raw:
        return 0.0
    text = raw.replace("Z", "+00:00")
    try:
        from datetime import datetime
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        try:
            from datetime import datetime, timezone
            return datetime.fromisoformat(raw[:10]).replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            return 0.0


def interleave_feed(cve_items, doc_items):
    """Soft-mix CVE and non-CVE so the stream is not a CVE dump when docs exist."""
    if not doc_items:
        return list(cve_items)
    if not cve_items:
        return list(doc_items)

    cves = sorted(cve_items, key=lambda r: (-_pub_ts(r), 1 if r.get("demo") else 0))
    docs = sorted(doc_items, key=lambda r: (-_pub_ts(r), 1 if r.get("demo") else 0))
    out = []
    i = j = 0
    while i < len(cves) or j < len(docs):
        for _ in range(2):
            if i < len(cves):
                out.append(cves[i])
                i += 1
        if j < len(docs):
            out.append(docs[j])
            j += 1
    return out


def _cve_product_key(row):
    product = (row.get("product") or "").strip().lower()
    if product and product not in {"llm", "ai", "unknown", "?"}:
        return product
    blob = " ".join([
        row.get("title") or "",
        row.get("description") or "",
        " ".join(row.get("affected") or []) if isinstance(row.get("affected"), list) else "",
        row.get("cve_id") or "",
    ]).lower()
    for name in (
        "vllm", "transformers", "langchain", "langgraph", "llama-index", "llamaindex",
        "huggingface", "openai", "ollama",
    ):
        if name in blob:
            return "llama-index" if name in {"llama-index", "llamaindex"} else name
    return product or "other"


def diversify_cves_by_product(cve_items, per_product_limit=10, limit=120):
    """Round-robin CVE cards by product so one component cannot monopolize the stream.

    Does not delete KB rows — only shapes the monitor feed window.
    """
    buckets = {}
    for row in cve_items:
        key = _cve_product_key(row)
        buckets.setdefault(key, []).append(row)
    for key, bucket in buckets.items():
        # Live rows first, then newer published_at.
        bucket.sort(
            key=lambda r: (
                0 if r.get("demo") else 1,
                str(r.get("published_at") or ""),
            ),
            reverse=True,
        )
        buckets[key] = bucket[: max(1, int(per_product_limit))]
    preferred = (
        "vllm", "transformers", "langchain", "langgraph", "llama-index",
        "huggingface", "openai", "ollama", "other",
    )
    order = [k for k in preferred if k in buckets] + sorted(k for k in buckets if k not in preferred)
    out = []
    while len(out) < limit and order:
        next_order = []
        for key in order:
            bucket = buckets.get(key) or []
            if not bucket:
                continue
            out.append(bucket.pop(0))
            if bucket:
                next_order.append(key)
        order = next_order
    return out


def feed_composition(items):
    """Honest mix stats for UI — not a scoring board."""
    by_kind = {"cve": 0, "document": 0}
    by_category = {}
    by_product = {}
    ollama_hits = 0
    for row in items:
        kind = row.get("kind") or "cve"
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if kind == "document":
            cat = doc_category_key(row)
            by_category[cat] = by_category.get(cat, 0) + 1
        product = (row.get("product") or "").strip().lower()
        if product:
            by_product[product] = by_product.get(product, 0) + 1
        blob = " ".join([
            product,
            row.get("title") or "",
            row.get("description") or "",
            row.get("cve_id") or "",
        ]).lower()
        if "ollama" in blob:
            ollama_hits += 1
    total = max(len(items), 1)
    return {
        "by_kind": by_kind,
        "by_category": by_category,
        "by_product": by_product,
        "ollama_mentions": ollama_hits,
        "ollama_share": round(ollama_hits / total, 3),
        "note": "构成统计按当前情报流条目；不含未入库来源。",
    }
