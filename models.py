# 三人共用的漏洞卡片。
# 缺的字段留空，不要编造分数、版本或链接。
# A 维护这个文件。B、C 只读取，不改字段名。

FIELDS = (
    "id",
    "cve_id",
    "title",
    "description",
    "source",
    "url",
    "published_at",
    "collected_at",
    "product",
    "affected",
    "cvss",
    "references",
)


def empty_card():
    return {
        "id": "",
        "cve_id": "",
        "title": "",
        "description": "",
        "source": "",
        "url": "",
        "published_at": "",
        "collected_at": "",
        "product": "",
        "affected": [],
        "cvss": None,
        "references": [],
    }


def normalize(row):
    """把旧卡片或采集结果收成同一种字段。同一条漏洞用 cve_id 合并。"""
    card = empty_card()
    if not isinstance(row, dict):
        return card
    cve_id = row.get("cve_id") or row.get("id") or ""
    description = row.get("description") or row.get("summary") or ""
    url = row.get("url") or row.get("link") or ""
    card["id"] = cve_id
    card["cve_id"] = cve_id
    card["title"] = row.get("title") or cve_id
    card["description"] = description
    card["source"] = row.get("source") or ""
    card["url"] = url
    card["published_at"] = row.get("published_at") or ""
    card["collected_at"] = row.get("collected_at") or ""
    card["product"] = row.get("product") or ""
    affected = row.get("affected") or []
    card["affected"] = affected if isinstance(affected, list) else [affected]
    card["cvss"] = row.get("cvss", None)
    references = row.get("references") or []
    card["references"] = references if isinstance(references, list) else [references]
    return card


def score_band(score):
    if score is None:
        return None
    if score >= 9:
        return "严重"
    if score >= 7:
        return "高"
    if score >= 4:
        return "中"
    return "低"


def intelligence_item(row):
    """计划里冻结的 IntelligenceItem。额外字段只做兼容，不改已有字段名。"""
    card = normalize(row)
    raw = row.get("raw_data") if isinstance(row, dict) and isinstance(row.get("raw_data"), dict) else {}
    if card.get("cvss") is not None and raw.get("cvss_score") is None:
        raw = dict(raw)
        raw["cvss_score"] = card["cvss"]
        raw["cvss_severity"] = raw.get("cvss_severity") or score_band(card["cvss"])
    sources = []
    if isinstance(row, dict):
        for name in row.get("sources") or []:
            if name and name not in sources:
                sources.append(name)
    for name in (card.get("source") or "").split("、"):
        name = name.strip()
        if name and name not in sources:
            sources.append(name)
    return {
        "id": card["cve_id"],
        "title": card["title"] or card["cve_id"],
        "description": card["description"],
        "source": card["source"],
        "url": card["url"],
        "published_at": card["published_at"],
        "cve_id": card["cve_id"],
        "raw_data": raw,
        "collected_at": card["collected_at"],
        "product": card["product"],
        "affected": card["affected"],
        "references": card["references"],
        "sources": sources,
    }


def cvss_from_raw(raw, fallback_score=None):
    raw = raw or {}
    score = raw.get("cvss_score")
    if score is None:
        score = fallback_score
    if score is None:
        return None
    return {
        "score": score,
        "severity": raw.get("cvss_severity") or score_band(score),
        "version": raw.get("cvss_version"),
        "vector": raw.get("cvss_vector"),
    }


def enriched_record(row):
    """计划里的 EnrichedIntelligence。查不到的维度保持空，不编造。"""
    if isinstance(row, dict) and isinstance(row.get("item"), dict):
        item = intelligence_item(row["item"])
        record = {
            "item": item,
            "cvss": row.get("cvss") or cvss_from_raw(item.get("raw_data")),
            "epss": row.get("epss"),
            "kev": row.get("kev"),
            "poc": row.get("poc") or [],
            "papers": row.get("papers") or [],
            "references": row.get("references") or item.get("references") or [],
        }
        return record
    item = intelligence_item(row if isinstance(row, dict) else {})
    return {
        "item": item,
        "cvss": cvss_from_raw(item.get("raw_data"), item.get("raw_data", {}).get("cvss_score")),
        "epss": None,
        "kev": None,
        "poc": [
            {"url": url, "note": "NVD 将该链接标为 Exploit，此处只保存链接"}
            for url in (item.get("raw_data") or {}).get("exploit_refs") or []
        ],
        "papers": [],
        "references": item.get("references") or [],
    }
