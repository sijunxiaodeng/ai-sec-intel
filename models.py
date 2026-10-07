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
