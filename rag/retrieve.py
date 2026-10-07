# 知识库检索。先做可运行的词法检索，向量检索由 C 接到 search() 上。

import re

from database.store import load_kb

TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{1,}", re.I)


def _blob(record):
    item = record.get("item") or {}
    parts = [
        item.get("cve_id") or "",
        item.get("title") or "",
        item.get("description") or "",
        item.get("product") or "",
        item.get("source") or "",
        " ".join(item.get("affected") or []),
    ]
    return " ".join(parts).lower()


def search(query, top_k=5):
    records = load_kb()
    text = (query or "").strip().lower()
    if not text:
        return records[:top_k]
    if text in ("全部", "所有", "列表"):
        return records[:top_k]
    if any(word in text for word in ("当前记录", "知识库", "这些漏洞", "有没有")):
        return records[:top_k]
    terms = TOKEN.findall(text) or [text]
    ranked = []
    for record in records:
        blob = _blob(record)
        cve_id = ((record.get("item") or {}).get("cve_id") or "").lower()
        score = 0
        if text in blob or text.upper() == cve_id.upper():
            score += 5
        if cve_id and cve_id in text:
            score += 8
        for term in terms:
            if term.lower() in blob:
                score += 1
        if score:
            ranked.append((score, record))
    ranked.sort(key=lambda pair: pair[0], reverse=True)
    return [record for score, record in ranked[:top_k]]
