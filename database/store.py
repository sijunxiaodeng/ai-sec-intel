# 知识库。同一 cve_id 只保留一条 EnrichedIntelligence。

import json
from pathlib import Path

from models import enriched_record, normalize

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
KB_PATH = DATA / "knowledge.json"
CARDS_PATH = ROOT / "cards.json"
CARDS_JS_PATH = ROOT / "cards.js"
RUNS_PATH = DATA / "runs.json"


def _ensure():
    DATA.mkdir(exist_ok=True)


def _read_list(path):
    if not path.exists():
        return None
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    if isinstance(rows, list):
        return rows
    return None


def import_cards():
    rows = _read_list(CARDS_PATH) or []
    records = []
    for row in rows:
        card = normalize(row)
        if card.get("cve_id"):
            records.append(enriched_record(card))
    save_kb(records)
    return records


def load_kb():
    _ensure()
    rows = _read_list(KB_PATH)
    if rows:
        return [enriched_record(row) for row in rows]
    return import_cards()


def _union(old_values, new_values):
    found = []
    for value in list(old_values or []) + list(new_values or []):
        if value and value not in found:
            found.append(value)
    return found


def merge_records(old, new):
    """同一编号合并。已有的分数和富化结果不被空值盖掉，采集时间保留第一次。"""
    old = enriched_record(old)
    new = enriched_record(new)
    old_item = old.get("item") or {}
    new_item = new.get("item") or {}
    sources = _union(old_item.get("sources"), new_item.get("sources"))
    description = old_item.get("description") or ""
    if len(new_item.get("description") or "") > len(description):
        description = new_item.get("description") or ""
    collected_times = [value for value in (old_item.get("collected_at"), new_item.get("collected_at")) if value]
    papers = []
    seen_papers = set()
    for paper in (old.get("papers") or []) + (new.get("papers") or []):
        url = paper.get("url") if isinstance(paper, dict) else ""
        if url and url not in seen_papers:
            seen_papers.add(url)
            papers.append(paper)
    poc = []
    seen_poc = set()
    for row in (old.get("poc") or []) + (new.get("poc") or []):
        url = row.get("url") if isinstance(row, dict) else ""
        if url and url not in seen_poc:
            seen_poc.add(url)
            poc.append(row)
    old_cvss = old.get("cvss") if (old.get("cvss") or {}).get("score") is not None else None
    item = dict(new_item)
    item.update({
        "title": old_item.get("title") or new_item.get("title"),
        "description": description,
        "source": "、".join(sources),
        "sources": sources,
        "url": old_item.get("url") or new_item.get("url"),
        "published_at": old_item.get("published_at") or new_item.get("published_at"),
        "collected_at": min(collected_times) if collected_times else "",
        "product": old_item.get("product") or new_item.get("product"),
        "affected": _union(old_item.get("affected"), new_item.get("affected"))[:8],
        "references": _union(old.get("references"), new.get("references")),
        "raw_data": dict(old_item.get("raw_data") or {}),
    })
    item["raw_data"].update(new_item.get("raw_data") or {})
    return enriched_record({
        "item": item,
        "cvss": old_cvss or new.get("cvss"),
        "epss": old.get("epss") if old.get("epss") is not None else new.get("epss"),
        "kev": old.get("kev") if old.get("kev") is not None else new.get("kev"),
        "poc": poc,
        "papers": papers,
        "references": item["references"],
    })


def save_kb(records):
    _ensure()
    merged = {}
    order = []
    for record in records:
        record = enriched_record(record)
        key = (record.get("item") or {}).get("cve_id") or ""
        if not key:
            continue
        if key not in merged:
            order.append(key)
            merged[key] = record
        else:
            merged[key] = merge_records(merged[key], record)
    rows = [merged[key] for key in order]
    rows.sort(key=lambda row: (row.get("item") or {}).get("published_at") or "", reverse=True)
    KB_PATH.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    export_cards(rows)
    return rows


def export_cards(records):
    cards = []
    for record in records:
        item = record.get("item") or {}
        cvss = record.get("cvss") or {}
        cards.append(normalize({
            "id": item.get("cve_id"),
            "cve_id": item.get("cve_id"),
            "title": item.get("title"),
            "description": item.get("description"),
            "source": item.get("source"),
            "url": item.get("url"),
            "published_at": item.get("published_at"),
            "collected_at": item.get("collected_at"),
            "product": item.get("product"),
            "affected": item.get("affected") or [],
            "cvss": cvss.get("score"),
            "references": record.get("references") or [],
        }))
    text = json.dumps(cards, ensure_ascii=False, indent=2)
    CARDS_PATH.write_text(text, encoding="utf-8")
    CARDS_JS_PATH.write_text("window.CARDS = %s;\n" % text, encoding="utf-8")


def upsert(records):
    current = load_kb()
    return save_kb(current + list(records))


def get_record(cve_id):
    for record in load_kb():
        if (record.get("item") or {}).get("cve_id") == cve_id:
            return record
    return None


def append_run(steps, kind):
    _ensure()
    runs = _read_list(RUNS_PATH) or []
    runs.insert(0, {"kind": kind, "steps": steps})
    RUNS_PATH.write_text(json.dumps(runs[:20], ensure_ascii=False, indent=2), encoding="utf-8")


def latest_run():
    runs = _read_list(RUNS_PATH) or []
    if not runs:
        return None
    return runs[0]
