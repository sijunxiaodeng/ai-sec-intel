# 卡片存在本目录的 cards.json。页面读取由它生成的 cards.js。

import json
from pathlib import Path

from models import normalize

HERE = Path(__file__).resolve().parent
CARDS_PATH = HERE / "cards.json"
CARDS_JS_PATH = HERE / "cards.js"


def load_cards():
    if not CARDS_PATH.exists():
        return []
    try:
        rows = json.loads(CARDS_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return []
    if not isinstance(rows, list):
        return []
    return [normalize(row) for row in rows]


def save_cards(cards):
    rows = [normalize(card) for card in cards]
    rows.sort(key=lambda row: row.get("published_at") or "", reverse=True)
    text = json.dumps(rows, ensure_ascii=False, indent=2)
    CARDS_PATH.write_text(text, encoding="utf-8")
    CARDS_JS_PATH.write_text("window.CARDS = %s;\n" % text, encoding="utf-8")
    return rows


def merge_cards(cards):
    """同一 cve_id 只保留一张。后写入的非空字段覆盖先写入的空字段。"""
    merged = {}
    order = []
    for card in cards:
        card = normalize(card)
        key = card.get("cve_id") or ""
        if not key:
            continue
        if key not in merged:
            merged[key] = card
            order.append(key)
            continue
        current = merged[key]
        for field, value in card.items():
            if value in ("", None, []):
                continue
            current[field] = value
    return [merged[key] for key in order]


def search_cards(query, cards=None):
    """按编号、产品名或摘要里的词查找。空查询返回全部。"""
    rows = load_cards() if cards is None else cards
    text = (query or "").strip().lower()
    if not text:
        return rows
    found = []
    for card in rows:
        blob = " ".join([
            card.get("id") or "",
            card.get("cve_id") or "",
            card.get("product") or "",
            card.get("title") or "",
            card.get("description") or "",
            " ".join(card.get("affected") or []),
        ]).lower()
        if text in blob:
            found.append(card)
    return found
