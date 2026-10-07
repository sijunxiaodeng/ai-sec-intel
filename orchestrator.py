# 命令行入口仍走同一条编排：监测、富化、入库。

from agents.orchestrator import run_collect
from database.store import load_kb
from rag.retrieve import search as search_records

KEYWORD = "ollama"


def collect_and_save(keyword=KEYWORD):
    print("正在请求 NVD，可能要等 1 分钟……")
    run_collect(keyword)
    cards = []
    for record in load_kb():
        item = record.get("item") or {}
        cards.append({
            "id": item.get("cve_id") or "",
            "cvss": (record.get("cvss") or {}).get("score"),
        })
    print("关键词 %s：卡片一共 %d 条。" % (keyword, len(cards)))
    return cards


def search(query):
    found = []
    for record in search_records(query):
        item = record.get("item") or {}
        found.append({
            "id": item.get("cve_id") or "",
            "description": item.get("description") or "",
        })
    return found
