# 这一周的编排只有一件事：采集、保存、按词搜索。
# A 维护这个文件。多角色交接放到报名之后再加。

from datetime import datetime, timezone

from collectors.nvd import fetch_nvd, to_card
from store import load_cards, merge_cards, save_cards, search_cards

KEYWORD = "ollama"


def collect_and_save(keyword=KEYWORD):
    print("正在请求 NVD，可能要等 1 分钟……")
    payload = fetch_nvd(keyword)
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fresh = []
    for item in payload.get("vulnerabilities") or []:
        card = to_card(item, keyword, collected_at)
        if card.get("cve_id"):
            fresh.append(card)
    cards = save_cards(merge_cards(load_cards() + fresh))
    print("关键词 %s：卡片一共 %d 条。" % (keyword, len(cards)))
    return cards


def search(query):
    return search_cards(query)
