from enrichment.service import apply_public_feeds, enrich


def run(items, online=False):
    records = [enrich(item) for item in items]
    detail = "已写入 CVSS 和参考链接。EPSS、KEV、论文留空，等待后续查询或 C 接入。"
    feed = None
    if online:
        feed = apply_public_feeds(records)
        detail = "已尝试从公开源补充 EPSS 与 CISA KEV。"
        if feed.get("epss_error") or feed.get("kev_error"):
            detail += " 有来源查询失败，对应字段标为失败，其余字段保留。"
    return {
        "records": records,
        "feed": feed,
        "steps": [{
            "role": "富化",
            "action": "整理情报字段",
            "detail": detail,
        }],
    }
