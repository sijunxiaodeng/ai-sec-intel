from collectors.nvd import NVDCollector
from collectors.osv import OSVCollector


def _safe(name, func):
    try:
        items = func()
        return items, {
            "role": "监测",
            "action": "调用 %s" % name,
            "detail": "得到 %d 条" % len(items),
        }
    except Exception as exc:
        return [], {
            "role": "监测",
            "action": "调用 %s 失败" % name,
            "detail": "已跳过，其他来源继续。%s" % exc,
        }


def run(keyword="ollama"):
    keyword = keyword or "ollama"
    nvd_items, nvd_step = _safe("NVD", lambda: NVDCollector(keyword=keyword).collect())
    osv_items, osv_step = _safe("OSV", lambda: OSVCollector(keyword=keyword).collect())
    return {
        "items": nvd_items + osv_items,
        "steps": [nvd_step, osv_step],
    }
