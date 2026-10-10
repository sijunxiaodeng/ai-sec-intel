"""A 监测智能体：NVD + OSV + 团队情报（B）。

默认主关键词为 llm（不再只盯 ollama）。
逗号分隔多词时：NVD/OSV 只用第一个词（避免外网限流拖死），
团队情报对每个词各查一次并按 cve_id 去重，以覆盖更广的 AI 安全集合。
"""
from collectors.intelligence import IntelligenceCollector, team_base_url
from collectors.nvd import NVDCollector
from collectors.osv import OSVCollector

DEFAULT_PRIMARY = "llm"
DEFAULT_TEAM_KEYWORDS = (
    "llm",
    "vllm",
    "langchain",
    "huggingface",
    "openai",
    "ollama",
    "adversarial",
    "jailbreak",
)


def _parse_keywords(keyword):
    text = (keyword or "").strip()
    if not text:
        return [DEFAULT_PRIMARY], list(DEFAULT_TEAM_KEYWORDS)
    parts = [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]
    if not parts:
        return [DEFAULT_PRIMARY], list(DEFAULT_TEAM_KEYWORDS)
    primary = parts[0]
    # Multi-word input expands team search; single word still searches that word on team.
    team_keys = parts if len(parts) > 1 else parts
    return [primary], team_keys


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


def _merge_by_cve(batches):
    seen = {}
    order = []
    for batch in batches:
        for item in batch:
            cve = (item.get("cve_id") if isinstance(item, dict) else None) or ""
            key = cve or id(item)
            if key in seen:
                continue
            seen[key] = item
            order.append(item)
    return order


def run(keyword="llm"):
    primary_list, team_keys = _parse_keywords(keyword)
    primary = primary_list[0]
    # Cap team multi-pass (local B is cheap; still bound work).
    team_keys = team_keys[:8]

    nvd_items, nvd_step = _safe("NVD", lambda: NVDCollector(keyword=primary).collect())
    osv_items, osv_step = _safe("OSV", lambda: OSVCollector(keyword=primary).collect())

    team_batches = []
    team_raw = 0
    team_err = None
    # Short timeout + fail-fast: B down must not freeze the whole monitor click.
    team_timeout = 5
    for kw in team_keys:
        items, step = _safe(
            "团队情报服务(%s)" % kw,
            lambda k=kw: IntelligenceCollector(
                keyword=k, base_url=team_base_url(), timeout=team_timeout, max_pages=5
            ).collect(),
        )
        team_batches.append(items)
        team_raw += len(items)
        if "失败" in step["action"]:
            team_err = step["detail"]
            # Connection refused / unreachable → skip remaining keywords immediately.
            detail_l = (step.get("detail") or "").lower()
            if any(token in detail_l for token in (
                "connection refused", "连接被拒绝", "timed out", "timeout",
                "name or service not known", "network is unreachable", "errno 111",
            )):
                break
    team_items = _merge_by_cve(team_batches)

    if team_err and not team_items:
        team_step = {
            "role": "监测",
            "action": "调用 团队情报服务 失败",
            "detail": "已跳过，其他来源继续。%s" % team_err,
        }
    else:
        detail = "关键词 %s；得到 %d 条（去重后 %d）" % (
            "、".join(team_keys), team_raw, len(team_items),
        )
        if team_err:
            detail += "；部分关键词失败已跳过"
        team_step = {
            "role": "监测",
            "action": "调用 团队情报服务",
            "detail": detail,
        }

    # Annotate NVD/OSV steps with primary keyword for clarity in overview.
    if "失败" not in nvd_step["action"]:
        nvd_step["detail"] = "关键词 %s；%s" % (primary, nvd_step["detail"])
    if "失败" not in osv_step["action"]:
        osv_step["detail"] = "关键词 %s；%s" % (primary, osv_step["detail"])

    return {
        "items": nvd_items + osv_items + team_items,
        "steps": [nvd_step, osv_step, team_step],
        "keywords": {"primary": primary, "team": team_keys},
    }
