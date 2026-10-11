"""监测智能体：NVD + OSV + 聚合库 CVE（同属情报监测一条流水线）。

默认主关键词为 llm（不再只盯 ollama）。
逗号分隔多词时：NVD/OSV 只用第一个词（避免外网限流拖死），
聚合库对每个词各查一次并按 cve_id 去重，以覆盖更广的 AI 安全集合。

Steps include optional did/got/produced/impact for the monitor pipeline panel.
"""
from collectors.intelligence import IntelligenceCollector, team_base_url
from collectors.nvd import NVDCollector
from collectors.osv import OSVCollector

DEFAULT_PRIMARY = "llm"
DEFAULT_TEAM_KEYWORDS = (
    "llm",
    "vllm",
    "transformers",
    "langchain",
    "llama-index",
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


def _step(action, detail, *, did="", got="", produced="", impact="", note="", ok=True):
    row = {
        "role": "监测",
        "action": action if ok else (action if "失败" in action else action + " 失败"),
        "detail": detail,
    }
    if did:
        row["did"] = did
    if got:
        row["got"] = got
    if produced:
        row["produced"] = produced
    if impact:
        row["impact"] = impact
    if note:
        row["note"] = note
    return row


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
    # Cap team multi-pass (local embed is cheap; still bound work).
    team_keys = team_keys[:10]

    nvd = NVDCollector(keyword=primary)
    try:
        nvd_items = nvd.collect()
        nvd_stats = dict(nvd.last_stats or {})
        nvd_ok = True
        nvd_err = ""
    except Exception as exc:
        nvd_items = []
        nvd_stats = {"fetched": 0, "kept": 0, "external_fetches": 0}
        nvd_ok = False
        nvd_err = str(exc)

    if nvd_ok:
        wm = nvd_stats.get("watermark_before") or ""
        nvd_step = _step(
            "调用 NVD",
            "关键词 %s；得到 %d 条" % (primary, len(nvd_items)),
            did="按关键词查询 NVD，变更窗 %s 天%s"
            % (
                nvd_stats.get("last_mod_days") if nvd_stats.get("last_mod_days") is not None else "不限",
                "（自上次成功位点续查）" if nvd_stats.get("incremental") else "",
            ),
            got="取回 %d 条候选" % nvd_stats.get("fetched", len(nvd_items)),
            produced="保留 %d 条进入整理" % len(nvd_items),
            impact="将与 OSV / 聚合库结果合并后入库",
            note=("上次位点 %s" % wm) if wm else "首次或无游标：使用默认近窗",
            ok=True,
        )
    else:
        nvd_step = _step(
            "调用 NVD 失败",
            "已跳过，其他来源继续。%s" % nvd_err,
            did="尝试访问 NVD API",
            got="失败",
            produced="0 条",
            impact="本轮无 NVD 增量",
            note=nvd_err[:200],
            ok=False,
        )

    osv = OSVCollector(keyword=primary)
    try:
        osv_items = osv.collect()
        osv_stats = dict(osv.last_stats or {})
        osv_ok = True
        osv_err = ""
    except Exception as exc:
        osv_items = []
        osv_stats = {"fetched": 0, "kept": 0, "external_fetches": 0, "packages_queried": 0}
        osv_ok = False
        osv_err = str(exc)

    if osv_ok:
        wm = osv_stats.get("watermark_before") or ""
        osv_step = _step(
            "调用 OSV",
            "关键词 %s；命中 %d，保留 %d"
            % (primary, osv_stats.get("fetched", 0), osv_stats.get("kept", len(osv_items))),
            did="按已登记 AI 组件包批量查询 OSV API",
            got="外部取回 %d 次包查询，命中 %d 条原始记录"
            % (osv_stats.get("packages_queried", 0), osv_stats.get("fetched", 0)),
            produced="保留 %d 条（游标之后的更新；单包有上限）" % len(osv_items),
            impact="保留条将进入整理与入库；0 保留仍表示已查过",
            note=(
                "Batch %d packages；自上次位点 %s 续查"
                % (osv_stats.get("packages_planned", 0), wm)
                if wm
                else "Batch %d packages；无游标，本轮全量截断保留"
                % osv_stats.get("packages_planned", 0)
            ),
            ok=True,
        )
    else:
        osv_step = _step(
            "调用 OSV 失败",
            "已跳过，其他来源继续。%s" % osv_err,
            did="尝试批量查询 OSV",
            got="失败",
            produced="0 条",
            impact="本轮无 OSV 增量",
            note=osv_err[:200],
            ok=False,
        )

    team_batches = []
    team_raw = 0
    team_err = None
    team_fetches = 0
    # Short timeout + fail-fast: B down must not freeze the whole monitor click.
    team_timeout = 5
    for kw in team_keys:
        try:
            items = IntelligenceCollector(
                keyword=kw, base_url=team_base_url(), timeout=team_timeout, max_pages=5
            ).collect()
            team_fetches += 1
            team_batches.append(items)
            team_raw += len(items)
        except Exception as exc:
            team_err = str(exc)
            detail_l = team_err.lower()
            if any(token in detail_l for token in (
                "connection refused", "连接被拒绝", "timed out", "timeout",
                "name or service not known", "network is unreachable", "errno 111",
            )):
                break
    team_items = _merge_by_cve(team_batches)

    if team_err and not team_items:
        team_step = _step(
            "调用 聚合库 失败",
            "已跳过，其他来源继续。%s" % team_err,
            did="读取本机聚合库中的 CVE",
            got="失败",
            produced="0 条",
            impact="本轮其余来源（NVD/OSV）仍继续",
            note=team_err[:200],
            ok=False,
        )
    else:
        detail = "关键词 %s；得到 %d 条（去重后 %d）" % (
            "、".join(team_keys), team_raw, len(team_items),
        )
        if team_err:
            detail += "；部分关键词失败已跳过"
        team_step = _step(
            "调用 聚合库",
            detail,
            did="按关键词读入本机聚合库 CVE（监测一路，非第二产品）",
            got="原始 %d 条" % team_raw,
            produced="去重后 %d 条" % len(team_items),
            impact="与 NVD/OSV 一并整理、入库",
            note="查询轮次 %d" % team_fetches,
            ok=True,
        )

    hit = (
        int(nvd_stats.get("fetched") or 0)
        + int(osv_stats.get("fetched") or 0)
        + int(team_raw or 0)
    )
    kept = len(nvd_items) + len(osv_items) + len(team_items)
    external = (
        int(nvd_stats.get("external_fetches") or 0)
        + int(osv_stats.get("external_fetches") or 0)
        + int(team_fetches or 0)
    )

    return {
        "items": nvd_items + osv_items + team_items,
        "steps": [nvd_step, osv_step, team_step],
        "keywords": {"primary": primary, "team": team_keys},
        "collectors": {"nvd": nvd if nvd_ok else None, "osv": osv if osv_ok else None},
        "stats": {
            "hit": hit,
            "kept": kept,
            "nvd": nvd_stats,
            "osv": osv_stats,
            "aggregate_raw": team_raw,
            "aggregate_kept": len(team_items),
            "external_fetches": external,
            "nvd_ok": nvd_ok,
            "osv_ok": osv_ok,
            "aggregate_ok": not (team_err and not team_items),
        },
    }
