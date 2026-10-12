"""监测智能体：NVD + OSV + 本机库 CVE（同属一次监测刷新）。

默认主关键词为 llm（不再只盯 ollama）。
逗号分隔多词时：NVD/OSV 只用第一个词（避免外网限流拖死），
本机库对每个词各查一次并按 cve_id 去重，以覆盖更广的 AI 安全集合。

Steps include optional did/got/produced/impact for the monitor pipeline panel.
"""
import os

from collectors.intelligence import IntelligenceCollector, team_base_url, team_intel_disabled
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

    # NVD 外网采集归 intelligence 模块（本机库）；壳侧不重复直采。
    # 仅当本机库关闭，或显式 ROOT_NVD_ENABLED=1 时走 legacy facade。
    setting = os.environ.get("ROOT_NVD_ENABLED")
    team_disabled = team_intel_disabled()
    root_nvd_enabled = (
        setting.strip().lower() not in {"0", "false", "no", "off"} if setting is not None else
        team_disabled
    )
    nvd = NVDCollector(keyword=primary) if root_nvd_enabled else None
    try:
        nvd_items = nvd.collect() if nvd is not None else []
        nvd_stats = dict(nvd.last_stats or {}) if nvd is not None else {
            "fetched": 0, "kept": 0, "external_fetches": 0, "disabled_duplicate": True,
        }
        nvd_ok = True
        nvd_err = ""
    except Exception as exc:
        nvd_items = []
        nvd_stats = {"fetched": 0, "kept": 0, "external_fetches": 0}
        nvd_ok = False
        nvd_err = str(exc)

    if nvd_stats.get("disabled_duplicate"):
        nvd_step = _step(
            "NVD 由本机库承担",
            "监测模块已采 NVD 入本机库；壳侧不重复联网查询",
            did="跳过壳侧 NVD 直采", got="本步骤无额外 NVD 请求", produced="由本机库步骤合并",
            impact="本机库未刷新时保留已有资料并展示状态",
            note="关闭本机库可设 TEAM_INTEL_MODE=off；临时回退可设 ROOT_NVD_ENABLED=1",
        )
    elif nvd_ok:
        wm = nvd_stats.get("watermark_before") or ""
        nvd_step = _step(
            "调用 NVD",
            "关键词 %s；得到 %d 条" % (primary, len(nvd_items)),
            did="按关键词完整分页查询 NVD：%s 至 %s"
            % (nvd_stats.get("window_start_at") or "历史起点",
               nvd_stats.get("window_end_at") or "本轮固定边界"),
            got="取回 %d 条候选" % nvd_stats.get("fetched", len(nvd_items)),
            produced="保留 %d 条进入整理" % len(nvd_items),
            impact="将与 OSV / 本机库结果合并后入库",
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
            produced="保留 %d 条（未保存或内容修订；其余延期续采）" % len(osv_items),
            impact="保留条将进入整理与入库；0 保留仍表示已查过",
            note=(
                "Batch %d packages；按包已入库修订续采（观察时间 %s）"
                % (osv_stats.get("packages_planned", 0), wm)
                if wm
                else "Batch %d packages；首次重放，按包确认入库后续采"
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
    for kw in ([] if team_disabled else team_keys):
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

    if team_disabled:
        team_step = _step(
            "跳过 本机库",
            "TEAM_INTEL_MODE 已禁用本机库，本轮不读本地情报库",
            did="按配置跳过来源", got="未发起查询", produced="0 条",
            impact="本轮仅使用已启用的 NVD/OSV 来源",
            note="禁用来源不计成功或失败",
        )
    elif team_err and not team_items:
        team_step = _step(
            "调用 本机库 失败",
            "已跳过，其他来源继续。%s" % team_err,
            did="读取本机情报库中的 CVE",
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
            "调用 本机库",
            detail,
            did="按关键词读入本机情报库 CVE",
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
            "nvd_disabled_duplicate": bool(nvd_stats.get("disabled_duplicate")),
            "osv_ok": osv_ok,
            "aggregate_disabled": team_disabled,
            "aggregate_ok": not team_disabled and not (team_err and not team_items),
        },
    }
