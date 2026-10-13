"""监测智能体：NVD + OSV + 多源 CVE（同属一次监测刷新）。

默认宽词为 llm；OSV 将宽词展开为已登记 AI 包集合。
NVD 不再永久只查首词 llm：对宽词/逗号串使用 AI 组件产品词
（open webui、vllm、ollama…）多词查询并按 CVE 去重，轮次有上限以防限流。

Steps include optional did/got/produced/impact for the monitor pipeline panel.
"""
import os
from datetime import datetime, timezone

from collectors.intelligence import IntelligenceCollector, team_base_url, team_intel_disabled
from collectors.nvd import NVDCollector
from collectors.osv import OSVCollector, BROAD_KEYWORDS

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
    "open-webui",
    "adversarial",
    "jailbreak",
)

# NVD free-text product terms (not OSV package ids). Prefer phrases NVD indexes.
NVD_PRODUCT_KEYWORDS = (
    "open webui",
    "vllm",
    "ollama",
    "transformers",
    "langchain",
    "openai",
    "huggingface",
    "llama-index",
)


def _nvd_keyword_limit():
    try:
        raw = int(os.environ.get("NVD_KEYWORD_LIMIT", "5") or "5")
    except ValueError:
        raw = 5
    return max(1, min(8, raw))


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


def _is_broad(token):
    return (token or "").strip().lower() in BROAD_KEYWORDS


def _nvd_keywords(parts):
    """Pick NVD free-text terms for this round (capped, rotated).

    Broad-only / empty → AI product stack.
    Comma list → concrete tokens first (drop abstract llm/ai/…), else stack.
    Single concrete token → that token only.
    """
    limit = _nvd_keyword_limit()
    cleaned = [p.strip() for p in (parts or []) if p and p.strip()]
    if not cleaned or (len(cleaned) == 1 and _is_broad(cleaned[0])):
        candidates = list(NVD_PRODUCT_KEYWORDS)
    elif len(cleaned) == 1:
        candidates = cleaned
    else:
        concrete = [p for p in cleaned if not _is_broad(p)]
        candidates = concrete if concrete else list(NVD_PRODUCT_KEYWORDS)
    # De-dupe case-insensitively, preserve order.
    seen, ordered = set(), []
    for item in candidates:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    if len(ordered) <= limit:
        return ordered
    # Pin highest-priority products (open webui first), rotate the remainder.
    pinned_n = min(2, limit)
    pinned = ordered[:pinned_n]
    rest = ordered[pinned_n:]
    now = datetime.now(timezone.utc)
    start = (now.timetuple().tm_yday + now.hour) % len(rest) if rest else 0
    rotated = (rest[start:] + rest[:start]) if rest else []
    return pinned + rotated[: max(0, limit - len(pinned))]


class _CursorGroup(object):
    """Commit several collectors after a successful upsert (NVD multi-keyword)."""

    def __init__(self, collectors):
        self._collectors = [c for c in (collectors or []) if c is not None]

    def commit_cursor(self):
        for coll in self._collectors:
            if hasattr(coll, "commit_cursor"):
                coll.commit_cursor()


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


def _sum_stats(rows):
    out = {
        "fetched": 0,
        "kept": 0,
        "external_fetches": 0,
        "keywords": [],
        "keyword_ok": 0,
        "keyword_fail": 0,
    }
    watermarks = []
    for row in rows:
        stats = row.get("stats") or {}
        out["fetched"] += int(stats.get("fetched") or 0)
        out["kept"] += int(stats.get("kept") or 0)
        out["external_fetches"] += int(stats.get("external_fetches") or 0)
        if stats.get("watermark_before"):
            watermarks.append(stats["watermark_before"])
        if row.get("ok"):
            out["keyword_ok"] += 1
        else:
            out["keyword_fail"] += 1
        out["keywords"].append(row.get("keyword") or "")
    if watermarks:
        out["watermark_before"] = max(watermarks)
    if rows:
        # Surfaces first window bounds for the pipeline note (best-effort).
        first = (rows[0].get("stats") or {})
        out["window_start_at"] = first.get("window_start_at") or ""
        out["window_end_at"] = first.get("window_end_at") or ""
    return out


def run(keyword="llm"):
    primary_list, team_keys = _parse_keywords(keyword)
    primary = primary_list[0]
    # Cap team multi-pass (local embed is cheap; still bound work).
    team_keys = team_keys[:10]
    # NVD uses product terms (or concrete tokens from the comma list), not only llm.
    text = (keyword or "").strip()
    parts = [p.strip() for p in text.replace(";", ",").split(",") if p.strip()] if text else []
    nvd_keys = _nvd_keywords(parts if parts else [primary])

    # NVD 外网采集归 intelligence 模块；壳侧不重复直采。
    # 仅当多源情报关闭，或显式 ROOT_NVD_ENABLED=1 时走 legacy facade。
    setting = os.environ.get("ROOT_NVD_ENABLED")
    team_disabled = team_intel_disabled()
    root_nvd_enabled = (
        setting.strip().lower() not in {"0", "false", "no", "off"} if setting is not None else
        team_disabled
    )

    nvd_collectors = []
    nvd_batches = []
    nvd_rows = []
    if root_nvd_enabled:
        for kw in nvd_keys:
            coll = NVDCollector(keyword=kw)
            try:
                items = coll.collect()
                nvd_batches.append(items)
                nvd_collectors.append(coll)
                nvd_rows.append({"keyword": kw, "ok": True, "stats": dict(coll.last_stats or {}), "err": ""})
            except Exception as exc:
                nvd_rows.append({
                    "keyword": kw, "ok": False,
                    "stats": {"fetched": 0, "kept": 0, "external_fetches": 0},
                    "err": str(exc),
                })
        nvd_items = _merge_by_cve(nvd_batches)
        nvd_stats = _sum_stats(nvd_rows)
        nvd_stats["kept"] = len(nvd_items)
        nvd_ok = bool(nvd_stats["keyword_ok"])
        nvd_err = "；".join(
            "%s: %s" % (row["keyword"], row["err"][:120])
            for row in nvd_rows if not row["ok"] and row.get("err")
        )
    else:
        nvd_items = []
        nvd_stats = {
            "fetched": 0, "kept": 0, "external_fetches": 0,
            "disabled_duplicate": True, "keywords": [],
        }
        nvd_ok = True
        nvd_err = ""

    if nvd_stats.get("disabled_duplicate"):
        nvd_step = _step(
            "NVD 由监测模块承担",
            "监测模块已采 NVD 入知识库链路；壳侧不重复联网查询",
            did="跳过壳侧 NVD 直采", got="本步骤无额外 NVD 请求", produced="由多源情报步骤合并",
            impact="多源情报未刷新时保留已有资料并展示状态",
            note="关闭多源情报可设 TEAM_INTEL_MODE=off；临时回退可设 ROOT_NVD_ENABLED=1",
        )
    elif nvd_ok:
        labels = "、".join(nvd_stats.get("keywords") or nvd_keys) or primary
        fail_note = ""
        if nvd_stats.get("keyword_fail"):
            fail_note = "；%d 个词失败已跳过" % nvd_stats["keyword_fail"]
        wm = nvd_stats.get("watermark_before") or ""
        nvd_step = _step(
            "调用 NVD",
            "关键词 %s；查询返回 %d，去重后保留 %d%s"
            % (labels, nvd_stats.get("fetched", 0), len(nvd_items), fail_note),
            did="按 AI 组件产品词分词查询 NVD（每轮最多 %d 个，轮换覆盖）" % _nvd_keyword_limit(),
            got="取回 %d 条候选（多词合计）" % nvd_stats.get("fetched", len(nvd_items)),
            produced="去重后保留 %d 条进入整理" % len(nvd_items),
            impact="将与 OSV / 多源情报结果合并后入库",
            note=("上次位点 %s" % wm) if wm else "首次或无游标：使用默认近窗",
            ok=True,
        )
    else:
        nvd_step = _step(
            "调用 NVD 失败",
            "已跳过，其他来源继续。%s" % nvd_err,
            did="尝试按产品词访问 NVD API",
            got="失败",
            produced="0 条",
            impact="本轮无 NVD 增量",
            note=nvd_err[:200],
            ok=False,
        )

    # OSV: broad primary still expands PACKAGES (incl. open-webui).
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
            "宽词/首词 %s → AI 组件包；查询返回 %d，水位后保留 %d"
            % (primary, osv_stats.get("fetched", 0), osv_stats.get("kept", len(osv_items))),
            did="按已登记 AI 组件包批量查询 OSV API",
            got="外部请求 %d 次包查询，查询返回 %d 条原始记录（含水位前历史）"
            % (osv_stats.get("packages_queried", 0), osv_stats.get("fetched", 0)),
            produced="水位后保留 %d 条（未保存或内容修订；其余延期续采）" % len(osv_items),
            impact="水位后保留条将进入整理与入库；0 保留仍表示已查过",
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
            "跳过 多源情报",
            "TEAM_INTEL_MODE 已禁用多源情报，本轮不读嵌入情报数据",
            did="按配置跳过来源", got="未发起查询", produced="0 条",
            impact="本轮仅使用已启用的 NVD/OSV 来源",
            note="禁用来源不计成功或失败",
        )
    elif team_err and not team_items:
        team_step = _step(
            "调用 多源情报 失败",
            "已跳过，其他来源继续。%s" % team_err,
            did="读取多源情报中的 CVE",
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
            "调用 多源情报",
            detail,
            did="按关键词读入多源情报 CVE",
            got="原始 %d 条" % team_raw,
            produced="去重后 %d 条" % len(team_items),
            impact="与 NVD/OSV 一并整理、入库",
            note="查询轮次 %d" % team_fetches,
            ok=True,
        )

    # Product copy: hit →「查询返回」(raw API rows, pre-cursor); kept →「水位后保留」.
    # OSV fetched sums ALL vulns returned per package (incl. already-saved revisions).
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

    nvd_handle = _CursorGroup(nvd_collectors) if nvd_collectors else None

    return {
        "items": nvd_items + osv_items + team_items,
        "steps": [nvd_step, osv_step, team_step],
        "keywords": {"primary": primary, "nvd": nvd_keys, "team": team_keys},
        "collectors": {"nvd": nvd_handle if nvd_ok else None, "osv": osv if osv_ok else None},
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
