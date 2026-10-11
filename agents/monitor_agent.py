"""A 监测智能体：NVD + OSV + 团队情报（B）。

默认主关键词为 llm（不再只盯 ollama）。
逗号分隔多词时：NVD/OSV 只用第一个词（避免外网限流拖死），
团队情报对每个词各查一次并按 cve_id 去重，以覆盖更广的 AI 安全集合。
"""
import os
from dataclasses import asdict

from collectors.intelligence import IncrementalIntelligenceCollector, team_base_url
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


def _classify_direct(items):
    # Same public scope policy as B; a search keyword alone is not evidence.
    from intelligence.classification.scope_policy import classify_scope
    accepted = []
    for item in items:
        decision = asdict(classify_scope(title=item.get("title", ""),
                                  description=item.get("description", ""),
                                  product=item.get("product", ""), record_kind="vulnerability"))
        if decision["is_ai_related"] is True and not decision["needs_review"]:
            item.setdefault("raw_data", {})["scope_classification"] = decision
            accepted.append(item)
    return accepted


def run(keyword="llm"):
    primary_list, _ = _parse_keywords(keyword)
    primary = primary_list[0]
    items, steps, sources = [], [], []
    changes = None
    # Production consumes every valid B record, rather than an eight-keyword subset.
    if os.environ.get("TEAM_ONLY_COLLECT", "1").lower() in {"0", "false", "no", "off"}:
        for name, collector in (("NVD", NVDCollector(keyword=primary)),
                                ("OSV", OSVCollector(keyword=primary))):
            raw, step = _safe(name, collector.collect)
            failed = "失败" in step["action"]
            selected = _classify_direct(raw) if not failed else []
            items.extend(selected)
            steps.append(step)
            sources.append({"source": name, "status": "failed" if failed else "success",
                            "fetched": len(raw), "accepted": len(selected)})
    try:
        changes = IncrementalIntelligenceCollector(base_url=team_base_url(), timeout=10).collect()
        items.extend(changes["items"])
        steps.append({"role": "监测", "action": "同步团队情报服务全部有效 AI 变更",
                      "detail": "接收 %d 条，撤回 %d 条；保存成功后才提交持久游标。" %
                      (len(changes["items"]), len(changes["retracted_ids"]))})
        sources.append({"source": "B", "status": "success", "fetched": len(changes["items"])})
    except Exception as exc:
        steps.append({"role": "监测", "action": "同步团队情报服务失败",
                      "detail": "游标保持不变，下轮重试。%s" % type(exc).__name__})
        sources.append({"source": "B", "status": "failed", "fetched": 0})
    successes = sum(row["status"] == "success" for row in sources)
    if not successes:
        # Old knowledge must not turn a failed collection into a successful run.
        raise RuntimeError("本轮所有情报来源失败；旧数据保留，增量游标未推进")
    status = "success" if successes == len(sources) else "partial"
    return {"items": items, "steps": steps, "status": status, "source_results": sources,
            "team_changes": changes, "keywords": {"primary": primary, "team": "all_valid_ai"}}
