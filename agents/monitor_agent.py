"""A consumes B's complete classified change feed; B owns public collection."""
from collectors.intelligence import IncrementalIntelligenceCollector


def run(keyword="llm"):
    # Keyword stays for API compatibility; display filters never limit import.
    # No environment switch bypasses B's shared classification policy.
    try:
        changes = IncrementalIntelligenceCollector(timeout=10).collect()
    except Exception as exc:
        raise RuntimeError("团队情报同步失败；旧数据保留，增量游标未推进") from exc
    items = changes["items"]
    return {
        "items": items, "team_changes": changes, "status": "success",
        "source_results": [{"source": "B", "status": "success", "fetched": len(items)}],
        "keywords": {"primary": keyword or "", "team": "all_valid_ai"},
        "steps": [{"role": "监测", "action": "同步团队情报服务全部有效 AI 变更",
                   "detail": "接收 %d 条，撤回 %d 条；保存成功后才提交持久游标。" %
                   (len(items), len(changes["retracted_ids"]))}],
    }
