"""An inspectable, rule-based planner for the durable enrichment worker."""
import re

PUBLIC_FEEDS = "enrichment.public_feeds"
PAPERS = "enrichment.papers"


def enrichment_plan(records, previous_errors=()):
    """Choose priority from explicit mechanisms or retry feedback; retain both tools."""
    errors = set(part for error in previous_errors for part in str(error).split(","))
    reason, policy = "补充利用概率与已知利用情况，再检索关联论文。", "impact_first"
    tools = [PUBLIC_FEEDS, PAPERS]
    if "papers_error" in errors and not errors.intersection({"epss_error", "kev_error", "public_feeds_error"}):
        tools = [PAPERS, PUBLIC_FEEDS]
        reason, policy = "上次论文工具失败，先重试该工具；其余维度继续执行。", "retry_feedback"
    elif errors.intersection({"epss_error", "kev_error", "public_feeds_error"}):
        reason, policy = "上次影响评估源失败，先重试该工具；论文查询独立执行。", "retry_feedback"
    else:
        text = " ".join(str(row.get("item", {}).get(key) or "") for row in records
                        for key in ("title", "description"))
        if re.search(r"(?<![a-z])(?:prompt[ -]+injection|data[ -]+poisoning|model[ -]+poisoning)(?![a-z])|提示(?:词)?注入|(?:数据|模型)投毒", text, re.I):
            tools = [PAPERS, PUBLIC_FEEDS]
            reason, policy = "情报明确提及提示注入或投毒机制，优先检索研究依据，再补充利用情况。", "research_first"
    return {"framework": "bounded-planner-executor-v1", "role": "enrichment",
            "decision": {"policy": policy, "reason": reason, "tools": tools}, "calls": []}
