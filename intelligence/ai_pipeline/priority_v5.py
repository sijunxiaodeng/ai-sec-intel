"""V5 read-only candidate planner for the existing V4 SQLite tables.

Does not mutate source_items, unified_vulnerabilities or ai_classifications.
Scans the current unprocessed CVEs before selecting a batch, so an older
AI-specific advisory is not buried behind thousands of ordinary recent CVEs.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .store import ClassificationStore, utc_now
from .worker import _vulnerability_from_row


@dataclass
class Candidate:
    row: dict[str, Any]
    priority: str
    score: int
    llm_required: bool
    reason: str
    old_record: bool
    updated_at: str
    from_pending: bool = False

    def brief(self) -> dict[str, Any]:
        payload = json.loads(self.row["payload_json"])
        return {
            "cve_id": self.row["cve_id"],
            "tier": self.priority,
            "reason": self.reason,
            "requires_llm": self.llm_required,
            "previously_classified": self.old_record,
            "title": (payload.get("title") or "")[:120],
        }


def _packages(vuln) -> list[str]:
    result = []
    for item in vuln.affected_packages or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        eco = str(item.get("ecosystem", "") or "").strip()
        if name:
            result.append(f"{eco}:{name}" if eco else name)
    return result


def _rank(row: dict, judge, pending=False) -> Candidate:
    """The cheap classifier and keyword router run LOCALLY, never the LLM."""
    try:
        vuln = _vulnerability_from_row(row)
        packages = _packages(vuln)
        rule = judge.rule_classifier.classify(
            title=vuln.title or "", description=vuln.description or "",
            vendor=vuln.vendor or "", product=vuln.product or "",
            package_names=packages,
        )
        if rule.is_ai_related:
            tier, base, llm, reason = "rule_ai", 400, False, "规则命中明确的 AI 产品/概念"
        else:
            routed, hits = judge._should_use_semantic_judge(
                title=vuln.title or "", description=vuln.description or "",
                vendor=vuln.vendor or "", product=vuln.product or "",
                package_names=packages,
            )
            if routed:
                tier, base, llm, reason = "semantic_ai_candidate", 300, True, "语义候选:" + ",".join(hits[:4])
            elif vuln.known_exploited:
                tier, base, llm, reason = "kev_risk", 200, False, "CISA KEV 已知遭利用；但不代表 AI 相关"
            else:
                tier, base, llm, reason = "general", 100, False, "普通历史/增量回填"
        if vuln.known_exploited and base >= 300:
            base += 10
        if (vuln.cvss_score or 0) >= 9:
            base += 2
    except Exception as exc:
        # Do not lose a malformed CVE: send it to the worker for persisted retry.
        tier, base, llm, reason = "invalid_needs_retry", 50, False, f"预筛字段错误:{type(exc).__name__}"
    return Candidate(
        row=row, priority=tier, score=base, llm_required=llm,
        reason=reason, old_record=bool(row.get("previously_classified")),
        updated_at=row.get("content_updated_at") or "", from_pending=pending,
    )


def plan_batch(store: ClassificationStore, version: str, judge,
               max_items: int, max_llm_calls: int, preview: bool = False):
    if max_items < 1 or max_llm_calls < 0:
        raise ValueError("max_items must be >= 1 and max_llm_calls must be >= 0")

    # Scan the entire current stale/missing set, not just newest N rows.
    # For the user's ~11k CVEs this is practical and prevents AI candidates
    # getting stuck behind the much larger ordinary-CVE backlog.
    with store.connect() as con:
        fresh_rows = [dict(r) for r in con.execute("""
            SELECT v.cve_id, v.payload_json, v.content_sha256,
                   v.content_updated_at, a.cve_id IS NOT NULL AS previously_classified
            FROM unified_vulnerabilities v
            LEFT JOIN ai_classifications a ON a.cve_id=v.cve_id
            WHERE a.cve_id IS NULL
               OR a.content_sha256 != v.content_sha256
               OR a.classifier_version != ?
        """, (version,))]
        # Backlog is separate from fresh. Retry cooldown must be respected.
        ready_pending = [dict(r) for r in con.execute("""
            SELECT v.cve_id, v.payload_json, v.content_sha256,
                   v.content_updated_at, 1 AS previously_classified
            FROM ai_classifications a
            JOIN unified_vulnerabilities v ON v.cve_id=a.cve_id
            WHERE a.content_sha256=v.content_sha256
              AND a.classifier_version=?
              AND (a.state='pending_llm' OR
                  (a.state='retry' AND (a.retry_after IS NULL OR a.retry_after<=?)))
        """, (version, utc_now()))] if max_llm_calls > 0 else []

    fresh = [_rank(r, judge) for r in fresh_rows]
    pending = [_rank(r, judge, pending=True) for r in ready_pending]
    # Rank by AI relevance first, then recency. Use CVE as stable tie-breaker.
    fresh.sort(key=lambda c: (c.score, c.updated_at, c.row["cve_id"]), reverse=True)
    pending.sort(key=lambda c: (c.score, c.updated_at, c.row["cve_id"]), reverse=True)

    # V5.1: budget is shared fairly between fresh semantic candidates and
    # previous pending records, but *unused* fresh semantic slots are given
    # back to pending. This avoids using only one of two API slots when there
    # are 178 pending records and no new semantic candidates.
    if max_llm_calls == 0:
        # Preserve V5 zero-budget mode: scan and queue fresh semantic items
        # as pending_llm without contacting a provider.
        selected = fresh[:max_items]
        pending_llm_quota = 0
        fresh_llm_quota = 0
    else:
        llm_budget = min(max_llm_calls, max_items)
        old_llm = [c for c in pending if c.llm_required]
        new_llm = [c for c in fresh if c.llm_required]

        # Reserve half of model calls for the old backlog (ceil to guarantee
        # progress with a one-call limit). The rest goes to fresh candidates.
        pending_llm_quota = min(len(old_llm), (llm_budget + 1) // 2)
        fresh_llm_quota = min(len(new_llm), llm_budget - pending_llm_quota)

        # The crucial V5.1 fix: reallocate any unused *fresh* share to old
        # pending records, then return unused old share to fresh candidates.
        spare = llm_budget - pending_llm_quota - fresh_llm_quota
        take_old = min(spare, len(old_llm) - pending_llm_quota)
        pending_llm_quota += take_old
        spare -= take_old
        fresh_llm_quota += min(spare, len(new_llm) - fresh_llm_quota)

        selected = old_llm[:pending_llm_quota] + new_llm[:fresh_llm_quota]
        chosen = {c.row["cve_id"] for c in selected}

        # Apply cheap rule classification without consuming API budget. AI
        # entity rules still rank above KEV/general records within this lane.
        cheap = ([c for c in fresh if not c.llm_required]
                 + [c for c in pending if not c.llm_required])
        cheap.sort(key=lambda c: (c.score, c.updated_at, c.row["cve_id"]), reverse=True)
        for cand in cheap:
            if len(selected) >= max_items:
                break
            if cand.row["cve_id"] not in chosen:
                selected.append(cand)
                chosen.add(cand.row["cve_id"])

        # If fewer than max_items were selected, use otherwise-unprocessed new
        # semantic candidates as pending_llm; never burn more API calls than
        # max_llm_calls. Existing pending rows are intentionally not rewritten
        # once model budget is exhausted.
        for cand in new_llm[fresh_llm_quota:]:
            if len(selected) >= max_items:
                break
            if cand.row["cve_id"] not in chosen:
                selected.append(cand)
                chosen.add(cand.row["cve_id"])

    metadata = {
        "pending_llm_quota": pending_llm_quota,
        "fresh_llm_quota": fresh_llm_quota,
        "fresh_candidates": len(fresh),
        "ready_pending_candidates": len(pending),
        "fresh_tiers": dict(Counter(c.priority for c in fresh)),
        "selected_tiers": dict(Counter(c.priority for c in selected)),
        "selected_existing_pending": sum(c.from_pending for c in selected),
        "selected_new_or_changed": sum(not c.from_pending for c in selected),
        "preview": preview,
    }
    return selected, metadata
