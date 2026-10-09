"""V5 incremental priority worker. Additive to V4; reuses V4 schema/version."""
from __future__ import annotations

from pathlib import Path

from classification.hybrid_classifier import HybridAIClassifier
from .priority_v5 import plan_batch
from .store import ClassificationStore, utc_now
from .worker import _vulnerability_from_row


def run_priority_batch(db_path: str | Path, version: str,
                       max_items: int = 300, max_llm_calls: int = 2,
                       classifier=None, verbose: bool = True) -> dict:
    if max_items < 1 or max_llm_calls < 0 or not version.strip():
        raise ValueError("Bad max_items/max_llm_calls/version")
    store = ClassificationStore(db_path)
    judge = classifier if classifier is not None else HybridAIClassifier()
    start = utc_now()
    stats = {
        "selected": 0, "classified": 0, "positive": 0,
        "rule_positive": 0, "rule_negative": 0,
        "semantic_calls": 0, "semantic_success": 0,
        "needs_review": 0, "pending_llm": 0,
        "retry": 0, "stale_skipped": 0,
        "newly_classified": 0, "reclassified_or_resumed": 0,
        "max_items": max_items, "max_llm_calls": max_llm_calls,
    }
    try:
        selected, meta = plan_batch(store, version, judge, max_items, max_llm_calls)
        stats["selection"] = meta
        stats["selected"] = len(selected)
        for idx, cand in enumerate(selected, 1):
            row = cand.row
            cve_id = row["cve_id"]
            try:
                if cand.llm_required and stats["semantic_calls"] >= max_llm_calls:
                    state, result, error = "pending_llm", None, "LLM budget exhausted; postponed"
                else:
                    if cand.llm_required and judge.semantic_judge.is_configured():
                        # Count the attempted invocation, including API/parse failures.
                        stats["semantic_calls"] += 1
                    result = judge.classify_vulnerability(_vulnerability_from_row(row))
                    error = None
                    if result.decision_source in ("semantic_error", "semantic_unavailable"):
                        state, error = "retry", result.reason
                    elif result.needs_review:
                        state = "review"
                    else:
                        state = "classified"

                wrote = store.record(row, version, state, result=result, error=error)
                if not wrote:
                    stats["stale_skipped"] += 1
                    if verbose:
                        print(f"[{idx}/{len(selected)}] {cve_id}: stale, postponed", flush=True)
                    continue

                if state == "classified":
                    stats["classified"] += 1
                    if result.is_ai_related:
                        stats["positive"] += 1
                    if result.decision_source in ("rule_positive", "rule_negative"):
                        stats[result.decision_source] += 1
                elif state == "review":
                    stats["needs_review"] += 1
                    if result.is_ai_related:
                        stats["positive"] += 1
                elif state == "pending_llm":
                    stats["pending_llm"] += 1
                elif state == "retry":
                    stats["retry"] += 1
                if cand.llm_required and state in ("review", "classified"):
                    stats["semantic_success"] += 1
                if state in ("review", "classified"):
                    if cand.old_record:
                        stats["reclassified_or_resumed"] += 1
                    else:
                        stats["newly_classified"] += 1
                if verbose:
                    print(f"[{idx}/{len(selected)}] {cve_id}: {state} ({cand.priority})", flush=True)
            except Exception as exc:
                msg = f"{type(exc).__name__}: classification processing failed"
                try:
                    wrote = store.record(row, version, "retry", error=msg)
                    if wrote:
                        stats["retry"] += 1
                    else:
                        stats["stale_skipped"] += 1
                except Exception as db_exc:
                    raise RuntimeError(f"Cannot persist retry for {cve_id}") from db_exc
                if verbose:
                    print(f"[{idx}/{len(selected)}] {cve_id}: retry ({msg[:140]})", flush=True)
        stats["remaining"] = store.stats(version)
        store.log_run(start, version, max_items, max_llm_calls, stats, "success")
        return stats
    except Exception as exc:
        store.log_run(start, version, max_items, max_llm_calls, stats,
                      "failed", f"{type(exc).__name__}: {exc}")
        raise
