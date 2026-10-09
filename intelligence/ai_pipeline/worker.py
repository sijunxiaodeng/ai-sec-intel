"""Budget-limited, resumable Hybrid V3.1 classification.

Original source_items/unified_vulnerabilities tables are read-only to this stage.
"""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

from classification.hybrid_classifier import HybridAIClassifier
from fusion.models import UnifiedVulnerability

from .store import ClassificationStore, utc_now


def _vulnerability_from_row(row: dict[str, Any]) -> UnifiedVulnerability:
    payload = json.loads(row["payload_json"])
    if not isinstance(payload, dict):
        raise ValueError("unified payload must be a JSON object")
    allowed = {f.name for f in fields(UnifiedVulnerability)}
    data = {k: v for k, v in payload.items() if k in allowed}
    if not data.get("cve_id"):
        data["cve_id"] = row["cve_id"]
    return UnifiedVulnerability(**data)


def _row_requires_semantic(row: dict[str, Any], judge) -> bool:
    try:
        vuln = _vulnerability_from_row(row)
        packages = []
        for pkg in vuln.affected_packages or []:
            if isinstance(pkg, dict) and pkg.get("name"):
                ecosystem = str(pkg.get("ecosystem") or "").strip()
                name = str(pkg["name"]).strip()
                packages.append(f"{ecosystem}:{name}" if ecosystem else name)
        inputs = dict(title=vuln.title or "", description=vuln.description or "",
                      vendor=vuln.vendor or "", product=vuln.product or "",
                      package_names=packages)
        if judge.rule_classifier.classify(**inputs).is_ai_related:
            return False
        return judge._should_use_semantic_judge(**inputs)[0]
    except Exception:
        return False


def run_batch(
    db_path: str | Path,
    version: str,
    max_items: int = 40,
    max_llm_calls: int = 3,
    classifier: HybridAIClassifier | None = None,
    *,
    verbose: bool = True,
) -> dict:
    if max_items < 1:
        raise ValueError("max_items must be >= 1")
    if max_llm_calls < 0:
        raise ValueError("max_llm_calls must be >= 0")
    if not version.strip():
        raise ValueError("classifier version is empty")

    store = ClassificationStore(db_path)
    judge = classifier if classifier is not None else HybridAIClassifier()
    start = utc_now()
    stats = {
        "selected": 0, "classified": 0, "positive": 0,
        "rule_positive": 0, "rule_negative": 0,
        "semantic_calls": 0, "semantic_success": 0,
        "needs_review": 0, "pending_llm": 0,
        "retry": 0, "stale_skipped": 0,
        "max_items": max_items, "max_llm_calls": max_llm_calls,
    }
    try:
        # Process reserved old work first; fresh candidates cannot consume
        # its model budget. Local retries must also progress with zero budget.
        older_ready = store.pending(version, 2**31 - 1)
        if max_llm_calls == 0:
            older_ready = [row for row in older_ready if not _row_requires_semantic(row, judge)]
        pending_slots = max(1, max_items // 4) if older_ready else 0
        older = older_ready[:pending_slots]
        new = store.fresh(version, max_items - len(older))
        if len(new) + len(older) < max_items:
            older = older_ready[:max_items - len(new)]
        selected = older + new
        stats["selected"] = len(selected)

        for i, row in enumerate(selected, 1):
            cve = row["cve_id"]
            try:
                vuln = _vulnerability_from_row(row)
                packages = []
                for pkg in vuln.affected_packages or []:
                    if isinstance(pkg, dict):
                        name = str(pkg.get("name", "") or "").strip()
                        ecosystem = str(pkg.get("ecosystem", "") or "").strip()
                        if name:
                            packages.append(f"{ecosystem}:{name}" if ecosystem else name)

                rule = judge.rule_classifier.classify(
                    title=vuln.title or "",
                    description=vuln.description or "",
                    vendor=vuln.vendor or "",
                    product=vuln.product or "",
                    package_names=packages,
                )
                to_llm = False
                if not rule.is_ai_related:
                    to_llm, _ = judge._should_use_semantic_judge(
                        title=vuln.title or "",
                        description=vuln.description or "",
                        vendor=vuln.vendor or "",
                        product=vuln.product or "",
                        package_names=packages,
                    )

                if to_llm and stats["semantic_calls"] >= max_llm_calls:
                    state, result, error = "pending_llm", None, "Reached LLM budget for this run"
                    # Do not overwrite an existing retry/error when budget is spent.
                    if row.get("previous_state"):
                        continue
                else:
                    if to_llm and judge.semantic_judge.is_configured():
                        stats["semantic_calls"] += 1
                    result = judge.classify_vulnerability(vuln)
                    if result.decision_source in ("semantic_unavailable", "semantic_error"):
                        state = "retry"
                        error = result.reason
                    elif result.needs_review:
                        state, error = "review", None
                    else:
                        state, error = "classified", None

                wrote = store.record(row, version, state, result=result, error=error)
                if not wrote:
                    stats["stale_skipped"] += 1
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
                if to_llm and state in ("review", "classified"):
                    stats["semantic_success"] += 1
                if verbose:
                    print(f"[{i}/{len(selected)}] {cve}: {state}", flush=True)

            except Exception as exc:
                message = f"{type(exc).__name__}: classification processing failed"
                # Classifier/data errors are persisted as retry, not false-negative.
                try:
                    if store.record(row, version, "retry", error=message):
                        stats["retry"] += 1
                    else:
                        stats["stale_skipped"] += 1
                except Exception as db_exc:
                    # Do NOT swallow database failures; surface them for alerting.
                    raise RuntimeError(
                        f"Cannot persist classification retry for {cve}"
                    ) from db_exc
                if verbose:
                    print(f"[{i}/{len(selected)}] {cve}: retry ({message[:200]})", flush=True)

        stats["remaining"] = store.stats(version)
        store.log_run(start, version, max_items, max_llm_calls, stats, "success")
        return stats

    except Exception as exc:
        store.log_run(start, version, max_items, max_llm_calls,
                      stats, "failed", f"{type(exc).__name__}: {exc}")
        raise
