"""Invoke B's multi-source monitor cycle inside the A process.

Uses intelligence/monitoring.multisource.run_cycle (same as run_monitor.py --once).
Per-source timeouts and overall wall-clock budget — partial success is OK.
Does not require a separate :8765 process or intelligence/.venv.
"""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any


def b_monitor_enabled() -> bool:
    return os.environ.get("B_MONITOR_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def b_monitor_on_refresh() -> bool:
    """Whether /api/monitor/run and the schedule should refresh B before reading."""
    if not b_monitor_enabled():
        return False
    return os.environ.get("B_MONITOR_ON_REFRESH", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def run_b_monitor_cycle(
    *,
    source_timeout: int | None = None,
    workers: int | None = None,
    overall_timeout: int | None = None,
) -> dict[str, Any]:
    """Run one B multi-source cycle in-process. Never raises for source failures."""
    if not b_monitor_enabled():
        return {"status": "disabled", "mode": "embed", "sources": {}}

    from api.b_embed import INTEL_ROOT, db_path, ensure_intelligence_path

    ensure_intelligence_path()
    root = INTEL_ROOT
    db = db_path()
    source_timeout = source_timeout if source_timeout is not None else _int_env(
        "B_MONITOR_SOURCE_TIMEOUT", 45
    )
    workers = workers if workers is not None else _int_env("B_MONITOR_WORKERS", 4)
    overall_timeout = overall_timeout if overall_timeout is not None else _int_env(
        "B_MONITOR_OVERALL_TIMEOUT", 180
    )
    # Keep demo responsive; clamp to sane bounds.
    source_timeout = max(5, min(source_timeout, 300))
    workers = max(1, min(workers, 8))
    overall_timeout = max(15, min(overall_timeout, 600))

    from monitoring.multisource import run_cycle

    holder: dict[str, Any] = {}

    def _call():
        holder["result"] = run_cycle(
            root,
            db_path=db,
            workers=workers,
            timeout_seconds=source_timeout,
            poll_interval_minutes=_int_env("MONITOR_INTERVAL_MINUTES", 15),
        )

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_call)
            fut.result(timeout=overall_timeout)
        result = holder.get("result") or {"status": "failed", "error": "empty result"}
    except FuturesTimeout:
        result = {
            "status": "timeout",
            "error": "B monitor exceeded %ss wall clock — seed/partial DB kept" % overall_timeout,
            "sources": {},
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "error": "%s: %s" % (type(exc).__name__, exc)[:200],
            "sources": {},
        }

    # Normalize for A UI / smoke
    status = result.get("status") or "failed"
    sources = result.get("sources") or {}
    summary = {
        "status": status,
        "mode": "embed",
        "db_path": str(db),
        "source_timeout_seconds": source_timeout,
        "workers": workers,
        "overall_timeout_seconds": overall_timeout,
        "configured_sources": result.get("configured_sources"),
        "success_sources": result.get("success_sources"),
        "failed_sources": result.get("failed_sources"),
        "source_names": sorted(sources.keys()) if isinstance(sources, dict) else [],
        "error": result.get("error"),
    }
    if status in {"success", "partial", "skipped", "timeout", "failed", "disabled"}:
        return summary
    summary["status"] = "partial"
    return summary


def run_b_monitor_async(callback=None) -> threading.Thread:
    """Fire-and-forget wrapper for schedule startup (daemon)."""

    def _target():
        result = run_b_monitor_cycle()
        if callback:
            try:
                callback(result)
            except Exception:
                pass

    thread = threading.Thread(target=_target, name="b-monitor-cycle", daemon=True)
    thread.start()
    return thread
