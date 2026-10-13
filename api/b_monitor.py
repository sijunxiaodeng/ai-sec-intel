"""Run B collection in an isolated process without changing A imports.

The embedded query API remains in A. Collector workers have their own package
namespace and process tree; a deadline terminates that tree rather than waiting
for a Python thread to finish its network work.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

_CYCLE_LOCK = threading.Lock()
_CLEANUP_TIMEOUT = 3
_MAX_RESULT_BYTES = 1024 * 1024


def b_monitor_enabled() -> bool:
    return os.environ.get("B_MONITOR_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def b_monitor_on_refresh() -> bool:
    return b_monitor_enabled() and os.environ.get("B_MONITOR_ON_REFRESH", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def _bounded(value, name, default, minimum, maximum):
    value = _int_env(name, default) if value is None else value
    if type(value) is not int:
        raise ValueError("%s must be an integer" % name)
    return max(minimum, min(value, maximum))


def _worker_command(root, db, result_path, source_timeout, workers, poll_minutes):
    return [os.environ.get("B_MONITOR_PYTHON") or sys.executable,
            str(root / "deployment" / "run_embedded_cycle.py"),
            "--db", str(db), "--result", str(result_path),
            "--timeout", str(source_timeout), "--workers", str(workers),
            "--poll-minutes", str(poll_minutes)]


def _stop_process_tree(child) -> bool:
    """Stop the owned worker and descendants, with bounded cleanup waits.

    Windows taskkill /T covers the worker's source subprocesses. POSIX workers
    start in a new session so killing their process group cannot kill A.
    Return false when tree termination could not be confirmed.
    """
    tree_stopped = False
    try:
        if os.name == "nt":
            killed = subprocess.run(
                ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=_CLEANUP_TIMEOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            tree_stopped = killed.returncode == 0
        else:
            try:
                os.killpg(child.pid, signal.SIGKILL)
                tree_stopped = True
            except ProcessLookupError:
                tree_stopped = True
    except (OSError, subprocess.SubprocessError):
        pass
    if child.poll() is None:
        try:
            child.kill()
        except OSError:
            pass
    try:
        child.wait(timeout=_CLEANUP_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return False
    return tree_stopped


def run_b_monitor_cycle(
    *, source_timeout: int | None = None, workers: int | None = None,
    overall_timeout: int | None = None,
) -> dict[str, Any]:
    """Run a collector worker; retain committed SQLite data after failures."""
    if not b_monitor_enabled():
        return {"status": "disabled", "mode": "embed", "execution": "subprocess", "sources": {}}
    if not _CYCLE_LOCK.acquire(blocking=False):
        return {"status": "skipped", "mode": "embed", "execution": "subprocess",
                "error": "B collector already running", "sources": {}}
    summary: dict[str, Any] = {"status": "failed", "mode": "embed", "execution": "subprocess"}
    child = None
    try:
        from api.b_embed import INTEL_ROOT, db_path
        from intelligence.deployment.state_role import claim_role
        db = db_path()
        # A mirror generation is immutable, even if its caller has write permission.
        for parent in (db.parent, *db.parents):
            marker = parent / ".writer-mode"
            if marker.exists() and marker.read_text().strip() == "actions-mirror":
                raise ValueError("Actions mirrors cannot run a second collector")
        claim_role(db.parent, "collector")
        source_timeout = _bounded(source_timeout, "B_MONITOR_SOURCE_TIMEOUT", 45, 5, 300)
        workers = _bounded(workers, "B_MONITOR_WORKERS", 4, 1, 8)
        overall_timeout = _bounded(overall_timeout, "B_MONITOR_OVERALL_TIMEOUT", 180, 1, 600)
        poll_minutes = _bounded(None, "MONITOR_INTERVAL_MINUTES", 15, 1, 1440)
        summary.update(db_path=str(db), source_timeout_seconds=source_timeout,
                       workers=workers, overall_timeout_seconds=overall_timeout)
        env = dict(
            os.environ,
            PYTHONUTF8="1",
            PYTHONIOENCODING="utf-8",
            CLASSIFY_V5_MAX_LLM_CALLS="0",
            CLASSIFY_V4_MAX_LLM_CALLS="0",
        )
        env.pop("DEEPSEEK_API_KEY", None)
        with tempfile.TemporaryDirectory(prefix="b-monitor-") as temporary:
            result_path = Path(temporary) / "result.json"
            command = _worker_command(INTEL_ROOT, db, result_path, source_timeout, workers, poll_minutes)
            with (Path(temporary) / "worker.log").open("wb") as log:
                options = {"start_new_session": True} if os.name != "nt" else {
                    "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
                }
                child = subprocess.Popen(command, cwd=INTEL_ROOT, env=env,
                                         stdout=log, stderr=subprocess.STDOUT, **options)
                try:
                    child.wait(timeout=overall_timeout)
                except subprocess.TimeoutExpired:
                    stopped = _stop_process_tree(child)
                    summary.update(status="timeout", termination_confirmed=stopped,
                                   error="B collector deadline exceeded; committed data retained"
                                         + ("; process tree termination unconfirmed" if not stopped else ""))
                    return summary
            if not result_path.is_file() or result_path.stat().st_size > _MAX_RESULT_BYTES:
                summary["error"] = "B collector worker produced no valid result (exit %s)" % child.returncode
                return summary
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if not isinstance(result, dict):
                raise ValueError("B collector worker returned an invalid result")
            sources = result.get("sources") or {}
            if not isinstance(sources, dict):
                raise ValueError("B collector worker returned invalid source names")
            status = result.get("status") or "failed"
            if child.returncode:
                status = "failed"
            summary.update(
                status=status if status in {"success", "partial", "skipped", "timeout", "failed", "disabled"} else "partial",
                configured_sources=result.get("configured_sources"),
                success_sources=result.get("success_sources"),
                failed_sources=result.get("failed_sources"),
                source_names=sorted(sources), error=result.get("error"),
            )
            if child.returncode and not summary["error"]:
                summary["error"] = "B collector worker failed (exit %s)" % child.returncode
            return summary
    except Exception as exc:
        if child is not None and child.poll() is None:
            summary["termination_confirmed"] = _stop_process_tree(child)
        summary["error"] = "%s: B collector worker could not complete" % type(exc).__name__
        return summary
    finally:
        _CYCLE_LOCK.release()


def run_b_monitor_async(callback=None) -> threading.Thread:
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
