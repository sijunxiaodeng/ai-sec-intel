"""Optional local B collector with process isolation and a real wall-clock limit.

Formal sidecar / Actions deployments keep this disabled. Running a collector in
its own process avoids changing A's collectors imports while handling requests.
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

_CYCLE_LOCK = threading.Lock()


def b_monitor_enabled():
    return os.environ.get("B_MONITOR_ENABLED", "0").lower() in {"1", "true", "yes", "on"}


def b_monitor_on_refresh():
    return b_monitor_enabled() and os.environ.get("B_MONITOR_ON_REFRESH", "1").lower() not in {"0", "false", "no", "off"}


def _integer(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def run_b_monitor_cycle(*, source_timeout=None, workers=None, overall_timeout=None):
    if not b_monitor_enabled():
        return {"status": "disabled", "mode": "subprocess", "sources": {}}
    if not _CYCLE_LOCK.acquire(blocking=False):
        return {"status": "skipped", "mode": "subprocess", "error": "collector already running"}
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
        source_timeout = max(5, min(source_timeout or _integer("B_MONITOR_SOURCE_TIMEOUT", 45), 300))
        workers = max(1, min(workers or _integer("B_MONITOR_WORKERS", 4), 8))
        overall_timeout = max(1, min(overall_timeout or _integer("B_MONITOR_OVERALL_TIMEOUT", 180), 600))
        env = dict(os.environ, CLASSIFY_V5_MAX_LLM_CALLS="0", CLASSIFY_V4_MAX_LLM_CALLS="0")
        env.pop("DEEPSEEK_API_KEY", None)
        with tempfile.TemporaryDirectory(prefix="b-monitor-") as temporary:
            result_path = Path(temporary) / "result.json"
            command = [os.environ.get("B_MONITOR_PYTHON") or sys.executable,
                       str(INTEL_ROOT / "deployment" / "run_embedded_cycle.py"),
                       "--db", str(db), "--result", str(result_path),
                       "--timeout", str(source_timeout), "--workers", str(workers)]
            with (Path(temporary) / "worker.log").open("wb") as log:
                child = subprocess.Popen(command, cwd=INTEL_ROOT, env=env, stdout=log,
                                         stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
                try:
                    child.wait(timeout=overall_timeout)
                except subprocess.TimeoutExpired:
                    if os.name == "nt":
                        subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                    else:
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                    return {"status": "timeout", "mode": "subprocess",
                            "error": "collector deadline exceeded; committed data retained"}
            if child.returncode or not result_path.is_file():
                return {"status": "failed", "mode": "subprocess", "error": "collector process failed"}
            result = json.loads(result_path.read_text())
        return {"status": result.get("status", "failed"), "mode": "subprocess",
                "configured_sources": result.get("configured_sources"),
                "success_sources": result.get("success_sources"),
                "failed_sources": result.get("failed_sources"),
                "source_names": sorted((result.get("sources") or {}).keys()),
                "error": result.get("error")}
    except Exception as exc:
        return {"status": "failed", "mode": "subprocess", "error": type(exc).__name__}
    finally:
        _CYCLE_LOCK.release()


def run_b_monitor_async(callback=None):
    def run():
        result = run_b_monitor_cycle()
        if callback:
            callback(result)
    thread = threading.Thread(target=run, name="b-monitor-cycle", daemon=True)
    thread.start()
    return thread
