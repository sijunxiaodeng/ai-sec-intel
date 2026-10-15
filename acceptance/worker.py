"""Resume durable observation windows while the application is running."""
from datetime import datetime, timezone
import os
import threading

_STOP = threading.Event()
_LOCK = threading.Lock()
_THREAD = None
_LATEST = {}
INTERVAL_SECONDS = 60


def state():
    return {"running": bool(_THREAD and _THREAD.is_alive()), "interval_seconds": INTERVAL_SECONDS,
            **dict(_LATEST), "note": "采样进程只读取采集记录，不发起采集或模型请求；停机空档不计作连续运行"}


def _loop():
    from acceptance.observation import tick
    while not _STOP.is_set():
        try:
            result = tick()
            _LATEST.update(last_tick_at=datetime.now(timezone.utc).isoformat(), last_error=None)
            if isinstance(result, dict):
                _LATEST["last_result"] = result
        except Exception as exc:
            # Never leak database locations or raw upstream payloads in a status response.
            _LATEST.update(last_tick_at=datetime.now(timezone.utc).isoformat(), last_error=type(exc).__name__)
        _STOP.wait(INTERVAL_SECONDS)


def start():
    global _THREAD
    from config.offline import enabled
    if enabled() or os.environ.get("ACCEPTANCE_OBSERVATION_ENABLED", "1").lower() in {"0", "false", "off"}:
        return
    with _LOCK:
        if _THREAD and _THREAD.is_alive():
            return
        _STOP.clear()
        _THREAD = threading.Thread(target=_loop, name="acceptance-observer", daemon=True)
        _THREAD.start()


def stop():
    _STOP.set()
    if _THREAD and _THREAD.is_alive():
        _THREAD.join(timeout=2)
