# 定时监测：默认持续自动采集宽范围 AI 安全情报；启动后立即跑一轮（后台），之后按间隔重复。

import json
import os
import threading
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from config.paths import DATA_ROOT

ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = DATA_ROOT / "monitor.json"
LOG_PATH = DATA_ROOT / "collect.log"
INTERVAL_MINUTES = max(1.0, float(os.environ.get("MONITOR_INTERVAL_MINUTES") or
                                   float(os.environ.get("MONITOR_INTERVAL_HOURS", "0.25")) * 60))
INTERVAL_HOURS = INTERVAL_MINUTES / 60
PUBLIC_LIBRARY_INTERVAL_HOURS = float(os.environ.get("PUBLIC_LIBRARY_INTERVAL_HOURS", "6"))
AUTO_ON_START = os.environ.get("AUTO_MONITOR_ON_START", "1").strip().lower() not in {
    "0", "false", "no", "off",
}
# Broad AI-security scope (comma-separated); matches api AUTO_MONITOR_KEYWORDS.
DEFAULT_KEYWORDS = os.environ.get(
    "AUTO_MONITOR_KEYWORDS",
    "llm,vllm,langchain,huggingface,openai,ollama,adversarial,jailbreak,prompt injection",
)
_STARTED = False
_RUN_LOCK = threading.Lock()
_STATE_LOCK = threading.RLock()
_STOP = threading.Event()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_state():
    if not STATE_PATH.exists():
        return {}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _write_state(data):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _STATE_LOCK:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=STATE_PATH.parent,
                                         prefix=".monitor-", delete=False) as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            temporary = Path(stream.name)
        temporary.replace(STATE_PATH)


def ensure_state():
    with _STATE_LOCK:
        data = _read_state()
        if not data.get("started_at"):
            data["started_at"] = _now()
        data["interval_hours"] = INTERVAL_HOURS
        data["interval_minutes"] = INTERVAL_MINUTES
        data["auto_on_start"] = AUTO_ON_START
        data.setdefault("last_run", "")
        data.setdefault("last_error", "")
        data.setdefault("last_count", 0)
        data.setdefault("last_keyword", "")
        data.setdefault("running", False)
        data.setdefault("mode", "automatic")
        _write_state(data)
        return data

def state():
    return ensure_state()


def parse_stamp(value):
    if not value:
        return None
    text = str(value).replace("Z", "")
    if "." in text:
        text = text.split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19] if "T" in fmt else text[:10], fmt)
        except ValueError:
            continue
    return None


def countable_latency(records):
    """只统计监测开始之后新公布的漏洞。更早的记录返回 0。"""
    started = parse_stamp(ensure_state().get("started_at"))
    count = 0
    if not started:
        return 0
    for record in records:
        item = record.get("item") or {}
        published = parse_stamp(item.get("published_at"))
        collected = parse_stamp(item.get("collected_at"))
        if not published or not collected or published < started:
            continue
        if (collected - published).total_seconds() >= 0:
            count += 1
    return count


def log_line(text):
    LOG_PATH.parent.mkdir(exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write("%s %s\n" % (_now(), text))


def _patch_state(**values):
    with _STATE_LOCK:
        data = ensure_state()
        data.update(values)
        _write_state(data)
        return data


def mark_run(*, count=0, keyword="", error="", status=None, source_results=None):
    return _patch_state(last_run=_now(), last_count=int(count or 0), last_keyword=keyword,
                        last_error=error, last_status=status or ("partial" if error else "success"),
                        source_results=source_results or [], running=False)


def run_once(keyword=None):
    from agents.orchestrator import run_collect
    from rag.library import sync_team_drain
    keyword = (keyword or "").strip() or DEFAULT_KEYWORDS
    if not _RUN_LOCK.acquire(blocking=False):
        return dict(ensure_state(), skipped="overlapping_cycle")
    collect_error = None
    try:
        _patch_state(running=True)
        try:
            result = run_collect(keyword)
            _patch_state(last_run=_now(), last_count=result.get("fetched", 0),
                         total_records=len(result.get("records") or []), last_keyword=keyword,
                         last_status=result.get("status", "success"),
                         source_results=result.get("source_results", []),
                         last_error="部分情报来源失败" if result.get("status") == "partial" else "")
            log_line("团队情报同步 %s，接收 %d 条" % (result.get("status"), result.get("fetched", 0)))
        except Exception as exc:
            collect_error = exc
            _patch_state(last_run=_now(), last_count=0, last_status="failed", last_error=str(exc))
            log_line("自动监测失败：%s" % exc)
        try:
            team = sync_team_drain(max_documents=200)
            errors = team.get("error") or team.get("status") in {"error", "failed", "partial"}
            _patch_state(team_library_last_run=_now(), team_library_last_ok=team.get("ok", 0),
                         team_library_last_error=str(team.get("error") or team.get("status")) if errors else "")
        except Exception as exc:
            _patch_state(team_library_last_run=_now(), team_library_last_error=type(exc).__name__)
            log_line("团队资料同步失败：%s" % type(exc).__name__)
        if collect_error:
            raise collect_error
        return ensure_state()
    finally:
        _patch_state(running=False)
        _RUN_LOCK.release()


def run_public_once():
    from rag.library import sync as sync_library
    try:
        library = sync_library(include_seeds=False)
        failures = [r["source_id"] for r in library["sources"] if r["status"] == "error"]
        return _patch_state(library_last_run=_now(), library_last_epoch=time.time(),
                            library_last_ok=library["ok"], library_last_error="部分来源失败" if failures else "",
                            library_source_errors=failures)
    except Exception as exc:
        return _patch_state(library_last_run=_now(), library_last_epoch=time.time(),
                            library_last_error=type(exc).__name__)


def _public_loop():
    # A slow catalog request never occupies the B synchronization lock.
    while not _STOP.is_set():
        data = ensure_state()
        due = time.time() - float(data.get("library_last_epoch", 0)) >= PUBLIC_LIBRARY_INTERVAL_HOURS * 3600
        if due:
            run_public_once()
        _STOP.wait(60)


def _loop():
    ensure_state()
    if _STOP.wait(2):
        return
    deadline = time.monotonic()
    if not AUTO_ON_START:
        deadline += INTERVAL_MINUTES * 60
    while not _STOP.is_set():
        if _STOP.wait(max(0, deadline - time.monotonic())):
            return
        try:
            run_once(DEFAULT_KEYWORDS)
        except Exception:
            pass
        deadline += INTERVAL_MINUTES * 60
        if deadline < time.monotonic():
            # No backlog of simultaneous cycles when one takes longer than the period.
            deadline = time.monotonic()


def start():
    global _STARTED
    if os.environ.get("AUTO_MONITOR_ENABLED", "1").lower() in {"0", "false", "no", "off"}:
        return
    if _STARTED:
        return
    _STARTED = True
    _STOP.clear()
    ensure_state()
    from automation.processing import start as start_processing
    start_processing()
    threading.Thread(target=_loop, name="monitor-schedule", daemon=True).start()
    threading.Thread(target=_public_loop, name="public-library-schedule", daemon=True).start()


def stop():
    _STOP.set()
    from automation.processing import stop as stop_processing
    stop_processing()
