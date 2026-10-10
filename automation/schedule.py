# 定时监测：默认持续自动采集宽范围 AI 安全情报；启动后立即跑一轮（后台），之后按间隔重复。

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = ROOT / "data" / "monitor.json"
LOG_PATH = ROOT / "data" / "collect.log"
INTERVAL_HOURS = int(os.environ.get("MONITOR_INTERVAL_HOURS", "6") or "6")
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
    STATE_PATH.parent.mkdir(exist_ok=True)
    STATE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def ensure_state():
    data = _read_state()
    if not data.get("started_at"):
        data["started_at"] = _now()
    data["interval_hours"] = INTERVAL_HOURS
    data["auto_on_start"] = AUTO_ON_START
    data.setdefault("last_run", "")
    data.setdefault("last_error", "")
    data.setdefault("last_count", 0)
    data.setdefault("last_keyword", "")
    data.setdefault("running", False)
    data.setdefault("run_phase", "")
    data.setdefault("run_started_at", "")
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


def mark_running(*, phase="starting", keyword=""):
    """Mark a manual or scheduled cycle as in-progress so the UI can show progress."""
    data = ensure_state()
    data["running"] = True
    data["run_phase"] = (phase or "starting")[:80]
    if not data.get("run_started_at"):
        data["run_started_at"] = _now()
    if keyword:
        data["last_keyword"] = keyword
    data["last_error"] = ""
    _write_state(data)
    return data


def mark_phase(phase):
    data = ensure_state()
    if data.get("running"):
        data["run_phase"] = (phase or "")[:80]
        _write_state(data)
    return data


def next_run_iso(data=None):
    """Best-effort next scheduled run (last_run + interval). Empty if unknown."""
    data = data or ensure_state()
    last = parse_stamp(data.get("last_run"))
    if not last:
        return ""
    hours = int(data.get("interval_hours") or INTERVAL_HOURS or 6)
    from datetime import timedelta

    nxt = last + timedelta(hours=max(hours, 1))
    return nxt.strftime("%Y-%m-%dT%H:%M:%SZ")


def mark_run(*, count=0, keyword="", error=""):
    """Update monitor state after a manual /api/monitor/run (or other external cycle)."""
    data = ensure_state()
    data["last_run"] = _now()
    data["last_count"] = int(count or 0)
    data["last_keyword"] = keyword or data.get("last_keyword") or ""
    data["last_error"] = error or ""
    data["running"] = False
    data["run_phase"] = ""
    data["run_started_at"] = ""
    _write_state(data)
    return data


def run_once(keyword=None):
    from agents.orchestrator import run_collect
    from rag.library import sync as sync_library

    keyword = (keyword or "").strip() or DEFAULT_KEYWORDS
    if not _RUN_LOCK.acquire(blocking=False):
        data = ensure_state()
        data["last_error"] = "上一轮自动监测仍在进行"
        _write_state(data)
        log_line("跳过重叠的自动监测请求")
        return ensure_state()

    collect_error = None
    try:
        data = ensure_state()
        data["running"] = True
        data["last_error"] = ""
        _write_state(data)
        # Refresh B multi-source DB in-process before A reads team intel (embed).
        try:
            from api.b_embed import embed_enabled
            from api.b_monitor import b_monitor_on_refresh, run_b_monitor_cycle

            if embed_enabled() and b_monitor_on_refresh():
                b_result = run_b_monitor_cycle()
                data = ensure_state()
                data["b_monitor_last_status"] = b_result.get("status")
                data["b_monitor_last_run"] = _now()
                _write_state(data)
                log_line(
                    "B 同进程多源：%s（成功 %s/%s）"
                    % (
                        b_result.get("status"),
                        b_result.get("success_sources"),
                        b_result.get("configured_sources"),
                    )
                )
        except Exception as exc:
            log_line("B 同进程多源跳过/失败：%s" % exc)

        result = run_collect(keyword)
        data = ensure_state()
        data["last_run"] = _now()
        data["last_error"] = ""
        data["last_count"] = len(result.get("records") or [])
        data["last_keyword"] = keyword
        data["running"] = False
        _write_state(data)
        log_line("自动监测完成，关键词 %s，库内 %d 条" % (keyword, data["last_count"]))
    except Exception as exc:
        collect_error = exc
        data = ensure_state()
        data["last_run"] = _now()
        data["last_error"] = str(exc)
        data["running"] = False
        _write_state(data)
        log_line("自动监测失败：%s" % exc)
    finally:
        _RUN_LOCK.release()

    try:
        library = sync_library(include_seeds=False)
        data = ensure_state()
        data["library_last_run"] = _now()
        data["library_last_ok"] = library["ok"]
        data["library_last_error"] = ""
        data["library_source_errors"] = [r["source_id"] for r in library["sources"] if r["status"] == "error"]
        _write_state(data)
        log_line("资料同步完成：成功 %d/%d，来源失败 %d" % (
            library["ok"], library["attempted"], len(data["library_source_errors"])))
    except Exception as exc:
        data = ensure_state()
        data["library_last_run"] = _now()
        data["library_last_error"] = str(exc)
        _write_state(data)
        log_line("资料同步失败：%s" % exc)

    if collect_error:
        raise collect_error
    return ensure_state()


def _loop():
    ensure_state()
    # Brief delay so uvicorn is accepting before the first collect hits NVD/OSV/B.
    threading.Event().wait(2.0)
    if AUTO_ON_START:
        log_line("定时监测已启动：启动后立即自动跑一轮，之后每 %d 小时。范围：宽范围 AI 安全。" % INTERVAL_HOURS)
        try:
            run_once(DEFAULT_KEYWORDS)
        except Exception:
            pass
    else:
        log_line("定时监测已启动，间隔 %d 小时。AUTO_MONITOR_ON_START 已关闭，启动不立即抓取。" % INTERVAL_HOURS)
    while True:
        threading.Event().wait(max(INTERVAL_HOURS, 1) * 3600)
        try:
            run_once(DEFAULT_KEYWORDS)
        except Exception:
            continue


def start():
    global _STARTED
    if _STARTED:
        return
    _STARTED = True
    ensure_state()
    thread = threading.Thread(target=_loop, name="monitor-schedule", daemon=True)
    thread.start()
