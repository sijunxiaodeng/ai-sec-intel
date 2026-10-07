# 定时监测。启动时不立刻抓取，避免把历史漏洞算进时效。

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = ROOT / "data" / "monitor.json"
LOG_PATH = ROOT / "data" / "collect.log"
INTERVAL_HOURS = 6
_STARTED = False


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
    data.setdefault("last_run", "")
    data.setdefault("last_error", "")
    data.setdefault("last_count", 0)
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


def run_once(keyword="ollama"):
    from agents.orchestrator import run_collect

    try:
        result = run_collect(keyword)
        data = ensure_state()
        data["last_run"] = _now()
        data["last_error"] = ""
        data["last_count"] = len(result.get("records") or [])
        data["last_keyword"] = keyword
        _write_state(data)
        log_line("自动监测完成，关键词 %s，库内 %d 条" % (keyword, data["last_count"]))
        return data
    except Exception as exc:
        data = ensure_state()
        data["last_run"] = _now()
        data["last_error"] = str(exc)
        _write_state(data)
        log_line("自动监测失败：%s" % exc)
        raise


def _loop():
    ensure_state()
    log_line("定时监测已启动，间隔 %d 小时。启动这一轮不立即抓取。" % INTERVAL_HOURS)
    while True:
        threading.Event().wait(INTERVAL_HOURS * 3600)
        try:
            run_once("ollama")
        except Exception:
            continue


def start():
    global _STARTED
    if _STARTED:
        return
    _STARTED = True
    ensure_state()
    thread = threading.Thread(target=_loop, name="monitor-schedule")
    thread.daemon = True
    thread.start()
