# 定时监测：默认持续自动采集宽范围 AI 安全情报；启动后立即跑一轮（后台），之后按间隔重复。

import json
import os
import tempfile
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from config.paths import DATA_ROOT

ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = DATA_ROOT / "monitor.json"
LOG_PATH = DATA_ROOT / "collect.log"


def _interval_minutes():
    # A minute-based setting wins; the old explicit hour setting still works.
    try:
        if os.environ.get("MONITOR_INTERVAL_MINUTES"):
            return max(1, int(os.environ["MONITOR_INTERVAL_MINUTES"]))
        if os.environ.get("MONITOR_INTERVAL_HOURS"):
            return max(1, int(os.environ["MONITOR_INTERVAL_HOURS"]) * 60)
    except ValueError:
        pass
    return 15


INTERVAL_MINUTES = _interval_minutes()
INTERVAL_HOURS = INTERVAL_MINUTES / 60
PUBLIC_LIBRARY_INTERVAL_HOURS = float(os.environ.get("PUBLIC_LIBRARY_INTERVAL_HOURS", "6"))
AUTO_ENABLED = os.environ.get("AUTO_MONITOR_ENABLED", "1").strip().lower() not in {
    "0", "false", "no", "off",
}
AUTO_ON_START = os.environ.get("AUTO_MONITOR_ON_START", "1").strip().lower() not in {
    "0", "false", "no", "off",
}
# Broad AI-security scope (comma-separated); matches api AUTO_MONITOR_KEYWORDS.
DEFAULT_KEYWORDS = os.environ.get(
    "AUTO_MONITOR_KEYWORDS",
    "llm,vllm,transformers,langchain,llama-index,huggingface,openai,ollama,"
    "open-webui,open webui,adversarial,jailbreak,prompt injection",
)
_STARTED = False
_RUN_LOCK = threading.Lock()
_STATE_LOCK = threading.RLock()
_STOP = threading.Event()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_state():
    with _STATE_LOCK:
        return _read_state_unlocked()


def _read_state_unlocked():
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
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=STATE_PATH.parent,
                prefix=STATE_PATH.name + ".", suffix=".tmp", delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(json.dumps(data, ensure_ascii=False, indent=2))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, STATE_PATH)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def ensure_state():
    with _STATE_LOCK:
        return _ensure_state_unlocked()


def _ensure_state_unlocked():
    data = _read_state_unlocked()
    previous = deepcopy(data)
    if not data.get("started_at"):
        data["started_at"] = _now()
    data["interval_hours"] = INTERVAL_HOURS
    data["interval_minutes"] = INTERVAL_MINUTES
    data["auto_on_start"] = AUTO_ON_START
    data["auto_enabled"] = AUTO_ENABLED
    data.setdefault("last_run", "")
    data.setdefault("last_error", "")
    data.setdefault("last_status", "")
    data.setdefault("last_warnings", [])
    data.setdefault("source_results", [])
    data.setdefault("last_count", 0)
    data.setdefault("last_keyword", "")
    data.setdefault("running", False)
    data.setdefault("run_phase", "")
    data.setdefault("run_started_at", "")
    data.setdefault("mode", "automatic")
    if not isinstance(data.get("pipeline"), dict):
        data["pipeline"] = {}
    # Status polling must not rewrite its read snapshot over collector progress.
    if data != previous:
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
    """Count precise UTC-compatible live samples, excluding backfill and future time."""
    try:
        from intelligence.monitoring.metrics import parse_timestamp
        started = parse_timestamp(ensure_state().get("started_at"))
        now = datetime.now(timezone.utc)
        count = 0
        if not started or started > now:
            return 0
        for record in records:
            item = record.get("item") or {}
            sources = item.get("sources") or [item.get("source")]
            published = parse_timestamp(item.get("published_at"), nvd_utc="NVD" in sources)
            collected = parse_timestamp(item.get("collected_at"))
            if (not published or not collected or published < started or collected < started
                    or published > now or collected > now):
                continue
            if (collected - published).total_seconds() >= 0:
                count += 1
        return count
    except Exception:
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
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write("%s %s\n" % (_now(), text))


def _patch_state(**values):
    with _STATE_LOCK:
        data = ensure_state()
        data.update(values)
        _write_state(data)
        return data


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
    if data.get("auto_enabled") is False:
        return ""
    last = parse_stamp(data.get("last_run"))
    if not last:
        return ""
    minutes = data.get("interval_minutes")
    if minutes is None:
        minutes = float(data.get("interval_hours") or INTERVAL_HOURS) * 60
    from datetime import timedelta
    nxt = last + timedelta(minutes=max(float(minutes), 1))
    return nxt.strftime("%Y-%m-%dT%H:%M:%SZ")


def library_outcome(result):
    """Read actual source/document failures, including a valid empty sync."""
    if result is None:
        return "skipped"
    status = result.get("status")
    if status in {"error", "failed", "busy", "timeout"}:
        return "failed"
    if status in {"skipped", "disabled"}:
        return "skipped"
    if status == "partial":
        return "partial"
    if status == "ok":
        return "success"
    sources = result.get("sources") or []
    failed_sources = sum(s.get("status") in {"error", "failed"} for s in sources)
    attempted, succeeded = int(result.get("attempted") or 0), int(result.get("ok") or 0)
    if attempted and not succeeded:
        return "failed"
    if failed_sources and failed_sources == len(sources) and not succeeded:
        return "failed"
    if failed_sources or succeeded < attempted:
        return "partial"
    return "success"


def combine_monitor_outcome(result, *, b_cycle=None, libraries=()):
    status = result.get("status") or "success"
    warnings = list(result.get("warnings") or [])
    if result.get("error") and result["error"] not in warnings:
        warnings.append(result["error"])
    if b_cycle and b_cycle.get("status") in {"failed", "timeout", "partial"}:
        warnings.append("多源情报来源刷新未全部完成，已有资料保留")
        sources = result.get("source_outcomes") or {}
        if b_cycle.get("status") in {"failed", "timeout"} and sources and not any(
                sources.get(name) in {"success", "partial"} for name in ("nvd", "osv")):
            status = "failed"
            warnings.append("外部采集未完成；读取缓存不代表本轮采集成功")
    for label, library in libraries:
        state = library_outcome(library)
        if state == "skipped" and library and library.get("enabled") is False:
            continue  # Configuration skip is neither an attempted success nor an outage.
        if state in {"failed", "partial", "skipped"}:
            warnings.append(label + ("已跳过" if state == "skipped" else "未全部完成"))
    warnings = list(dict.fromkeys(warnings))
    if status != "failed" and warnings:
        status = "partial"
    return {
        "status": status,
        "warnings": warnings,
        "error": (result.get("error") or "本轮漏洞采集未完成，已有情报保留") if status == "failed"
        else "；".join(warnings) if status == "partial" else "",
    }


def mark_run(*, count=0, keyword="", error="", status=None, warnings=None,
             metrics=None, source_results=None, received=None):
    """Update monitor state after a manual /api/monitor/run (or other external cycle)."""
    data = ensure_state()
    data["last_run"] = _now()
    data["last_count"] = int(count or 0)
    if received is not None:
        data["last_received"] = int(received or 0)
    data["last_keyword"] = keyword or data.get("last_keyword") or ""
    data["last_error"] = error or ""
    status = status or ("failed" if error else "success")
    data["last_status"] = status
    data["last_warnings"] = list(warnings or [])
    if source_results is not None:
        data["source_results"] = list(source_results or [])
    data["running"] = False
    data["run_phase"] = ""
    data["run_started_at"] = ""
    pipe = data.get("pipeline")
    if isinstance(pipe, dict) and pipe.get("stages"):
        from automation.pipeline import _recount
        pipe["status"] = {"failed": "error", "partial": "partial"}.get(status, "done")
        pipe["outcome"] = status
        pipe["finished_at"] = data["last_run"]
        started = parse_stamp(pipe.get("started_at"))
        finished = parse_stamp(data["last_run"])
        if started and finished:
            pipe["elapsed_sec"] = max(0, int((finished - started).total_seconds()))
        if metrics:
            pipe.setdefault("metrics", {}).update(
                {key: int(value) for key, value in metrics.items() if value is not None})
        _recount(pipe)
        if status in {"partial", "failed"}:
            pipe["summary"] = ("本轮监测未完成：" if status == "failed" else "本轮部分完成：") + (
                error or "；".join(warnings or []))
        elif not pipe.get("summary"):
            pipe["summary"] = "本轮查询完成，新增 %d 条；成功空轮不表示来源失败。" % data["last_count"]
    _write_state(data)
    return data


def run_once(keyword=None):
    from database.store import StoreBusy, collection_lock

    try:
        with collection_lock(timeout=0):
            return _run_once(keyword)
    except StoreBusy:
        # Do not overwrite the live round's pipeline/error/running fields.
        log_line("跳过重叠的监测请求：已有采集正在进行")
        return dict(_read_state(), status="busy", error="已有采集或监测正在进行，请稍后重试")


def _run_once(keyword=None):
    from agents.orchestrator import run_collect
    from rag.library import sync_team_drain
    from automation.pipeline import begin_pipeline, update_stage, finish_pipeline

    keyword = (keyword or "").strip() or DEFAULT_KEYWORDS
    if not _RUN_LOCK.acquire(blocking=False):
        data = ensure_state()
        data["last_error"] = "上一轮自动监测仍在进行"
        _write_state(data)
        log_line("跳过重叠的自动监测请求")
        return dict(ensure_state(), skipped="overlapping_cycle")

    collect_error, b_result, result, team_library = None, None, None, None
    try:
        begin_pipeline()
        mark_running(phase="监测刷新中", keyword=keyword)

        def on_phase(stage_id, **fields):
            update_stage(stage_id, **fields)
            if fields.get("phase"):
                mark_phase(fields["phase"])

        # Refresh B multi-source DB in-process before A reads intel (embed).
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
            b_result = {"status": "failed"}
            log_line("B 同进程多源跳过/失败：%s" % exc)

        try:
            result = run_collect(keyword, on_phase=on_phase)
        except Exception as exc:
            collect_error = exc
            result = {
                "status": "failed",
                "error": "漏洞采集流程未完成（%s），已有资料保留。" % type(exc).__name__,
                "records": [],
            }
            on_phase("monitoring", status="error", note=result["error"])
            on_phase("persist", status="skip", note="采集流程未完成，不追加新的入库操作")

        # B owns source collection. Drain its committed documents independently
        # of CVE success; public catalog fetching has its own slower schedule.
        on_phase("library_sync", status="running", phase="资料同步",
                 did="按持久游标同步知识资料")
        try:
            team_library = sync_team_drain(max_documents=200)
        except Exception as exc:
            team_library = {"status": "error", "error": "资料摘要同步未完成（%s）" % type(exc).__name__}
        libraries = (("资料摘要同步", team_library),)
        library_states = [(label, library_outcome(value)) for label, value in libraries]
        configured_skip = library_outcome(team_library) == "skipped" and team_library.get("enabled") is False
        issues = [
            label + "未全部同步" for label, state in library_states
            if state != "success" and not (label == "资料摘要同步" and configured_skip)
        ]
        data = ensure_state()
        data["library_last_run"] = _now()
        data["library_last_ok"] = int(team_library.get("ok") or 0)
        data["library_last_error"] = "；".join(issues)
        data["library_team_last_status"] = library_outcome(team_library)
        data["library_team_last_ok"] = int(team_library.get("ok") or 0)
        data["library_team_last_checked_at"] = _now()
        data["library_team_last_error"] = (
            "" if configured_skip or library_outcome(team_library) == "success"
            else "资料摘要未全部同步"
        )
        data["team_library_last_run"] = _now()
        data["team_library_last_ok"] = int(team_library.get("ok") or 0)
        data["team_library_last_error"] = data["library_team_last_error"]
        if not configured_skip:
            data["library_team_last_run"] = _now()
        _write_state(data)
        active_states = [
            state for label, state in library_states
            if not (label == "资料摘要同步" and configured_skip)
        ]
        on_phase(
            "library_sync",
            status="error" if active_states and all(state == "failed" for state in active_states) else "ok",
            got="资料摘要 %s；公开资料由独立任务同步" % library_outcome(team_library),
            produced="本轮成功 %d 条" % int(team_library.get("ok") or 0),
            note="；".join(issues) if issues else "已启用的资料同步完成（含合法空轮）",
        )
        outcome = combine_monitor_outcome(result, b_cycle=b_result, libraries=libraries)
        if outcome["status"] == "failed":
            on_phase("monitoring", status="error", note=outcome["error"])
        round_stats = result.get("round_stats") or {}
        finish_pipeline(
            ok=outcome["status"] == "success",
            summary=outcome.get("error") or "",
            metrics=round_stats,
            tech_detail=result.get("tech_detail"),
        )
        # Preserve partial and failed outcomes after the generic finalizer.
        mark_run(
            count=round_stats.get("inserted", 0),
            received=result.get("fetched", round_stats.get("kept", 0)),
            keyword=keyword,
            metrics={key: round_stats.get(key, 0) for key in ("hit", "kept", "inserted", "merged", "external_fetches")},
            source_results=result.get("source_results"),
            **outcome,
        )
        log_line(
            "自动监测 %s，关键词 %s，本轮新增 %d；%s"
            % (outcome["status"], keyword, int(round_stats.get("inserted") or 0), outcome["error"] or "查询完成")
        )
    except Exception as exc:
        collect_error = exc
        mark_run(count=0, keyword=keyword, status="failed", error="监测流程未完成（%s）" % type(exc).__name__)
        try:
            finish_pipeline(ok=False, summary=str(exc)[:200])
        except Exception:
            pass
    finally:
        _patch_state(running=False, run_phase="", run_started_at="")
        _RUN_LOCK.release()

    if collect_error:
        raise collect_error
    return ensure_state()


def run_public_once():
    from rag.library import sync as sync_library
    try:
        library = sync_library(include_seeds=False)
        failures = [r["source_id"] for r in library.get("sources", [])
                    if r.get("status") in {"error", "failed"} and r.get("source_id")]
        outcome = library_outcome(library)
        error = "" if outcome == "success" else "公开资料同步未全部完成"
        return _patch_state(
            library_last_run=_now(),
            library_last_epoch=time.time(),
            library_last_ok=int(library.get("ok") or 0),
            library_last_error=error,
            library_source_errors=failures,
            library_public_last_run=_now(),
            library_public_last_status=outcome,
            library_public_last_ok=int(library.get("ok") or 0),
            library_public_last_error=error,
        )
    except Exception as exc:
        return _patch_state(
            library_last_run=_now(),
            library_last_epoch=time.time(),
            library_last_ok=0,
            library_last_error=type(exc).__name__,
            library_public_last_run=_now(),
            library_public_last_status="failed",
            library_public_last_ok=0,
            library_public_last_error=type(exc).__name__,
        )


def _public_loop():
    # A slow catalog request never occupies the B synchronization lock.
    while not _STOP.is_set():
        data = ensure_state()
        due = time.time() - float(data.get("library_last_epoch", 0)) >= PUBLIC_LIBRARY_INTERVAL_HOURS * 3600
        if due:
            run_public_once()
        _STOP.wait(60)


def _loop():
    if not AUTO_ENABLED:
        return
    ensure_state()
    if _STOP.wait(2):
        return
    deadline = time.monotonic()
    if AUTO_ON_START:
        log_line("定时监测已启动：启动后立即自动跑一轮，之后每 %d 分钟。范围：宽范围 AI 安全。" % INTERVAL_MINUTES)
        try:
            run_once(DEFAULT_KEYWORDS)
        except Exception as exc:
            log_line("启动首轮自动监测失败（将按间隔重试）：%s: %s" % (type(exc).__name__, exc))
    else:
        log_line("定时监测已启动，间隔 %d 分钟。AUTO_MONITOR_ON_START 已关闭，启动不立即抓取。" % INTERVAL_MINUTES)
    deadline += INTERVAL_MINUTES * 60
    while not _STOP.is_set():
        if _STOP.wait(max(0, deadline - time.monotonic())):
            return
        try:
            run_once(DEFAULT_KEYWORDS)
        except Exception as exc:
            log_line("定时自动监测失败（继续等待下一轮）：%s: %s" % (type(exc).__name__, exc))
        deadline += INTERVAL_MINUTES * 60
        if deadline < time.monotonic():
            # No backlog of simultaneous cycles when one takes longer than the period.
            deadline = time.monotonic()


def start():
    global _STARTED
    # Asset and explicit research tasks also run with public monitoring disabled.
    from automation.processing import start as start_processing
    start_processing()
    if _STARTED:
        return
    if not AUTO_ENABLED:
        ensure_state()
        return
    _STARTED = True
    _STOP.clear()
    ensure_state()
    threading.Thread(target=_loop, name="monitor-schedule", daemon=True).start()
    threading.Thread(target=_public_loop, name="public-library-schedule", daemon=True).start()


def stop():
    _STOP.set()
    from automation.processing import stop as stop_processing
    stop_processing()
