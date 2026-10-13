# Coarse collect pipeline state for monitor refresh UI.
# Product: one 监测 action — NOT per-source stage rows (NVD/OSV/多源情报).
# Honest job state on disk; UI polls.

from copy import deepcopy
from datetime import datetime, timezone
from functools import wraps

from automation.schedule import ensure_state, _write_state, _STATE_LOCK


def _state_transaction(function):
    """Keep each read/modify/write atomic with scheduler state updates."""
    @wraps(function)
    def locked(*args, **kwargs):
        with _STATE_LOCK:
            return function(*args, **kwargs)
    return locked

# Product-level stages only. Internal collectors stay in code, not in UI checklist.
STAGE_DEFS = [
    {
        "id": "monitoring",
        "title": "监测中",
        "subtitle": "同步多源已分类情报及变更",
    },
    {
        "id": "persist",
        "title": "整理入库",
        "subtitle": "规范化并合并写入知识库",
    },
    {
        "id": "library_sync",
        "title": "资料同步",
        "subtitle": "公开与资料摘要（可选）",
    },
]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _blank_stage(defn):
    return {
        "id": defn["id"],
        "title": defn["title"],
        "subtitle": defn["subtitle"],
        "status": "pending",
        "did": "",
        "got": "",
        "produced": "",
        "impact": "",
        "note": "",
    }


def empty_pipeline():
    return {
        "status": "idle",
        "started_at": "",
        "finished_at": "",
        "elapsed_sec": 0,
        "metrics": {
            "stages_done": 0,
            "stages_total": len(STAGE_DEFS),
            "external_fetches": 0,
            "failures": 0,
            "skipped": 0,
            "hit": 0,
            "kept": 0,
            "inserted": 0,
            "merged": 0,
        },
        "stages": [_blank_stage(d) for d in STAGE_DEFS],
        "summary": "",
        # Optional collapsed technical note (not a per-source stage list).
        "tech_detail": "",
    }


@_state_transaction
def begin_pipeline():
    pipe = empty_pipeline()
    pipe["status"] = "running"
    pipe["started_at"] = _now()
    data = ensure_state()
    data["pipeline"] = pipe
    data["running"] = True
    data["run_phase"] = "监测刷新中"
    data["run_started_at"] = pipe["started_at"]
    _write_state(data)
    return pipe


def _stage_ids_match(pipe):
    """True when persisted stages match current product schema (coarse only)."""
    expected = [d["id"] for d in STAGE_DEFS]
    got = [s.get("id") for s in (pipe.get("stages") or [])]
    return got == expected


def _sync_stage_copy(pipe):
    """Keep product titles/subtitles in sync with STAGE_DEFS (ban stale 聚合 copy)."""
    by_id = {d["id"]: d for d in STAGE_DEFS}
    changed = False
    for stage in pipe.get("stages") or []:
        defn = by_id.get(stage.get("id"))
        if not defn:
            continue
        if stage.get("title") != defn["title"]:
            stage["title"] = defn["title"]
            changed = True
        if stage.get("subtitle") != defn["subtitle"]:
            stage["subtitle"] = defn["subtitle"]
            changed = True
    return changed


@_state_transaction
def _load_pipeline():
    data = ensure_state()
    pipe = data.get("pipeline")
    # Migrate away from old per-source stage checklists left in monitor.json
    # (e.g. fetch_nvd / fetch_osv / 抓取·多路采集) so UI cannot resurrect them.
    if not isinstance(pipe, dict) or not pipe.get("stages") or not _stage_ids_match(pipe):
        kept_metrics = {}
        kept_summary = ""
        kept_tech = ""
        kept_status = "idle"
        if isinstance(pipe, dict):
            kept_metrics = dict(pipe.get("metrics") or {})
            kept_summary = pipe.get("summary") or ""
            kept_tech = pipe.get("tech_detail") or ""
            # Never keep a "done" status that still advertised per-source rows.
            if pipe.get("status") == "running" and _stage_ids_match(pipe):
                kept_status = "running"
        pipe = empty_pipeline()
        if kept_metrics:
            pipe["metrics"].update({
                k: int(v) for k, v in kept_metrics.items()
                if k in pipe["metrics"] and v is not None
            })
        if kept_summary and "抓取" not in kept_summary:
            pipe["summary"] = kept_summary
        if kept_tech:
            pipe["tech_detail"] = kept_tech[:500]
        pipe["status"] = kept_status
        data["pipeline"] = pipe
        _write_state(data)
    elif _sync_stage_copy(pipe):
        data["pipeline"] = pipe
        _write_state(data)
    return data, pipe


@_state_transaction
def update_stage(stage_id, *, status=None, did="", got="", produced="", impact="", note="", phase=None, metrics=None):
    data, pipe = _load_pipeline()
    for stage in pipe.get("stages") or []:
        if stage.get("id") != stage_id:
            continue
        if status:
            stage["status"] = status
        if did:
            stage["did"] = did
        if got:
            stage["got"] = got
        if produced:
            stage["produced"] = produced
        if impact:
            stage["impact"] = impact
        if note:
            stage["note"] = note
        break
    if phase:
        data["run_phase"] = phase[:80]
    else:
        for stage in pipe.get("stages") or []:
            if stage.get("id") == stage_id:
                data["run_phase"] = str(stage.get("title") or stage_id)[:80]
                break
    # Mid-run partial counts (e.g. hit after 监测中 ends, before 整理入库 finishes).
    if metrics:
        pipe_metrics = pipe.setdefault("metrics", {})
        for key, value in metrics.items():
            if key in pipe_metrics and value is not None:
                pipe_metrics[key] = int(value)
    _recount(pipe)
    data["pipeline"] = pipe
    _write_state(data)
    return pipe


@_state_transaction
def set_tech_detail(text):
    """Single optional technical note (e.g. 多方面来源摘要), not a stage checklist."""
    data, pipe = _load_pipeline()
    pipe["tech_detail"] = (text or "")[:500]
    data["pipeline"] = pipe
    _write_state(data)
    return pipe


@_state_transaction
def bump_metrics(**kwargs):
    data, pipe = _load_pipeline()
    metrics = pipe.setdefault("metrics", {})
    for key, value in kwargs.items():
        if key in metrics and value is not None:
            metrics[key] = int(value)
    _recount(pipe)
    data["pipeline"] = pipe
    _write_state(data)
    return pipe


def _elapsed_sec(started_at, finished_at=None):
    if not started_at:
        return 0
    try:
        t0 = datetime.strptime(str(started_at)[:19], "%Y-%m-%dT%H:%M:%S")
        t1 = (
            datetime.strptime(str(finished_at)[:19], "%Y-%m-%dT%H:%M:%S")
            if finished_at
            else datetime.now(timezone.utc).replace(tzinfo=None)
        )
        return max(0, int((t1 - t0).total_seconds()))
    except ValueError:
        return 0


def _recount(pipe):
    stages = pipe.get("stages") or []
    done = sum(1 for s in stages if s.get("status") in {"ok", "skip", "error"})
    failures = sum(1 for s in stages if s.get("status") == "error")
    skipped = sum(1 for s in stages if s.get("status") == "skip")
    metrics = pipe.setdefault("metrics", {})
    metrics["stages_done"] = done
    metrics["stages_total"] = len(stages) or len(STAGE_DEFS)
    metrics["failures"] = failures
    metrics["skipped"] = skipped
    if pipe.get("status") == "running":
        pipe["elapsed_sec"] = _elapsed_sec(pipe.get("started_at"))


@_state_transaction
def finish_pipeline(*, ok=True, summary="", metrics=None, tech_detail=None):
    data, pipe = _load_pipeline()
    pipe["status"] = "done" if ok else "error"
    pipe["finished_at"] = _now()
    pipe["elapsed_sec"] = _elapsed_sec(pipe.get("started_at"), pipe["finished_at"])
    if metrics:
        pipe["metrics"].update({k: int(v) for k, v in metrics.items()
                                if k in empty_pipeline()["metrics"] and v is not None})
    if tech_detail is not None:
        pipe["tech_detail"] = (tech_detail or "")[:500]
    # A finished cycle must not leave the UI showing a permanently running step.
    for stage in pipe.get("stages") or []:
        if stage.get("status") == "running":
            stage["status"] = "ok" if ok else "error"
        elif stage.get("status") == "pending":
            stage["status"] = "skip"
            stage["note"] = "本轮未执行此阶段"
    _recount(pipe)
    if summary:
        pipe["summary"] = summary
    else:
        m = pipe.get("metrics") or {}
        pipe["summary"] = (
            "本轮监测：查询返回 %(hit)s，水位后保留 %(kept)s，"
            "新增 %(inserted)s，合并 %(merged)s；"
            "外部请求 %(external_fetches)s，失败 %(failures)s。"
            % {
                "hit": m.get("hit", 0),
                "kept": m.get("kept", 0),
                "inserted": m.get("inserted", 0),
                "merged": m.get("merged", 0),
                "external_fetches": m.get("external_fetches", 0),
                "failures": m.get("failures", 0),
            }
        )
    data["pipeline"] = pipe
    data["running"] = False
    data["run_phase"] = ""
    data["run_started_at"] = ""
    _write_state(data)
    return deepcopy(pipe)


@_state_transaction
def get_pipeline():
    _data, pipe = _load_pipeline()
    pipe = deepcopy(pipe)
    if pipe.get("status") == "running":
        pipe["elapsed_sec"] = _elapsed_sec(pipe.get("started_at"))
    return pipe
