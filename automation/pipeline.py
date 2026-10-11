# Structured collect pipeline state for monitor refresh UI.
# Honest job state on disk — UI polls; not fake websocket theater.

from copy import deepcopy
from datetime import datetime, timezone

from automation.schedule import ensure_state, _write_state

STAGE_DEFS = [
    {
        "id": "fetch_multisource",
        "title": "抓取 · 多路采集",
        "subtitle": "刷新本机聚合情报库",
    },
    {
        "id": "fetch_nvd",
        "title": "抓取 · NVD",
        "subtitle": "按关键词与变更窗取回",
    },
    {
        "id": "fetch_osv",
        "title": "抓取 · OSV",
        "subtitle": "按 AI 组件包批量查询",
    },
    {
        "id": "fetch_aggregate",
        "title": "抓取 · 聚合库 CVE",
        "subtitle": "读取本机多路采集结果",
    },
    {
        "id": "normalize",
        "title": "整理 · 字段规范化",
        "subtitle": "统一成同一种入库格式",
    },
    {
        "id": "upsert",
        "title": "入库 · 合并去重",
        "subtitle": "写入知识库并合并同编号",
    },
    {
        "id": "library_sync",
        "title": "同步 · 资料库",
        "subtitle": "公开资料与聚合摘要（可选）",
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
    }


def begin_pipeline():
    pipe = empty_pipeline()
    pipe["status"] = "running"
    pipe["started_at"] = _now()
    data = ensure_state()
    data["pipeline"] = pipe
    data["running"] = True
    data["run_phase"] = "准备采集流水线"
    data["run_started_at"] = pipe["started_at"]
    _write_state(data)
    return pipe


def _load_pipeline():
    data = ensure_state()
    pipe = data.get("pipeline")
    if not isinstance(pipe, dict) or not pipe.get("stages"):
        pipe = empty_pipeline()
        data["pipeline"] = pipe
        _write_state(data)
    return data, pipe


def update_stage(stage_id, *, status=None, did="", got="", produced="", impact="", note="", phase=None):
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
        pipe_status_phase = phase
    else:
        # Derive short phase from stage title.
        for stage in pipe.get("stages") or []:
            if stage.get("id") == stage_id:
                pipe_status_phase = stage.get("title") or stage_id
                data["run_phase"] = str(pipe_status_phase)[:80]
                break
    _recount(pipe)
    data["pipeline"] = pipe
    _write_state(data)
    return pipe


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


def finish_pipeline(*, ok=True, summary="", metrics=None):
    data, pipe = _load_pipeline()
    pipe["status"] = "done" if ok else "error"
    pipe["finished_at"] = _now()
    pipe["elapsed_sec"] = _elapsed_sec(pipe.get("started_at"), pipe["finished_at"])
    if metrics:
        pipe["metrics"].update({k: int(v) for k, v in metrics.items() if v is not None})
    _recount(pipe)
    if summary:
        pipe["summary"] = summary
    else:
        m = pipe.get("metrics") or {}
        pipe["summary"] = (
            "本轮命中 %(hit)s，保留 %(kept)s，新增 %(inserted)s，合并已有 %(merged)s；"
            "外部取回 %(external_fetches)s，失败 %(failures)s，跳过 %(skipped)s。"
            % {
                "hit": m.get("hit", 0),
                "kept": m.get("kept", 0),
                "inserted": m.get("inserted", 0),
                "merged": m.get("merged", 0),
                "external_fetches": m.get("external_fetches", 0),
                "failures": m.get("failures", 0),
                "skipped": m.get("skipped", 0),
            }
        )
    data["pipeline"] = pipe
    data["running"] = False
    data["run_phase"] = ""
    data["run_started_at"] = ""
    _write_state(data)
    return deepcopy(pipe)


def get_pipeline():
    _data, pipe = _load_pipeline()
    pipe = deepcopy(pipe)
    if pipe.get("status") == "running":
        pipe["elapsed_sec"] = _elapsed_sec(pipe.get("started_at"))
    return pipe
