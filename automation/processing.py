"""Durable enrichment/document/index work; collection never waits for network enrichment."""
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager

from database import store
from agents.planning import enrichment_plan, PUBLIC_FEEDS, PAPERS
from agents.tool_registry import (ToolRegistry, validate_records, validate_mapping,
                                  validate_papers, validate_paper_result)

_STOP = threading.Event()
_THREAD = None
_RUN_LOCK = threading.Lock()
STAGES = ("enrich", "documents", "investigate", "index")


@contextmanager
def _connection():
    path = store.database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        # Serialize old-schema inspection and ALTER across startup workers.
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS processing_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
            revision TEXT NOT NULL, stage TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            available_at REAL NOT NULL, lease_until REAL, lease_token TEXT,
            error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
            agent_trace_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(cve_id,revision,stage))""")
        if "agent_trace_json" not in {row[1] for row in conn.execute("PRAGMA table_info(processing_jobs)")}:
            conn.execute("ALTER TABLE processing_jobs ADD COLUMN agent_trace_json TEXT NOT NULL DEFAULT '{}'")
        if "context_json" not in {row[1] for row in conn.execute("PRAGMA table_info(processing_jobs)")}:
            conn.execute("ALTER TABLE processing_jobs ADD COLUMN context_json TEXT NOT NULL DEFAULT '{}'")
        conn.execute("""CREATE TABLE IF NOT EXISTS processing_runs (
            run_id TEXT PRIMARY KEY, job_id INTEGER NOT NULL, cve_id TEXT NOT NULL,
            stage TEXT NOT NULL, status TEXT NOT NULL, completed_at REAL NOT NULL,
            trace_json TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS processing_due ON processing_jobs(status,available_at)")
        conn.commit()
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def revision(record):
    """Upstream content fingerprint; enrichment results and local bookkeeping are excluded."""
    return store.source_revision(record)


class StaleWork(RuntimeError):
    pass


@contextmanager
def _commit_guard(job):
    """Fence C evidence writes with the main transaction, after network fetching."""
    conn = store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT payload_json FROM knowledge_records WHERE cve_id=?",
                           (job["cve_id"],)).fetchone()
        lease = conn.execute("SELECT status,lease_token,lease_until FROM processing_jobs WHERE id=?",
                             (job["id"],)).fetchone()
        record = json.loads(row[0]) if row else None
        if (not record or (record["item"].get("raw_data") or {}).get("_store", {}).get("in_scope") is False
                or revision(record) != job["revision"] or not lease or lease[0] != "running"
                or lease[1] != job["lease_token"] or (lease[2] or 0) < time.time()):
            raise StaleWork("Stale or withdrawn processing task")
        yield
        conn.commit()
    finally:
        conn.rollback()
        conn.close()


def enqueue(records):
    """Idempotent reconciliation also closes a crash between saving a record and enqueueing."""
    records = list(records)
    now = time.time()
    rows = []
    for record in records:
        item = record.get("item") or {}
        if not item.get("cve_id") or (item.get("raw_data") or {}).get("sample_mode"):
            continue
        rows.extend((item["cve_id"], revision(record), stage, now, now, now)
                    for stage in ("enrich", "documents"))
    with _connection() as conn:
        before = conn.total_changes
        conn.executemany("""INSERT OR IGNORE INTO processing_jobs
            (cve_id,revision,stage,available_at,created_at,updated_at) VALUES (?,?,?,?,?,?)""", rows)
        inserted = conn.total_changes - before
    from automation.investigation_queue import reconcile
    reconcile(records)
    return inserted


def _claim(stage, limit=10, lease_seconds=900):
    now, token = time.time(), uuid.uuid4().hex
    with _connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""UPDATE processing_jobs SET status='retry',lease_token=NULL,lease_until=NULL
            WHERE status='running' AND lease_until < ?""", (now,))
        rows = conn.execute("""SELECT * FROM processing_jobs WHERE stage=?
            AND status IN ('pending','retry','deferred') AND available_at <= ?
            AND (stage != 'investigate' OR NOT EXISTS (
                SELECT 1 FROM processing_jobs prerequisite
                WHERE prerequisite.cve_id=processing_jobs.cve_id
                  AND prerequisite.revision=processing_jobs.revision
                  AND prerequisite.stage IN ('enrich','documents')
                  AND (prerequisite.status='running' OR
                       (prerequisite.status='pending' AND prerequisite.attempts=0))))
            ORDER BY id LIMIT ?""",
                            (stage, now, limit)).fetchall()
        for row in rows:
            conn.execute("""UPDATE processing_jobs SET status='running',attempts=attempts+1,
                lease_token=?,lease_until=?,updated_at=? WHERE id=?""",
                         (token, now + lease_seconds, now, row["id"]))
    return [dict(row, lease_token=token, attempts=row["attempts"] + 1) for row in rows]


def _finish(job, error="", *, skipped=False, trace=None, deferred=False):
    now = time.time()
    exhausted = job["attempts"] >= int(os.environ.get("PROCESSING_MAX_ATTEMPTS", "6"))
    status = "skipped" if skipped else (("failed" if exhausted else "retry") if error else "done")
    if deferred and not skipped:
        status = "deferred"
    delay = min(3600, 30 * 2 ** min(job["attempts"] - 1, 7)) if error else 0
    if deferred:
        delay = 300
    if trace is not None:
        reflection = dict(trace.get("reflection") or {}, task_status=status)
        if skipped:
            reflection.update(status="skipped", reason="记录已撤回、修订改变或任务校验未通过；未提交该任务结果。")
        elif status == "failed":
            reflection.update(status="failed", reason="已保存成功维度；重试次数已耗尽，失败任务等待排查或手动重新排队。")
        trace = dict(trace, reflection=reflection)
    with _connection() as conn:
        changed = conn.execute("""UPDATE processing_jobs SET status=?,error=?,available_at=?,
            agent_trace_json=COALESCE(?,agent_trace_json),
            lease_token=NULL,lease_until=NULL,attempts=CASE WHEN ? THEN 0 ELSE attempts END,
            updated_at=? WHERE id=? AND lease_token=?
            AND status='running' AND lease_until>=?""",
                     (status, str(error)[:500], now + delay,
                      json.dumps(trace, ensure_ascii=False) if trace is not None else None,
                      deferred, now, job["id"], job["lease_token"], now)).rowcount
        if changed and trace is not None:
            conn.execute("""INSERT OR IGNORE INTO processing_runs VALUES (?,?,?,?,?,?,?)""",
                         (str(job["id"]) + "-" + job["lease_token"], job["id"], job["cve_id"],
                          job["stage"], status, now, json.dumps(trace, ensure_ascii=False)))


def _current(job):
    record = store.get_record(job["cve_id"])
    if not record or revision(record) != job["revision"]:
        _finish(job, skipped=True)
        return None
    return record


def _enqueue_index(job):
    now = time.time()
    with _connection() as conn:
        conn.execute("""INSERT INTO processing_jobs(cve_id,revision,stage,available_at,created_at,updated_at)
            VALUES (?,?,'index',?,?,?) ON CONFLICT(cve_id,revision,stage) DO UPDATE SET
            status='pending',attempts=0,lease_token=NULL,lease_until=NULL,error='',
            available_at=excluded.available_at,updated_at=excluded.updated_at""",
                     (job["cve_id"], job["revision"], now, now, now))


def run_batch(batch_size=10):
    """One bounded batch, preserving partial enrichment and retrying actual failures."""
    if not _RUN_LOCK.acquire(blocking=False):
        return {"busy": True}
    processed = 0
    try:
        from enrichment.service import apply_public_feeds
        from enrichment.papers import fetch_papers
        from rag.ingest import ingest
        from rag.hybrid import update_index

        enqueue(store.load_kb())
        jobs, records = [], []
        for job in _claim("enrich", batch_size):
            record = _current(job)
            if record:
                jobs.append(job)
                records.append(record)
        if jobs:
            trace = enrichment_plan(records, [job.get("error", "") for job in jobs])
            updated = []
            try:
                registry = ToolRegistry()
                registry.register(PUBLIC_FEEDS, role="impact_enrichment", handler=apply_public_feeds,
                                  validate=validate_records, validate_result=validate_mapping)
                registry.register(PAPERS, role="research_enrichment", handler=fetch_papers,
                                  validate=validate_papers, validate_result=validate_paper_result)
                feed, papers, errors = {}, {}, []
                arguments = {PUBLIC_FEEDS: {"records": records},
                             PAPERS: {"cve_ids": [job["cve_id"] for job in jobs]}}
                for name in trace["decision"]["tools"]:
                    call = registry.execute(name, arguments[name], trace)
                    if name == PUBLIC_FEEDS:
                        if call.ok:
                            feed = call.value
                            errors.extend(key for key in ("epss_error", "kev_error") if feed.get(key))
                        else:
                            errors.append("public_feeds_error")
                    elif call.ok:
                        papers, paper_error = call.value
                        if paper_error:
                            errors.append("papers_error")
                    else:
                        errors.append("papers_error")
                for job, record in zip(jobs, records):
                    if papers.get(job["cve_id"]):
                        record["papers"] = papers[job["cve_id"]]
                updated = store.apply_enrichment(records,
                    expected_revisions={job["cve_id"]: job["revision"] for job in jobs},
                    job_tokens={job["cve_id"]: {"id": job["id"], "lease_token": job["lease_token"]}
                                for job in jobs})
                trace["reflection"] = {"status": "retry" if errors else "complete",
                                       "failed_dimensions": errors,
                                       "reason": "已保存成功维度；失败维度由持久队列退避重试。" if errors else "注册工具已完成，写入通过版本与租约校验。"}
                for job in jobs:
                    job_trace = dict(trace, cve_id=job["cve_id"], revision=job["revision"],
                                     attempt=job["attempts"], committed=job["cve_id"] in updated)
                    _finish(job, ",".join(errors), skipped=job["cve_id"] not in updated, trace=job_trace)
                processed += len(jobs)
            except Exception as exc:
                trace["reflection"] = {"status": "retry", "error_type": type(exc).__name__,
                                       "reason": "写入或编排失败，未报告任务完成。"}
                for job in jobs:
                    _finish(job, type(exc).__name__, trace=dict(trace, cve_id=job["cve_id"],
                            revision=job["revision"], attempt=job["attempts"], committed=job["cve_id"] in updated))
        for job in _claim("documents", batch_size):
            record = _current(job)
            if not record:
                continue
            try:
                result = ingest(record, max_sources=5, update_index_on_ingest=False,
                                commit_guard=lambda: _commit_guard(job))
                _enqueue_index(job)
                if int(result.get("ok", 0)) > 0:
                    from automation.investigation_queue import evidence_updated
                    evidence_updated(record)
                failed = int(result.get("attempted", 0)) - int(result.get("ok", 0))
                _finish(job, "%d document sources failed" % failed if failed else "")
                processed += 1
            except StaleWork:
                _finish(job, skipped=True)
            except Exception as exc:
                _finish(job, type(exc).__name__)
        from automation.investigation_queue import run_pending
        processed += run_pending(limit=min(batch_size, 2))
        index_jobs = [job for job in _claim("index", batch_size) if _current(job)]
        if index_jobs:
            try:
                result = update_index()
                error = "index_error" if result.get("status") == "error" else ""
                for job in index_jobs:
                    _finish(job, error, deferred=result.get("status") == "deferred")
                processed += len(index_jobs)
            except Exception as exc:
                for job in index_jobs:
                    _finish(job, type(exc).__name__)
        return {"processed": processed, **state()}
    finally:
        _RUN_LOCK.release()


def state():
    with _connection() as conn:
        counts = {row[0]: row[1] for row in conn.execute(
            "SELECT status,count(*) FROM processing_jobs GROUP BY status")}
        failures = [dict(row) for row in conn.execute("""SELECT id,cve_id,stage,status,attempts,error
            FROM processing_jobs WHERE status IN ('retry','failed','deferred') ORDER BY updated_at DESC LIMIT 20""")]
        traces = []
        for row in conn.execute("""SELECT id,cve_id,stage,status,agent_trace_json FROM processing_jobs
            WHERE agent_trace_json != '{}' ORDER BY updated_at DESC,id DESC LIMIT 20"""):
            try:
                trace = json.loads(row["agent_trace_json"])
            except (ValueError, TypeError):
                continue
            traces.append({"job_id": row["id"], "cve_id": row["cve_id"], "stage": row["stage"],
                           "status": row["status"], "trace": trace})
    return {"counts": counts, "failures": failures, "agent_traces": traces}


def retry_failed():
    with _connection() as conn:
        return conn.execute("""UPDATE processing_jobs SET status='retry',attempts=0,available_at=?
            WHERE status='failed'""", (time.time(),)).rowcount


def _loop():
    while not _STOP.is_set():
        try:
            run_batch(int(os.environ.get("PROCESSING_BATCH_SIZE", "10")))
        except Exception:
            # Individual job errors are durable. A worker-level failure is visible in the log.
            import logging
            logging.getLogger(__name__).exception("Processing worker failed")
        _STOP.wait(10)


def start():
    global _THREAD
    if _THREAD and _THREAD.is_alive():
        return
    if os.environ.get("AUTO_INGEST_ON_COLLECT", "1").lower() in {"0", "false", "no", "off"}:
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, name="processing-worker", daemon=True)
    _THREAD.start()


def stop():
    _STOP.set()
