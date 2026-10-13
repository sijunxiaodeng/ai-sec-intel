"""Durable enrichment/document/index work; collection never waits for network enrichment."""
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager

from database import store

_STOP = threading.Event()
_THREAD = None
_RUN_LOCK = threading.Lock()
STAGES = ("enrich", "documents", "index")


@contextmanager
def _connection():
    path = store.database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS processing_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
            revision TEXT NOT NULL, stage TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            available_at REAL NOT NULL, lease_until REAL, lease_token TEXT,
            error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
            UNIQUE(cve_id,revision,stage))""")
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
        return conn.total_changes - before


def _claim(stage, limit=10, lease_seconds=900):
    now, token = time.time(), uuid.uuid4().hex
    with _connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""UPDATE processing_jobs SET status='retry',lease_token=NULL,lease_until=NULL
            WHERE status='running' AND lease_until < ?""", (now,))
        rows = conn.execute("""SELECT * FROM processing_jobs WHERE stage=?
            AND status IN ('pending','retry') AND available_at <= ? ORDER BY id LIMIT ?""",
                            (stage, now, limit)).fetchall()
        for row in rows:
            conn.execute("""UPDATE processing_jobs SET status='running',attempts=attempts+1,
                lease_token=?,lease_until=?,updated_at=? WHERE id=?""",
                         (token, now + lease_seconds, now, row["id"]))
    return [dict(row, lease_token=token, attempts=row["attempts"] + 1) for row in rows]


def _finish(job, error="", *, skipped=False):
    now = time.time()
    exhausted = job["attempts"] >= int(os.environ.get("PROCESSING_MAX_ATTEMPTS", "6"))
    status = "skipped" if skipped else (("failed" if exhausted else "retry") if error else "done")
    delay = min(3600, 30 * 2 ** min(job["attempts"] - 1, 7)) if error else 0
    with _connection() as conn:
        conn.execute("""UPDATE processing_jobs SET status=?,error=?,available_at=?,
            lease_token=NULL,lease_until=NULL,updated_at=? WHERE id=? AND lease_token=?
            AND status='running' AND lease_until>=?""",
                     (status, str(error)[:500], now + delay, now, job["id"], job["lease_token"], now))


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
            try:
                feed = apply_public_feeds(records)
                papers, paper_error = fetch_papers([job["cve_id"] for job in jobs])
                for job, record in zip(jobs, records):
                    if papers.get(job["cve_id"]):
                        record["papers"] = papers[job["cve_id"]]
                updated = store.apply_enrichment(records,
                    expected_revisions={job["cve_id"]: job["revision"] for job in jobs},
                    job_tokens={job["cve_id"]: {"id": job["id"], "lease_token": job["lease_token"]}
                                for job in jobs})
                errors = [key for key in ("epss_error", "kev_error") if feed.get(key)]
                if paper_error:
                    errors.append("papers_error")
                for job in jobs:
                    _finish(job, ",".join(errors), skipped=job["cve_id"] not in updated)
                processed += len(jobs)
            except Exception as exc:
                for job in jobs:
                    _finish(job, type(exc).__name__)
        for job in _claim("documents", batch_size):
            record = _current(job)
            if not record:
                continue
            try:
                result = ingest(record, max_sources=5, update_index_on_ingest=False,
                                commit_guard=lambda: _commit_guard(job))
                _enqueue_index(job)
                failed = int(result.get("attempted", 0)) - int(result.get("ok", 0))
                _finish(job, "%d document sources failed" % failed if failed else "")
                processed += 1
            except StaleWork:
                _finish(job, skipped=True)
            except Exception as exc:
                _finish(job, type(exc).__name__)
        index_jobs = [job for job in _claim("index", batch_size) if _current(job)]
        if index_jobs:
            try:
                result = update_index()
                error = "index_error" if result.get("status") == "error" else ""
                for job in index_jobs:
                    _finish(job, error)
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
            FROM processing_jobs WHERE status IN ('retry','failed') ORDER BY updated_at DESC LIMIT 20""")]
    return {"counts": counts, "failures": failures}


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
