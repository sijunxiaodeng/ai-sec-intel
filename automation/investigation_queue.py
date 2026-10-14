"""Asset and intelligence triggers on the existing durable processing queue."""
import json
import copy
import os
import time

from database import store
from enrichment.assets import load_assets


def reconcile(records=None, *, reason="intelligence_updated", force=False, explicit=False,
              invalidate_running=False):
    """Reconcile after either trigger or a crash; unchanged inventories do not replay work.

    Explicit research can run without assets. Background research is restricted to
    candidate assets; the ordinary monitoring/enrichment pipeline remains independent.
    """
    from automation import processing
    from enrichment.risk_register import candidate_assets, inventory_fingerprint
    assets = load_assets()
    if not assets and not explicit:
        return 0
    fingerprint = inventory_fingerprint(assets)
    records = store.load_kb() if records is None else records
    with processing._connection() as conn:
        linked = {row[0] for row in conn.execute("SELECT DISTINCT cve_id FROM asset_risks")} if conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='asset_risks'").fetchone() else set()
    rows = []
    for record in records:
        item = record.get("item") or {}
        if not item.get("cve_id") or (item.get("raw_data") or {}).get("sample_mode"):
            continue
        # A changed component must also revisit its existing risk links.
        related = bool(candidate_assets(record, assets)) or item["cve_id"] in linked
        if not explicit and not related:
            continue
        context = {"inventory_fingerprint": fingerprint, "reason": reason, "explicit": explicit}
        rows.append((item["cve_id"], processing.revision(record), context))
    inserted, now = 0, time.time()
    with processing._connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        for cve_id, revision, context in rows:
            old = conn.execute("""SELECT id,context_json,status FROM processing_jobs
                WHERE cve_id=? AND revision=? AND stage='investigate'""", (cve_id, revision)).fetchone()
            if old:
                previous = json.loads(old["context_json"])
                changed = previous.get("inventory_fingerprint") != fingerprint
                # A manual retry must not steal the lease from an active identical task.
                if not changed and (not force or (old["status"] == "running" and not invalidate_running)):
                    continue
                conn.execute("""UPDATE processing_jobs SET status='pending',attempts=0,error='',
                    lease_token=NULL,lease_until=NULL,available_at=?,updated_at=?,context_json=?,
                    agent_trace_json='{}' WHERE id=?""",
                             (now, now, json.dumps(context), old["id"]))
            else:
                conn.execute("""INSERT INTO processing_jobs
                    (cve_id,revision,stage,available_at,created_at,updated_at,context_json)
                    VALUES (?,?,'investigate',?,?,?,?)""",
                             (cve_id, revision, now, now, now, json.dumps(context)))
            inserted += 1
            if reason == "evidence_updated" and cve_id in linked:
                from enrichment.risk_register import _invalidate
                for saved in conn.execute("SELECT payload_json FROM asset_risks WHERE cve_id=?", (cve_id,)).fetchall():
                    _invalidate(conn, json.loads(saved[0]), "evidence_updated")
    return inserted


def evidence_updated(record):
    """Refresh derived identity and wake research after a document retry or manual fetch.

    The assessment is read from verified archives, never accepted from an API
    request. Replacing a running job's token fences its obsolete result.
    """
    from enrichment.assessment import assess
    current = store.get_record((record.get("item") or {}).get("cve_id", ""))
    if current is None or store.source_revision(current) != store.source_revision(record):
        return 0
    refreshed = copy.deepcopy(current)
    refreshed["item"].setdefault("raw_data", {})["automatic_assessment"] = assess(current["item"]["cve_id"])
    accepted = store.apply_enrichment([refreshed], expected_revisions={current["item"]["cve_id"]: store.source_revision(current)})
    if not accepted:
        return 0
    return reconcile([refreshed], reason="evidence_updated", force=True, invalidate_running=True)


def run_pending(limit=2):
    from automation import processing
    from agents.investigation import run
    from enrichment.risk_register import evaluate_record, inventory_fingerprint, StaleInventory
    completed = 0
    for job in processing._claim("investigate", max(1, min(int(limit), 10))):
        record = processing._current(job)
        if record is None:
            continue
        context = json.loads(job["context_json"])
        expected = context.get("inventory_fingerprint")
        trace = {"trigger": context.get("reason"), "cve_id": job["cve_id"],
                 "revision": job["revision"], "attempt": job["attempts"],
                 "run_id": str(job["id"]) + "-" + job["lease_token"], "committed": False}
        try:
            if expected != inventory_fingerprint():
                processing._finish(job, skipped=True, trace=trace)
                continue
            result = run(record, commit_guard=lambda: processing._commit_guard(job))
            trace.update(result["trace"])
            result["record"]["item"].setdefault("raw_data", {})["automatic_assessment"] = result["assessment"]
            if expected != inventory_fingerprint():
                raise processing.StaleWork("Asset inventory changed during research")
            accepted = store.apply_enrichment([result["record"]],
                expected_revisions={job["cve_id"]: job["revision"]},
                job_tokens={job["cve_id"]: {"id": job["id"], "lease_token": job["lease_token"]}})
            if job["cve_id"] not in accepted:
                raise processing.StaleWork("Source revision or worker lease changed")
            risks = evaluate_record(result["record"], assessment=result["assessment"],
                run_id=trace["run_id"], job_id=job["id"],
                expected_inventory_fingerprint=expected)
            if risks.get("status") == "skipped":
                raise processing.StaleWork("Risk input changed before commit")
            trace.update(committed=True, risk_summary={k: v for k, v in risks.items() if k != "risks"})
            if result.get("documents_changed"):
                processing._enqueue_index(job)
            error = ",".join(result.get("errors") or []) if result.get("retryable") else ""
            processing._finish(job, error, trace=trace)
            completed += 1
        except (processing.StaleWork, StaleInventory):
            processing._finish(job, skipped=True, trace=trace)
        except Exception as exc:
            trace["error_type"] = type(exc).__name__
            processing._finish(job, type(exc).__name__, trace=trace)
    return completed


def tasks(*, limit=50, offset=0):
    from automation import processing
    limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
    with processing._connection() as conn:
        total = conn.execute("SELECT count(*) FROM processing_jobs WHERE stage='investigate'").fetchone()[0]
        rows = conn.execute("""SELECT id,cve_id,revision,status,attempts,error,created_at,updated_at,
            context_json,agent_trace_json FROM processing_jobs WHERE stage='investigate'
            ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?""", (limit, offset)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["context"] = json.loads(item.pop("context_json"))
            item["trace"] = json.loads(item.pop("agent_trace_json"))
            items.append(item)
    return {"items": items, "total": total, "limit": limit, "offset": offset,
            "worker_enabled": os.environ.get("AUTO_INGEST_ON_COLLECT", "1").lower() not in {"0", "false", "no", "off"}}


def history(job_id):
    from automation import processing
    with processing._connection() as conn:
        rows = conn.execute("""SELECT run_id,status,completed_at,trace_json FROM processing_runs
            WHERE job_id=? ORDER BY completed_at DESC LIMIT 100""", (job_id,)).fetchall()
    return [{"run_id": r[0], "status": r[1], "completed_at": r[2], "trace": json.loads(r[3])} for r in rows]
