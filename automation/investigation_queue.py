"""Asset and intelligence triggers on the existing durable processing queue."""
import json
import copy
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


def run_pending(limit=2, *, explicit_only=None):
    from automation import processing
    from agents.investigation import run
    from enrichment.risk_register import evaluate_record, inventory_fingerprint, StaleInventory
    completed = 0
    for job in processing._claim("investigate", max(1, min(int(limit), 10)), explicit_only=explicit_only):
        record = processing._current(job)
        if record is None:
            continue
        context = json.loads(job["context_json"])
        expected = context.get("inventory_fingerprint")
        trace = {"trigger": context.get("reason"), "cve_id": job["cve_id"],
                 "revision": job["revision"], "attempt": job["attempts"],
                 "run_id": str(job["id"]) + "-" + job["lease_token"], "committed": False}
        if context.get("explicit"):
            trace["evidence_notice"] = "显式研判先使用当前证据；后台富集可能尚未完成，缺失证据由 Agent 按预算补充，未补足部分保留为缺口。"
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


def _wait_reason(item, worker, prerequisites, now):
    """Explain a read snapshot without claiming work or rewriting attempt counts."""
    status = item["status"]
    lane = worker["explicit" if item["context"].get("explicit") else "background"]
    if status == "running":
        if (item.get("lease_until") or 0) <= now:
            return {"code": "lease_expired", "label": "保留上次执行标记，租约已到期；待工作线程运行时回收后重试。"}
        if not lane["alive"]:
            return {"code": "execution_unconfirmed", "label": "保留上次执行标记，但当前对应线程未运行，无法确认执行进度；待线程恢复且租约到期后回收。",
                    "lease_until": item["lease_until"]}
        if not lane["running"]:
            return {"code": "execution_stopping", "label": "保留执行标记；对应线程正在停止，可能仍有在途处理，等待退出或租约回收。",
                    "lease_until": item["lease_until"]}
        return {"code": "executing", "label": "任务持有未到期执行租约；尝试次数是任务领取次数，不是模型调用次数。"}
    if status in {"done", "failed", "skipped"}:
        return {"code": {"done": "completed", "failed": "failed", "skipped": "skipped"}[status],
                "label": {"done": "本任务已完成，可查看结论与执行证据。",
                          "failed": "执行重试已耗尽，可查看错误与历次执行后重新排队。",
                          "skipped": "记录、资产清单或任务版本已变化，本次结果未提交。"}[status]}
    if not worker["configured_enabled"] and not lane["alive"]:
        return {"code": "worker_disabled", "label": "此实例后台处理已关闭；请在运行该服务的电脑启用自动处理并重启服务。"}
    if not lane["running"]:
        return {"code": "worker_not_running", "label": "对应工作线程尚未运行或已停止；请检查此实例启动日志并重启服务。"}
    if item["available_at"] > now:
        return {"code": "retry_wait", "label": "等待重试退避时间到期。", "available_at": item["available_at"]}
    explicit = bool(item["context"].get("explicit"))
    blocked = [row for row in prerequisites if row["status"] == "running"
               or (row["status"] == "pending" and row["attempts"] == 0 and not explicit)]
    if blocked:
        stages = {"enrich": "富化", "documents": "资料抓取"}
        labels = [stages[row["stage"]] + ("保留执行租约" if row["status"] == "running" else "尚未首次执行")
                  for row in blocked]
        return {"code": "prerequisites", "label": "等待同一漏洞的前置处理：" + "、".join(labels) + "。",
                "prerequisites": blocked}
    return {"code": "queued", "label": "已进入执行队列，等待工作线程领取；尝试 0 次表示尚未开始。"}


def tasks(*, limit=50, offset=0):
    from automation import processing
    limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
    worker, now = processing.worker_state(), time.time()
    with processing._connection() as conn:
        total = conn.execute("SELECT count(*) FROM processing_jobs WHERE stage='investigate'").fetchone()[0]
        rows = conn.execute("""SELECT id,cve_id,revision,status,attempts,error,created_at,updated_at,available_at,lease_until,
            context_json,agent_trace_json FROM processing_jobs WHERE stage='investigate'
            ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?""", (limit, offset)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["context"] = json.loads(item.pop("context_json"))
            item["trace"] = json.loads(item.pop("agent_trace_json"))
            # Claiming first recovers expired leases; those rows are no longer a
            # prerequisite once a worker reaches this task. Reading must not do
            # that recovery itself or inflate attempts just to render the page.
            prerequisites = [dict(row) for row in conn.execute("""SELECT stage,status,attempts FROM processing_jobs
                WHERE cve_id=? AND revision=? AND stage IN ('enrich','documents')
                  AND (status != 'running' OR lease_until IS NULL OR lease_until >= ?)""",
                (item["cve_id"], item["revision"], now))] if item["status"] in {"pending", "retry", "deferred"} else []
            item["wait_reason"] = _wait_reason(item, worker, prerequisites, now)
            items.append(item)
    return {"items": items, "total": total, "limit": limit, "offset": offset,
            "worker_enabled": worker["configured_enabled"], "worker": worker}


def history(job_id):
    from automation import processing
    with processing._connection() as conn:
        rows = conn.execute("""SELECT run_id,status,completed_at,trace_json FROM processing_runs
            WHERE job_id=? ORDER BY completed_at DESC LIMIT 100""", (job_id,)).fetchall()
    return [{"run_id": r[0], "status": r[1], "completed_at": r[2], "trace": json.loads(r[3])} for r in rows]
