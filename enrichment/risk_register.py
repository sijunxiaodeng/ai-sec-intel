"""Persistent asset/CVE decisions from the existing conservative version matcher.

No network calls, model decisions, asset scanning or exploit execution. A closed
ticket means the current declared inventory no longer matches cited ranges; it
does not mean that a deployed system has been tested for exploitability.
"""

from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time

from database import store
from enrichment import assets as inventory
from enrichment.assessment import assess


DISPOSITIONS = {
    "pending": "待处理", "in_progress": "处理中", "pending_review": "待复核",
    "resolved": "已解决", "accepted_risk": "接受风险",
}
STATES = {"matched_version", "unknown", "not_matched", "invalidated"}
SCHEMA_VERSION = 1


class StaleInventory(ValueError):
    """The inventory changed after a job was planned or during evaluation."""


def _check_job(conn, job_id, run_id, cve_id, source_revision):
    if job_id is None:
        return
    # Reuse the queue's stale-work signal without a module-level cycle.
    from automation.processing import StaleWork
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='processing_jobs'").fetchone()
    job = conn.execute("SELECT cve_id,revision,status,lease_token,lease_until,stage FROM processing_jobs WHERE id=?", (job_id,)).fetchone() if exists else None
    if (not job or job["cve_id"] != cve_id or job["revision"] != source_revision
            or job["stage"] not in {"investigate", "asset_match"} or job["status"] != "running"
            or not job["lease_token"] or (job["lease_until"] or 0) <= time.time()
            or run_id != str(job_id) + "-" + job["lease_token"]):
        raise StaleWork("资产评估任务的版本或租约已失效")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def asset_fingerprint(asset):
    """Ignore reimport timestamps; include every actual inventory field."""
    return _digest({key: value for key, value in asset.items() if key not in {"recorded_at", "inventory_source"}})


def inventory_fingerprint(assets=None, asset_db=None):
    values = inventory.load_assets(asset_db) if assets is None else assets
    return _digest(sorted((asset["asset_id"], asset_fingerprint(asset)) for asset in values))


@contextmanager
def _connection(db_path=None):
    path = Path(db_path or store.database_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        # BEGIN IMMEDIATE serializes read/modify/write decisions and disposition
        # changes, including workers in other processes sharing the main DB.
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS asset_risks (
            asset_id TEXT NOT NULL, cve_id TEXT NOT NULL, payload_json TEXT NOT NULL,
            PRIMARY KEY(asset_id,cve_id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS asset_risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL,
            cve_id TEXT NOT NULL, event TEXT NOT NULL, at TEXT NOT NULL,
            payload_json TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS asset_risk_history_pair ON asset_risk_history(asset_id,cve_id,id)")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _read(conn, asset_id, cve_id):
    row = conn.execute("SELECT payload_json FROM asset_risks WHERE asset_id=? AND cve_id=?", (asset_id, cve_id)).fetchone()
    return json.loads(row[0]) if row else None


def _save(conn, risk, event):
    conn.execute("""INSERT INTO asset_risks VALUES(?,?,?) ON CONFLICT(asset_id,cve_id)
        DO UPDATE SET payload_json=excluded.payload_json""", (risk["asset_id"], risk["cve_id"], _json(risk)))
    if event:
        conn.execute("INSERT INTO asset_risk_history(asset_id,cve_id,event,at,payload_json) VALUES(?,?,?,?,?)",
                     (risk["asset_id"], risk["cve_id"], event, _now(), _json(risk)))


def _withdrawn(record):
    item = record.get("item") or {}
    raw = item.get("raw_data") or {}
    if ((raw.get("_store") or {}).get("in_scope") is False
            or bool(item.get("withdrawn") or raw.get("withdrawn") or record.get("withdrawn"))
            or str(item.get("status") or raw.get("vulnStatus") or raw.get("status") or "").lower()
            in {"withdrawn", "rejected", "retracted"}):
        return True
    by_source = raw.get("raw_by_source") or {}
    nvd = (by_source.get("NVD") or []) if isinstance(by_source, dict) else []
    records = [raw] + ([nvd] if isinstance(nvd, dict) else nvd if isinstance(nvd, list) else [])
    for source in records:
        if not isinstance(source, dict):
            continue
        source = source.get("cve") or source
        if isinstance(source, dict) and source.get("id", item.get("cve_id")) == item.get("cve_id"):
            if str(source.get("vulnStatus") or "").lower() in {"withdrawn", "rejected", "retracted"}:
                return True
    return False


def _current_source(conn, cve_id):
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "scope_tombstones" in tables and conn.execute("SELECT 1 FROM scope_tombstones WHERE cve_id=?", (cve_id,)).fetchone():
        return None, "source_retracted"
    if "knowledge_records" not in tables:
        return None, None  # Explicit input / isolated library use.
    row = conn.execute("SELECT payload_json FROM knowledge_records WHERE cve_id=?", (cve_id,)).fetchone()
    if not row:
        return None, "record_removed"
    record = json.loads(row[0])
    return record, "source_retracted" if _withdrawn(record) else None


def _invalidate(conn, risk, reason):
    if risk["status"] == "invalidated" and risk.get("invalidation_reason") == reason:
        return False
    risk.update(status="invalidated", lifecycle="invalidated", label="旧结论已失效，待重新评估",
                invalidation_reason=reason, updated_at=_now(), verification="unverified")
    if risk["disposition"] in {"resolved", "accepted_risk"}:
        risk["disposition"] = "pending_review"
        risk["disposition_label"] = DISPOSITIONS["pending_review"]
    _save(conn, risk, "invalidated")
    return True


def _reconcile(conn, registered, *, cve_id=None, asset_id=None):
    """Invalidate stale decisions before display or disposition updates."""
    changed = 0
    source_cache = {}
    conditions, values = [], []
    for column, value in (("cve_id", cve_id), ("asset_id", asset_id)):
        if value is not None:
            conditions.append(column + "=?")
            values.append(value)
    sql = "SELECT payload_json FROM asset_risks" + (" WHERE " + " AND ".join(conditions) if conditions else "")
    for row in conn.execute(sql, values).fetchall():
        risk = json.loads(row[0])
        asset = registered.get(risk["asset_id"])
        if asset is None:
            reason = "asset_removed"
        elif asset_fingerprint(asset) != risk["asset_fingerprint"]:
            reason = "asset_changed"
        else:
            if risk["cve_id"] not in source_cache:
                source_cache[risk["cve_id"]] = _current_source(conn, risk["cve_id"])
            current, reason = source_cache[risk["cve_id"]]
            if not current and not reason and risk.get("source_guard", True):
                reason = "record_removed"
            if not reason and current and store.source_revision(current) != risk["source_revision"]:
                reason = "source_changed"
        if reason:
            changed += int(_invalidate(conn, risk, reason))
    return changed


def _identity(row):
    parts = re.split(r"(?<!\\):", str(row.get("criteria") or ""))
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return None
    values = tuple(value.lower() for value in parts[2:5])
    return values if all(value and not any(ch in value for ch in "*?\\") for value in values) else None


def _source_identities(record, assessment):
    """Read explicit CPE identities as routing hints, never as impact proof."""
    identities = {identity for row in assessment.get("affected_ranges") or []
                  if (identity := _identity(row)) is not None}
    if identities:
        return identities
    item = record.get("item") or {}
    raw = item.get("raw_data") or {}
    for package in raw.get("affected_packages") or []:
        if not isinstance(package, dict):
            continue
        identity = _identity({"criteria": package.get("cpe") or package.get("criteria")})
        if identity:
            identities.add(identity)
    by_source = raw.get("raw_by_source") or {}
    nvd = (by_source.get("NVD") or []) if isinstance(by_source, dict) else []
    records = [raw] + ([nvd] if isinstance(nvd, dict) else nvd if isinstance(nvd, list) else [])
    for candidate in records:
        if not isinstance(candidate, dict):
            continue
        candidate = candidate.get("cve") or candidate
        if not isinstance(candidate, dict) or (candidate.get("id") and candidate["id"] != item.get("cve_id")):
            continue
        frontier = list(candidate.get("configurations") or [])
        visited = 0
        while frontier and visited < 10000:
            node = frontier.pop()
            visited += 1
            if not isinstance(node, dict) or node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if isinstance(match, dict) and match.get("vulnerable") is True:
                    identity = _identity(match)
                    if identity:
                        identities.add(identity)
            frontier.extend(node.get("nodes") or [])
            frontier.extend(node.get("children") or [])
    return identities


def _candidate(asset, assessment, record, identities=None):
    identity = (asset["part"], asset["vendor"], asset["product"])
    if identities is None:
        identities = _source_identities(record, assessment)
    if identity in identities:
        return True
    # When the source has no usable CPE identity, an exact explicit product
    # name can open a pending-information risk. Never fuzzy-match descriptions.
    if not identities:
        products = re.split(r"[,;|、，；]", str((record.get("item") or {}).get("product") or ""))
        return asset["product"] in {value.strip().lower() for value in products}
    return False


def _uncertainties(report, result):
    messages = []
    if result["status"] == "unknown":
        messages.append(result["reason"])
    if not report.get("fix_records"):
        messages.append("当前报告未收录有引用的修复措施正文")
    if not report.get("poc_candidates"):
        messages.append("当前报告未收录 PoC 参考线索；不等于不存在")
    messages.append("尚未主动扫描或验证漏洞可利用性")
    return list(dict.fromkeys(messages + list(report.get("warnings") or [])))


def candidate_assets(record, assets, assessment=None):
    """Conservative candidates only; this function does not decide impact."""
    report = assessment if assessment is not None else ((record.get("item") or {}).get("raw_data") or {}).get("automatic_assessment") or {}
    identities = _source_identities(record, report)
    return [asset for asset in assets if _candidate(asset, report, record, identities)]


def evaluate_record(record, *, assessment=None, db_path=None, asset_db=None, evidence_db=None,
                    run_id=None, job_id=None, expected_inventory_fingerprint=None,
                    require_current_record=True, evaluation_mode="agent_research"):
    """Upsert current decisions for a record and all relevant registered assets.

    The optional assessment is a program-generated ``assessment.assess`` report,
    not a user/LLM verdict. Existing associations are reevaluated even when the
    current source no longer names their product. Unrelated products create no
    rows. Historical decisions remain auditable after updates/invalidation.
    """
    record = copy.deepcopy(record)
    cve_id = str((record.get("item") or {}).get("cve_id") or "").upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        raise ValueError("需要有效的 CVE 编号")
    registered = {asset["asset_id"]: asset for asset in inventory.load_assets(asset_db)}
    inventory_revision = inventory_fingerprint(list(registered.values()))
    if expected_inventory_fingerprint is not None and inventory_revision != expected_inventory_fingerprint:
        raise StaleInventory("资产清单已变化，请按当前清单重新评估")
    source_revision = store.source_revision(record)
    report = copy.deepcopy(assessment) if assessment is not None else (
        assess(cve_id, evidence_db) if evidence_db is not None else assess(cve_id))
    if report.get("cve_id") != cve_id:
        raise ValueError("评估报告与情报 CVE 不一致")
    identities = _source_identities(record, report)
    ranges_by_identity = {}
    for row in report.get("affected_ranges") or []:
        ranges_by_identity.setdefault(_identity(row), []).append(row)
    created = updated = 0
    risks = []
    with _connection(db_path) as conn:
        _check_job(conn, job_id, run_id, cve_id, source_revision)
        invalidated = _reconcile(conn, registered, cve_id=cve_id)
        current, reason = _current_source(conn, cve_id)
        if require_current_record and current is None and not reason:
            reason = "record_removed"
        if _withdrawn(record):
            reason = "source_retracted"
        if not reason and current and store.source_revision(current) != source_revision:
            reason = "stale_source_revision"
        if reason:
            if reason != "stale_source_revision":
                for row in conn.execute("SELECT payload_json FROM asset_risks WHERE cve_id=?", (cve_id,)).fetchall():
                    invalidated += int(_invalidate(conn, json.loads(row[0]), reason))
            return {"cve_id": cve_id, "status": "skipped", "reason": reason,
                    "evaluated": 0, "created": 0, "updated": 0, "invalidated": invalidated, "risks": []}
        previous_risks = {row[0]: json.loads(row[1]) for row in conn.execute(
            "SELECT asset_id,payload_json FROM asset_risks WHERE cve_id=?", (cve_id,))}
        for asset_id, asset in registered.items():
            previous = previous_risks.get(asset_id)
            if not previous and not _candidate(asset, report, record, identities):
                continue
            scoped = copy.deepcopy(report)
            relevant = ranges_by_identity.get((asset["part"], asset["vendor"], asset["product"]))
            if relevant:
                scoped["affected_ranges"] = relevant
            result = inventory.impact_report(scoped, [asset])["results"][0]
            fingerprint = _digest({"schema": SCHEMA_VERSION, "asset": asset_fingerprint(asset),
                                   "source_revision": source_revision, "assessment": report})
            changed = not previous or fingerprint != previous["fingerprint"] or previous["status"] == "invalidated"
            disposition = (previous or {}).get("disposition", "pending")
            if changed and disposition in {"resolved", "accepted_risk"}:
                disposition = "pending_review"
            state = result["status"]
            evidence_ids = result["evidence_ids"]
            supporting_ids = set(evidence_ids)
            for field in ("fix_records", "poc_candidates", "attack_conditions"):
                for entry in report.get(field) or []:
                    supporting_ids.update(entry.get("evidence_ids") or [])
            cited = [entry for entry in report.get("evidence") or [] if entry.get("citation_id") in supporting_ids]
            risk = {
                "schema_version": SCHEMA_VERSION, "asset_id": asset_id, "cve_id": cve_id,
                "asset": asset, "title": (record.get("item") or {}).get("title") or cve_id,
                "status": state, "label": result["label"],
                "lifecycle": "cleared" if state == "not_matched" else "active",
                "priority": result["priority"], "priority_rank": 0 if result["priority"] == "优先核查" else 1 if state == "matched_version" else 2 if state == "unknown" else 3,
                "reason": result["reason"], "checks": result["checks"], "evidence_ids": evidence_ids,
                "evidence": cited, "source": report.get("source"), "assessment_status": report.get("status"),
                "cvss": report.get("cvss"), "warnings": report.get("warnings") or [],
                "fix_records": report.get("fix_records") or [], "poc_candidates": report.get("poc_candidates") or [],
                "attack_conditions": report.get("attack_conditions") or [], "uncertainties": _uncertainties(report, result),
                "limitations": inventory.impact_report(scoped, [])["limitations"],
                "asset_fingerprint": asset_fingerprint(asset), "source_revision": source_revision,
                "inventory_fingerprint": inventory_revision, "source_guard": require_current_record,
                "fingerprint": fingerprint, "disposition": disposition,
                "disposition_label": DISPOSITIONS[disposition], "disposition_note": (previous or {}).get("disposition_note", ""),
                "disposition_updated_at": (previous or {}).get("disposition_updated_at"),
                "verification": "verified" if disposition == "resolved" else "unverified",
                "verification_scope": "declared_inventory_and_cited_version_ranges", "validation": "not_tested",
                "created_at": (previous or {}).get("created_at") or _now(),
                "updated_at": _now() if changed else previous["updated_at"], "evaluated_at": _now(),
                "run_id": run_id, "job_id": job_id, "invalidation_reason": None,
                "evaluation_mode": evaluation_mode,
            }
            _save(conn, risk, "evaluated" if changed else None)
            created += int(previous is None)
            updated += int(previous is not None and changed)
            risks.append(risk)
        if inventory_fingerprint(asset_db=asset_db) != inventory_revision:
            raise StaleInventory("评估期间资产清单已变化，旧结果未提交")
        _check_job(conn, job_id, run_id, cve_id, source_revision)
    return {"cve_id": cve_id, "status": "evaluated", "evaluated": len(risks),
            "created": created, "updated": updated, "invalidated": invalidated, "risks": risks}


def list_risks(*, db_path=None, asset_db=None, status=None, disposition=None,
               asset_id=None, cve_id=None, limit=200, offset=0, actionable=False):
    if status is not None and status not in STATES:
        raise ValueError("无效的风险结论")
    if disposition is not None and disposition not in DISPOSITIONS:
        raise ValueError("无效的处置状态")
    registered = {asset["asset_id"]: asset for asset in inventory.load_assets(asset_db)}
    with _connection(db_path) as conn:
        _reconcile(conn, registered, cve_id=cve_id.upper() if cve_id else None, asset_id=asset_id)
        rows = [json.loads(row[0]) for row in conn.execute("SELECT payload_json FROM asset_risks")]
    rows = [row for row in rows if (not status or row["status"] == status)
            and (not disposition or row["disposition"] == disposition)
            and (not actionable or (row["disposition"] in {"pending", "in_progress", "pending_review"} and row["status"] != "not_matched"))
            and (not asset_id or row["asset_id"] == asset_id)
            and (not cve_id or row["cve_id"] == cve_id.upper())]
    rows.sort(key=lambda row: (row["status"] == "invalidated", row["priority_rank"], row["asset_id"], row["cve_id"]))
    start, size = max(0, int(offset)), max(1, min(1000, int(limit)))
    return {"items": rows[start:start + size], "total": len(rows),
            "counts": {state: sum(row["status"] == state for row in rows) for state in sorted(STATES)}}


def get_risk(asset_id, cve_id, *, db_path=None, asset_db=None):
    registered = {asset["asset_id"]: asset for asset in inventory.load_assets(asset_db)}
    with _connection(db_path) as conn:
        _reconcile(conn, registered, cve_id=cve_id.upper(), asset_id=asset_id)
        risk = _read(conn, asset_id, cve_id.upper())
        if risk:
            risk["history"] = [{"id": row[0], "event": row[1], "at": row[2], "snapshot": json.loads(row[3])}
                               for row in conn.execute("SELECT id,event,at,payload_json FROM asset_risk_history WHERE asset_id=? AND cve_id=? ORDER BY id DESC LIMIT 100", (asset_id, cve_id.upper()))]
        return risk


def update_disposition(asset_id, cve_id, status, *, note="", expected_fingerprint=None,
                       db_path=None, asset_db=None):
    if status not in DISPOSITIONS:
        raise ValueError("无效的处置状态")
    if not isinstance(note, str) or len(note) > 2000:
        raise ValueError("处置说明不能超过 2000 字符")
    if status in {"resolved", "accepted_risk"} and not note.strip():
        raise ValueError("关闭或接受风险需要填写处置依据")
    registered = {asset["asset_id"]: asset for asset in inventory.load_assets(asset_db)}
    inventory_revision = inventory_fingerprint(list(registered.values()))
    # Commit invalidations even if the requested transition is later rejected.
    failure = None
    with _connection(db_path) as conn:
        _reconcile(conn, registered, cve_id=cve_id.upper(), asset_id=asset_id)
        risk = _read(conn, asset_id, cve_id.upper())
        if not risk:
            failure = KeyError("未找到资产风险记录")
        elif expected_fingerprint is not None and expected_fingerprint != risk["fingerprint"]:
            failure = ValueError("评估已更新，请刷新后再处置")
        elif status == "resolved" and not (risk["status"] == "not_matched"
                and risk["assessment_status"] in {"ok", "partial"} and risk["evidence_ids"]
                and risk["checks"] and all(check["status"] == "not_matched" for check in risk["checks"])):
            failure = ValueError("只有当前证据明确未命中版本范围的记录才能验证关闭；待确认或失效结论不能关闭")
        elif status == "accepted_risk" and risk["status"] == "invalidated":
            failure = ValueError("结论已失效，重新评估后才能接受风险")
        else:
            risk.update(disposition=status, disposition_label=DISPOSITIONS[status], disposition_note=note.strip(),
                        disposition_updated_at=_now(), verification="verified" if status == "resolved" else "unverified")
            _save(conn, risk, "disposition_changed")
            if inventory_fingerprint(asset_db=asset_db) != inventory_revision:
                raise StaleInventory("处置期间资产清单已变化，请刷新当前评估")
    if failure:
        raise failure
    return risk
