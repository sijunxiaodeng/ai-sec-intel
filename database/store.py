"""Transactional main knowledge store with compatible team record dictionaries.

Legacy JSON is imported once and left untouched. Runtime exports live under
``data``; repository cards are only an explicitly enabled demo seed.
"""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from uuid import uuid4

from models import enriched_record, normalize
from config.paths import DATA_ROOT

ROOT = Path(__file__).resolve().parent.parent
DATA = DATA_ROOT
KB_PATH = DATA / "knowledge.json"  # Read-only legacy migration input.
DB_PATH = DATA / "knowledge.sqlite3"
SEED_CARDS_PATH = ROOT / "cards.json"
CARDS_PATH = DATA / "cards.json"
CARDS_JS_PATH = DATA / "cards.js"
RUNS_PATH = DATA / "runs.json"  # Read-only legacy migration input.


def database_path():
    """Database shared by the API, scheduler, and durable processing queues."""
    return Path(os.environ.get("MAIN_KB_DB_PATH") or DB_PATH)


class StaleSyncPage(RuntimeError):
    """Another sync cycle committed after this collector read its checkpoint."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _time(value):
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (TypeError, ValueError):
        return ""


def _earliest(values):
    valid = [(stamp, value) for value in values if (stamp := _time(value))]
    return min(valid)[1] if valid else next((value for value in values if value), "")


def _read_list(path):
    if not path.exists():
        return None
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("Legacy knowledge data must be a JSON list: " + str(path))
    return rows


def _union(old_values, new_values):
    found = []
    for value in list(old_values or []) + list(new_values or []):
        if value and value not in found:
            found.append(value)
    return found


def _source(record, field, value):
    item = record.get("item") or {}
    raw = item.get("raw_data") or {}
    if isinstance(value, dict) and value.get("source"):
        return str(value["source"])
    if field == "cvss" and raw.get("cvss_source"):
        return str(raw["cvss_source"])
    if field == "epss":
        return "FIRST"
    if field == "kev":
        return "CISA_KEV"
    explicit = (raw.get("field_sources") or {}).get(field)
    return explicit or next(iter(item.get("sources") or []), item.get("source") or "unknown")


def _authority(source):
    name = str(source).upper()
    if name in {"FIRST", "CISA", "CISA_KEV"}:
        return 100
    if name == "NVD" or "CNA" in name:
        return 90
    if "VENDOR" in name or "SECURITY_ADVISORY" in name:
        return 85
    if "GITHUB" in name:
        return 80
    if name == "OSV":
        return 75
    return 50


def _quality(field, value, record):
    if value is None or value == "" or value == [] or value == {}:
        return 0
    if field == "cvss":
        try:
            score = float(value.get("score"))
            return 2 if 0 <= score <= 10 and not value.get("error") else 0
        except (AttributeError, TypeError, ValueError):
            return 0
    if field in {"epss", "kev"}:
        if not isinstance(value, dict):
            return 0
        status = value.get("status")
        if status in {"error", "failed", "unknown", "pending", "unavailable"}:
            return 0
        if field == "epss":
            try:
                score = float(value.get("score"))
                return 2 if status in {None, "ok", "success"} and 0 <= score <= 1 else 0
            except (TypeError, ValueError):
                return 1 if status == "empty" else 0
        return 2 if status in {"listed", "not_listed"} else 0
    if field == "title" and value == (record.get("item") or {}).get("cve_id"):
        return 1
    return 2


def _field_meta(record, field, value, observed_at):
    item = record.get("item") or {}
    raw = item.get("raw_data") or {}
    stored = ((raw.get("_store") or {}).get("fields") or {}).get(field) or {}
    # A stale caller snapshot keeps its old provenance. A changed field (for
    # example a newly fetched EPSS value) obtains a new observation stamp.
    if stored.get("value_sha256") == _digest(value):
        return dict(stored)
    stamps = []
    if isinstance(value, dict):
        stamps.extend(value.get(key) for key in ("updated_at", "retrieved_at", "fetched_at", "date"))
    stamps.extend(raw.get(key) for key in ("content_updated_at", "source_updated_at", "modified_at", "updated_at"))
    for source in raw.get("source_evidence") or []:
        if isinstance(source, dict) and source.get("source") == _source(record, field, value):
            stamps.append(source.get("modified_at"))
    valid = [_time(stamp) for stamp in stamps if _time(stamp)]
    return {"updated_at": max(valid) if valid else observed_at,
            "time_basis": "source" if valid else "observed",
            "source": _source(record, field, value),
            "quality": _quality(field, value, record), "value_sha256": _digest(value)}


def _pick(old, new, field, old_value, new_value, observed_at):
    old_meta = _field_meta(old, field, old_value, observed_at)
    new_meta = _field_meta(new, field, new_value, observed_at)
    if old_value == new_value and old_meta.get("source") == new_meta.get("source") and new_meta.get("time_basis") == "observed":
        return old_value, old_meta
    old_quality, new_quality = old_meta.get("quality", 0), new_meta.get("quality", 0)
    if old_quality != new_quality:
        choose_new = new_quality > old_quality
    elif not new_quality:
        choose_new = old_value is None and new_value is not None
    else:
        # Provenance outranks a later low-authority copy; equally authoritative
        # sources use source modification / observation time, never score max.
        old_rank = (_authority(old_meta.get("source")), old_meta.get("time_basis") == "source", _time(old_meta.get("updated_at")))
        new_rank = (_authority(new_meta.get("source")), new_meta.get("time_basis") == "source", _time(new_meta.get("updated_at")))
        choose_new = new_rank >= old_rank
    return (new_value, new_meta) if choose_new else (old_value, old_meta)


def _merge_links(old, new):
    rows = {}
    for row in list(old or []) + list(new or []):
        if isinstance(row, dict) and row.get("url"):
            rows[row["url"]] = dict(rows.get(row["url"], {}), **row)
    return list(rows.values())


def merge_records(old, new, *, observed_at=None):
    """Merge by field quality, provenance and freshness; preserve first seen."""
    observed_at = observed_at or _now()
    old, new = enriched_record(old), enriched_record(new)
    old_item, new_item = old["item"], new["item"]
    fields = {}
    item = dict(old_item)
    for field in ("title", "description", "url", "product", "affected"):
        item[field], fields[field] = _pick(old, new, field, old_item.get(field), new_item.get(field), observed_at)
    item["sources"] = _union(old_item.get("sources"), new_item.get("sources"))
    item["source"] = "、".join(item["sources"])
    item["published_at"] = _earliest([old_item.get("published_at"), new_item.get("published_at")])
    item["collected_at"] = _earliest([old_item.get("collected_at"), new_item.get("collected_at")])
    item["references"] = _union(old.get("references"), new.get("references"))
    raw = dict(old_item.get("raw_data") or {})
    old_raw, new_raw = old_item.get("raw_data") or {}, new_item.get("raw_data") or {}
    # Raw source snapshots remain available for verification, including when
    # their contribution loses the authoritative business-field selection.
    for key, value in new_raw.items():
        if key == "_store":
            continue
        if key == "raw_by_source" and isinstance(value, dict):
            raw[key] = dict(raw.get(key) or {}, **value)
        elif key == "source_evidence" and isinstance(value, list):
            raw[key] = _union(old_raw.get(key), value)
        elif value is not None and value != "" and value != [] and value != {}:
            if key not in old_raw or _time(new_raw.get("content_updated_at") or observed_at) >= _time(old_raw.get("content_updated_at")):
                raw[key] = value
    item["raw_data"] = raw
    result = {"item": item, "references": item["references"]}
    for field in ("cvss", "epss", "kev"):
        result[field], fields[field] = _pick(old, new, field, old.get(field), new.get(field), observed_at)
    for field in ("papers", "poc"):
        result[field] = _merge_links(old.get(field), new.get(field))
    # Keep raw CVSS aligned with the selected authoritative dimension.
    if result.get("cvss"):
        for key in ("score", "severity", "version", "vector"):
            raw["cvss_" + key] = result["cvss"].get(key)
        raw["cvss_source"] = fields["cvss"].get("source")
    previous = old_raw.get("_store") or {}
    raw["_store"] = dict(previous, fields=fields, in_scope=True,
                         first_seen_at=item["collected_at"], updated_at=observed_at)
    return enriched_record(result)


def _schema(con):
    con.executescript("""
        CREATE TABLE IF NOT EXISTS knowledge_records (
          cve_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
          first_seen_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS knowledge_revisions (
          id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
          recorded_at TEXT NOT NULL, event TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS knowledge_revisions_cve ON knowledge_revisions(cve_id,id);
        CREATE TABLE IF NOT EXISTS knowledge_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS knowledge_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sync_cursors (
          source TEXT PRIMARY KEY, cursor_json TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scope_tombstones (
          cve_id TEXT PRIMARY KEY, first_retracted_at TEXT NOT NULL,
          last_retracted_at TEXT NOT NULL);
    """)


def _read_records(con, include_out_of_scope=False):
    records = [json.loads(row[0]) for row in con.execute("SELECT payload_json FROM knowledge_records")]
    if not include_out_of_scope:
        records = [row for row in records if ((row["item"].get("raw_data") or {}).get("_store") or {}).get("in_scope", True)]
    return sorted(records, key=lambda row: row["item"].get("published_at") or "", reverse=True)


def _write_records(con, records, sync_source=None):
    now = _now()
    for record in records:
        record = enriched_record(record)
        cve_id = record["item"].get("cve_id") or ""
        if not cve_id:
            continue
        old = con.execute("SELECT payload_json FROM knowledge_records WHERE cve_id=?", (cve_id,)).fetchone()
        previous = json.loads(old[0]) if old else enriched_record({"cve_id": cve_id})
        merged = merge_records(previous, record, observed_at=now)
        if sync_source:
            meta = merged["item"]["raw_data"]["_store"]
            meta["sync_sources"] = _union(meta.get("sync_sources"), [sync_source])
        # Observation time alone must not cause revision or work-queue growth.
        old_comparable = json.loads(_json(previous))
        new_comparable = json.loads(_json(merged))
        for candidate in (old_comparable, new_comparable):
            ((candidate["item"].get("raw_data") or {}).get("_store") or {}).pop("updated_at", None)
        if old and _json(old_comparable) == _json(new_comparable):
            continue
        con.execute("DELETE FROM scope_tombstones WHERE cve_id=?", (cve_id,))
        payload = _json(merged)
        con.execute("""INSERT INTO knowledge_records VALUES(?,?,?,?)
          ON CONFLICT(cve_id) DO UPDATE SET payload_json=excluded.payload_json,
          first_seen_at=excluded.first_seen_at,updated_at=excluded.updated_at""",
                    (cve_id, payload, merged["item"]["collected_at"], now))
        con.execute("INSERT INTO knowledge_revisions(cve_id,recorded_at,event,payload_json) VALUES(?,?,?,?)",
                    (cve_id, now, "upsert", payload))


def _migrate(con):
    if con.execute("SELECT 1 FROM knowledge_meta WHERE key='legacy_migrated'").fetchone():
        return
    rows = _read_list(KB_PATH)
    if rows is None and os.environ.get("MAIN_IMPORT_DEMO_CARDS", "0").lower() in {"1", "true", "yes"}:
        rows = _read_list(SEED_CARDS_PATH)
    _write_records(con, rows or [])
    for row in reversed(_read_list(RUNS_PATH) or []):
        con.execute("INSERT INTO knowledge_runs(run_id,created_at,payload_json) VALUES(?,?,?)",
                    (uuid4().hex, _now(), _json(row)))
    con.execute("INSERT INTO knowledge_meta VALUES('legacy_migrated',?)", (_now(),))


def _connect():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        _schema(con)
        if not con.execute("SELECT 1 FROM knowledge_meta WHERE key='legacy_migrated'").fetchone():
            con.execute("BEGIN IMMEDIATE")
            _migrate(con)
            con.commit()
    except BaseException:
        con.rollback()
        con.close()
        raise
    return con


def import_cards():
    """Explicitly import repository demo cards; never called implicitly."""
    return upsert(_read_list(SEED_CARDS_PATH) or [])


def load_kb(include_out_of_scope=False):
    con = _connect()
    try:
        return _read_records(con, include_out_of_scope)
    finally:
        con.close()


def save_kb(records):
    """Compatible merge operation; omitted rows are never silently deleted."""
    return upsert(records)


def upsert(records):
    con = _connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        _write_records(con, records)
        rows = _read_records(con)
        # Exports serialize under the writer lock; SQLite remains authoritative.
        export_cards(rows)
        con.commit()
        return rows
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def _atomic_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temp_path, path)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def export_cards(records):
    cards = []
    for record in records:
        item = record.get("item") or {}
        cvss = record.get("cvss") or {}
        cards.append(normalize(dict(item, cvss=cvss.get("score"), references=record.get("references") or [])))
    text = json.dumps(cards, ensure_ascii=False, indent=2)
    _atomic_text(CARDS_PATH, text)
    _atomic_text(CARDS_JS_PATH, "window.CARDS = %s;\n" % text)


def get_record(cve_id, include_out_of_scope=False):
    con = _connect()
    try:
        row = con.execute("SELECT payload_json FROM knowledge_records WHERE cve_id=?", (cve_id,)).fetchone()
        if not row:
            return None
        record = json.loads(row[0])
        in_scope = ((record["item"].get("raw_data") or {}).get("_store") or {}).get("in_scope", True)
        return record if include_out_of_scope or in_scope else None
    finally:
        con.close()


def _retract(con, cve_ids):
    changed, now = 0, _now()
    for cve_id in dict.fromkeys(cve_ids):
        if not cve_id:
            continue
        tombstone = con.execute("SELECT 1 FROM scope_tombstones WHERE cve_id=?", (cve_id,)).fetchone()
        con.execute("""INSERT INTO scope_tombstones VALUES(?,?,?) ON CONFLICT(cve_id)
          DO UPDATE SET last_retracted_at=excluded.last_retracted_at""", (cve_id, now, now))
        row = con.execute("SELECT payload_json FROM knowledge_records WHERE cve_id=?", (cve_id,)).fetchone()
        if not row:
            if not tombstone:
                con.execute("INSERT INTO knowledge_revisions(cve_id,recorded_at,event,payload_json) VALUES(?,?,?,?)",
                            (cve_id, now, "retract", _json({"cve_id": cve_id, "in_scope": False})))
                changed += 1
            continue
        record = json.loads(row[0])
        meta = record["item"].setdefault("raw_data", {}).setdefault("_store", {})
        if meta.get("in_scope") is False:
            continue
        meta.update(in_scope=False, retracted_at=now, updated_at=now)
        payload = _json(record)
        con.execute("UPDATE knowledge_records SET payload_json=?,updated_at=? WHERE cve_id=?", (payload, now, cve_id))
        con.execute("INSERT INTO knowledge_revisions(cve_id,recorded_at,event,payload_json) VALUES(?,?,?,?)",
                    (cve_id, now, "retract", payload))
        changed += 1
    return changed


def retract(cve_ids):
    """Hide reclassified records while retaining their payload and history."""
    con = _connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        changed = _retract(con, cve_ids)
        export_cards(_read_records(con))
        con.commit()
        return changed
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def retracted_ids():
    """Persistent scope exclusions also cover evidence with no main record."""
    con = _connect()
    try:
        return {row[0] for row in con.execute("SELECT cve_id FROM scope_tombstones")}
    finally:
        con.close()


def source_revision(record):
    """Hash the upstream item without derived enrichment or local metadata."""
    item = dict(record.get("item") or {})
    raw = dict(item.get("raw_data") or {})
    for key in ("_store", "automatic_assessment", "related_guidance"):
        raw.pop(key, None)
    item["raw_data"] = raw
    item.pop("collected_at", None)
    return _digest(item)


def apply_enrichment(records, expected_revisions, job_tokens=None):
    """CAS derived fields without changing upstream content or restoring scope.

    Network calls occur before this short transaction. A changed source record,
    scope withdrawal, reclaimed worker lease, or expired lease rejects its old
    result. The processing worker may then mark the obsolete job as skipped.
    """
    con = _connect()
    accepted, now = [], _now()
    try:
        con.execute("BEGIN IMMEDIATE")
        for incoming in records:
            incoming = enriched_record(incoming)
            cve_id = incoming["item"].get("cve_id") or ""
            row = con.execute("SELECT payload_json FROM knowledge_records WHERE cve_id=?", (cve_id,)).fetchone()
            if not row or con.execute("SELECT 1 FROM scope_tombstones WHERE cve_id=?", (cve_id,)).fetchone():
                continue
            current = json.loads(row[0])
            meta = ((current["item"].get("raw_data") or {}).get("_store") or {})
            if meta.get("in_scope", True) is False or source_revision(current) != expected_revisions.get(cve_id):
                continue
            if job_tokens is not None:
                token = job_tokens.get(cve_id) or {}
                if not token.get("id") or not token.get("lease_token"):
                    continue
                if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='processing_jobs'").fetchone():
                    continue
                job = con.execute("""SELECT cve_id,status,lease_token,lease_until,revision
                  FROM processing_jobs WHERE id=?""", (token["id"],)).fetchone()
                if (not job or job[0] != cve_id or job[1] != "running" or job[2] != token["lease_token"]
                        or (job[3] or 0) < time.time() or job[4] != expected_revisions[cve_id]):
                    continue
            for field in ("epss", "kev"):
                value = incoming.get(field)
                if isinstance(value, dict) and not any(value.get(key) for key in ("retrieved_at", "fetched_at", "updated_at", "date")):
                    incoming[field] = dict(value, retrieved_at=now)
            merged = merge_records(current, incoming, observed_at=now)
            # Only derived dimensions and approved local assessments may change.
            # Keep the upstream raw CVSS / package / classification snapshot
            # untouched so enrichment cannot recursively create new source jobs.
            item = json.loads(_json(current["item"]))
            raw = item.setdefault("raw_data", {})
            current_meta = json.loads(_json(meta))
            current_meta["fields"] = dict(current_meta.get("fields") or {})
            for field in ("cvss", "epss", "kev"):
                current_meta["fields"][field] = merged["item"]["raw_data"]["_store"]["fields"][field]
            current_meta["updated_at"] = now
            raw["_store"] = current_meta
            for key in ("automatic_assessment", "related_guidance"):
                if key in incoming["item"].get("raw_data", {}):
                    raw[key] = incoming["item"]["raw_data"][key]
            merged["item"] = item
            merged["item"]["raw_data"]["_store"]["in_scope"] = True
            payload = _json(merged)
            con.execute("UPDATE knowledge_records SET payload_json=?,updated_at=? WHERE cve_id=?", (payload, now, cve_id))
            con.execute("INSERT INTO knowledge_revisions(cve_id,recorded_at,event,payload_json) VALUES(?,?,?,?)",
                        (cve_id, now, "enrich", payload))
            accepted.append(cve_id)
        if accepted:
            export_cards(_read_records(con))
        con.commit()
        return accepted
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def _set_sync_cursor(con, source, cursor):
    if not source or not isinstance(cursor, dict):
        raise ValueError("A nonempty sync source and dictionary cursor are required")
    saved = _saved_cursor(cursor)
    con.execute("""INSERT INTO sync_cursors VALUES(?,?,?) ON CONFLICT(source)
      DO UPDATE SET cursor_json=excluded.cursor_json,updated_at=excluded.updated_at""", (source, _json(saved), _now()))


def _saved_cursor(cursor):
    return {key: value for key, value in cursor.items() if key not in {"expected_cursor", "reset"}}


def get_sync_cursor(source):
    con = _connect()
    try:
        row = con.execute("SELECT cursor_json FROM sync_cursors WHERE source=?", (source,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        con.close()


def set_sync_cursor(source, cursor):
    con = _connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        _set_sync_cursor(con, source, cursor)
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def apply_sync_page(records, *, source, cursor, retracted_ids=()):
    """Commit a complete feed cycle and its checkpoint atomically.

    A reset must contain the complete replacement snapshot (all pages). Only
    records managed by this sync source participate in reset reconciliation.
    """
    if not isinstance(cursor, dict):
        raise ValueError("Dictionary sync cursor required")
    records = list(records)
    con = _connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        old_cursor_row = con.execute("SELECT cursor_json FROM sync_cursors WHERE source=?", (source,)).fetchone()
        old_cursor = json.loads(old_cursor_row[0]) if old_cursor_row else {}
        if "expected_cursor" in cursor:
            expected = cursor["expected_cursor"]
            if not isinstance(expected, dict) or _saved_cursor(expected) != _saved_cursor(old_cursor):
                raise StaleSyncPage("The sync checkpoint changed during collection; retry from the current cursor")
        reset = bool(cursor.get("reset"))
        for key in ("epoch", "base_url"):
            if old_cursor.get(key) and cursor.get(key) != old_cursor[key]:
                reset = True
        if type(cursor.get("seq")) is int and type(old_cursor.get("seq")) is int and cursor["seq"] < old_cursor["seq"] and not reset:
            raise StaleSyncPage("A stale cycle cannot move the sync checkpoint backwards")
        if reset:
            incoming_ids = {(enriched_record(record)["item"].get("cve_id") or "") for record in records}
            absent = [row["item"]["cve_id"] for row in _read_records(con, include_out_of_scope=True)
                      if source in (((row["item"].get("raw_data") or {}).get("_store") or {}).get("sync_sources", []))
                      and row["item"]["cve_id"] not in incoming_ids]
            _retract(con, absent)
        _write_records(con, records, sync_source=source)
        _retract(con, retracted_ids)
        _set_sync_cursor(con, source, cursor)
        rows = _read_records(con)
        export_cards(rows)
        con.commit()
        return rows
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def append_run(steps, kind):
    con = _connect()
    try:
        run = {"run_id": uuid4().hex, "created_at": _now(), "kind": kind, "steps": steps}
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT INTO knowledge_runs(run_id,created_at,payload_json) VALUES(?,?,?)",
                    (run["run_id"], run["created_at"], _json(run)))
        con.commit()
        return run
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def latest_run():
    con = _connect()
    try:
        row = con.execute("SELECT payload_json FROM knowledge_runs ORDER BY id DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None
    finally:
        con.close()
