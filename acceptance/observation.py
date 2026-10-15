"""Durable, local-only observation windows. Never collect or rewrite B data.

Snapshots reference append-only compact record/run versions instead of copying
the upstream payload database every minute. A final report is frozen from the
actual captured versions, never reconstructed by assigning current data an old
capture timestamp. An upstream inventory is a declaration, not certified truth.
"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit
import uuid

from acceptance import storage

DEFAULT_SCOPE = "注册来源原始记录；AI范围需清单in_scope核对"
THRESHOLDS = (6, 12, 24)
INTERVAL = 60
STATES = ("collected", "late", "missing", "unknown", "not_due", "excluded")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _stamp(value, *, nvd=False):
    if not isinstance(value, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            if not nvd:
                return None
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _required(value, name):
    parsed = _stamp(value)
    if parsed is None:
        raise ValueError(f"{name} requires a precise timestamp including seconds and timezone")
    return parsed


def _now(value=None):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("now must include timezone")
        return value.astimezone(timezone.utc)
    return _required(value if value is not None else storage.now_iso(), "now")


def _iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _source_commit():
    """Only the known deployment marker; never search user files or run Git."""
    try:
        value = (Path(__file__).resolve().parents[2] / "VERSION.txt").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    return value.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", value) else None


def _ensure(con):
    con.executescript("""
      CREATE TABLE IF NOT EXISTS observation_windows (
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, config_json TEXT NOT NULL,
        config_sha256 TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active',
        frozen_at TEXT, frozen_json TEXT, frozen_sha256 TEXT);
      CREATE TABLE IF NOT EXISTS observation_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT, window_id TEXT NOT NULL,
        record_key TEXT NOT NULL, content_json TEXT NOT NULL, sha256 TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        UNIQUE(window_id,record_key,captured_at,sha256));
      CREATE INDEX IF NOT EXISTS observation_records_window_key ON observation_records(window_id,record_key,id);
      CREATE TABLE IF NOT EXISTS observation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, window_id TEXT NOT NULL,
        record_key TEXT NOT NULL, content_json TEXT NOT NULL, sha256 TEXT NOT NULL,
        captured_at TEXT NOT NULL, UNIQUE(window_id,record_key,captured_at,sha256));
      CREATE INDEX IF NOT EXISTS observation_runs_window_key ON observation_runs(window_id,record_key,id);
      CREATE TABLE IF NOT EXISTS observation_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, window_id TEXT NOT NULL,
        captured_at TEXT NOT NULL, content_json TEXT NOT NULL, sha256 TEXT NOT NULL,
        UNIQUE(window_id,captured_at));
      CREATE INDEX IF NOT EXISTS observation_snapshots_window ON observation_snapshots(window_id,id);
      CREATE TABLE IF NOT EXISTS observation_inventories (
        window_id TEXT NOT NULL, source TEXT NOT NULL, imported_at TEXT NOT NULL,
        content_json TEXT NOT NULL, sha256 TEXT NOT NULL,
        PRIMARY KEY(window_id,source));
    """)


def _load(con, window_id):
    row = con.execute("SELECT * FROM observation_windows WHERE id=?", (window_id,)).fetchone()
    if row is None:
        raise ValueError("Observation window not found")
    if storage.canonical_hash(json.loads(row["config_json"])) != row["config_sha256"]:
        raise ValueError("Window configuration integrity check failed")
    return dict(row)


def _default_sources():
    # This module imports only standard-library dependencies and has no package
    # path mutation, B application construction, network or DB migration.
    from intelligence.monitoring.source_registry import get_sources
    return [source.name for source in get_sources()]


def create_window(payload, db_path=None, now=None):
    if not isinstance(payload, dict):
        raise ValueError("window payload must be an object")
    allowed = {"name", "sources", "scope", "duration_hours", "target_hours", "maturity_hours"}
    if set(payload) - allowed:
        raise ValueError("Window start/end/as_of and statistical policy are server controlled")
    for key, expected in (("duration_hours", 72), ("target_hours", 6), ("maturity_hours", 24)):
        if key in payload and (type(payload[key]) is not int or payload[key] != expected):
            raise ValueError(f"{key} must be {expected}")
    if "sources" in payload and not isinstance(payload["sources"], list):
        raise ValueError("sources must be a list")
    sources = payload.get("sources") or _default_sources()
    if (not isinstance(sources, list) or not sources or len(sources) > 100
            or any(not isinstance(s, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", s) for s in sources)
            or len(set(sources)) != len(sources)):
        raise ValueError("sources must contain unique nonempty source names")
    name, scope = payload.get("name", "72小时持续观测"), payload.get("scope", DEFAULT_SCOPE)
    if any(not isinstance(s, str) or not s.strip() or len(s) > 500 for s in (name, scope)):
        raise ValueError("name and scope must be nonempty text")
    start = _now(now)
    config = {"name": name.strip(), "scope": scope.strip(), "sources": sorted(sources),
              "start_at": _iso(start), "end_at": _iso(start + timedelta(hours=72)),
              "maturity_end_at": _iso(start + timedelta(hours=96)), "duration_hours": 72,
              "target_hours": 6, "threshold_hours": list(THRESHOLDS), "maturity_hours": 24,
              "statistical_unit": "source_record", "snapshot_interval_seconds": INTERVAL,
              "source_commit": _source_commit()}
    identity = uuid.uuid4().hex
    with storage.connect(db_path) as con:
        _ensure(con)
        con.execute("INSERT INTO observation_windows(id,created_at,config_json,config_sha256) VALUES(?,?,?,?)",
                    (identity, _iso(start), _json(config), storage.canonical_hash(config)))
    return get_window(identity, db_path=db_path, now=start)


def _tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(con, table):
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def _read_b(config, since, current, intelligence_db):
    if intelligence_db is None:
        from api.b_embed import db_path
        intelligence_db = db_path()
    path = Path(intelligence_db).resolve(strict=True)
    result = {"database_status": "ok", "database_error": None, "available_tables": [],
              "records": [], "runs": [], "read_cutoff": _iso(current)}
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=15)) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        tables = _tables(con)
        result["available_tables"] = sorted(tables & {"source_items", "knowledge_documents", "collector_runs", "document_source_runs"})
        slots = ",".join("?" for _ in config["sources"])
        # Inclusive one-second overlap compensates SQLite datetime precision.
        # Only compact columns are transferred; raw payloads remain in B.
        after = _iso(since - timedelta(seconds=1))
        for table, identity in (("source_items", "source_id"), ("knowledge_documents", "document_id")):
            if table not in tables:
                continue
            cols = _columns(con, table)
            updated = "content_updated_at" if "content_updated_at" in cols else "first_seen_at"
            publication = ("published_at" if table == "knowledge_documents" else
                           "CASE WHEN json_valid(payload_json) THEN json_extract(payload_json,'$.published_at') END")
            cve = "cve_id" if "cve_id" in cols else "NULL"
            digest = "content_sha256" if "content_sha256" in cols else "NULL"
            url = "url" if "url" in cols else "CASE WHEN json_valid(payload_json) THEN json_extract(payload_json,'$.url') END"
            upstream_id = "CASE WHEN json_valid(payload_json) THEN COALESCE(json_extract(payload_json,'$.raw_data.id'),json_extract(payload_json,'$.raw_data.advisory.id')) END"
            query = (f"SELECT source,{identity} AS native_id,{cve} AS cve_id,{publication} AS published_at,"
                     f"first_seen_at,{updated} AS content_updated_at,{digest} AS source_content_sha256,{url} AS url,{upstream_id} AS upstream_id "
                     f"FROM {table} WHERE source IN ({slots}) AND "
                     f"(datetime({updated})>=datetime(?) OR datetime(first_seen_at)>=datetime(?))")
            for row in con.execute(query, (*config["sources"], after, after)):
                item = dict(row)
                item.update(table=table, record_key=f"{table}:{item['source']}:{item['native_id']}")
                seen = _stamp(item["first_seen_at"])
                published = _stamp(item["published_at"], nvd=item["source"] == "NVD")
                start, end = _stamp(config["start_at"]), _stamp(config["end_at"])
                # Keep newly observed historical/unknown timing records for
                # explicit exclusions, but not every old record updated today.
                if seen and start <= seen <= current or published and start <= published < end or seen is None:
                    result["records"].append(item)
        for table, source_col in (("collector_runs", "collector"), ("document_source_runs", "source")):
            if table not in tables:
                continue
            for row in con.execute(f"SELECT * FROM {table} WHERE {source_col} IN ({slots}) AND datetime(finished_at)>=datetime(?)",
                                   (*config["sources"], after)):
                item = dict(row)
                item.update(source=item[source_col], table=table, record_key=f"{table}:{item['id']}")
                finished = _stamp(item.get("finished_at"))
                if finished and _stamp(config["start_at"]) <= finished <= current:
                    result["runs"].append(item)
        if not tables & {"source_items", "knowledge_documents"}:
            result["database_status"] = "unavailable"
            result["database_error"] = "No supported intelligence record tables"
    return result


def _save_versions(con, table, window_id, rows, captured):
    ids = []
    for item in rows:
        sha = storage.canonical_hash(item)
        previous = con.execute(f"SELECT sha256 FROM {table} WHERE window_id=? AND record_key=? ORDER BY id DESC LIMIT 1",
                               (window_id, item["record_key"])).fetchone()
        if previous and previous[0] == sha:
            continue
        cursor = con.execute(f"INSERT OR IGNORE INTO {table}(window_id,record_key,content_json,sha256,captured_at) VALUES(?,?,?,?,?)",
                             (window_id, item["record_key"], _json(item), sha, captured))
        if cursor.rowcount:
            ids.append({"id": cursor.lastrowid, "sha256": sha})
    return ids


def tick(db_path=None, intelligence_db=None, now=None):
    current = _now(now)
    with storage.connect(db_path) as con:
        _ensure(con)
        windows = [dict(r) for r in con.execute("SELECT * FROM observation_windows WHERE state='active' ORDER BY created_at,id")]
    results = []
    for window in windows:
        config = json.loads(window["config_json"])
        if current < _stamp(config["start_at"]):
            results.append({"id": window["id"], "status": "clock_before_window"})
            continue
        with storage.connect(db_path) as con:
            last = con.execute("SELECT * FROM observation_snapshots WHERE window_id=? ORDER BY id DESC LIMIT 1", (window["id"],)).fetchone()
            good = con.execute("SELECT captured_at FROM observation_snapshots WHERE window_id=? AND json_extract(content_json,'$.database_status')='ok' ORDER BY id DESC LIMIT 1", (window["id"],)).fetchone()
        if last and current <= _stamp(last["captured_at"]):
            results.append({"id": window["id"], "status": "already_sampled"})
            continue
        since = _stamp(good[0]) if good else _stamp(config["start_at"])
        try:
            captured = _read_b(config, since, current, intelligence_db)
        except (OSError, sqlite3.Error, ValueError) as exc:
            captured = {"database_status": "failed", "database_error": f"{type(exc).__name__}: {str(exc)[:400]}",
                        "available_tables": [], "records": [], "runs": [], "read_cutoff": _iso(current)}
        with storage.connect(db_path) as con:
            con.execute("BEGIN IMMEDIATE")
            live = _load(con, window["id"])
            last = con.execute("SELECT * FROM observation_snapshots WHERE window_id=? ORDER BY id DESC LIMIT 1", (window["id"],)).fetchone()
            if live["state"] != "active" or last and current <= _stamp(last["captured_at"]):
                continue
            record_ids = _save_versions(con, "observation_records", window["id"], captured.pop("records"), _iso(current))
            run_ids = _save_versions(con, "observation_runs", window["id"], captured.pop("runs"), _iso(current))
            snapshot = dict(captured, captured_at=_iso(current), record_versions=record_ids, run_versions=run_ids,
                            previous_sha256=last["sha256"] if last else None,
                            config_sha256=window["config_sha256"],
                            source_commit=_source_commit(),
                            late_capture_seconds=max(0, (current - _stamp(config["maturity_end_at"])).total_seconds()))
            sha = storage.canonical_hash(snapshot)
            con.execute("INSERT INTO observation_snapshots(window_id,captured_at,content_json,sha256) VALUES(?,?,?,?)",
                        (window["id"], _iso(current), _json(snapshot), sha))
            if current >= _stamp(config["maturity_end_at"]):
                con.execute("UPDATE observation_windows SET state='ready' WHERE id=? AND state='active'", (window["id"],))
            results.append({"id": window["id"], "status": snapshot["database_status"], "snapshot_sha256": sha,
                            "new_record_versions": len(record_ids), "new_run_versions": len(run_ids)})
    return {"sampled_at": _iso(current), "windows": results}


def _url(value, field):
    try:
        parsed = urlsplit(value) if isinstance(value, str) else None
        if not parsed or parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError()
        parsed.port
    except ValueError:
        raise ValueError(f"{field} requires an HTTP(S) URL without credentials") from None
    return value


def import_inventory(window_id, payload, db_path=None):
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise ValueError("inventory requires schema_version=1")
    current = _now()
    with storage.connect(db_path) as con:
        _ensure(con)
        con.execute("BEGIN IMMEDIATE")
        window = _load(con, window_id)
        if window["state"] == "frozen":
            raise ValueError("Frozen window cannot accept another inventory")
        config = json.loads(window["config_json"])
        source = payload.get("source")
        if source not in config["sources"] or payload.get("scope") != config["scope"]:
            raise ValueError("inventory source and scope must match the frozen window")
        if con.execute("SELECT 1 FROM observation_inventories WHERE window_id=? AND source=?", (window_id, source)).fetchone():
            raise ValueError("A frozen inventory for this source already exists and cannot be replaced")
        captured, start, end = [_required(payload.get(k), k) for k in ("captured_at", "coverage_start", "coverage_end")]
        if not _stamp(config["start_at"]) <= start < end <= _stamp(config["end_at"]) or not end <= captured <= current:
            raise ValueError("inventory coverage must be inside the window and already elapsed at capture/import")
        if type(payload.get("completeness_declaration")) is not bool:
            raise ValueError("completeness_declaration must be a boolean declaration")
        _url(payload.get("reference_url"), "reference_url")
        digest = payload.get("response_sha256")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-fA-F]{64}", digest):
            raise ValueError("response_sha256 requires 64 hexadecimal characters")
        if "response_body" in payload:
            body = payload["response_body"]
            if not isinstance(body, str) or len(body.encode("utf-8")) > 4 * 1024 * 1024:
                raise ValueError("response_body must be UTF-8 text no larger than 4 MiB")
            if hashlib.sha256(body.encode("utf-8")).hexdigest() != digest.lower():
                raise ValueError("response_body does not match response_sha256")
        items = payload.get("items")
        if not isinstance(items, list) or len(items) > 100000:
            raise ValueError("items must be a bounded list")
        identities = set()
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("inventory items must be objects")
            identity = item.get("id")
            if not isinstance(identity, str) or not identity.strip() or len(identity) > 500 or identity != identity.strip():
                raise ValueError("item id must be nonempty trimmed text")
            canonical = identity.upper() if identity.upper().startswith("CVE-") else identity
            if canonical in identities:
                raise ValueError("inventory identities must be unique")
            identities.add(canonical)
            if "in_scope" not in item or item["in_scope"] is not None and type(item["in_scope"]) is not bool:
                raise ValueError("in_scope must be true, false or null")
            _url(item.get("url"), "item.url")
            publication = item.get("published_at")
            if not isinstance(publication, str):
                raise ValueError("published_at must preserve the source timestamp text")
            precise = _stamp(publication)
            if precise:
                if not start <= precise < end:
                    raise ValueError("item publication is outside inventory coverage")
            else:
                try:
                    datetime.fromisoformat(publication)
                except ValueError:
                    raise ValueError("published_at must be an ISO date/timestamp; imprecise times remain unknown") from None
        con.execute("INSERT INTO observation_inventories VALUES(?,?,?,?,?)",
                    (window_id, source, _iso(current), _json(payload), storage.canonical_hash(payload)))
    return get_window(window_id, db_path=db_path, now=current)


def _latest_versions(con, table, window_id):
    return [dict(r) for r in con.execute(f"SELECT r.* FROM {table} r WHERE window_id=? AND id=(SELECT MAX(x.id) FROM {table} x WHERE x.window_id=r.window_id AND x.record_key=r.record_key) ORDER BY r.record_key", (window_id,))]


def _histogram(items):
    by_threshold = {}
    for hours in THRESHOLDS:
        counts = Counter(item["thresholds"][str(hours)] for item in items)
        denominator = sum(counts[s] for s in ("collected", "late", "missing"))
        by_threshold[str(hours)] = {**{s: counts[s] for s in STATES}, "denominator": denominator,
                                     "within_rate": counts["collected"] / denominator if denominator else None}
    return by_threshold


def _latency(items):
    values = sorted(i["delay_seconds"] for i in items if i.get("delay_seconds") is not None)
    return {"samples": len(values), "p50_seconds": values[math.ceil(.5 * len(values)) - 1] if values else None,
            "p95_seconds": values[math.ceil(.95 * len(values)) - 1] if values else None,
            "max_seconds": values[-1] if values else None}


def _assess(source, identity, published_text, record, as_of, config, *, scope=True, reason=None, absent_unknown=False):
    published = _stamp(published_text, nvd=source == "NVD")
    seen = _stamp(record.get("first_seen_at")) if record else None
    excluded = False
    if scope is False:
        reason, excluded = "declared_out_of_scope", True
    elif scope is None:
        reason = "scope_unknown"
    elif source == "CISA_KEV":
        reason, excluded = "kev_listing_is_not_original_publication", True
    elif published is None:
        reason = "missing_or_imprecise_publication_time"
    elif not _stamp(config["start_at"]) <= published < _stamp(config["end_at"]):
        reason, excluded = "outside_publication_window", True
    elif record and _stamp(record.get("published_at"), nvd=source == "NVD") != published:
        reason = "source_publication_time_conflict"
    elif record and seen is None:
        reason = "missing_or_imprecise_first_seen"
    elif seen and seen < _stamp(config["start_at"]):
        reason = "preexisting_first_seen_with_publication_revision"
    elif seen and seen < published:
        reason = "negative_delay"
    elif seen and seen > as_of:
        reason = "first_seen_after_capture"
    elif published > as_of:
        reason = "publication_after_capture"
    elif absent_unknown and not record:
        reason = "source_record_snapshot_unavailable"
    delay = (seen - published).total_seconds() if seen and published and not reason else None
    thresholds = {}
    for hours in THRESHOLDS:
        if reason:
            status = "excluded" if excluded else "unknown"
        elif seen:
            status = "collected" if delay <= hours * 3600 else "late"
        else:
            status = "not_due" if as_of < published + timedelta(hours=hours) else "missing"
        thresholds[str(hours)] = status
    return {"source": source, "id": identity, "published_at": published_text,
            "source_published_at": record.get("published_at") if record else None,
            "record_key": record.get("record_key") if record else None,
            "url": record.get("url") if record else None,
            "first_seen_at": record.get("first_seen_at") if record else None,
            "delay_seconds": delay, "match_status": "matched" if record else "unmatched",
            "reason": reason, "thresholds": thresholds}


def _gaps(times, start, end):
    points = [start] + sorted({t for t in times if start <= t <= end}) + [end]
    return [max(0, (b - a).total_seconds()) for a, b in zip(points, points[1:])]


def _report(con, row, current):
    config = json.loads(row["config_json"])
    snapshots = [dict(r) for r in con.execute("SELECT * FROM observation_snapshots WHERE window_id=? ORDER BY id", (row["id"],))]
    snapdata = [json.loads(r["content_json"]) for r in snapshots]
    if snapshots and current < _stamp(snapshots[-1]["captured_at"]):
        raise ValueError("Current clock precedes the last captured snapshot")
    good = [s for s in snapdata if s["database_status"] == "ok"]
    last_good = good[-1] if good else None
    as_of = _stamp(last_good["captured_at"]) if good else _stamp(config["start_at"])
    record_versions = _latest_versions(con, "observation_records", row["id"])
    records = [json.loads(r["content_json"]) for r in record_versions]
    runs = [json.loads(r["content_json"]) for r in _latest_versions(con, "observation_runs", row["id"])]
    inventories = [dict(r) for r in con.execute("SELECT * FROM observation_inventories WHERE window_id=? ORDER BY source", (row["id"],))]
    observed = [_assess(r["source"], r["native_id"], r.get("published_at"), r, as_of, config) for r in records]
    invitems, meta, full_sources = [], [], set()
    by_native, by_cve, by_url, by_upstream = {}, {}, {}, {}
    for record in records:
        by_native.setdefault((record["source"], record["native_id"]), []).append(record)
        if isinstance(record.get("url"), str) and record["url"]:
            by_url.setdefault((record["source"], record["url"]), []).append(record)
        if isinstance(record.get("upstream_id"), str) and record["upstream_id"]:
            by_upstream.setdefault((record["source"], record["upstream_id"]), []).append(record)
        if record.get("cve_id"):
            by_cve.setdefault((record["source"], record["cve_id"].upper()), []).append(record)
    for entry in inventories:
        inventory = json.loads(entry["content_json"])
        if storage.canonical_hash(inventory) != entry["sha256"]:
            raise ValueError("Inventory integrity check failed")
        full = (inventory["completeness_declaration"] and _stamp(inventory["coverage_start"]) == _stamp(config["start_at"])
                and _stamp(inventory["coverage_end"]) == _stamp(config["end_at"]))
        if full:
            full_sources.add(entry["source"])
        meta.append({k: inventory[k] for k in ("source", "scope", "captured_at", "coverage_start", "coverage_end", "completeness_declaration", "reference_url", "response_sha256")})
        meta[-1].update(item_count=len(inventory["items"]), payload_sha256=entry["sha256"],
                        completeness_verified=False, response_hash_verified="response_body" in inventory,
                        response_sha256_verified="response_body" in inventory)
        native_ids = {item["id"] for item in inventory["items"]}
        matches, upstream_groups = [], {}
        for item in inventory["items"]:
            candidates = by_native.get((entry["source"], item["id"]), [])
            alias = False
            if not candidates:
                hashed = "doc-" + hashlib.sha256((entry["source"] + "\0" + item["id"]).encode("utf-8")).hexdigest()
                candidates = by_native.get((entry["source"], hashed), [])
                alias = bool(candidates)
            if not candidates:
                candidates = by_upstream.get((entry["source"], item["id"]), [])
                alias = bool(candidates)
            if not candidates:
                candidates = by_url.get((entry["source"], item["url"]), [])
                alias = bool(candidates)
            if not candidates and item["id"].upper().startswith("CVE-"):
                candidates = by_cve.get((entry["source"], item["id"].upper()), [])
                alias = True
            record = candidates[0] if len(candidates) == 1 else None
            reason = "ambiguous_identity" if len(candidates) > 1 else None
            if record and record.get("url") and record["url"] != item["url"]:
                record, reason = None, "source_url_conflict"
            if record and alias and not record.get("url"):
                record, reason = None, "alias_requires_matching_source_url"
            matches.append((item, record, reason, alias))
            if record:
                for field in ("upstream_id", "url"):
                    value = record.get(field)
                    if isinstance(value, str) and value:
                        upstream_groups.setdefault((field, value), set()).add(record["record_key"])
        # A source can materialize one advisory as both a raw record and a
        # document. Exclude every matching representation before scoring so
        # differing first-seen times cannot make inventory order decide delay.
        duplicate_upstream = {key for group in upstream_groups.values() if len(group) > 1 for key in group}
        claimed = set()
        for item, record, reason, alias in matches:
            if record and record["record_key"] in duplicate_upstream:
                record, reason = None, "duplicate_upstream_identity"
            if record and (record["record_key"] in claimed or alias and record["native_id"] in native_ids):
                record, reason = None, "duplicate_collected_identity"
            if record:
                claimed.add(record["record_key"])
            available = set(last_good["available_tables"]) if good else set()
            known_vulnerability_source = entry["source"] in {"NVD", "GITHUB_ADVISORY", "CISA_KEV", "OSV"}
            expected_table = "source_items" if known_vulnerability_source else "knowledge_documents"
            absence_unverifiable = not good or expected_table not in available
            assessed = _assess(entry["source"], item["id"], item["published_at"], record, as_of, config,
                               scope=item["in_scope"], reason=reason, absent_unknown=absence_unverifiable)
            assessed["inventory_url"] = item["url"]
            assessed["matched_record_key"] = record["record_key"] if record else None
            invitems.append(assessed)
    inv_thresholds = _histogram(invitems)
    full_coverage = set(config["sources"]) == full_sources
    eligible = [i for i in invitems if any(i["thresholds"][str(h)] in ("collected", "late", "missing", "not_due") for h in THRESHOLDS)]
    unknown = any(i["thresholds"]["6"] == "unknown" for i in invitems)
    recall = (sum(i["match_status"] == "matched" for i in eligible) / len(eligible)
              if full_coverage and eligible and not unknown and good
              and all(i["thresholds"]["6"] != "not_due" for i in eligible) else None)
    observation_end = min(current, _stamp(config["maturity_end_at"]))
    heartbeat_gaps = _gaps([_stamp(s["captured_at"]) for s in snapdata], _stamp(config["start_at"]), observation_end)
    histories = []
    for source in config["sources"]:
        source_runs = [r for r in runs if r["source"] == source]
        statuses = Counter(r.get("status", "unknown") for r in source_runs)
        times = [t for r in source_runs if (t := _stamp(r.get("finished_at"))) is not None]
        gaps = _gaps(times, _stamp(config["start_at"]), min(current, _stamp(config["end_at"])))
        latest_run = max(source_runs, key=lambda r: _stamp(r.get("finished_at")) or _stamp(config["start_at"])) if source_runs else None
        histories.append({"source": source, "runs": len(source_runs), "success": statuses["success"],
                          "partial": statuses["partial"], "failed": statuses["failed"],
                          "last_run_at": _iso(max(times)) if times else None,
                          "max_run_gap_seconds": max(gaps, default=0),
                          "latest_status": latest_run.get("status") if latest_run else "unknown",
                          "latest_error": latest_run.get("error_text") if latest_run else None})
    state = ("frozen" if row["state"] == "frozen" else "ready" if current >= _stamp(config["maturity_end_at"])
             else "maturing" if current >= _stamp(config["end_at"]) else "active")
    return {"schema_version": 1, "id": row["id"], **config, "status": state,
            "config_sha256": row["config_sha256"], "snapshots_count": len(snapshots),
            "latest_snapshot_at": snapshots[-1]["captured_at"] if snapshots else None,
            "evidence_as_of": _iso(as_of) if good else None,
            "latest_snapshot_sha256": snapshots[-1]["sha256"] if snapshots else None,
            "versions_seen": list(dict.fromkeys([config.get("source_commit")] + [s.get("source_commit") for s in snapdata])),
            "progress": min(1.0, max(0.0, (current - _stamp(config["start_at"])).total_seconds() / (72 * 3600))),
            "coverage": {"snapshot_interval_seconds": INTERVAL, "heartbeat_max_gap_seconds": max(heartbeat_gaps, default=0),
                         "missing_heartbeat_intervals": sum(max(0, math.floor(g / INTERVAL) - 1) for g in heartbeat_gaps if g > INTERVAL * 2),
                         "database_failures": sum(s["database_status"] != "ok" for s in snapdata),
                         "latest_database_status": snapdata[-1]["database_status"] if snapdata else "not_sampled",
                         "source_run_history": histories,
                         "late_capture_seconds": max((s["late_capture_seconds"] for s in snapdata), default=0)},
            "metrics": {"observed": {"record_count": len(observed), "eligible_count": sum(i["reason"] is None for i in observed),
                                      "excluded": dict(Counter(i["reason"] for i in observed if i["reason"])),
                                      "latency": _latency(observed), "by_threshold": _histogram(observed), "items": observed},
                        "inventory": {"inventory_count": len(inventories), "item_count": len(invitems),
                                      "source_coverage_complete": full_coverage, "completeness_verified": False,
                                      "recall": recall, "sla_verified": None, "latency": _latency(invitems),
                                      "by_threshold": inv_thresholds, "items": invitems}},
            "inventories": meta, "sla_verified": None, "frozen_at": row["frozen_at"], "frozen_sha256": row["frozen_sha256"],
            "limits": ["Source records are not unique CVEs or verified AI-relevant records; inventories supply in_scope declarations.",
                       "Inventory completeness and response hashes are user declarations; deletion or omission upstream is not independently verified.",
                       "Without response_body its hash is only registered; a matching body verifies file integrity, not origin or complete item extraction.",
                       "Heartbeat gaps describe sampler availability; persisted source run gaps describe collector stages, not continuous source uptime.",
                       "Absence is assessed at the latest readable snapshot, never at an uncaptured future cutoff.",
                       "Historical snapshot chains require the local acceptance audit database; the frozen JSON independently hashes the final measured report only.",
                       "The initial deployment commit is frozen, but versions_seen records changes or unknown version markers during observation.",
                       "No SLA certification is produced; real collection failures, unknown times and missing inventories remain visible."],
            "frozen_report": None}


def get_window(window_id, db_path=None, now=None):
    current = _now(now)
    with storage.connect(db_path) as con:
        _ensure(con)
        row = _load(con, window_id)
        if row["state"] == "frozen":
            report = json.loads(row["frozen_json"])
            if storage.canonical_hash(report) != row["frozen_sha256"]:
                raise ValueError("Frozen report integrity check failed")
            return {**report, "status": "frozen", "frozen_at": row["frozen_at"],
                    "frozen_sha256": row["frozen_sha256"], "frozen_report": report}
        return _report(con, row, current)


def list_windows(db_path=None):
    with storage.connect(db_path) as con:
        _ensure(con)
        ids = [r[0] for r in con.execute("SELECT id FROM observation_windows ORDER BY created_at DESC,id")]
    return [get_window(identity, db_path=db_path) for identity in ids]


def freeze_window(window_id, db_path=None, now=None):
    current = _now(now)
    with storage.connect(db_path) as con:
        _ensure(con)
        con.execute("BEGIN IMMEDIATE")
        row = _load(con, window_id)
        if row["state"] == "frozen":
            raise ValueError("Window is already frozen and cannot be overwritten")
        config = json.loads(row["config_json"])
        if current < _stamp(config["end_at"]):
            raise ValueError("Cannot freeze a future/incomplete 72-hour window")
        report = _report(con, row, current)
        captured = _stamp(report["latest_snapshot_at"])
        if (captured is None or captured < _stamp(config["end_at"]) or captured > current
                or report["coverage"]["latest_database_status"] != "ok"):
            raise ValueError("Freeze needs a successful actual snapshot after the publication window ended")
        if row["state"] != "ready" and (current - captured).total_seconds() > INTERVAL * 2:
            raise ValueError("Snapshot is stale; wait for the observation worker before freezing")
        measurable_inventory = any(item["thresholds"]["6"] in {"collected", "late", "missing", "not_due"}
                                   for item in report["metrics"]["inventory"]["items"])
        if not report["metrics"]["observed"]["eligible_count"] and not measurable_inventory:
            raise ValueError("Empty or entirely unmeasurable window cannot be frozen as a successful report")
        previous = None
        for snapshot in con.execute("SELECT content_json,sha256 FROM observation_snapshots WHERE window_id=? ORDER BY id", (window_id,)):
            value = json.loads(snapshot["content_json"])
            if storage.canonical_hash(value) != snapshot["sha256"] or value["previous_sha256"] != previous:
                raise ValueError("Snapshot hash-chain integrity check failed")
            for table, field in (("observation_records", "record_versions"), ("observation_runs", "run_versions")):
                for reference in value[field]:
                    version = con.execute(f"SELECT content_json,sha256 FROM {table} WHERE window_id=? AND id=?", (window_id, reference["id"])).fetchone()
                    if not version or version["sha256"] != reference["sha256"] or storage.canonical_hash(json.loads(version["content_json"])) != reference["sha256"]:
                        raise ValueError("Captured version integrity check failed")
            previous = snapshot["sha256"]
        report.update(status="frozen", frozen_at=_iso(current), frozen_report=None, frozen_sha256=None)
        report["sample_records"] = [json.loads(r["content_json"]) for r in _latest_versions(con, "observation_records", window_id)]
        report["source_runs"] = [json.loads(r["content_json"]) for r in _latest_versions(con, "observation_runs", window_id)]
        report["inventory_payloads"] = [json.loads(r[0]) for r in con.execute("SELECT content_json FROM observation_inventories WHERE window_id=? ORDER BY source", (window_id,))]
        report["snapshot_hashes"] = [dict(r) for r in con.execute("SELECT id,captured_at,sha256 FROM observation_snapshots WHERE window_id=? ORDER BY id", (window_id,))]
        sha = storage.canonical_hash(report)
        con.execute("UPDATE observation_windows SET state='frozen',frozen_at=?,frozen_json=?,frozen_sha256=? WHERE id=? AND frozen_at IS NULL",
                    (_iso(current), _json(report), sha, window_id))
    return get_window(window_id, db_path=db_path, now=current)
