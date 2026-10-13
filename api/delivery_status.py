"""Read persisted consumer checkpoints without initializing or changing stores."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from team_change_protocol import validate_page

MAX_CURSOR_BYTES = 64 * 1024


def _read_cursor(path, *, table, field, key, identity):
    path = Path(path)
    if not path.is_file():
        return None
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if table not in tables:
            return None
        row = connection.execute(f"SELECT {field} FROM {table} WHERE {key}=?", (identity,)).fetchone()
        if not row:
            return None
        if not isinstance(row[0], str) or len(row[0].encode()) > MAX_CURSOR_BYTES:
            raise ValueError("Invalid saved cursor")
        cursor = json.loads(row[0])
        if (not isinstance(cursor, dict) or not isinstance(cursor.get("epoch"), str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", cursor["epoch"])
                or type(cursor.get("seq")) is not int or cursor["seq"] < 0
                or (cursor.get("through") is not None and
                    (type(cursor["through"]) is not int or cursor["through"] < cursor["seq"]))):
            raise ValueError("Invalid saved cursor")
        return cursor


def _compare(cursor, *, base_url, upstream):
    if cursor is None:
        return {"status": "not_started", "checkpoint": None, "lag_events": None}
    safe = {key: cursor[key] for key in ("epoch", "seq", "through") if key in cursor}
    status, lag = "unverified", None
    if cursor.get("base_url", base_url) != base_url:
        status = "source_changed"
    elif upstream:
        if cursor["epoch"] != upstream["epoch"] or cursor["seq"] > upstream["through"]:
            status = "reset_required"
        else:
            lag = upstream["through"] - cursor["seq"]
            status = "caught_up" if lag == 0 and cursor.get("through") is None else "lagging"
    return {"status": status, "checkpoint": safe, "lag_events": lag}


def consumer_checkpoints(*, knowledge_db, library_db, base_url, upstream=None):
    result = {}
    for kind, parameters in (
        ("cve", dict(path=knowledge_db, table="sync_cursors", field="cursor_json", key="source", identity="b_intelligence")),
        ("document", dict(path=library_db, table="team_sync_cursors", field="payload", key="base_url", identity=base_url)),
    ):
        try:
            result[kind] = _compare(_read_cursor(**parameters), base_url=base_url, upstream=upstream)
        except (OSError, ValueError, TypeError, sqlite3.Error):
            result[kind] = {"status": "unverified", "checkpoint": None, "lag_events": None}
    result["all_caught_up"] = bool(upstream) and all(item["status"] == "caught_up" for item in result.values())
    # Committed checkpoints establish durable import; asynchronous enrichment
    # and index completion need separate processing evidence.
    result["processing_completion_verified"] = False
    return result


def consumption_status():
    from collectors.intelligence import team_intel_disabled
    from collectors.team_documents import TeamDocumentCollector
    from database.store import database_path
    from rag.library import LIBRARY_DB

    if team_intel_disabled():
        return {"status": "disabled", "upstream": None, "consumers": None}
    try:
        collector = TeamDocumentCollector(max_documents=1, use_changefeed=True, timeout=5)
    except ValueError:
        return {"status": "unverified", "reason_category": "invalid_upstream_configuration",
                "upstream": None, "consumers": None}
    upstream = None
    try:
        response = collector.get("/api/team/changes?kind=document&cursor=0&limit=1")
        page = validate_page(json.loads(response["body"]), 0)
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", page["epoch"]):
            raise ValueError("Invalid upstream database identity")
        upstream = {"epoch": page["epoch"], "through": page["through"]}
    except Exception:
        # No credentials, API payloads, paths or exception strings enter public facts.
        pass
    consumers = consumer_checkpoints(knowledge_db=database_path(), library_db=LIBRARY_DB,
                                     base_url=collector.base_url, upstream=upstream)
    return {"status": "caught_up" if consumers["all_caught_up"] else "pending" if upstream else "unverified",
            "upstream": upstream, "consumers": consumers}
