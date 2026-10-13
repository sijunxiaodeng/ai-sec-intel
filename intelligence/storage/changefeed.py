"""Transactional, monotonic team delivery log; initialized by writers only.

The API stays read-only. Triggers append changes in the same transaction as
source/fusion/classification writes, including verdicts becoming stale/negative.
Consumers replay from zero once and persist a cursor only after durable import.
"""
from __future__ import annotations

import sqlite3
import uuid


def ensure_changefeed(connection: sqlite3.Connection) -> None:
    connection.execute("""CREATE TABLE IF NOT EXISTS team_feed_meta (
        key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
    connection.execute("INSERT OR IGNORE INTO team_feed_meta VALUES ('epoch',?)", (uuid.uuid4().hex,))
    connection.execute("""CREATE TABLE IF NOT EXISTS team_changes (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL CHECK(kind IN ('cve','document')),
        entity_id TEXT NOT NULL,
        changed_at TEXT NOT NULL)""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_team_changes_entity ON team_changes(kind,entity_id,seq)")
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    # Fixed internal identifiers only; never interpolate an external table name.
    for table, key, kind, content_column in (
        ("unified_vulnerabilities", "cve_id", "cve", "content_sha256"),
        ("knowledge_documents", "document_id", "document", "content_sha256"),
        ("ai_classifications", "cve_id", "cve", None),
        ("document_ai_classifications", "document_id", "document", None),
    ):
        if table not in tables:
            continue
        for operation in ("INSERT", "UPDATE", "DELETE"):
            reference = "OLD" if operation == "DELETE" else "NEW"
            condition = (f" WHEN NEW.{content_column} != OLD.{content_column}"
                         if operation == "UPDATE" and content_column else "")
            connection.execute(f"""CREATE TRIGGER IF NOT EXISTS team_feed_{table}_{operation.lower()}
                AFTER {operation} ON {table}{condition} BEGIN
                  INSERT INTO team_changes(kind,entity_id,changed_at)
                  VALUES ('{kind}',{reference}.{key},strftime('%Y-%m-%dT%H:%M:%fZ','now'));
                END""")
        # Migration backfills every retained entity, independent of a latest-N
        # window. Reinitialization never duplicates the backfill.
        connection.execute(f"""INSERT INTO team_changes(kind,entity_id,changed_at)
            SELECT ?, t.{key}, strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM {table} t
            WHERE NOT EXISTS (SELECT 1 FROM team_changes c WHERE c.kind=? AND c.entity_id=t.{key})
            ORDER BY t.{key}""", (kind, kind))
