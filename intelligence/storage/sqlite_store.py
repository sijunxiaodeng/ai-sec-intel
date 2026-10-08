"""SQLite storage with cross-run de-duplication and cross-batch CVE re-fusion.

This module reuses the EXISTING project interfaces:
- collectors.base.IntelligenceItem
- fusion.merger.merge_by_cve

It does not call the AI classifier or LLM; classification remains a separate stage.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from collectors.base import IntelligenceItem
from fusion.merger import merge_by_cve


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_of(value: Any) -> str:
    return hashlib.sha256(to_json(value).encode("utf-8")).hexdigest()


class SQLiteIntelligenceStore:
    def __init__(self, db_path: str | Path = "data/intelligence.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        """Always commit/rollback and close the SQLite connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("PRAGMA journal_mode = WAL")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS source_items (
                    source TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    cve_id TEXT,
                    payload_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    content_updated_at TEXT NOT NULL,
                    PRIMARY KEY (source, source_id)
                );
                CREATE INDEX IF NOT EXISTS idx_source_items_cve
                    ON source_items(cve_id);

                CREATE TABLE IF NOT EXISTS unified_vulnerabilities (
                    cve_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    content_updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS collector_state (
                    collector TEXT PRIMARY KEY,
                    last_success_at TEXT NOT NULL,
                    last_fetched_count INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS collector_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collector TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('success', 'failed')),
                    fetched_count INTEGER NOT NULL DEFAULT 0,
                    inserted_count INTEGER NOT NULL DEFAULT 0,
                    updated_count INTEGER NOT NULL DEFAULT 0,
                    unchanged_count INTEGER NOT NULL DEFAULT 0,
                    refreshed_cve_count INTEGER NOT NULL DEFAULT 0,
                    new_cve_count INTEGER NOT NULL DEFAULT 0,
                    error_text TEXT
                );
            """)

    @staticmethod
    def _to_item(row: sqlite3.Row) -> IntelligenceItem:
        raw = json.loads(row["payload_json"])
        allowed = {field.name for field in fields(IntelligenceItem)}
        return IntelligenceItem(**{key: val for key, val in raw.items() if key in allowed})

    def _refresh_cve(self, conn: sqlite3.Connection, cve_id: str, now: str) -> bool:
        """Rebuild one CVE from ALL persisted sources, across previous runs.

        Return True only when the unified CVE did not already exist.
        """
        source_rows = conn.execute(
            """SELECT payload_json FROM source_items
               WHERE cve_id = ?
               ORDER BY CASE source
                   WHEN 'NVD' THEN 0
                   WHEN 'CISA_KEV' THEN 1
                   WHEN 'GITHUB_ADVISORY' THEN 2
                   ELSE 3 END, source, source_id""",
            (cve_id,),
        ).fetchall()

        if not source_rows:
            conn.execute("DELETE FROM unified_vulnerabilities WHERE cve_id = ?", (cve_id,))
            return False

        items = [self._to_item(row) for row in source_rows]
        combined = merge_by_cve(items)
        selected = next((v for v in combined if v.cve_id == cve_id), None)
        if selected is None:
            raise ValueError(f"merge_by_cve did not produce expected {cve_id}")

        if is_dataclass(selected):
            payload = asdict(selected)
        elif isinstance(selected, dict):
            payload = selected
        else:
            payload = vars(selected)

        content_hash = sha256_of(payload)
        existing = conn.execute(
            "SELECT content_sha256 FROM unified_vulnerabilities WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()

        if existing is None:
            conn.execute(
                """INSERT INTO unified_vulnerabilities
                   (cve_id,payload_json,content_sha256,first_seen_at,content_updated_at)
                   VALUES (?,?,?,?,?)""",
                (cve_id, to_json(payload), content_hash, now, now),
            )
            return True

        if existing["content_sha256"] != content_hash:
            conn.execute(
                """UPDATE unified_vulnerabilities
                   SET payload_json = ?, content_sha256 = ?, content_updated_at = ?
                   WHERE cve_id = ?""",
                (to_json(payload), content_hash, now, cve_id),
            )
        return False

    def ingest_batch(
        self,
        collector: str,
        items: Iterable[IntelligenceItem],
        started_at: str | None = None,
    ) -> dict[str, int | str]:
        """Commit one successful collection, preserving cross-run source history.

        NOTE: caller should invoke this only after collection succeeded.
        An empty *successful* batch updates collector_state, but does not delete
        previous vulnerabilities (empty response does not mean deletion).
        """
        if not collector.strip():
            raise ValueError("collector name must not be empty")

        materialized = list(items)
        now = utc_now()
        started_at = started_at or now
        counts = {
            "collector": collector,
            "fetched": len(materialized),
            "inserted": 0,
            "updated": 0,
            "unchanged": 0,
            "refreshed_cves": 0,
            "new_cves": 0,
        }
        touched_cves: set[str] = set()

        with self._connect() as conn:
            for item in materialized:
                if not is_dataclass(item):
                    raise TypeError("Collectors must return IntelligenceItem dataclass objects")
                source = (item.source or "").strip()
                source_id = (item.source_id or "").strip()
                if not source or not source_id:
                    raise ValueError("source and source_id are mandatory for stable de-duplication")
                # Protect against accidentally attributing one source's items to another run.
                if source != collector:
                    raise ValueError(f"collector={collector} received item.source={source}")

                payload = asdict(item)
                digest = sha256_of(payload)
                cve_id = (item.cve_id or "").strip().upper() or None

                old = conn.execute(
                    """SELECT cve_id, content_sha256 FROM source_items
                       WHERE source = ? AND source_id = ?""",
                    (source, source_id),
                ).fetchone()

                if old is None:
                    conn.execute(
                        """INSERT INTO source_items
                           (source,source_id,cve_id,payload_json,content_sha256,
                            first_seen_at,last_seen_at,content_updated_at)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (source, source_id, cve_id, to_json(payload), digest, now, now, now),
                    )
                    counts["inserted"] += 1
                    if cve_id:
                        touched_cves.add(cve_id)
                elif old["content_sha256"] != digest or old["cve_id"] != cve_id:
                    conn.execute(
                        """UPDATE source_items
                           SET cve_id = ?, payload_json = ?, content_sha256 = ?,
                               last_seen_at = ?, content_updated_at = ?
                           WHERE source = ? AND source_id = ?""",
                        (cve_id, to_json(payload), digest, now, now, source, source_id),
                    )
                    counts["updated"] += 1
                    if cve_id:
                        touched_cves.add(cve_id)
                    if old["cve_id"]:
                        touched_cves.add(old["cve_id"])
                else:
                    conn.execute(
                        """UPDATE source_items SET last_seen_at = ?
                           WHERE source = ? AND source_id = ?""",
                        (now, source, source_id),
                    )
                    counts["unchanged"] += 1

            for cve_id in sorted(touched_cves):
                if self._refresh_cve(conn, cve_id, now):
                    counts["new_cves"] += 1
                counts["refreshed_cves"] += 1

            conn.execute(
                """INSERT INTO collector_state (collector,last_success_at,last_fetched_count)
                   VALUES (?,?,?)
                   ON CONFLICT(collector) DO UPDATE SET
                       last_success_at = excluded.last_success_at,
                       last_fetched_count = excluded.last_fetched_count""",
                (collector, now, len(materialized)),
            )
            conn.execute(
                """INSERT INTO collector_runs
                   (collector,started_at,finished_at,status,fetched_count,
                    inserted_count,updated_count,unchanged_count,
                    refreshed_cve_count,new_cve_count)
                   VALUES (?,?,?,'success',?,?,?,?,?,?)""",
                (
                    collector, started_at, now, len(materialized),
                    counts["inserted"], counts["updated"], counts["unchanged"],
                    counts["refreshed_cves"], counts["new_cves"],
                ),
            )
        return counts

    def record_failure(self, collector: str, error: str, started_at: str | None = None) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO collector_runs
                   (collector,started_at,finished_at,status,error_text)
                   VALUES (?, ?, ?, 'failed', ?)""",
                (collector, started_at or now, now, str(error)[:2000]),
            )

    def get_vulnerability(self, cve_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM unified_vulnerabilities WHERE cve_id = ?",
                (cve_id.strip().upper(),),
            ).fetchone()
            return json.loads(row["payload_json"]) if row else None

    def list_vulnerabilities(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be a positive integer")
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT payload_json FROM unified_vulnerabilities
                   ORDER BY content_updated_at DESC, cve_id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [json.loads(row["payload_json"]) for row in rows]

    def export_jsonl(self, destination: str | Path, limit: int | None = None) -> int:
        """Export unified CVEs for team C's RAG pipeline and team A's backend."""
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        sql = "SELECT payload_json FROM unified_vulnerabilities ORDER BY cve_id"
        params: tuple = ()
        if limit is not None:
            if limit <= 0:
                raise ValueError("limit must be positive")
            sql += " LIMIT ?"
            params = (limit,)
        n = 0
        with self._connect() as conn, destination.open("w", encoding="utf-8") as f:
            for row in conn.execute(sql, params):
                f.write(row["payload_json"] + "\n")
                n += 1
        return n

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            raw_count = conn.execute("SELECT count(*) FROM source_items").fetchone()[0]
            cve_count = conn.execute("SELECT count(*) FROM unified_vulnerabilities").fetchone()[0]
            states = [dict(row) for row in conn.execute(
                "SELECT collector,last_success_at,last_fetched_count FROM collector_state ORDER BY collector"
            )]
        return {"source_records": raw_count, "unified_cves": cve_count, "collectors": states}
