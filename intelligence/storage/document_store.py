"""Transactional storage for non-CVE security knowledge and its provenance.

These additive tables share a database with vulnerability intelligence without
altering its schema. Publication precision and raw source data are preserved;
collection timestamps never become publication timestamps.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable

from collectors.documents import KnowledgeDocument

SOURCE_CATEGORIES = frozenset({
    "vulnerability_database", "security_community", "vendor_advisory",
    "security_blog", "academic_paper", "technical_standard",
    "policy_regulation", "government_alert",
})
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_timestamp(value: str | None) -> str | None:
    """Normalize known timezones while retaining day/unknown-zone precision."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise TypeError("timestamps must be strings or None")
    value = value.strip()
    if not value:
        return None
    if DATE_PATTERN.fullmatch(value):
        date.fromisoformat(value)  # Reject impossible dates without inventing an hour.
        return value
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError(f"Invalid publication/run timestamp: {value}") from error
    if parsed.tzinfo is None:
        return value
    return parsed.astimezone(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


class SQLiteDocumentStore:
    def __init__(self, db_path: str | Path = "data/intelligence.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(str(self.db_path), timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _init_db(self):
        statements = (
            """CREATE TABLE IF NOT EXISTS knowledge_documents (
                document_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                source_category TEXT NOT NULL,
                content_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                url TEXT NOT NULL,
                published_at TEXT,
                modified_at TEXT,
                cve_ids_json TEXT NOT NULL DEFAULT '[]',
                payload_json TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                content_updated_at TEXT NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_documents_source ON knowledge_documents(source)",
            "CREATE INDEX IF NOT EXISTS idx_documents_category ON knowledge_documents(source_category)",
            "CREATE INDEX IF NOT EXISTS idx_documents_updated ON knowledge_documents(content_updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_documents_published ON knowledge_documents(published_at)",
            """CREATE TABLE IF NOT EXISTS document_source_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_category TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('success','failed')),
                fetched_count INTEGER NOT NULL DEFAULT 0,
                inserted_count INTEGER NOT NULL DEFAULT 0,
                updated_count INTEGER NOT NULL DEFAULT 0,
                unchanged_count INTEGER NOT NULL DEFAULT 0,
                error_text TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_document_runs_source ON document_source_runs(source,id)",
            """CREATE TABLE IF NOT EXISTS document_http_state (
                source TEXT PRIMARY KEY,
                etag TEXT,
                last_modified TEXT,
                last_success_at TEXT NOT NULL
            )""",
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for statement in statements:
                connection.execute(statement)

    @staticmethod
    def _run_identity(source: str, category: str) -> tuple[str, str]:
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must not be empty")
        if not isinstance(category, str) or category.strip().lower() not in SOURCE_CATEGORIES:
            raise ValueError("source category is not a supported knowledge category")
        return source.strip(), category.strip().lower()

    @staticmethod
    def _payload(document: KnowledgeDocument, source: str, category: str) -> dict:
        if not isinstance(document, KnowledgeDocument):
            raise TypeError("document collectors must return KnowledgeDocument objects")
        payload = asdict(document)
        if (document.source.strip() != source
                or document.source_category.strip().lower() != category):
            raise ValueError("document source/category does not match the collection run")
        for field in ("document_id", "content_type", "title", "url"):
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise ValueError(f"document {field} is mandatory")
            payload[field] = payload[field].strip()
        if not isinstance(payload.get("description"), str):
            raise TypeError("document description must be a string")
        if not isinstance(payload.get("raw_data"), dict):
            raise TypeError("document raw_data must be a dictionary")
        cve_ids = []
        for cve_id in payload.get("cve_ids") or []:
            if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id.strip().upper()):
                raise ValueError("document cve_ids must contain valid CVE identifiers")
            cve_ids.append(cve_id.strip().upper())
        payload.update(source=source, source_category=category,
                       cve_ids=sorted(set(cve_ids)),
                       published_at=normalize_timestamp(payload.get("published_at")),
                       modified_at=normalize_timestamp(payload.get("modified_at")))
        return payload

    def ingest(self, source: str, category: str, items: Iterable[KnowledgeDocument],
               started_at: str | None = None) -> dict[str, int]:
        """Atomically commit one successful collection, including an empty/304 run.

        Empty responses keep historical documents. A failed validation rolls
        back both document updates and the success run; callers can then record
        failure separately. HTTP validators are saved only after this succeeds.
        """
        source, category = self._run_identity(source, category)
        documents = list(items)
        now = utc_now()
        started_at = normalize_timestamp(started_at) or now
        counts = {"fetched": len(documents), "inserted": 0, "updated": 0, "unchanged": 0}
        observed_ids: set[str] = set()
        inserted_ids: set[str] = set()
        updated_ids: set[str] = set()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = utc_now()  # Includes time waiting for the write lock.
            for document in documents:
                payload = self._payload(document, source, category)
                observed_ids.add(payload["document_id"])
                # Generated observation metadata does not change source content.
                # Every raw_data field remains exact and contributes to the hash.
                content = {key: value for key, value in payload.items() if key != "observed_at"}
                digest = hashlib.sha256(_json(content).encode("utf-8")).hexdigest()
                serialized = _json(payload)
                old = connection.execute(
                    "SELECT source,content_sha256 FROM knowledge_documents WHERE document_id=?",
                    (payload["document_id"],),
                ).fetchone()
                if old and old["source"] != source:
                    raise ValueError("document_id is already attributed to a different source")
                if old is None:
                    connection.execute(
                        """INSERT INTO knowledge_documents
                           (document_id,source,source_category,content_type,title,description,
                            url,published_at,modified_at,cve_ids_json,payload_json,content_sha256,
                            first_seen_at,last_seen_at,content_updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (payload["document_id"], source, category, payload["content_type"],
                         payload["title"], payload["description"], payload["url"],
                         payload["published_at"], payload["modified_at"], _json(payload["cve_ids"]),
                         serialized, digest, now, now, now),
                    )
                    counts["inserted"] += 1
                    inserted_ids.add(payload["document_id"])
                elif old["content_sha256"] != digest:
                    connection.execute(
                        """UPDATE knowledge_documents SET source_category=?,content_type=?,title=?,
                           description=?,url=?,published_at=?,modified_at=?,cve_ids_json=?,
                           payload_json=?,content_sha256=?,last_seen_at=?,content_updated_at=?
                           WHERE document_id=?""",
                        (category, payload["content_type"], payload["title"], payload["description"],
                         payload["url"], payload["published_at"], payload["modified_at"],
                         _json(payload["cve_ids"]), serialized, digest, now, now, payload["document_id"]),
                    )
                    counts["updated"] += 1
                    updated_ids.add(payload["document_id"])
                else:
                    connection.execute("UPDATE knowledge_documents SET last_seen_at=? WHERE document_id=?",
                                       (now, payload["document_id"]))
                    counts["unchanged"] += 1
            # Stamp availability after processing, close to the actual commit.
            # A slow validation/batch must not get the earlier poll-start time.
            now = utc_now()
            connection.executemany(
                "UPDATE knowledge_documents SET last_seen_at=? WHERE document_id=?",
                ((now, document_id) for document_id in sorted(observed_ids)),
            )
            connection.executemany(
                """UPDATE knowledge_documents SET first_seen_at=?,content_updated_at=?
                   WHERE document_id=?""",
                ((now, now, document_id) for document_id in sorted(inserted_ids)),
            )
            connection.executemany(
                "UPDATE knowledge_documents SET content_updated_at=? WHERE document_id=?",
                ((now, document_id) for document_id in sorted(updated_ids)),
            )
            connection.execute(
                """INSERT INTO document_source_runs
                   (source,source_category,started_at,finished_at,status,
                    fetched_count,inserted_count,updated_count,unchanged_count)
                   VALUES (?,?,?,?,'success',?,?,?,?)""",
                (source, category, started_at, now, counts["fetched"], counts["inserted"],
                 counts["updated"], counts["unchanged"]),
            )
        return counts

    def record_failure(self, source: str, category: str, error: str,
                       started_at: str | None = None):
        source, category = self._run_identity(source, category)
        start = normalize_timestamp(started_at) or utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = utc_now()
            connection.execute(
                """INSERT INTO document_source_runs
                   (source,source_category,started_at,finished_at,status,error_text)
                   VALUES (?,?,?,?,'failed',?)""",
                (source, category, start, now, str(error)[:2000]),
            )

    @staticmethod
    def _document(row: sqlite3.Row) -> dict:
        payload = json.loads(row["payload_json"])
        payload.update(first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
                       content_updated_at=row["content_updated_at"],
                       content_sha256=row["content_sha256"])
        return payload

    def get_document(self, document_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM knowledge_documents WHERE document_id=?",
                                     (document_id.strip(),)).fetchone()
            return self._document(row) if row else None

    def list_documents(self, limit: int = 100, offset: int = 0, *,
                       source: str | None = None, category: str | None = None,
                       content_type: str | None = None, cve_id: str | None = None) -> list[dict]:
        if (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
                or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0):
            raise ValueError("limit must be a positive integer and offset a nonnegative integer")
        filters = []
        values = []
        for column, value in (("source", source), ("source_category", category),
                              ("content_type", content_type)):
            if value is not None:
                filters.append(f"{column}=?")
                values.append(value)
        if cve_id is not None:
            filters.append("EXISTS (SELECT 1 FROM json_each(cve_ids_json) WHERE value=?)")
            values.append(cve_id.strip().upper())
        where = " WHERE " + " AND ".join(filters) if filters else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM knowledge_documents" + where
                + " ORDER BY content_updated_at DESC,document_id ASC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
            return [self._document(row) for row in rows]

    def stats(self) -> dict:
        with self._connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM knowledge_documents").fetchone()[0]
            categories = {row["source_category"]: row["n"] for row in connection.execute(
                "SELECT source_category,COUNT(*) n FROM knowledge_documents GROUP BY source_category")}
            sources = {row["source"]: row["n"] for row in connection.execute(
                "SELECT source,COUNT(*) n FROM knowledge_documents GROUP BY source")}
            runs = [dict(row) for row in connection.execute(
                """SELECT * FROM document_source_runs r
                   WHERE r.id=(SELECT MAX(x.id) FROM document_source_runs x WHERE x.source=r.source)
                   ORDER BY r.source""")]
        return {"documents": total, "source_categories": categories,
                "sources": sources, "latest_runs": runs}

    def get_http_state(self, source: str) -> dict | None:
        """Never return validators for a source whose documents were cleared."""
        with self._connect() as connection:
            row = connection.execute(
                """SELECT etag,last_modified,last_success_at FROM document_http_state h
                   WHERE h.source=? AND EXISTS
                     (SELECT 1 FROM knowledge_documents d WHERE d.source=h.source)""",
                (source.strip(),),
            ).fetchone()
            return dict(row) if row else None

    def save_http_state(self, source: str, etag: str | None = None,
                        last_modified: str | None = None):
        """Commit response validators only after a successful document ingest.

        Explicit None clears a validator. A 304 response omitting these headers
        should supply the previous values. Failed runs retain the earlier state.
        """
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            last_run = connection.execute(
                "SELECT status,finished_at FROM document_source_runs WHERE source=? ORDER BY id DESC LIMIT 1",
                (source.strip(),),
            ).fetchone()
            if not last_run or last_run["status"] != "success":
                raise ValueError("HTTP state can only be saved after a successful document ingest")
            connection.execute(
                """INSERT INTO document_http_state (source,etag,last_modified,last_success_at)
                   VALUES (?,?,?,?) ON CONFLICT(source) DO UPDATE SET
                   etag=excluded.etag,last_modified=excluded.last_modified,
                   last_success_at=excluded.last_success_at""",
                (source.strip(), etag, last_modified, last_run["finished_at"]),
            )
