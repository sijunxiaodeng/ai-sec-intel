"""Read-only queries for non-CVE documents; never initialize a database."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

DOCUMENT_COLUMNS = frozenset({
    "document_id", "source", "source_category", "content_type", "title",
    "description", "url", "published_at", "modified_at", "cve_ids_json",
    "payload_json", "first_seen_at", "last_seen_at", "content_updated_at",
})
RUN_COLUMNS = frozenset({
    "id", "source", "source_category", "started_at", "finished_at", "status",
    "fetched_count", "inserted_count", "updated_count", "unchanged_count", "error_text",
})


def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class DocumentRepository:
    def __init__(self, db_path: Path, root: Path):
        self.db_path = Path(db_path).resolve()
        self.root = Path(root).resolve()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        if not self.db_path.is_file():
            raise FileNotFoundError(str(self.db_path))
        with closing(sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True, timeout=20)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA busy_timeout=20000")
            yield connection

    @staticmethod
    def _has_columns(connection: sqlite3.Connection, table: str, required: frozenset[str]) -> bool:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,),
        ).fetchone()
        if not exists:
            return False
        # Only fixed internal table names reach this helper.
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        return required.issubset(columns)

    @classmethod
    def _available(cls, connection: sqlite3.Connection) -> bool:
        return cls._has_columns(connection, "knowledge_documents", DOCUMENT_COLUMNS)

    def available(self) -> bool:
        with self.read() as connection:
            return self._available(connection)

    @staticmethod
    def _record(row: sqlite3.Row, include_raw: bool) -> dict:
        payload = json.loads(row["payload_json"])
        if not isinstance(payload, dict):
            raise ValueError(f"Invalid knowledge document payload for {row['document_id']}")
        # SQL keys and metadata are authoritative even for older payloads.
        for field in ("document_id", "source", "source_category", "content_type", "title",
                      "description", "url", "published_at", "modified_at",
                      "first_seen_at", "last_seen_at", "content_updated_at"):
            payload[field] = row[field]
        payload["cve_ids"] = json.loads(row["cve_ids_json"])
        if not include_raw:
            payload.pop("raw_data", None)
        return payload

    @staticmethod
    def _where(*, q: str | None, source: str | None, category: str | None,
               content_type: str | None, cve_id: str | None) -> tuple[str, tuple]:
        filters = []
        parameters = []
        if q and q.strip():
            value = "%" + escape_like(q.strip()) + "%"
            filters.append("""(
                d.title LIKE ? ESCAPE '\\'
                OR d.description LIKE ? ESCAPE '\\'
                OR EXISTS (SELECT 1 FROM json_each(d.cve_ids_json)
                           WHERE value LIKE ? ESCAPE '\\')
            )""")
            parameters.extend([value] * 3)
        for field, value in (("source", source), ("source_category", category),
                             ("content_type", content_type)):
            if value is not None:
                filters.append(f"d.{field}=?")
                parameters.append(value.strip())
        if cve_id is not None:
            filters.append("EXISTS (SELECT 1 FROM json_each(d.cve_ids_json) WHERE value=?)")
            parameters.append(cve_id.strip().upper())
        return (" WHERE " + " AND ".join(filters) if filters else ""), tuple(parameters)

    def list_items(self, q: str | None = None, source: str | None = None,
                   category: str | None = None, content_type: str | None = None,
                   cve_id: str | None = None, limit: int = 20, offset: int = 0,
                   include_raw: bool = False) -> dict:
        if (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
                or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0):
            raise ValueError("limit must be a positive integer and offset a nonnegative integer")
        result = {"total": 0, "limit": limit, "offset": offset, "items": []}
        where, parameters = self._where(q=q, source=source, category=category,
                                        content_type=content_type, cve_id=cve_id)
        with self.read() as connection:
            if not self._available(connection):
                return result
            result["total"] = connection.execute(
                "SELECT COUNT(*) FROM knowledge_documents d" + where, parameters,
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT d.* FROM knowledge_documents d" + where
                + " ORDER BY d.content_updated_at DESC,d.document_id ASC LIMIT ? OFFSET ?",
                parameters + (limit, offset),
            ).fetchall()
            result["items"] = [self._record(row, include_raw) for row in rows]
        return result

    def one(self, document_id: str, include_raw: bool = False) -> dict | None:
        with self.read() as connection:
            if not self._available(connection):
                return None
            row = connection.execute(
                "SELECT * FROM knowledge_documents WHERE document_id=?", (document_id.strip(),),
            ).fetchone()
            return self._record(row, include_raw) if row else None

    def stats(self) -> dict:
        result = {"total_documents": 0, "source_record_counts": {},
                  "source_category_counts": {}, "content_type_counts": {}, "latest_runs": []}
        with self.read() as connection:
            if not self._available(connection):
                return result
            result["total_documents"] = connection.execute(
                "SELECT COUNT(*) FROM knowledge_documents",
            ).fetchone()[0]
            for column, field in (("source", "source_record_counts"),
                                  ("source_category", "source_category_counts"),
                                  ("content_type", "content_type_counts")):
                result[field] = {row[column]: row["n"] for row in connection.execute(
                    f"SELECT {column},COUNT(*) n FROM knowledge_documents GROUP BY {column} ORDER BY {column}",
                )}
            if self._has_columns(connection, "document_source_runs", RUN_COLUMNS):
                result["latest_runs"] = [dict(row) for row in connection.execute(
                    """SELECT r.* FROM document_source_runs r
                       WHERE r.id=(SELECT MAX(x.id) FROM document_source_runs x WHERE x.source=r.source)
                       ORDER BY r.source""",
                )]
        return result
