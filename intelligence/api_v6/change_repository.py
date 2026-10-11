"""Read-only team change pages with a stable high-water mark and DB identity."""
from __future__ import annotations

import sqlite3
import json

from .repository import _record, current_classifier_version
from .document_repository import DocumentRepository
from .team_adapter import to_team_item


class ChangeRepository:
    def __init__(self, repository):
        self.repository = repository

    def page(self, *, kind: str, cursor: int = 0, through: int | None = None,
             epoch: str | None = None, limit: int = 100) -> dict:
        if kind not in {"cve", "document"}:
            raise ValueError("unknown feed kind")
        version = current_classifier_version(self.repository.root)
        with self.repository.read() as connection:
            connection.execute("BEGIN")  # Bind metadata, classification and rows to one read snapshot.
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"team_feed_meta", "team_changes"}.issubset(tables):
                raise sqlite3.OperationalError("team change feed unavailable; upgrade the collection writer first")
            identity = connection.execute("SELECT value FROM team_feed_meta WHERE key='epoch'").fetchone()[0]
            high = connection.execute("SELECT COALESCE(MAX(seq),0) FROM team_changes").fetchone()[0]
            reset = epoch is not None and epoch != identity
            if reset:
                cursor, through = 0, None
            if cursor > high or (through is not None and through > high):
                # Restored backups with the same epoch must never silently skip
                # historical rows just because the saved cursor is ahead.
                cursor, through, reset = 0, None, True
            bound = high if through is None else min(through, high)
            if bound < cursor:
                raise ValueError("feed through must not be below cursor")
            rows = connection.execute("""SELECT entity_id,MAX(seq) seq FROM team_changes
                WHERE kind=? AND seq>? AND seq<=? GROUP BY entity_id
                ORDER BY seq LIMIT ?""", (kind, cursor, bound, limit + 1)).fetchall()
            has_more = len(rows) > limit
            rows = rows[:limit]
            changes = []
            for row in rows:
                item = self._item(connection, tables, kind, row["entity_id"], version)
                changes.append({"seq": row["seq"], "entity_id": row["entity_id"],
                                "operation": "upsert" if item is not None else "retract", "item": item})
            next_cursor = rows[-1]["seq"] if has_more else bound
            return {"epoch": identity, "reset": reset, "cursor": cursor,
                    "next_cursor": next_cursor, "through": bound,
                    "has_more": has_more, "changes": changes}

    def _item(self, connection, tables, kind, identity, version):
        if kind == "cve":
            base, params = self.repository._base_query(version, "ai_classifications" in tables)
            row = connection.execute("SELECT " + self.repository._columns() + base
                + " WHERE v.cve_id=? AND a.state='classified' AND a.ai_related=1",
                params + (identity,)).fetchone()
            if row is None:
                return None
            record = _record(row, full=True, include_raw=True)
            item = to_team_item(record)
            item["raw_data"]["content_updated_at"] = record["content_updated_at"]
            item["raw_data"]["team_managed"] = True
            return item
        if "document_ai_classifications" not in tables or "knowledge_documents" not in tables:
            return None
        row = connection.execute("""SELECT d.*, a.state cls_state, a.ai_related cls_related,
            a.ai_category cls_category, a.confidence cls_confidence, a.reason cls_reason,
            a.evidence_json cls_evidence, a.decision_source cls_source,
            a.needs_review cls_review, a.classifier_version cls_version,
            a.updated_at cls_updated FROM knowledge_documents d
            JOIN document_ai_classifications a ON a.document_id=d.document_id
             AND a.content_sha256=d.content_sha256 AND a.classifier_version=?
            WHERE d.document_id=? AND a.state='classified' AND a.ai_related=1""",
            (version or "__missing_classifier_sources__", identity)).fetchone()
        if row is None:
            return None
        document = DocumentRepository._record(row, False)
        document["classification"] = {"state": row["cls_state"], "is_ai_related": bool(row["cls_related"]),
            "category": row["cls_category"], "confidence": row["cls_confidence"], "reason": row["cls_reason"],
            "evidence": json.loads(row["cls_evidence"]), "decision_source": row["cls_source"],
            "needs_review": bool(row["cls_review"]), "classifier_version": row["cls_version"],
            "updated_at": row["cls_updated"]}
        return document
