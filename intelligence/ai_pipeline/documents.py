"""Versioned, transactional AI-security verdicts for every knowledge source."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from classification.scope_policy import classify_scope
from storage.changefeed import ensure_changefeed
from .store import utc_now


class DocumentClassificationStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(str(self.db_path))
        with self.connect() as con:
            if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='knowledge_documents'").fetchone():
                raise RuntimeError("Database has no knowledge_documents table")
            con.execute("""CREATE TABLE IF NOT EXISTS document_ai_classifications (
                document_id TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL,
                classifier_version TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('classified','review','pending_llm','retry')),
                ai_related INTEGER,
                ai_category TEXT NOT NULL,
                confidence REAL,
                reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                decision_source TEXT NOT NULL,
                needs_review INTEGER NOT NULL,
                rule_score REAL,
                updated_at TEXT NOT NULL
            )""")
            ensure_changefeed(con)

    @contextmanager
    def connect(self):
        con = sqlite3.connect(str(self.db_path), timeout=30)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA journal_mode=WAL")
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def fresh(self, version: str, limit: int) -> list[dict]:
        with self.connect() as con:
            return [dict(row) for row in con.execute("""
                SELECT d.document_id,d.payload_json,d.content_sha256
                FROM knowledge_documents d
                LEFT JOIN document_ai_classifications a ON a.document_id=d.document_id
                WHERE a.document_id IS NULL OR a.content_sha256!=d.content_sha256
                   OR a.classifier_version!=?
                ORDER BY d.content_updated_at DESC,d.document_id ASC LIMIT ?
            """, (version, limit))]

    def record(self, row: dict, version: str, result) -> bool:
        state = "review" if result.needs_review else "classified"
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            current = con.execute("SELECT content_sha256 FROM knowledge_documents WHERE document_id=?",
                                  (row["document_id"],)).fetchone()
            if current is None or current["content_sha256"] != row["content_sha256"]:
                return False
            con.execute("""INSERT INTO document_ai_classifications
                (document_id,content_sha256,classifier_version,state,ai_related,ai_category,
                 confidence,reason,evidence_json,decision_source,needs_review,rule_score,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(document_id) DO UPDATE SET
                  content_sha256=excluded.content_sha256,classifier_version=excluded.classifier_version,
                  state=excluded.state,ai_related=excluded.ai_related,ai_category=excluded.ai_category,
                  confidence=excluded.confidence,reason=excluded.reason,evidence_json=excluded.evidence_json,
                  decision_source=excluded.decision_source,needs_review=excluded.needs_review,
                  rule_score=excluded.rule_score,updated_at=excluded.updated_at
            """, (row["document_id"], row["content_sha256"], version, state,
                  None if result.is_ai_related is None else int(result.is_ai_related),
                  result.category, result.confidence, result.reason,
                  json.dumps(result.evidence, ensure_ascii=False), result.decision_source,
                  int(result.needs_review), result.rule_score, utc_now()))
        return True

    def stats(self, version: str) -> dict:
        with self.connect() as con:
            states = {row["state"]: row["n"] for row in con.execute("""
                SELECT a.state,COUNT(*) AS n FROM document_ai_classifications a
                JOIN knowledge_documents d ON d.document_id=a.document_id
                  AND d.content_sha256=a.content_sha256
                WHERE a.classifier_version=? GROUP BY a.state
            """, (version,))}
            positive = con.execute("""SELECT COUNT(*) FROM document_ai_classifications a
                JOIN knowledge_documents d ON d.document_id=a.document_id
                  AND d.content_sha256=a.content_sha256
                WHERE a.classifier_version=? AND a.state='classified' AND a.ai_related=1
            """, (version,)).fetchone()[0]
            pending = con.execute("""SELECT COUNT(*) FROM knowledge_documents d
                LEFT JOIN document_ai_classifications a ON a.document_id=d.document_id
                WHERE a.document_id IS NULL OR a.content_sha256!=d.content_sha256
                   OR a.classifier_version!=?
            """, (version,)).fetchone()[0]
            return {"states": states, "classified_ai_positive": positive,
                    "need_initial_or_refresh": pending}


def _source_fields(payload: dict) -> dict:
    """Use explicit affected packages from vendor payloads, never source names."""
    packages = []
    raw = payload.get("raw_data") or {}
    advisory = raw.get("advisory") or {} if isinstance(raw, dict) else {}
    if isinstance(advisory, dict):
        for vulnerability in advisory.get("vulnerabilities") or []:
            package = vulnerability.get("package") or {} if isinstance(vulnerability, dict) else {}
            if isinstance(package, dict) and package.get("name"):
                packages.append(str(package["name"]))
        # OSV states affected packages explicitly, including advisories without CVEs.
        for affected in advisory.get("affected") or []:
            package = affected.get("package") or {} if isinstance(affected, dict) else {}
            if isinstance(package, dict) and package.get("name"):
                packages.append(str(package["name"]))
    return {"title": payload.get("title") or "", "description": payload.get("description") or "",
            "package_names": packages, "record_kind": "document",
            "content_type": payload.get("content_type") or ""}


def run_document_batch(db_path, version: str, max_items: int = 300, *, decision=classify_scope) -> dict:
    """Apply rules to fresh/changed documents without any paid/model invocation."""
    if not version.strip() or max_items < 1:
        raise ValueError("Invalid classification version or item budget")
    result = {"selected": 0, "classified": 0, "positive": 0, "needs_review": 0,
              "stale_skipped": 0, "model_calls": 0}
    # Legacy CVE-only databases remain usable. The classifier never fabricates
    # a knowledge table or claims document coverage when that module is absent.
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(str(path))
    with closing(sqlite3.connect(str(path))) as con:
        available = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='knowledge_documents'").fetchone()
    if not available:
        return {**result, "status": "not_available"}
    store = DocumentClassificationStore(db_path)
    rows = store.fresh(version, max_items)
    result["selected"] = len(rows)
    for row in rows:
        payload = json.loads(row["payload_json"])
        verdict = decision(**_source_fields(payload))
        if not store.record(row, version, verdict):
            result["stale_skipped"] += 1
        elif verdict.needs_review:
            result["needs_review"] += 1
        else:
            result["classified"] += 1
            result["positive"] += int(verdict.is_ai_related is True)
    result["remaining"] = store.stats(version)
    return result
