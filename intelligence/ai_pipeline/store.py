"""Additive AI classification store. NEVER mutates existing source/unified tables."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ClassificationStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"找不到现有数据库 {self.db_path}。请先完成 V3.2 三源采集，不要创建空数据库。"
            )
        self._init_schema()

    @contextmanager
    def connect(self):
        con = sqlite3.connect(str(self.db_path), timeout=30)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout = 30000")
            con.execute("PRAGMA journal_mode = WAL")
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_schema(self):
        with self.connect() as con:
            tables = {
                r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "unified_vulnerabilities" not in tables:
                raise RuntimeError("数据库缺少统一漏洞表 unified_vulnerabilities")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS ai_classifications (
                    cve_id TEXT PRIMARY KEY,
                    content_sha256 TEXT NOT NULL,
                    classifier_version TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('classified','review','pending_llm','retry')),
                    ai_related INTEGER,
                    ai_category TEXT NOT NULL DEFAULT 'unknown',
                    confidence REAL,
                    reason TEXT NOT NULL DEFAULT '',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    decision_source TEXT NOT NULL DEFAULT '',
                    needs_review INTEGER NOT NULL DEFAULT 0,
                    rule_score REAL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    error_text TEXT,
                    retry_after TEXT,
                    classified_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_classifications_state
                    ON ai_classifications(state, retry_after, updated_at);
                CREATE TABLE IF NOT EXISTS ai_classification_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    classifier_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    max_items INTEGER NOT NULL,
                    max_llm_calls INTEGER NOT NULL,
                    stats_json TEXT NOT NULL,
                    error_text TEXT
                );
            """)

    def _select(self, sql: str, params: tuple) -> list[dict[str, Any]]:
        with self.connect() as con:
            return [dict(r) for r in con.execute(sql, params)]

    def fresh(self, version: str, limit: int) -> list[dict[str, Any]]:
        """New CVEs and CVEs with changed merged hash or classifier version."""
        if limit <= 0:
            return []
        return self._select("""
            SELECT v.cve_id, v.payload_json, v.content_sha256
            FROM unified_vulnerabilities v
            LEFT JOIN ai_classifications a ON a.cve_id = v.cve_id
            WHERE a.cve_id IS NULL
               OR a.content_sha256 != v.content_sha256
               OR a.classifier_version != ?
            ORDER BY v.content_updated_at DESC, v.cve_id DESC
            LIMIT ?
        """, (version, limit))

    def pending(self, version: str, limit: int) -> list[dict[str, Any]]:
        """Previously postponed API calls; transient failures respect retry time."""
        if limit <= 0:
            return []
        return self._select("""
            SELECT v.cve_id, v.payload_json, v.content_sha256
            FROM ai_classifications a
            JOIN unified_vulnerabilities v ON v.cve_id = a.cve_id
            WHERE a.content_sha256 = v.content_sha256
              AND a.classifier_version = ?
              AND (
                  a.state = 'pending_llm'
                  OR (a.state = 'retry'
                      AND (a.retry_after IS NULL OR a.retry_after <= ?))
              )
            ORDER BY CASE a.state WHEN 'retry' THEN 0 ELSE 1 END,
                     a.updated_at ASC, v.cve_id ASC
            LIMIT ?
        """, (version, utc_now(), limit))

    def record(
        self, row: dict[str, Any], version: str, state: str,
        *, result: Any = None, error: str | None = None
    ) -> bool:
        """Atomic optimistic check: do not save a classification of stale CVE content."""
        if state not in {"classified", "review", "pending_llm", "retry"}:
            raise ValueError(f"Unknown state: {state}")
        now = utc_now()
        if result is None:
            related = None
            category = "unknown"
            conf = None
            reason = (error or "等待语义判断")[:2000]
            evidence = []
            source = ""
            review = 0
            rule_score = None
        else:
            related = int(bool(result.is_ai_related))
            category = result.category
            conf = float(result.confidence)
            reason = result.reason
            evidence = list(result.evidence)
            source = result.decision_source
            review = int(bool(result.needs_review))
            rule_score = float(result.rule_score)
        retry_after = (
            (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(timespec="seconds")
            if state == "retry" else None
        )
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute(
                "SELECT content_sha256 FROM unified_vulnerabilities WHERE cve_id=?",
                (row["cve_id"],)
            ).fetchone()
            if cur is None or cur["content_sha256"] != row["content_sha256"]:
                return False
            con.execute("""
                INSERT INTO ai_classifications
                (cve_id,content_sha256,classifier_version,state,ai_related,ai_category,
                 confidence,reason,evidence_json,decision_source,needs_review,rule_score,
                 attempts,error_text,retry_after,classified_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                  content_sha256=excluded.content_sha256,
                  classifier_version=excluded.classifier_version,
                  state=excluded.state,
                  ai_related=excluded.ai_related,
                  ai_category=excluded.ai_category,
                  confidence=excluded.confidence,
                  reason=excluded.reason,
                  evidence_json=excluded.evidence_json,
                  decision_source=excluded.decision_source,
                  needs_review=excluded.needs_review,
                  rule_score=excluded.rule_score,
                  attempts=CASE
                      WHEN ai_classifications.content_sha256=excluded.content_sha256
                      AND ai_classifications.classifier_version=excluded.classifier_version
                      THEN ai_classifications.attempts+1 ELSE 1 END,
                  error_text=excluded.error_text,
                  retry_after=excluded.retry_after,
                  classified_at=excluded.classified_at,
                  updated_at=excluded.updated_at
            """, (
                row["cve_id"], row["content_sha256"], version, state,
                related, category, conf, reason,
                json.dumps(evidence, ensure_ascii=False),
                source, review, rule_score,
                (error or "")[:2000] or None, retry_after,
                now if state in {"classified", "review"} else None,
                now,
            ))
        return True

    def log_run(
        self, start: str, version: str, max_items: int, llm_cap: int,
        stats: dict, status: str, error: str | None = None
    ):
        with self.connect() as con:
            con.execute("""
                INSERT INTO ai_classification_runs
                (started_at,finished_at,classifier_version,status,max_items,max_llm_calls,
                 stats_json,error_text) VALUES (?,?,?,?,?,?,?,?)
            """, (
                start, utc_now(), version, status, max_items, llm_cap,
                json.dumps(stats, ensure_ascii=False), error
            ))

    def stats(self, version: str) -> dict:
        with self.connect() as con:
            total = con.execute("SELECT COUNT(*) FROM unified_vulnerabilities").fetchone()[0]
            states = {r["state"]: r["n"] for r in con.execute(
                """SELECT state,COUNT(*) n FROM ai_classifications a
                   JOIN unified_vulnerabilities v ON v.cve_id=a.cve_id
                   WHERE a.classifier_version=? AND a.content_sha256=v.content_sha256
                   GROUP BY state""", (version,)
            )}
            needs_new = con.execute("""
                SELECT COUNT(*) FROM unified_vulnerabilities v
                LEFT JOIN ai_classifications a ON a.cve_id = v.cve_id
                WHERE a.cve_id IS NULL OR a.content_sha256 != v.content_sha256
                   OR a.classifier_version != ?
            """, (version,)).fetchone()[0]
            ai_positive = con.execute("""
                SELECT COUNT(*) FROM ai_classifications a
                JOIN unified_vulnerabilities v ON v.cve_id=a.cve_id
                WHERE a.classifier_version=? AND a.content_sha256=v.content_sha256
                  AND a.state IN ('classified','review') AND a.ai_related=1
            """, (version,)).fetchone()[0]
        return {
            "total_cves": total, "need_initial_or_refresh": needs_new,
            "states": states, "classified_ai_positive": ai_positive,
        }

    def export_jsonl(self, path: str | Path, version: str, only_ai: bool = False) -> int:
        """Export only completed classifications with current hash/version."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        sql = """
            SELECT v.payload_json, a.ai_related, a.ai_category, a.confidence,
                   a.reason, a.evidence_json, a.decision_source, a.needs_review,
                   a.state, a.classifier_version, a.classified_at
            FROM ai_classifications a
            JOIN unified_vulnerabilities v ON v.cve_id=a.cve_id
            WHERE a.content_sha256=v.content_sha256
              AND a.classifier_version=?
              AND a.state IN ('classified','review')
        """
        params: tuple = (version,)
        if only_ai:
            sql += " AND a.ai_related=1"
        sql += " ORDER BY v.cve_id"
        n = 0
        with self.connect() as con, path.open("w", encoding="utf-8", newline="\n") as f:
            for r in con.execute(sql, params):
                obj = json.loads(r["payload_json"])
                obj["ai_related"] = bool(r["ai_related"])
                obj["ai_category"] = r["ai_category"]
                obj["ai_evidence"] = json.loads(r["evidence_json"])
                obj["ai_classification"] = {
                    "state": r["state"],
                    "confidence": r["confidence"],
                    "reason": r["reason"],
                    "decision_source": r["decision_source"],
                    "needs_review": bool(r["needs_review"]),
                    "classifier_version": r["classifier_version"],
                    "classified_at": r["classified_at"],
                }
                f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
                n += 1
        return n
