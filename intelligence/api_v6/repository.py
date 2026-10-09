"""Read-only access to the V2/V5.1 SQLite store, with hash/version freshness checks."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from monitoring.metrics import baseline, latency_report

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CLASSIFIER_FILES = (
    "classification/ai_relevance.py",
    "classification/hybrid_classifier.py",
    "classification/semantic_judge.py",
)


def current_classifier_version(root: Path) -> str | None:
    """Same digest as run_ai_classification_v4.classifier_version().

    None means source code was not found, so no historical classification is
    assumed current. We never fall back to a potentially stale DB version.
    """
    paths = [root / item for item in CLASSIFIER_FILES]
    if not all(path.is_file() for path in paths):
        return None
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return "hybrid-v3.1-" + digest.hexdigest()[:12]


def escape_like(text: str) -> str:
    """Match literal search text (no user-controlled LIKE wildcards)."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _classification_from_sql(row: sqlite3.Row) -> dict | None:
    if row["cls_state"] is None:
        return None
    evidence_text = row["cls_evidence_json"] or "[]"
    try:
        evidence = json.loads(evidence_text)
    except (ValueError, TypeError):
        evidence = []
    return {
        "state": row["cls_state"],
        "is_ai_related": None if row["cls_ai_related"] is None else bool(row["cls_ai_related"]),
        "category": row["cls_category"],
        "confidence": row["cls_confidence"],
        "reason": row["cls_reason"],
        "evidence": evidence,
        "decision_source": row["cls_decision_source"],
        "needs_review": bool(row["cls_needs_review"]),
        "classified_at": row["cls_classified_at"],
        "classifier_version": row["cls_classifier_version"],
    }


def _record(row: sqlite3.Row, full: bool = False, include_raw: bool = False) -> dict:
    payload = json.loads(row["payload_json"])
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid unified payload for {row['cve_id']}")
    classification = _classification_from_sql(row)
    summary = {
        "cve_id": row["cve_id"],
        "title": payload.get("title") or row["cve_id"],
        "description": payload.get("description") or "",
        "vendor": payload.get("vendor"),
        "product": payload.get("product"),
        "severity": payload.get("severity"),
        "cvss_score": payload.get("cvss_score"),
        "epss_score": payload.get("epss_score"),
        "known_exploited": bool(payload.get("known_exploited", False)),
        "sources": payload.get("sources") or [],
        "published_at": payload.get("published_at"),
        "modified_at": payload.get("modified_at"),
        "first_seen_at": row["first_seen_at"],
        "content_updated_at": row["content_updated_at"],
        "classification_state": (classification or {}).get("state") or "unclassified_or_stale",
        "is_ai_related": (classification or {}).get("is_ai_related"),
        "ai_category": (classification or {}).get("category") if classification else None,
        "ai_confidence": (classification or {}).get("confidence") if classification else None,
        "needs_review": (classification or {}).get("needs_review") if classification else None,
    }
    if full:
        if not include_raw:
            payload.pop("raw_by_source", None)
        summary["item"] = payload
        summary["classification"] = classification
    else:
        summary["description"] = summary["description"][:360]
    return summary


class IntelligenceRepository:
    def __init__(self, db_path: Path, root: Path):
        self.db_path = Path(db_path).resolve()
        self.root = Path(root).resolve()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        """Open an SQLite URI in mode=ro; never initialize or mutate schemas."""
        if not self.db_path.is_file():
            raise FileNotFoundError(str(self.db_path))
        uri = self.db_path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=20)) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only = ON")
            con.execute("PRAGMA busy_timeout = 20000")
            yield con

    @staticmethod
    def _base_query(version: str | None, classification_available: bool = True) -> tuple[str, tuple]:
        # Classification is optional. A freshly collected database has no
        # classification table; keep the API read-only and return unknowns.
        table = "ai_classifications" if classification_available else """(
            SELECT NULL AS cve_id, NULL AS content_sha256,
                   NULL AS classifier_version, NULL AS state, NULL AS ai_related,
                   NULL AS ai_category, NULL AS confidence, NULL AS reason,
                   NULL AS evidence_json, NULL AS decision_source,
                   NULL AS needs_review, NULL AS classified_at WHERE 0
        )"""
        sql = f"""
            FROM unified_vulnerabilities AS v
            LEFT JOIN {table} AS a
              ON a.cve_id = v.cve_id
             AND a.content_sha256 = v.content_sha256
             AND a.classifier_version = ?
        """
        return sql, (version or "__missing_classifier_sources__",)

    @staticmethod
    def _classification_available(con: sqlite3.Connection) -> bool:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ai_classifications'"
        ).fetchone() is not None

    @staticmethod
    def _columns() -> str:
        return """
          v.cve_id, v.payload_json, v.first_seen_at, v.content_updated_at,
          a.state AS cls_state, a.ai_related AS cls_ai_related,
          a.ai_category AS cls_category, a.confidence AS cls_confidence,
          a.reason AS cls_reason, a.evidence_json AS cls_evidence_json,
          a.decision_source AS cls_decision_source, a.needs_review AS cls_needs_review,
          a.classified_at AS cls_classified_at, a.classifier_version AS cls_classifier_version
        """

    @staticmethod
    def _where(*, q: str | None, source: str | None,
               ai_related: bool | None, category: str | None,
               state: str | None) -> tuple[str, tuple]:
        filters: list[str] = []
        params: list[Any] = []
        if q:
            value = "%" + escape_like(q.strip()) + "%"
            filters.append("""(
                v.cve_id LIKE ? ESCAPE '\\'
                OR COALESCE(json_extract(v.payload_json, '$.title'), '') LIKE ? ESCAPE '\\'
                OR COALESCE(json_extract(v.payload_json, '$.description'), '') LIKE ? ESCAPE '\\'
                OR COALESCE(json_extract(v.payload_json, '$.product'), '') LIKE ? ESCAPE '\\'
                OR COALESCE(json_extract(v.payload_json, '$.vendor'), '') LIKE ? ESCAPE '\\'
            )""")
            params.extend([value] * 5)
        if source:
            filters.append("""EXISTS (
                SELECT 1 FROM source_items s
                WHERE s.cve_id = v.cve_id AND s.source = ?
            )""")
            params.append(source.strip().upper())
        if ai_related is not None:
            filters.append("a.state IN ('classified', 'review') AND a.ai_related = ?")
            params.append(int(ai_related))
        if category:
            filters.append("a.state IN ('classified', 'review') AND a.ai_category = ?")
            params.append(category)
        if state:
            if state == "unclassified_or_stale":
                filters.append("a.cve_id IS NULL")
            else:
                filters.append("a.state = ?")
                params.append(state)
        return (" WHERE " + " AND ".join(filters) if filters else ""), tuple(params)

    def list_items(self, *, q: str | None = None, source: str | None = None,
                   ai_related: bool | None = None, category: str | None = None,
                   state: str | None = None, limit: int = 20, offset: int = 0,
                   sort: str = "updated", full: bool = False,
                   include_raw: bool = False) -> dict:
        version = current_classifier_version(self.root)
        where, where_params = self._where(q=q, source=source, ai_related=ai_related,
                                          category=category, state=state)
        orders = {
            "updated": "v.content_updated_at DESC, v.cve_id DESC",
            "published": "json_extract(v.payload_json, '$.published_at') DESC, v.cve_id DESC",
            "cvss": "CAST(json_extract(v.payload_json, '$.cvss_score') AS REAL) DESC, v.cve_id DESC",
        }
        order = orders[sort]  # validated against Literal in API; never accept raw SQL
        with self.read() as con:
            base, base_params = self._base_query(version, self._classification_available(con))
            total = con.execute("SELECT COUNT(*) " + base + where,
                                base_params + where_params).fetchone()[0]
            rows = con.execute(
                "SELECT " + self._columns() + base + where
                + " ORDER BY " + order + " LIMIT ? OFFSET ?",
                base_params + where_params + (limit, offset),
            ).fetchall()
        return {
            "total": total, "limit": limit, "offset": offset,
            "classifier_version": version,
            "items": [_record(row, full=full, include_raw=include_raw) for row in rows],
        }

    def one(self, cve_id: str, include_raw: bool = False) -> dict | None:
        version = current_classifier_version(self.root)
        with self.read() as con:
            base, base_params = self._base_query(version, self._classification_available(con))
            row = con.execute(
                "SELECT " + self._columns() + base + " WHERE v.cve_id = ?",
                base_params + (cve_id.upper(),),
            ).fetchone()
        return None if row is None else _record(row, full=True, include_raw=include_raw)

    def stats(self) -> dict:
        version = current_classifier_version(self.root)
        with self.read() as con:
            base, base_params = self._base_query(version, self._classification_available(con))
            total = con.execute("SELECT COUNT(*) FROM unified_vulnerabilities").fetchone()[0]
            state_rows = con.execute("""
                SELECT COALESCE(a.state, 'unclassified_or_stale') AS state,
                       COUNT(*) AS n
            """ + base + " GROUP BY COALESCE(a.state, 'unclassified_or_stale')",
                                     base_params).fetchall()
            positive = con.execute("""
                SELECT COUNT(*) """ + base
                + " WHERE a.state = 'classified' AND a.ai_related = 1",
                base_params).fetchone()[0]
            review_positive = con.execute(
                "SELECT COUNT(*) " + base + " WHERE a.state = 'review' AND a.ai_related = 1",
                base_params).fetchone()[0]
            cats = con.execute("""
                SELECT a.ai_category AS category, COUNT(*) AS n """ + base
                + " WHERE a.state = 'classified' AND a.ai_related = 1"
                  " GROUP BY a.ai_category ORDER BY n DESC, a.ai_category",
                base_params).fetchall()
            by_source = con.execute(
                "SELECT source, COUNT(*) AS n FROM source_items GROUP BY source ORDER BY source"
            ).fetchall()
            src_total = sum(row["n"] for row in by_source)
        return {
            "total_cves": total,
            "total_source_records": src_total,
            "classifier_version": version,
            "classification_states": {row["state"]: row["n"] for row in state_rows},
            "classified_ai_positive": positive,
            "review_ai_positive": review_positive,
            "ai_categories": {row["category"]: row["n"] for row in cats},
            "source_record_counts": {row["source"]: row["n"] for row in by_source},
            "note": "分类仅统计与当前 CVE 内容哈希、分类器版本均一致的结果；待复核正例未视作人工确认。",
        }

    def recent_collectors(self) -> list[dict]:
        with self.read() as con:
            rows = con.execute("""
                SELECT r.collector, r.status, r.started_at, r.finished_at,
                       r.fetched_count, r.inserted_count, r.updated_count,
                       r.unchanged_count, r.new_cve_count
                FROM collector_runs r
                WHERE r.id = (SELECT MAX(x.id) FROM collector_runs x
                              WHERE x.collector = r.collector)
                ORDER BY r.collector
            """).fetchall()
        return [dict(row) for row in rows]

    def monitoring_metrics(self) -> dict:
        with self.read() as con:
            return latency_report(con, baseline(self.root, state_dir=self.db_path.parent))
