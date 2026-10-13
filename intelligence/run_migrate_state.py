"""Upgrade retained collector state offline before publishing a new code version."""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from ai_pipeline.documents import DocumentClassificationStore, run_document_batch
from ai_pipeline.store import ClassificationStore, utc_now
from ai_pipeline.worker_v5 import run_priority_batch
from deployment.actions_state import StateError, validate_baseline, validate_database
from deployment.snapshot_contract import database_contract, runtime_classifier_version
from monitoring.lock import ProcessFileLock
from run_ai_classification_v4 import atomic_status
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

HISTORY_TABLES = ("source_items", "unified_vulnerabilities", "knowledge_documents",
                  "source_observation_baselines", "incremental_cursors", "document_http_state")


def _history_digests(db: Path) -> dict:
    """Hash retained rows (including evidence/timestamps), without printing data."""
    digests = {}
    with closing(sqlite3.connect(db)) as con:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in HISTORY_TABLES:
            if table not in tables:
                continue
            columns = [row[1] for row in con.execute(f"PRAGMA table_info({table})")]
            digest = hashlib.sha256()
            for row in con.execute(f"SELECT * FROM {table} ORDER BY " + ",".join(columns)):
                digest.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                digest.update(b"\n")
            digests[table] = digest.hexdigest()
    return digests


def _archive_verdicts(db: Path, version: str) -> int:
    """Keep old classification reasons/evidence as audit data, never current truth."""
    count = 0
    with closing(sqlite3.connect(db)) as con, con:
        con.row_factory = sqlite3.Row
        con.execute("""CREATE TABLE IF NOT EXISTS classification_migration_history (
            kind TEXT NOT NULL, entity_id TEXT NOT NULL,
            record_sha256 TEXT NOT NULL, record_json TEXT NOT NULL,
            archived_at TEXT NOT NULL,
            PRIMARY KEY(kind,entity_id,record_sha256))""")
        for table, key, kind, entities in (
            ("ai_classifications", "cve_id", "cve", "unified_vulnerabilities"),
            ("document_ai_classifications", "document_id", "document", "knowledge_documents"),
        ):
            rows = con.execute(f"""SELECT a.* FROM {table} a JOIN {entities} e ON e.{key}=a.{key}
                WHERE a.classifier_version!=? OR a.content_sha256!=e.content_sha256""", (version,)).fetchall()
            for row in rows:
                payload = json.dumps(dict(row), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                count += con.execute("""INSERT OR IGNORE INTO classification_migration_history
                    VALUES (?,?,?,?,?)""", (kind, row[key], hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                                             payload, utc_now())).rowcount
    return count


def migrate_state(directory: Path | str, *, allow_new: bool = False) -> dict:
    """Idempotent writer migration; no requests, model calls, or timestamp resets."""
    directory = Path(directory).resolve()
    db = directory / "intelligence.db"
    if not db.is_file() and allow_new:
        # Only restore_latest's verified, genuinely first deployment grants
        # this flag in Actions. Existing/incomplete state is never reset.
        directory.mkdir(parents=True, exist_ok=True)
        if any(directory.iterdir()):
            raise StateError("New deployment requires completely empty state; incomplete history cannot be reset")
        return {"status": "new_deployment", "initial_collection_required": True,
                "semantic_calls": 0, "history_preserved": True}
    validate_database(db)
    validate_baseline(directory / "monitoring_baseline.json")
    baseline_bytes = (directory / "monitoring_baseline.json").read_bytes()
    with ProcessFileLock(directory / ".monitoring.lock"), ProcessFileLock(directory / ".ai_classification.lock"):
        before = _history_digests(db)
        SQLiteIntelligenceStore(db)
        SQLiteDocumentStore(db)
        cves = ClassificationStore(db)
        documents = DocumentClassificationStore(db)
        version = runtime_classifier_version()
        archived = _archive_verdicts(db, version)
        cve_before, doc_before = cves.stats(version), documents.stats(version)
        cve_report, doc_report = {}, {}
        if cve_before["need_initial_or_refresh"]:
            # A complete cheap re-evaluation is required for a classifier rollout;
            # the normal per-cycle budget would leave thousands of stale verdicts.
            cve_report = run_priority_batch(db, version, max(1, cve_before["total_cves"]),
                                            max_llm_calls=0, verbose=False)
        if doc_before["need_initial_or_refresh"]:
            with closing(sqlite3.connect(db)) as con:
                total_docs = con.execute("SELECT COUNT(*) FROM knowledge_documents").fetchone()[0]
            doc_report = run_document_batch(db, version, max(1, total_docs))
        contract = database_contract(db, classifier_version=version)
        cve_after, doc_after = cves.stats(version), documents.stats(version)
        after = _history_digests(db)
        if any(after.get(table) != digest for table, digest in before.items()):
            raise RuntimeError("Migration altered retained source/evidence/history rows")
        if (directory / "monitoring_baseline.json").read_bytes() != baseline_bytes:
            raise RuntimeError("Migration altered the original monitoring baseline")
        if (not contract["ready"] or cve_after["need_initial_or_refresh"]
                or doc_after["need_initial_or_refresh"]):
            raise RuntimeError("Collector state migration is incomplete; do not publish this state")
        report = {"status": "ready", "classifier_version": version,
                  "archived_verdicts": archived, "semantic_calls": 0, "history_preserved": True,
                  "cves": {"before": cve_before, "after": cve_after, "batch": cve_report},
                  "documents": {"before": doc_before, "after": doc_after, "batch": doc_report},
                  "compatibility": contract}
        atomic_status(directory / "migration_status.json", report)
        return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default=str(Path(__file__).resolve().parent / "data"))
    parser.add_argument("--allow-new", action="store_true",
                        help="Permit an empty first deployment only after restore verified no prior writer")
    args = parser.parse_args(argv)
    report = migrate_state(args.directory, allow_new=args.allow_new)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
