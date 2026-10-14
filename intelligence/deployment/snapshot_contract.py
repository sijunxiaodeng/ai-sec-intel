"""Read-only deployment contract checks; usable before dependencies install."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
try:
    from classification.version import CLASSIFIER_FILES, classifier_version
except ModuleNotFoundError as exc:
    if exc.name != "classification":
        raise
    # actions_state.py also runs directly, before pip installs and without the
    # intelligence root on sys.path. Load the same stdlib-only helper by path.
    import importlib.util
    spec = importlib.util.spec_from_file_location("_snapshot_classifier_version", Path(__file__).resolve().parents[1] / "classification" / "version.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    CLASSIFIER_FILES, classifier_version = module.CLASSIFIER_FILES, module.classifier_version

CONTRACT_VERSION = 1


def runtime_classifier_version(root: Path | None = None) -> str:
    return classifier_version(root)


def database_contract(path: Path, *, classifier_version: str | None = None) -> dict:
    """Inspect real schema/verdicts, never trust a manifest's readiness claim.

    Missing or content-stale classifications are an explicit collection backlog.
    A different classifier version is a code rollout incompatibility, which must
    be migrated before publishing. Pending semantic verdicts remain unknown.
    """
    version = classifier_version or runtime_classifier_version()
    result = {"version": CONTRACT_VERSION, "classifier_version": version,
              "ready": False, "problems": [], "classification": {}}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {
            "team_feed_meta": {"key", "value"},
            "team_changes": {"seq", "kind", "entity_id", "changed_at"},
            "unified_vulnerabilities": {"cve_id", "content_sha256"},
            "knowledge_documents": {"document_id", "content_sha256"},
            "ai_classifications": {"cve_id", "content_sha256", "classifier_version", "state", "ai_related"},
            "document_ai_classifications": {"document_id", "content_sha256", "classifier_version", "state", "ai_related"},
        }
        for table, columns in required.items():
            actual = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if table not in tables or not columns <= actual:
                result["problems"].append(f"missing_schema:{table}")
        if result["problems"]:
            return result
        epoch = db.execute("SELECT value FROM team_feed_meta WHERE key='epoch'").fetchone()
        if epoch is None or not epoch[0]:
            result["problems"].append("missing_changefeed_epoch")
        triggers = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        for table, key, kind, verdicts in (
            ("unified_vulnerabilities", "cve_id", "cve", "ai_classifications"),
            ("knowledge_documents", "document_id", "document", "document_ai_classifications"),
        ):
            for writer in (table, verdicts):
                if not {f"team_feed_{writer}_{operation}" for operation in ("insert", "update", "delete")} <= triggers:
                    result["problems"].append(f"missing_changefeed_triggers:{writer}")
            missing_events = db.execute(f"""SELECT COUNT(*) FROM {table} e WHERE NOT EXISTS (
                SELECT 1 FROM team_changes c WHERE c.kind=? AND c.entity_id=e.{key})""", (kind,)).fetchone()[0]
            if missing_events:
                result["problems"].append(f"missing_changefeed_backfill:{kind}:{missing_events}")
            counts = db.execute(f"""SELECT COUNT(*),
                SUM(CASE WHEN a.{key} IS NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN a.{key} IS NOT NULL AND a.classifier_version!=? THEN 1 ELSE 0 END),
                SUM(CASE WHEN a.{key} IS NOT NULL AND a.content_sha256!=e.content_sha256 THEN 1 ELSE 0 END),
                SUM(CASE WHEN a.classifier_version=? AND a.content_sha256=e.content_sha256
                    AND a.state='classified' AND a.ai_related=1 THEN 1 ELSE 0 END)
                FROM {table} e LEFT JOIN {verdicts} a ON a.{key}=e.{key}""", (version, version)).fetchone()
            stats = dict(zip(("total", "missing", "version_stale", "content_stale", "current_ai_positive"),
                             (int(value or 0) for value in counts)))
            result["classification"][kind] = stats
            if stats["version_stale"]:
                result["problems"].append(f"classifier_version_stale:{kind}:{stats['version_stale']}")
    result["ready"] = not result["problems"]
    return result
