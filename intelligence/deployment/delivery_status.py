"""Read-only evidence of the generation actually opened by a deployment API."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .snapshot_contract import database_contract

MAX_STATUS_BYTES = 64 * 1024


def _json(path):
    if path.stat().st_size > MAX_STATUS_BYTES:
        raise ValueError("Status file too large")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Status must be an object")
    return result


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.utcoffset() is not None else None
    except ValueError:
        return None


def deployment_delivery(database, *, classifier_version, now=None):
    """Bind manifest, schema and feed metadata to one resolved generation.

    Poll observations establish a recent checked snapshot, not process uptime.
    Serving a B generation does not establish the main application's consumption.
    """
    now = now or datetime.now(timezone.utc)
    target = Path(database).absolute()
    generation = target.resolve().parent
    result = {"status": "unverified", "database_available": False, "generation": None,
              "compatibility": {"ready": False}, "changefeed": None,
              "poller_observation": "not_observed", "last_checked_at": None,
              "consumer_status": "unverified"}
    try:
        manifest = _json(generation / "manifest.json")
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(manifest.get("repository", "")))
                or manifest.get("branch") != "main" or manifest.get("workflow") != "intelligence-collect.yml"
                or type(manifest.get("run_id")) is not int or manifest["run_id"] <= 0
                or type(manifest.get("run_number")) is not int or manifest["run_number"] <= 0
                or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("collector_commit", "")))):
            raise ValueError("Invalid generation lineage")
        result["generation"] = {key: manifest[key] for key in
                                ("repository", "branch", "workflow", "run_id", "run_number", "collector_commit")}
        if not classifier_version:
            result["status"] = "incompatible"
            return result
        # Use the resolved DB path, so a concurrent current/ switch cannot mix generations.
        database = generation / target.name
        contract = database_contract(database, classifier_version=classifier_version)
        result["compatibility"] = contract
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("SELECT COUNT(*) FROM unified_vulnerabilities").fetchone()
            result["database_available"] = True
            if contract["ready"]:
                epoch = connection.execute("SELECT value FROM team_feed_meta WHERE key='epoch'").fetchone()[0]
                through = connection.execute("SELECT COALESCE(MAX(seq),0) FROM team_changes").fetchone()[0]
                result["changefeed"] = {"epoch": epoch, "through": through}
        result["status"] = "serving_verified_generation" if contract["ready"] else "incompatible"
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return result

    # Only a managed current/ volume has a mirror poller status. Standalone
    # authenticated push installations do not claim an automatic pull process.
    try:
        poll = _json(target.parent.parent / "mirror_status.json") if target.parent.name == "current" else {}
        checked = _timestamp(poll.get("checked_at"))
        interval = poll.get("poll_interval_seconds", 60)
        interval = interval if type(interval) is int and 30 <= interval <= 3600 else 60
        if checked:
            result["last_checked_at"] = checked.isoformat()
            age = (now - checked).total_seconds()
            if age < 0 or age > 2 * interval + 30:
                result["poller_observation"] = "stale"
            elif poll.get("status") == "degraded":
                result["poller_observation"] = "degraded"
            elif (poll.get("status") == "ready" and poll.get("run_id") == manifest["run_id"]
                  and poll.get("collector_commit") == manifest["collector_commit"]):
                result["poller_observation"] = "ready"
            else:
                result["poller_observation"] = "generation_mismatch"
    except (OSError, ValueError, TypeError):
        pass
    return result
