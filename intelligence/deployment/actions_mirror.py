"""Deliver verified main-branch Actions snapshots to a read-only B API.

This process is a consumer, never a second collector. Each generation is fully
validated before an atomic symlink switch; readers finish on their old SQLite
connection while subsequent requests open the new generation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

try:
    from .actions_state import ARTIFACT_PREFIX, GitHubClient, MAX_SNAPSHOT_BYTES, StateError, restore_archive, validate_deployment_state
    from .file_lock import exclusive_file_lock
    from .state_role import claim_role
except ImportError:  # Direct script invocation in the B container.
    from actions_state import ARTIFACT_PREFIX, GitHubClient, MAX_SNAPSHOT_BYTES, StateError, restore_archive, validate_deployment_state
    from file_lock import exclusive_file_lock
    from state_role import claim_role


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise StateError("History timestamp must include a timezone")
    return parsed


def verify_history(previous, incoming):
    """No reset/later first-seen or disappearance of previously observed data."""
    if _read_json(previous / "monitoring_baseline.json")["started_at"] != _read_json(incoming / "monitoring_baseline.json")["started_at"]:
        raise StateError("Incoming state resets the original monitoring baseline")
    with closing(sqlite3.connect(previous.joinpath("intelligence.db").as_uri() + "?mode=ro", uri=True)) as old:
        with closing(sqlite3.connect(incoming.joinpath("intelligence.db").as_uri() + "?mode=ro", uri=True)) as new:
            for table, keys in (("source_items", ("source", "source_id")),
                                ("unified_vulnerabilities", ("cve_id",)),
                                ("knowledge_documents", ("document_id",)),
                                ("source_observation_baselines", ("source",))):
                old_columns = {row[1] for row in old.execute(f"PRAGMA table_info({table})")}
                if not old_columns:
                    continue
                new_columns = {row[1] for row in new.execute(f"PRAGMA table_info({table})")}
                timestamp = "started_at" if table == "source_observation_baselines" else "first_seen_at"
                if not set(keys + (timestamp,)) <= old_columns or not old_columns <= new_columns:
                    raise StateError("Incoming state lacks the prior history schema")
                selected = ",".join(keys + (timestamp,))
                predicate = " AND ".join(f"{key}=?" for key in keys)
                for row in old.execute(f"SELECT {selected} FROM {table}"):
                    found = new.execute(f"SELECT {timestamp} FROM {table} WHERE {predicate}", row[:-1]).fetchone()
                    if found is None or _timestamp(found[0]) > _timestamp(row[-1]):
                        raise StateError("Incoming state loses or resets previously observed history")


def latest_snapshot(client, *, workflow="intelligence-collect.yml", branch="main"):
    """Bind an artifact to the exact trusted workflow, branch and run."""
    workflow_id = client.workflow_id(workflow)
    runs = sorted(client.runs(workflow, branch), key=lambda item: int(item["run_number"]), reverse=True)
    for run in runs:
        if (run.get("workflow_id") != workflow_id or run.get("head_branch") != branch
                or run.get("event") not in {"schedule", "workflow_dispatch"} or run.get("status") != "completed"):
            continue
        full = client.run(run["id"])
        if (full.get("workflow_id") != workflow_id or full.get("head_branch") != branch
                or (full.get("head_repository") or {}).get("full_name") != client.repository):
            raise StateError("Workflow run repository or branch provenance is invalid")
        matching = [artifact for artifact in client.artifacts(run["id"])
                    if artifact.get("name") == ARTIFACT_PREFIX + str(run["id"])]
        if matching:
            if (len(matching) != 1 or matching[0].get("expired")
                    or (matching[0].get("workflow_run") or {}).get("id") != run["id"]):
                raise StateError("Latest writer artifact is expired or has invalid run provenance")
            return full, matching[0]
        if client.collection_started(run["id"]):
            raise StateError("Latest writer snapshot is missing; refusing to publish older state")
    raise StateError("No trusted completed collector snapshot is available")


def install_snapshot(payload, directory, *, repository, branch, run_id,
                     workflow="intelligence-collect.yml", collector_commit=None,
                     run_number=None, source="authenticated-ingest"):
    """Validate one generation and atomically publish it; never replace live DBs.

    Pull binds provenance to GitHub metadata. HTTP push binds it to the configured
    repository plus authenticated sender, and requires the same manifest lineage.
    A separate publication lock serializes push, CLI installs and mirror polling.
    """
    if branch != "main":
        raise StateError("Deployment mirrors consume only the main branch")
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise StateError("Snapshot exceeds size limit")
    directory = Path(directory).absolute()
    claim_role(directory, "actions-mirror")
    with exclusive_file_lock(directory / ".publication.lock", timeout=120):
        current = directory / "current"
        if current.exists() and not current.is_symlink():
            raise StateError("Current generation must be a managed symlink")
        previous = current.resolve() if current.is_symlink() else None
        snapshots = directory / "snapshots"
        snapshots.mkdir(exist_ok=True)
        if previous and (previous.parent != snapshots.resolve() or not previous.is_dir()):
            raise StateError("Current generation points outside the managed snapshots")
        previous_manifest = _read_json(previous / "manifest.json") if previous else None
        with tempfile.TemporaryDirectory(prefix=".incoming-", dir=directory) as temporary:
            staged = Path(temporary) / "state"
            manifest = restore_archive(payload, staged, repository=repository,
                                       branch=branch, run_id=run_id)
            validate_deployment_state(staged, manifest=manifest)
            if (manifest.get("workflow") != workflow
                    or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("collector_commit", "")))
                    or type(manifest.get("run_number")) is not int
                    or manifest["run_number"] <= 0):
                raise StateError("Snapshot code/workflow lineage is absent or invalid")
            if ((collector_commit is not None and manifest["collector_commit"] != collector_commit)
                    or (run_number is not None and manifest["run_number"] != run_number)):
                raise StateError("Snapshot code/workflow lineage does not match the verified main run")
            result = {"run_id": int(run_id), "run_number": manifest["run_number"],
                      "collector_commit": manifest["collector_commit"], "repository": repository,
                      "branch": branch, "workflow": workflow, "source": source,
                      "synced_at": datetime.now(timezone.utc).isoformat()}
            if previous_manifest:
                if (previous_manifest.get("repository") != repository
                        or previous_manifest.get("branch") != branch
                        or previous_manifest.get("workflow") != workflow):
                    raise StateError("The existing mirror belongs to another data lineage")
                if manifest["run_number"] < previous_manifest["run_number"]:
                    raise StateError("Incoming workflow run would roll back the deployed data lineage")
                if manifest["run_number"] == previous_manifest["run_number"]:
                    if (manifest != previous_manifest):
                        raise StateError("Workflow run identity or contents conflict with the deployed lineage")
                    return {"changed": False, **result}
                verify_history(previous, staged)
            (staged / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            target = snapshots / str(int(run_id))
            temporary_link = directory / ".current-next"
            temporary_link.unlink(missing_ok=True)
            try:
                # Test link permission before moving or making the validated
                # generation immutable. Never fall back to copying live DBs.
                temporary_link.symlink_to(Path("snapshots") / str(int(run_id)), target_is_directory=True)
            except OSError as exc:
                raise StateError("Atomic snapshot publication requires directory symlink permission; "
                                 "on Windows enable Developer Mode or use the Linux Docker deployment") from exc
            try:
                if target.exists():
                    if previous and target.resolve() == previous:
                        raise StateError("A conflicting active snapshot generation exists")
                    target.chmod(0o755)
                    shutil.rmtree(target)
                staged.replace(target)
                for path in target.iterdir():
                    path.chmod(0o444)
                target.chmod(0o555)
                temporary_link.replace(current)
            finally:
                temporary_link.unlink(missing_ok=True)
        generations = sorted((path for path in snapshots.iterdir() if path.is_dir() and path.name.isdigit()),
                             key=lambda path: int(_read_json(path / "manifest.json")["run_number"]), reverse=True)
        for old in generations[8:]:
            old.chmod(0o755)
            shutil.rmtree(old)
        return {"changed": True, **result}


def deliver_latest(client, directory, *, workflow="intelligence-collect.yml", branch="main"):
    run, artifact = latest_snapshot(client, workflow=workflow, branch=branch)
    result = install_snapshot(client.download(artifact["id"]), directory,
                              repository=client.repository, branch=branch, run_id=run["id"],
                              workflow=workflow, collector_commit=run.get("head_sha"),
                              run_number=run.get("run_number"), source="github-artifact")
    return {**result, "artifact_id": artifact["id"],
            "artifact_name": artifact.get("name"), "workflow_run_url": run.get("html_url"),
            "source_run_completed_at": run.get("updated_at")}


def record_status(directory, **status):
    status["checked_at"] = datetime.now(timezone.utc).isoformat()
    destination = Path(directory) / "mirror_status.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    temporary.replace(destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY", "sijunxiaodeng/ai-sec-intel"))
    parser.add_argument("--workflow", default="intelligence-collect.yml")
    parser.add_argument("--interval-seconds", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if not 30 <= args.interval_seconds <= 3600:
        parser.error("Mirror polling interval must be 30..3600 seconds")
    directory = Path(args.directory).absolute()
    try:
        claim_role(directory, "actions-mirror")
        client = GitHubClient(os.getenv("GITHUB_TOKEN"), args.repository)
        try:
            with exclusive_file_lock(directory / ".mirror.lock", blocking=False):
                while True:
                    try:
                        result = deliver_latest(client, directory, workflow=args.workflow)
                        record_status(directory, status="ready", poll_interval_seconds=args.interval_seconds, **result)
                        print(f"Verified Actions delivery: run {result['run_id']}; changed={result['changed']}", flush=True)
                        failed = False
                    except (StateError, ValueError, KeyError, sqlite3.DatabaseError, OSError, zipfile.BadZipFile):
                        # No response bodies, token-bearing URLs or exception details.
                        record_status(directory, status="degraded", reason="delivery_validation_or_network_failed",
                                      poll_interval_seconds=args.interval_seconds,
                                      serving_previous=bool((directory / "current/intelligence.db").is_file()))
                        print("Actions delivery failed; previous verified generation retained", flush=True)
                        failed = True
                    if args.once:
                        return 1 if failed else 0
                    time.sleep(args.interval_seconds)
        except OSError as exc:
            raise StateError("Another mirror already owns this volume") from exc
    except (StateError, RuntimeError, OSError):
        print("Actions mirror cannot start; verify token access and use a separate mirror volume", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
