"""Durable public-data snapshots for the scheduled GitHub Actions collector.

Only the SQLite database and an explicit JSON allowlist are exported. A missing,
expired, or corrupt snapshot stops collection instead of resetting timestamps.
This module uses the standard library so state restore precedes pip installation.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_PREFIX = "intelligence-state-"
BOOTSTRAP_ASSET = "intelligence-bootstrap-state.zip"
COLLECTION_STEP = "Collect public intelligence"
STATE_FILES = {"intelligence.db", "monitoring_baseline.json", "monitoring_status.json", "classification_status.json",
               "deepseek_status.json", "actions_report.json"}
REQUIRED_FILES = {"intelligence.db", "monitoring_baseline.json"}
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024


class StateError(RuntimeError):
    """Collection must not start with unknown or invalid prior state."""


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


class GitHubClient:
    def __init__(self, token, repository, api_url="https://api.github.com"):
        if not token or len(repository.split("/")) != 2:
            raise StateError("GITHUB_TOKEN and owner/repository are required")
        self.token = token
        self.repository = repository
        self.api_url = api_url.rstrip("/")
        self.opener = urllib.request.build_opener(SafeRedirect())

    def request(self, path, *, binary=False, accept="application/vnd.github+json", method="GET"):
        url = f"{self.api_url}/repos/{self.repository}/{path}"
        req = urllib.request.Request(url, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ai-sec-intel-state",
        })
        try:
            with self.opener.open(req, timeout=60) as response:
                payload = response.read(MAX_SNAPSHOT_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise StateError(f"GitHub state API failed: HTTP {exc.code}; no collection was started") from None
        except (OSError, urllib.error.URLError):
            raise StateError("GitHub state API unavailable; no collection was started") from None
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise StateError("State response exceeds the snapshot size limit")
        return payload if binary else json.loads(payload) if payload else None

    def runs(self, workflow, branch):
        # At most 500 recent runs. An older-only snapshot is not silently trusted.
        for page in range(1, 6):
            query = urllib.parse.urlencode({"branch": branch, "status": "completed", "per_page": 100, "page": page})
            result = self.request(f"actions/workflows/{urllib.parse.quote(workflow, safe='')}/runs?{query}")
            runs = result["workflow_runs"]
            yield from runs
            if len(runs) < 100:
                return
        raise StateError("Too many historical runs to establish state lineage; recover an explicit backup")

    def artifacts(self, run_id):
        return self.request(f"actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]

    def collection_started(self, run_id):
        result = self.request(f"actions/runs/{run_id}/jobs?filter=all&per_page=100")
        return any(step.get("name") == COLLECTION_STEP and step.get("conclusion") != "skipped"
                   and step.get("started_at") for job in result["jobs"] for step in job.get("steps", []))

    def download(self, artifact_id):
        return self.request(f"actions/artifacts/{artifact_id}/zip", binary=True)

    def workflow_id(self, workflow):
        return self.request(f"actions/workflows/{urllib.parse.quote(workflow, safe='')}")["id"]

    def all_artifacts(self):
        for page in range(1, 11):
            values = self.request(f"actions/artifacts?per_page=100&page={page}")["artifacts"]
            yield from values
            if len(values) < 100:
                return
        raise StateError("Too many repository artifacts to establish safe cleanup scope")

    def run(self, run_id):
        return self.request(f"actions/runs/{run_id}")

    def delete_artifact(self, artifact_id):
        self.request(f"actions/artifacts/{artifact_id}", method="DELETE")

    def bootstrap(self, tag):
        # Fixed asset in this same repository only; never accepts external URLs.
        # The tag endpoint only returns published releases. Listing is necessary
        # for a draft seed and still requires the caller's repository permission.
        matches = []
        for page in range(1, 11):
            releases = self.request(f"releases?per_page=100&page={page}")
            matches.extend(item for item in releases if item.get("tag_name") == tag)
            if len(releases) < 100:
                break
        else:
            raise StateError("Too many releases to establish a unique bootstrap source")
        if len(matches) != 1:
            raise StateError("Bootstrap release is not uniquely visible; verify draft read permission")
        release = matches[0]
        matches = [asset for asset in release.get("assets", []) if asset.get("name") == BOOTSTRAP_ASSET]
        if len(matches) != 1:
            raise StateError("Bootstrap release must contain exactly one fixed-name snapshot asset")
        if matches[0].get("size", 0) > MAX_SNAPSHOT_BYTES:
            raise StateError("Bootstrap asset exceeds size limit")
        return self.request(f"releases/assets/{matches[0]['id']}", binary=True, accept="application/octet-stream")

    def bootstrap_commit(self, commit_sha):
        """Read one fixed seed file at an immutable commit in this repository."""
        if not isinstance(commit_sha, str) or re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha) is None:
            raise StateError("Bootstrap state commit must be a full 40-character hexadecimal commit SHA")
        commit_sha = commit_sha.lower()
        commit = self.request(f"git/commits/{commit_sha}")
        if str(commit.get("sha", "")).lower() != commit_sha:
            raise StateError("Bootstrap source did not resolve to the requested immutable commit")
        # GitHub's raw Contents representation supports files above the inline
        # base64 limit without following download_url or another repository.
        return self.request(f"contents/{BOOTSTRAP_ASSET}?ref={commit_sha}", binary=True,
                            accept="application/vnd.github.raw+json")


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_database(path):
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=30)) as db:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise StateError("SQLite snapshot integrity check failed")
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"source_items", "unified_vulnerabilities", "source_observation_baselines"} <= names:
            raise StateError("SQLite snapshot lacks collection history/baselines")


def validate_baseline(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    value = datetime.fromisoformat(payload["started_at"].replace("Z", "+00:00"))
    if value.utcoffset() is None:
        raise StateError("Monitoring baseline must have a timezone")


def save_state(source, destination, *, repository, branch, run_id):
    source, destination = Path(source), Path(destination)
    if not (source / "intelligence.db").is_file() or not (source / "monitoring_baseline.json").is_file():
        raise StateError("No complete database/baseline available to snapshot")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise StateError("Snapshot destination must be empty")
    # Online backup includes committed WAL pages and does not copy transient locks.
    uri = f"{(source / 'intelligence.db').resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=30)) as live:
        with closing(sqlite3.connect(destination / "intelligence.db", timeout=30)) as backup:
            live.backup(backup)
            backup.execute("PRAGMA journal_mode = DELETE")
    validate_database(destination / "intelligence.db")
    for name in sorted(STATE_FILES - {"intelligence.db"}):
        current = source / name
        if current.is_file():
            if current.is_symlink():
                raise StateError("Snapshot source JSON cannot be a symlink")
            payload = json.loads(current.read_text(encoding="utf-8"))
            (destination / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    validate_baseline(destination / "monitoring_baseline.json")
    manifest = {
        "format_version": 1, "repository": repository, "branch": branch, "run_id": int(run_id),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": {p.name: {"sha256": _sha256(p), "bytes": p.stat().st_size} for p in sorted(destination.iterdir())},
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def restore_archive(payload, destination, *, repository, branch, run_id):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise StateError("Restore destination must be empty; existing state is never overwritten")
    with tempfile.TemporaryDirectory(prefix="intel-state-", dir=destination.parent) as temporary:
        staged = Path(temporary)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or not set(names) <= STATE_FILES | {"manifest.json"}:
                raise StateError("Unexpected or duplicate snapshot member")
            if not REQUIRED_FILES | {"manifest.json"} <= set(names):
                raise StateError("Snapshot is incomplete")
            if sum(item.file_size for item in archive.infolist()) > MAX_SNAPSHOT_BYTES:
                raise StateError("Expanded snapshot exceeds size limit")
            for name in names:
                (staged / name).write_bytes(archive.read(name))
        manifest = json.loads((staged / "manifest.json").read_text(encoding="utf-8"))
        if (manifest.get("format_version") != 1 or manifest.get("repository") != repository
                or manifest.get("branch") != branch or manifest.get("run_id") != int(run_id)):
            raise StateError("Snapshot provenance does not match this workflow run")
        files = manifest.get("files", {})
        if set(files) != set(names) - {"manifest.json"}:
            raise StateError("Snapshot manifest does not describe every file")
        for name, expected in files.items():
            path = staged / name
            if expected.get("bytes") != path.stat().st_size or expected.get("sha256") != _sha256(path):
                raise StateError("Snapshot checksum mismatch")
        validate_database(staged / "intelligence.db")
        validate_baseline(staged / "monitoring_baseline.json")
        for name in files:
            (staged / name).replace(destination / name)
    return manifest


def restore_latest(client, destination, *, workflow, branch, run_id, run_number, run_attempt=1,
                   bootstrap_release_tag=None, bootstrap_state_commit=None):
    """Use the newest completed writer; refuse to hide lost state or history."""
    if int(run_attempt) > 1:
        # Replaying an older run can overwrite newer state even when that older
        # run failed before collecting. A fresh dispatch always has a new run ID.
        raise StateError("Reruns cannot write collection state; dispatch a new run to preserve the latest history")
    saw_prior_run = False
    saw_prior_writer = False
    for run in client.runs(workflow, branch):
        if str(run["id"]) == str(run_id) or run.get("event") not in {"schedule", "workflow_dispatch"}:
            continue
        if run.get("head_branch") != branch:
            continue
        if run.get("run_number", 0) >= int(run_number):
            # GitHub concurrency does not guarantee run-number ordering. A
            # delayed older run must never overwrite a newer completed writer.
            later_artifacts = client.artifacts(run["id"])
            if (any(item.get("name") == ARTIFACT_PREFIX + str(run["id"]) for item in later_artifacts)
                    or client.collection_started(run["id"])):
                raise StateError("A newer run already collected; dispatch a fresh run instead of rolling back its history")
            continue
        saw_prior_run = True
        expected_name = ARTIFACT_PREFIX + str(run["id"])
        matching = [item for item in client.artifacts(run["id"]) if item.get("name") == expected_name]
        if matching:
            if len(matching) != 1 or matching[0].get("expired"):
                raise StateError("Latest collector snapshot expired or ambiguous; restore a backup before continuing")
            manifest = restore_archive(client.download(matching[0]["id"]), destination,
                                       repository=client.repository, branch=branch, run_id=run["id"])
            print(f"Restored public collection state from run {run['id']}; original timestamps preserved", flush=True)
            return manifest
        if client.collection_started(run["id"]):
            saw_prior_writer = True
            raise StateError("A previous collection started but its snapshot is missing; recover its state before continuing")
    if ((bootstrap_state_commit or bootstrap_release_tag) and not saw_prior_writer
            and (int(run_number) == 1 or saw_prior_run)):
        payload = (client.bootstrap_commit(bootstrap_state_commit) if bootstrap_state_commit
                   else client.bootstrap(bootstrap_release_tag))
        manifest = restore_archive(payload, destination,
                                   repository=client.repository, branch=branch, run_id=0)
        print("Restored initial deployment from same-repository seed; original first-seen/baselines preserved", flush=True)
        return manifest
    # Workflow run number remains >1 even when users delete its visible history.
    if saw_prior_run or int(run_number) != 1:
        raise StateError("No durable state found for an existing workflow; refusing to reset collection history")
    Path(destination).mkdir(parents=True, exist_ok=True)
    if any(Path(destination).iterdir()):
        raise StateError("Initial collection requires an empty state directory")
    print("First deployment: a new monitoring observation period starts now; historical SLA is not rewritten", flush=True)
    return None


def prune_states(client, *, workflow, branch, run_id, uploaded_artifact_id, keep=8):
    """Delete old snapshots only after verifying this run's new uploaded artifact."""
    if keep < 2:
        raise StateError("At least two state snapshots must be retained")
    current_name = ARTIFACT_PREFIX + str(run_id)
    current = [item for item in client.artifacts(int(run_id))
               if item.get("name") == current_name and str(item.get("id")) == str(uploaded_artifact_id)
               and not item.get("expired")]
    if len(current) != 1:
        raise StateError("Current uploaded snapshot is not confirmed; no old snapshots deleted")
    workflow_id = client.workflow_id(workflow)
    candidates = []
    for artifact in client.all_artifacts():
        name = artifact.get("name", "")
        if not name.startswith(ARTIFACT_PREFIX):
            continue
        suffix = name[len(ARTIFACT_PREFIX):]
        if not suffix.isdigit():
            continue
        candidate_run_id = int(suffix)
        if (artifact.get("workflow_run") or {}).get("id") != candidate_run_id:
            continue
        run = client.run(candidate_run_id)
        if (run.get("workflow_id") != workflow_id or run.get("head_branch") != branch
                or run.get("event") not in {"schedule", "workflow_dispatch"}):
            continue
        candidates.append((run["run_number"], artifact))
    # Do not perform partial cleanup before all metadata and the current state
    # have been verified. Other workflows, branches and release assets are excluded.
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    if not any(str(item["id"]) == str(uploaded_artifact_id) for _, item in candidates[:keep]):
        raise StateError("Uploaded snapshot is not among the retained trusted states; no cleanup performed")
    deleted = []
    for _, artifact in candidates[keep:]:
        client.delete_artifact(artifact["id"])
        deleted.append(artifact["id"])
    print(f"State cleanup: retained {min(keep, len(candidates))} trusted snapshots; deleted {len(deleted)} older snapshots", flush=True)
    return deleted


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("restore", "restore-file", "save", "prune"))
    parser.add_argument("--directory", required=True)
    parser.add_argument("--source")
    parser.add_argument("--archive")
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--branch", default=os.getenv("GITHUB_REF_NAME"))
    parser.add_argument("--run-id", default=os.getenv("GITHUB_RUN_ID"))
    parser.add_argument("--run-number", default=os.getenv("GITHUB_RUN_NUMBER"))
    parser.add_argument("--run-attempt", default=os.getenv("GITHUB_RUN_ATTEMPT", "1"))
    parser.add_argument("--uploaded-artifact-id")
    parser.add_argument("--keep", type=int, default=8)
    parser.add_argument("--workflow", default="intelligence-collect.yml")
    parser.add_argument("--bootstrap-release-tag", default=os.getenv("INTELLIGENCE_BOOTSTRAP_RELEASE_TAG"))
    parser.add_argument("--bootstrap-state-commit", default=os.getenv("INTELLIGENCE_BOOTSTRAP_STATE_COMMIT"))
    args = parser.parse_args(argv)
    if not args.repository or not args.branch or not args.run_id:
        parser.error("Repository, branch and run ID are required")
    try:
        if args.command == "save":
            if not args.source:
                parser.error("--source is required for save")
            save_state(args.source, args.directory, repository=args.repository, branch=args.branch, run_id=args.run_id)
            print("Public SQLite/history snapshot verified; no credentials or runtime files exported", flush=True)
        elif args.command == "restore-file":
            if not args.archive:
                parser.error("--archive is required for restore-file")
            path = Path(args.archive)
            if path.stat().st_size > MAX_SNAPSHOT_BYTES:
                raise StateError("Snapshot file exceeds size limit")
            restore_archive(path.read_bytes(), args.directory, repository=args.repository,
                            branch=args.branch, run_id=args.run_id)
            print("Local downloaded state restored; original timestamps preserved", flush=True)
        elif args.command == "restore":
            if not args.run_number:
                parser.error("--run-number is required for restore")
            client = GitHubClient(os.getenv("GITHUB_TOKEN"), args.repository, os.getenv("GITHUB_API_URL", "https://api.github.com"))
            restore_latest(client, args.directory, workflow=args.workflow, branch=args.branch,
                           run_id=args.run_id, run_number=args.run_number, run_attempt=args.run_attempt,
                           bootstrap_release_tag=args.bootstrap_release_tag,
                           bootstrap_state_commit=args.bootstrap_state_commit)
        else:
            if not args.uploaded_artifact_id:
                parser.error("--uploaded-artifact-id is required for prune")
            client = GitHubClient(os.getenv("GITHUB_TOKEN"), args.repository, os.getenv("GITHUB_API_URL", "https://api.github.com"))
            prune_states(client, workflow=args.workflow, branch=args.branch, run_id=args.run_id,
                         uploaded_artifact_id=args.uploaded_artifact_id, keep=args.keep)
    except (StateError, ValueError, KeyError, sqlite3.DatabaseError, zipfile.BadZipFile) as exc:
        # Do not expose remote response bodies or credential-bearing URLs.
        print(f"State persistence error: {exc}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
