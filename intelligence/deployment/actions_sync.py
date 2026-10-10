"""Bridge GitHub Actions collection snapshots into a running deploy/demo DB.

Actions already upload ``intelligence-state-<run_id>`` artifacts. This module
is the missing deploy-side half:

* ``pull``  — download the latest trusted artifact via GitHub API and install it
* ``install-file`` — install a locally downloaded zip (same validation)
* ``push``  — POST a prepared snapshot directory/zip to a deploy ingest URL

Install replaces only the allowlisted state files under the data directory; it
does not wipe unrelated runtime files. Checksums and provenance match
``actions_state.restore_archive``.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from deployment.actions_state import (
        ARTIFACT_PREFIX,
        GitHubClient,
        MAX_SNAPSHOT_BYTES,
        REQUIRED_FILES,
        STATE_FILES,
        StateError,
        _sha256,
        validate_baseline,
        validate_database,
    )
except ImportError:  # running as a sibling module under intelligence/deployment
    from actions_state import (  # type: ignore
        ARTIFACT_PREFIX,
        GitHubClient,
        MAX_SNAPSHOT_BYTES,
        REQUIRED_FILES,
        STATE_FILES,
        StateError,
        _sha256,
        validate_baseline,
        validate_database,
    )

SYNC_MARKER = "actions_sync.json"
WORKFLOW_DEFAULT = "intelligence-collect.yml"


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_latest_state(client: GitHubClient, *, workflow: str, branch: str):
    """Return (run, artifact) for the newest non-expired collector snapshot."""
    for run in client.runs(workflow, branch):
        if run.get("head_branch") != branch:
            continue
        if run.get("event") not in {"schedule", "workflow_dispatch"}:
            continue
        expected = ARTIFACT_PREFIX + str(run["id"])
        matching = [
            item
            for item in client.artifacts(run["id"])
            if item.get("name") == expected and not item.get("expired")
        ]
        if not matching:
            continue
        if len(matching) != 1:
            raise StateError("Latest collector snapshot is ambiguous; refusing to pull")
        return run, matching[0]
    raise StateError("No durable Actions snapshot found to pull")


def _stage_archive(payload: bytes, *, repository: str, branch: str, run_id: int) -> tuple[Path, dict, tempfile.TemporaryDirectory]:
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise StateError("Snapshot exceeds size limit")
    temporary = tempfile.TemporaryDirectory(prefix="intel-sync-")
    staged = Path(temporary.name)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not set(names) <= STATE_FILES | {"manifest.json"}:
            temporary.cleanup()
            raise StateError("Unexpected or duplicate snapshot member")
        if not REQUIRED_FILES | {"manifest.json"} <= set(names):
            temporary.cleanup()
            raise StateError("Snapshot is incomplete")
        if sum(item.file_size for item in archive.infolist()) > MAX_SNAPSHOT_BYTES:
            temporary.cleanup()
            raise StateError("Expanded snapshot exceeds size limit")
        for name in names:
            (staged / name).write_bytes(archive.read(name))
    try:
        manifest = json.loads((staged / "manifest.json").read_text(encoding="utf-8"))
        if (
            manifest.get("format_version") != 1
            or manifest.get("repository") != repository
            or manifest.get("branch") != branch
            or int(manifest.get("run_id")) != int(run_id)
        ):
            raise StateError("Snapshot provenance does not match expected repository/branch/run")
        files = manifest.get("files") or {}
        if set(files) != set(names) - {"manifest.json"}:
            raise StateError("Snapshot manifest does not describe every file")
        for name, expected in files.items():
            path = staged / name
            if expected.get("bytes") != path.stat().st_size or expected.get("sha256") != _sha256(path):
                raise StateError("Snapshot checksum mismatch")
        validate_database(staged / "intelligence.db")
        validate_baseline(staged / "monitoring_baseline.json")
    except Exception:
        temporary.cleanup()
        raise
    return staged, manifest, temporary


def install_archive(
    payload: bytes,
    destination: Path | str,
    *,
    repository: str,
    branch: str,
    run_id: int,
    source: str = "pull",
) -> dict:
    """Validate zip and replace allowlisted state files in ``destination``."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    staged, manifest, temporary = _stage_archive(
        payload, repository=repository, branch=branch, run_id=run_id
    )
    try:
        backup_root = destination / (".actions-sync-backup-%s" % int(time.time()))
        backed = []
        for name in list(STATE_FILES) + ["manifest.json"]:
            current = destination / name
            if current.is_file() or current.is_symlink():
                backup_root.mkdir(parents=True, exist_ok=True)
                shutil.move(str(current), str(backup_root / name))
                backed.append(name)
        # Drop SQLite sidecars so the process cannot reopen a stale WAL.
        for side in ("intelligence.db-wal", "intelligence.db-shm"):
            side_path = destination / side
            if side_path.exists():
                side_path.unlink()
        installed = []
        for name in sorted(p.name for p in staged.iterdir()):
            shutil.copy2(staged / name, destination / name)
            installed.append(name)
        marker = {
            "synced_at": _utc_now(),
            "source": source,
            "repository": repository,
            "branch": branch,
            "run_id": int(run_id),
            "artifact_prefix": ARTIFACT_PREFIX,
            "files": installed,
            "backup": str(backup_root.name) if backed else None,
            "manifest_created_at": manifest.get("created_at"),
        }
        (destination / SYNC_MARKER).write_text(
            json.dumps(marker, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        return marker
    finally:
        temporary.cleanup()


def pull_latest(
    destination: Path | str,
    *,
    token: str,
    repository: str,
    branch: str = "main",
    workflow: str = WORKFLOW_DEFAULT,
    api_url: str = "https://api.github.com",
) -> dict:
    client = GitHubClient(token, repository, api_url=api_url)
    run, artifact = find_latest_state(client, workflow=workflow, branch=branch)
    payload = client.download(artifact["id"])
    marker = install_archive(
        payload,
        destination,
        repository=repository,
        branch=branch,
        run_id=int(run["id"]),
        source="github-artifact",
    )
    marker["artifact_id"] = artifact["id"]
    marker["artifact_name"] = artifact.get("name")
    marker["workflow_run_url"] = run.get("html_url")
    return marker


def zip_directory(directory: Path | str) -> bytes:
    directory = Path(directory)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.iterdir()):
            if path.is_file() and not path.name.startswith("."):
                archive.write(path, arcname=path.name)
    return buffer.getvalue()


def push_snapshot(
    *,
    url: str,
    token: str,
    repository: str,
    branch: str,
    run_id: int,
    directory: Path | str | None = None,
    archive: Path | str | None = None,
    timeout: int = 120,
) -> dict:
    if bool(directory) == bool(archive):
        raise StateError("Provide exactly one of --directory or --archive for push")
    if directory:
        payload = zip_directory(directory)
    else:
        path = Path(archive)
        payload = path.read_bytes()
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise StateError("Snapshot file exceeds size limit")
    endpoint = url.rstrip("/")
    if not endpoint.endswith("/api/admin/actions-sync"):
        endpoint = endpoint + "/api/admin/actions-sync"
    request = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": "Bearer %s" % token,
            "Content-Type": "application/zip",
            "X-Actions-Repository": repository,
            "X-Actions-Branch": branch,
            "X-Actions-Run-Id": str(int(run_id)),
            "User-Agent": "ai-sec-intel-actions-sync",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:400].decode("utf-8", "replace")
        raise StateError("Deploy ingest failed: HTTP %s %s" % (exc.code, detail)) from None
    except (OSError, urllib.error.URLError) as exc:
        raise StateError("Deploy ingest unreachable: %s" % exc) from None
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        return {"ok": True, "raw": body[:200].decode("utf-8", "replace")}


def read_sync_marker(destination: Path | str) -> dict | None:
    path = Path(destination) / SYNC_MARKER
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("pull", "install-file", "push", "status"))
    parser.add_argument("--directory", default=os.getenv("INTELLIGENCE_DATA_DIR") or "intelligence/data")
    parser.add_argument("--archive")
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY") or "sijunxiaodeng/ai-sec-intel")
    parser.add_argument("--branch", default=os.getenv("ACTIONS_SYNC_BRANCH") or "main")
    parser.add_argument("--run-id", default=os.getenv("GITHUB_RUN_ID"))
    parser.add_argument("--workflow", default=WORKFLOW_DEFAULT)
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or os.getenv("ACTIONS_SYNC_TOKEN"))
    parser.add_argument("--url", default=os.getenv("DEPLOY_INGEST_URL"))
    parser.add_argument("--ingest-token", default=os.getenv("DEPLOY_INGEST_TOKEN") or os.getenv("ACTIONS_INGEST_TOKEN"))
    parser.add_argument("--api-url", default=os.getenv("GITHUB_API_URL") or "https://api.github.com")
    args = parser.parse_args(argv)

    try:
        if args.command == "status":
            marker = read_sync_marker(args.directory) or {}
            print(json.dumps(marker or {"synced": False}, ensure_ascii=False, indent=2))
            return 0
        if args.command == "pull":
            if not args.token:
                raise StateError("GITHUB_TOKEN / GH_TOKEN / ACTIONS_SYNC_TOKEN required for pull")
            marker = pull_latest(
                args.directory,
                token=args.token,
                repository=args.repository,
                branch=args.branch,
                workflow=args.workflow,
                api_url=args.api_url,
            )
            print(json.dumps(marker, ensure_ascii=False, indent=2))
            print("Actions snapshot installed into %s" % args.directory, flush=True)
            return 0
        if args.command == "install-file":
            if not args.archive or not args.run_id:
                raise StateError("--archive and --run-id are required for install-file")
            payload = Path(args.archive).read_bytes()
            marker = install_archive(
                payload,
                args.directory,
                repository=args.repository,
                branch=args.branch,
                run_id=int(args.run_id),
                source="local-file",
            )
            print(json.dumps(marker, ensure_ascii=False, indent=2))
            return 0
        if not args.url or not args.ingest_token:
            raise StateError("DEPLOY_INGEST_URL and DEPLOY_INGEST_TOKEN required for push")
        if not args.run_id:
            raise StateError("--run-id is required for push")
        result = push_snapshot(
            url=args.url,
            token=args.ingest_token,
            repository=args.repository,
            branch=args.branch,
            run_id=int(args.run_id),
            directory=args.directory if not args.archive else None,
            archive=args.archive,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except StateError as exc:
        print("ERROR: %s" % exc, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
