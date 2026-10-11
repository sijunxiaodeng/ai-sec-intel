"""Deliver GitHub Actions snapshots to an isolated read-only deployment mirror.

Actions already upload ``intelligence-state-<run_id>`` artifacts. This module
is the missing deploy-side half:

* ``pull``  — download the latest trusted artifact via GitHub API and install it
* ``install-file`` — install a locally downloaded zip (same validation)
* ``push``  — POST a prepared snapshot directory/zip to a deploy ingest URL

Every entry point uses actions_mirror validation and an atomic current symlink.
Collector data is never overwritten; rollback and lost observation history fail closed.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

try:
    from .actions_state import GitHubClient, MAX_SNAPSHOT_BYTES, STATE_FILES, StateError
    from .actions_mirror import deliver_latest, install_snapshot, latest_snapshot
except ImportError:  # Direct script invocation.
    from actions_state import GitHubClient, MAX_SNAPSHOT_BYTES, STATE_FILES, StateError
    from actions_mirror import deliver_latest, install_snapshot, latest_snapshot

SYNC_MARKER = "actions_sync.json"
WORKFLOW_DEFAULT = "intelligence-collect.yml"


def find_latest_state(client: GitHubClient, *, workflow: str, branch: str):
    return latest_snapshot(client, workflow=workflow, branch=branch)


def install_archive(payload: bytes, destination: Path | str, *, repository: str,
                    branch: str, run_id: int, source: str = "pull") -> dict:
    """Publish a verified immutable generation; refuse collector directories."""
    return install_snapshot(payload, destination, repository=repository,
                            branch=branch, run_id=run_id, source=source)


def pull_latest(destination: Path | str, *, token: str, repository: str,
                branch: str = "main", workflow: str = WORKFLOW_DEFAULT,
                api_url: str = "https://api.github.com") -> dict:
    client = GitHubClient(token, repository, api_url=api_url)
    return deliver_latest(client, destination, workflow=workflow, branch=branch)


def zip_directory(directory: Path | str) -> bytes:
    directory = Path(directory)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.iterdir()):
            if path.is_file() and path.name in STATE_FILES | {"manifest.json"}:
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
    path = Path(destination) / "current" / "manifest.json"
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
    parser.add_argument("--directory", default=os.getenv("ACTIONS_SYNC_DIRECTORY") or "intelligence/actions-mirror")
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
    except (StateError, RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print("ERROR: %s" % exc, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
