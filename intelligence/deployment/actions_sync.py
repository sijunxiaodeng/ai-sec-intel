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
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from .actions_state import GitHubClient, MAX_SNAPSHOT_BYTES, STATE_FILES, StateError
    from .actions_mirror import deliver_latest, install_snapshot, latest_snapshot
except ImportError:  # Direct script invocation.
    from actions_state import GitHubClient, MAX_SNAPSHOT_BYTES, STATE_FILES, StateError
    from actions_mirror import deliver_latest, install_snapshot, latest_snapshot

SYNC_MARKER = "actions_sync.json"
WORKFLOW_DEFAULT = "intelligence-collect.yml"
DELIVERY_STATUS = "delivery_status.json"
MAX_RESPONSE_BYTES = 64 * 1024


def _manifest(payload, *, repository, branch, run_id):
    """Bind the receipt to the outgoing generation, not only an HTTP status."""
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise StateError("Snapshot exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        if archive.namelist().count("manifest.json") != 1:
            raise StateError("Snapshot must contain one manifest")
        info = archive.getinfo("manifest.json")
        if info.file_size > MAX_RESPONSE_BYTES:
            raise StateError("Snapshot manifest exceeds size limit")
        manifest = json.loads(archive.read(info))
    if (not isinstance(manifest, dict) or manifest.get("repository") != repository
            or manifest.get("branch") != branch or manifest.get("run_id") != int(run_id)
            or manifest.get("workflow") != WORKFLOW_DEFAULT
            or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("collector_commit", "")))
            or type(manifest.get("run_number")) is not int or manifest["run_number"] <= 0):
        raise StateError("Snapshot manifest does not match the requested delivery")
    return manifest


def _endpoint(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
    except ValueError:
        raise StateError("Deploy ingest URL is invalid") from None
    # Remote credentials must use TLS. HTTP loopback is useful for local checks.
    local = hostname in {"localhost", "127.0.0.1", "::1"}
    if (not hostname or any(ord(char) < 33 or ord(char) == 127 for char in url)
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.scheme not in {"http", "https"} or (parsed.scheme == "http" and not local)):
        raise StateError("Deploy ingest URL must use HTTPS without URL credentials or query parameters")
    endpoint = url.rstrip("/")
    return endpoint if endpoint.endswith("/api/admin/actions-sync") else endpoint + "/api/admin/actions-sync"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        # A redirected request must never carry the deploy bearer token elsewhere.
        return None


def _receipt(body, manifest):
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise StateError("Deploy ingest returned an invalid JSON receipt") from None
    installed = data.get("installed") if isinstance(data, dict) else None
    lineage = ("repository", "branch", "run_id", "run_number", "collector_commit", "workflow")
    if (not isinstance(data, dict) or data.get("ok") is not True or not isinstance(installed, dict)
            or type(installed.get("changed")) is not bool
            or any(installed.get(key) != manifest.get(key) for key in lineage)
            or type(installed.get("run_id")) is not int
            or type(installed.get("run_number")) is not int):
        raise StateError("Deploy ingest receipt does not confirm the outgoing generation")
    # Do not print server response bodies, paths, or user-supplied extra fields.
    return {"ok": True, "installed": {key: installed[key] for key in lineage},
            "changed": installed["changed"], "consumer_verified": False}


def record_delivery(path, *, run_id, status, reason_category, receipt=None):
    """Persist only this run's sanitized delivery facts outside the snapshot."""
    facts = {"run_id": str(run_id), "status": status, "reason_category": reason_category,
             "recorded_at": datetime.now(timezone.utc).isoformat(),
             "pull_status": "unverified", "consumer_status": "unverified"}
    if receipt:
        facts["installed"] = receipt["installed"]
        facts["changed"] = receipt["changed"]
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return facts


def delivery_status(path, *, run_id, configured, push_outcome, upload_outcome):
    """Disabled push and absent pull evidence are distinct from verified delivery."""
    if not configured:
        return record_delivery(path, run_id=run_id, status="disabled", reason_category="missing_ingest_configuration")
    if upload_outcome != "success":
        return record_delivery(path, run_id=run_id, status="blocked", reason_category="snapshot_not_uploaded")
    try:
        target = Path(path)
        if target.is_symlink() or target.stat().st_size > MAX_RESPONSE_BYTES:
            raise ValueError("Invalid delivery status")
        facts = json.loads(target.read_text(encoding="utf-8"))
        if (str(facts.get("run_id")) == str(run_id) and facts.get("status") == "verified"
                and push_outcome == "success"):
            return facts
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return record_delivery(path, run_id=run_id, status="failed" if push_outcome == "failure" else "unknown",
                           reason_category="ingest_not_verified")


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
    manifest = _manifest(payload, repository=repository, branch=branch, run_id=run_id)
    endpoint = _endpoint(url)
    if not token or len(token.strip()) < 16 or any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise StateError("Deploy ingest token must contain at least 16 characters")
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
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise StateError("Deploy ingest failed: HTTP %s" % exc.code) from None
    except (OSError, urllib.error.URLError):
        raise StateError("Deploy ingest unreachable") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise StateError("Deploy ingest receipt exceeds size limit")
    return _receipt(body, manifest)


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
    parser.add_argument("command", choices=("pull", "install-file", "push", "status", "delivery-status"))
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
    parser.add_argument("--status-file", default=os.getenv("DELIVERY_STATUS_FILE"))
    args = parser.parse_args(argv)

    try:
        if args.command == "delivery-status":
            if not args.run_id or not args.status_file:
                raise StateError("--run-id and --status-file are required for delivery status")
            facts = delivery_status(args.status_file, run_id=args.run_id,
                                    configured=os.getenv("DEPLOY_INGEST_CONFIGURED") == "true",
                                    push_outcome=os.getenv("PUSH_OUTCOME", "unknown"),
                                    upload_outcome=os.getenv("UPLOAD_OUTCOME", "unknown"))
            print("::notice title=Actions delivery::push=%s pull=unverified consumer=unverified" % facts["status"], flush=True)
            return 0
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
        if args.status_file:
            record_delivery(args.status_file, run_id=args.run_id, status="verified",
                            reason_category="installed_receipt_verified", receipt=result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (StateError, RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
        if args.command == "push" and args.status_file and args.run_id:
            record_delivery(args.status_file, run_id=args.run_id, status="failed", reason_category="ingest_not_verified")
        print("ERROR: %s" % exc, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
