"""Secure ingest of GitHub Actions intelligence snapshots into the deploy DB.

Owned by the main app (path ``/api/admin/actions-sync``) so EmbedBMiddleware
never intercepts it. Disabled unless ``ACTIONS_INGEST_TOKEN`` is configured.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/admin", tags=["actions-sync"])


def ingest_token() -> str:
    return (os.environ.get("ACTIONS_INGEST_TOKEN") or "").strip()


def ingest_enabled() -> bool:
    token = ingest_token()
    return len(token) >= 16


def data_directory() -> Path:
    from api.b_embed import DEFAULT_DB, db_path

    configured = os.environ.get("INTELLIGENCE_DATA_DIR", "").strip()
    if configured:
        return Path(configured).resolve()
    try:
        return db_path().parent
    except Exception:
        return DEFAULT_DB.parent


def _sync_module():
    from api.b_embed import ensure_intelligence_path

    ensure_intelligence_path()
    import deployment.actions_sync as sync

    return sync


def _authorize(authorization: str | None) -> None:
    expected = ingest_token()
    if not ingest_enabled():
        raise HTTPException(
            status_code=503,
            detail="Actions ingest disabled — set ACTIONS_INGEST_TOKEN (≥16 chars) on the deploy",
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=403, detail="Invalid ingest token")


@router.get("/actions-sync")
def actions_sync_status():
    """Public-ish status (no secrets). Shows last successful sync marker if any."""
    sync = _sync_module()
    marker = sync.read_sync_marker(data_directory()) or {}
    return {
        "enabled": ingest_enabled(),
        "data_dir": str(data_directory()),
        "synced": bool(marker.get("run_id")),
        "last_sync": marker or None,
    }


@router.post("/actions-sync")
async def actions_sync_ingest(
    request: Request,
    authorization: str | None = Header(default=None),
    x_actions_repository: str | None = Header(default=None),
    x_actions_branch: str | None = Header(default=None),
    x_actions_run_id: str | None = Header(default=None),
):
    _authorize(authorization)
    repository = (x_actions_repository or "").strip()
    branch = (x_actions_branch or "").strip() or "main"
    run_id_raw = (x_actions_run_id or "").strip()
    if not repository or "/" not in repository or not run_id_raw.isdigit():
        raise HTTPException(
            status_code=422,
            detail="X-Actions-Repository, X-Actions-Branch, X-Actions-Run-Id headers required",
        )
    body = await request.body()
    if not body:
        raise HTTPException(status_code=422, detail="Empty snapshot body")
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type and content_type not in {"application/zip", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="Content-Type must be application/zip")

    sync = _sync_module()
    try:
        marker = sync.install_archive(
            body,
            data_directory(),
            repository=repository,
            branch=branch,
            run_id=int(run_id_raw),
            source="deploy-ingest",
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Snapshot rejected: %s" % exc) from None

    return JSONResponse(
        {
            "ok": True,
            "installed": marker,
            "notice": "多源库已替换为 Actions 快照；若进程内连接仍缓存旧句柄，请重启主应用以彻底切换。",
            "restart_recommended": True,
        }
    )


def maybe_pull_on_startup() -> dict | None:
    """Optional boot pull when ACTIONS_SYNC_ON_START=1 and a GitHub token is set."""
    flag = os.environ.get("ACTIONS_SYNC_ON_START", "").strip().lower()
    if flag not in {"1", "true", "yes", "on"}:
        return None
    token = (
        os.environ.get("ACTIONS_SYNC_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or ""
    ).strip()
    repository = (
        os.environ.get("ACTIONS_SYNC_REPOSITORY")
        or os.environ.get("GITHUB_REPOSITORY")
        or "sijunxiaodeng/ai-sec-intel"
    ).strip()
    branch = (os.environ.get("ACTIONS_SYNC_BRANCH") or "main").strip()
    if not token:
        return {"status": "skipped", "error": "no GitHub token for Actions pull"}
    sync = _sync_module()
    try:
        marker = sync.pull_latest(
            data_directory(),
            token=token,
            repository=repository,
            branch=branch,
        )
        return {"status": "ok", "marker": marker}
    except Exception as exc:
        return {"status": "error", "error": "%s: %s" % (type(exc).__name__, exc)[:240]}
