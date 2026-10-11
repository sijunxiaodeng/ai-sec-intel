"""Reverse-proxy B intelligence API under the main :8023 process.

B stays a separate process (pydantic/FastAPI major versions differ), bound to
localhost :8765 by default. Users and smoke only need http://127.0.0.1:8023 —
paths /api/intelligence/* and GET /api/documents* are forwarded here.

Server-side collectors must call TEAM_INTEL_UPSTREAM (8765) directly, not this
proxy, to avoid single-worker self-request deadlocks.
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request

from fastapi import HTTPException, Request, Response

DEFAULT_UPSTREAM = "http://127.0.0.1:8765"


def team_intel_upstream() -> str:
    return (
        os.environ.get("TEAM_INTEL_UPSTREAM")
        or os.environ.get("TEAM_INTEL_BASE_URL")
        or DEFAULT_UPSTREAM
    ).rstrip("/")


def public_b_base(main_port: str | None = None) -> str:
    """URL users should use — always the main app port when proxy is enabled."""
    host = os.environ.get("APP_HOST", "127.0.0.1")
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    port = main_port or os.environ.get("APP_PORT", "8023")
    return "http://%s:%s" % (host, port)


def proxy_enabled() -> bool:
    return os.environ.get("TEAM_INTEL_PROXY", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def forward(request: Request, path: str) -> Response:
    """Forward request path (must start with /api/) to B upstream."""
    if not path.startswith("/"):
        path = "/" + path
    upstream = team_intel_upstream()
    query = request.url.query
    url = upstream + path + (("?" + query) if query else "")
    body = None
    # Starlette Request.body is async; callers use sync endpoint wrappers.
    try:
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "content-length", "transfer-encoding", "connection"}
        }
        headers.setdefault("User-Agent", "ai-sec-intel-b-proxy")
        method = request.method.upper()
        data = body
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read()
            out_headers = {}
            ctype = resp.headers.get("Content-Type")
            if ctype:
                out_headers["Content-Type"] = ctype
            return Response(content=payload, status_code=resp.status, headers=out_headers)
    except urllib.error.HTTPError as exc:
        payload = exc.read() if hasattr(exc, "read") else b""
        ctype = exc.headers.get("Content-Type") if exc.headers else None
        headers = {"Content-Type": ctype} if ctype else {}
        return Response(content=payload, status_code=exc.code, headers=headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(
            status_code=502,
            detail="团队情报服务暂不可达（经 8023 反代 → %s）：%s" % (upstream, exc),
        ) from exc


async def forward_async(request: Request, path: str) -> Response:
    upstream = team_intel_upstream()
    query = request.url.query
    url = upstream + path + (("?" + query) if query else "")
    body = await request.body()
    try:
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "content-length", "transfer-encoding", "connection"}
        }
        headers.setdefault("User-Agent", "ai-sec-intel-b-proxy")
        req = urllib.request.Request(
            url, data=body if body else None, headers=headers, method=request.method.upper()
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read()
            out_headers = {}
            ctype = resp.headers.get("Content-Type")
            if ctype:
                out_headers["Content-Type"] = ctype
            return Response(content=payload, status_code=resp.status, headers=out_headers)
    except urllib.error.HTTPError as exc:
        payload = exc.read() if hasattr(exc, "read") else b""
        ctype = exc.headers.get("Content-Type") if exc.headers else None
        headers = {"Content-Type": ctype} if ctype else {}
        return Response(content=payload, status_code=exc.code, headers=headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(
            status_code=502,
            detail="团队情报服务暂不可达（经 8023 反代 → %s）：%s" % (upstream, exc),
        ) from exc
