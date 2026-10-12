"""Embed B query routes using the shared FastAPI/Pydantic stack.

A's collectors package contains import/query adapters. B public collectors run
in their own subprocess to avoid overlapping top-level package names.
TEAM_INTEL_MODE=sidecar optionally queries the same B API over HTTP.
"""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEL_ROOT = ROOT / "intelligence"
DEFAULT_DB = INTEL_ROOT / "data" / "intelligence.db"

_b_app = None
_b_app_path = None
_PATH_LOCK = threading.RLock()


def team_intel_mode() -> str:
    """embed (default) | sidecar | off"""
    return os.environ.get("TEAM_INTEL_MODE", "embed").strip().lower()


def embed_enabled() -> bool:
    return team_intel_mode() in {"embed", "inprocess", "1", "true", "yes"}


def sidecar_enabled() -> bool:
    return team_intel_mode() in {"sidecar", "proxy", "http"}


def _purge_intelligence_collectors() -> None:
    """Drop collectors.* if they were loaded from intelligence/ (name clash)."""
    coll = sys.modules.get("collectors")
    if coll is None:
        return
    origin = (getattr(coll, "__file__", "") or "").replace("\\", "/")
    if "/intelligence/" not in origin and not origin.endswith("/intelligence/collectors/__init__.py"):
        # Also treat namespace packages whose path is under intelligence/
        paths = [str(p).replace("\\", "/") for p in (getattr(coll, "__path__", None) or [])]
        if not any("/intelligence/" in p for p in paths):
            return
    for key in list(sys.modules):
        if key == "collectors" or key.startswith("collectors."):
            sys.modules.pop(key, None)


def prefer_root_packages() -> None:
    """Keep ROOT before intelligence/ so A collectors.* import correctly."""
    with _PATH_LOCK:
        root = str(ROOT.resolve())
        intel = str(INTEL_ROOT.resolve())
        for path in (intel, root):
            while path in sys.path:
                sys.path.remove(path)
        sys.path.insert(0, root)
        sys.path.insert(1, intel)
        _purge_intelligence_collectors()
        os.environ.setdefault(
            "INTELLIGENCE_DB_PATH",
            str(Path(os.environ.get("INTELLIGENCE_DB_PATH") or DEFAULT_DB).absolute()),
        )


def ensure_intelligence_path() -> Path:
    """Ensure intelligence is importable without shadowing root collectors."""
    prefer_root_packages()
    return INTEL_ROOT


def db_path() -> Path:
    ensure_intelligence_path()
    target = Path(os.environ.get("INTELLIGENCE_DB_PATH") or DEFAULT_DB)
    if not target.is_absolute():
        target = INTEL_ROOT / target
    return target.absolute()


def get_b_app():
    """Lazy-create B FastAPI app inside this process."""
    global _b_app, _b_app_path
    target = db_path()
    with _PATH_LOCK:
        if _b_app is None or _b_app_path != target:
            ensure_intelligence_path()
            from api_v6.app import create_app
            _b_app = create_app(root=INTEL_ROOT, db_path=target)
            _b_app_path = target
        return _b_app


def _is_b_http_path(method: str, path: str) -> bool:
    if path == "/api/team/changes" or path.startswith("/api/intelligence"):
        return True
    # A owns POST /api/documents (CVE ingest). B owns GET document query APIs.
    if method == "GET" and (path == "/api/documents" or path.startswith("/api/documents/")):
        return True
    return False


class EmbedBMiddleware:
    """ASGI middleware: serve B routes from the in-process B app."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and embed_enabled():
            path = scope.get("path") or ""
            method = scope.get("method") or "GET"
            if _is_b_http_path(method, path):
                await get_b_app()(scope, receive, send)
                return
        await self.app(scope, receive, send)


def inprocess_health() -> dict:
    """Health for visibility / monitor status without HTTP to :8765."""
    prefer_root_packages()
    path = db_path()
    public = public_b_base()
    if not path.is_file():
        return {
            "reachable": False,
            "base_url": public,
            "public_base": public,
            "mode": "embed",
            "via_proxy": False,
            "database_available": False,
            "error": (
                "缺少 intelligence.db（%s）。请先执行："
                "配置正式 B 采集服务，或向独立 Actions 镜像交付数据，"
                "并将 INTELLIGENCE_DB_PATH 指向镜像的 current/intelligence.db"
            ) % path,
        }
    try:
        ensure_intelligence_path()
        from api_v6.repository import IntelligenceRepository
        from api_v6.document_repository import DocumentRepository
        repo = IntelligenceRepository(path, INTEL_ROOT)
        docs = DocumentRepository(path, INTEL_ROOT)
        repo.stats()
        return {
            "reachable": True,
            "base_url": public,
            "public_base": public,
            "mode": "embed",
            "via_proxy": False,
            "database_available": True,
            "knowledge_documents_available": bool(docs.available()),
        }
    except Exception as exc:
        return {
            "reachable": False,
            "base_url": public,
            "public_base": public,
            "mode": "embed",
            "via_proxy": False,
            "database_available": path.is_file(),
            "error": "%s: %s" % (type(exc).__name__, exc)[:160],
        }


def public_b_base(main_port: str | None = None) -> str:
    host = os.environ.get("APP_HOST", "127.0.0.1")
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    port = main_port or os.environ.get("APP_PORT", "8023")
    return "http://%s:%s" % (host, port)


def list_team_page(keyword: str = "", *, limit: int = 100, offset: int = 0, ai_only: bool = True) -> dict:
    """In-process equivalent of GET /api/intelligence/team."""
    ensure_intelligence_path()
    from api_v6.repository import IntelligenceRepository
    from api_v6.team_adapter import to_team_item

    repo = IntelligenceRepository(db_path(), INTEL_ROOT)
    result = repo.list_items(
        q=keyword or None,
        ai_related=True if ai_only else None,
        state="classified" if ai_only else None,
        limit=limit,
        offset=offset,
        full=True,
        include_raw=True,
    )
    result["items"] = [to_team_item(item) for item in result["items"]]
    return result


def list_documents_page(q: str = "", *, limit: int = 40, offset: int = 0) -> dict:
    """List B documents without reordering sys.path / purging collectors.

    Safe to call while ``b_monitor`` holds the intelligence import scope — we
    only ensure ``intelligence/`` is importable (append), never prefer it over
    root ``collectors.*``.
    """
    intel = str(INTEL_ROOT.resolve())
    if intel not in sys.path:
        sys.path.append(intel)
    from api_v6.document_repository import DocumentRepository

    path = Path(os.environ.get("INTELLIGENCE_DB_PATH") or DEFAULT_DB)
    if not path.is_absolute():
        path = INTEL_ROOT / path
    docs = DocumentRepository(path.absolute(), INTEL_ROOT)
    return docs.list_items(q=q or None, limit=limit, offset=offset, include_raw=False)


def list_changes_page(*, kind="cve", cursor=0, through=None, epoch=None, limit=100) -> dict:
    """Use the persistent B change feed without constructing a second ASGI app."""
    ensure_intelligence_path()
    from api_v6.repository import IntelligenceRepository
    from api_v6.change_repository import ChangeRepository

    return ChangeRepository(IntelligenceRepository(db_path(), INTEL_ROOT)).page(
        kind=kind, cursor=cursor, through=through, epoch=epoch, limit=limit)
