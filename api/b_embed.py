"""Embed B's query API in the A process (real unification, not a forever-sidecar).

Conflict fact: root pins fastapi==0.95.2 / pydantic==1.10; intelligence.lock
pins fastapi 0.143 / pydantic 2.x. We do NOT upgrade the whole A stack here.
Empirically `intelligence/api_v6.create_app()` loads and serves under the root
venv — so we ASGI-dispatch B routes in-process and call B repositories from
IntelligenceCollector. Optional TEAM_INTEL_MODE=sidecar keeps the old :8765 path.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEL_ROOT = ROOT / "intelligence"
DEFAULT_DB = INTEL_ROOT / "data" / "intelligence.db"

_b_app = None


def team_intel_mode() -> str:
    """embed (default) | sidecar | off"""
    return os.environ.get("TEAM_INTEL_MODE", "embed").strip().lower()


def embed_enabled() -> bool:
    return team_intel_mode() in {"embed", "inprocess", "1", "true", "yes"}


def sidecar_enabled() -> bool:
    return team_intel_mode() in {"sidecar", "proxy", "http"}


def ensure_intelligence_path() -> Path:
    path = str(INTEL_ROOT.resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    os.environ.setdefault("INTELLIGENCE_DB_PATH", str(Path(
        os.environ.get("INTELLIGENCE_DB_PATH") or DEFAULT_DB
    ).resolve()))
    return INTEL_ROOT


def db_path() -> Path:
    ensure_intelligence_path()
    target = Path(os.environ.get("INTELLIGENCE_DB_PATH") or DEFAULT_DB)
    if not target.is_absolute():
        target = INTEL_ROOT / target
    return target.resolve()


def get_b_app():
    """Lazy-create B FastAPI app inside this process."""
    global _b_app
    if _b_app is None:
        ensure_intelligence_path()
        from api_v6.app import create_app
        _b_app = create_app(root=INTEL_ROOT, db_path=db_path())
    return _b_app


def _is_b_http_path(method: str, path: str) -> bool:
    if path.startswith("/api/intelligence"):
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
            "error": "intelligence.db missing — run seed or B monitor",
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
    ensure_intelligence_path()
    from api_v6.document_repository import DocumentRepository

    docs = DocumentRepository(db_path(), INTEL_ROOT)
    return docs.list_items(q=q or None, limit=limit, offset=offset, include_raw=False)
