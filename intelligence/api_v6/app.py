"""Local-only FastAPI adapter for the B module's existing intelligence.db."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .repository import CVE_PATTERN, IntelligenceRepository, current_classifier_version

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
FilterState = Literal["classified", "review", "pending_llm", "retry", "unclassified_or_stale"]
SortKey = Literal["updated", "published", "cvss"]


def _public_status(path: Path, kind: str) -> dict:
    if not path.is_file():
        return {"available": False, "status": "not_found"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("status file is not an object")
        result = {
            "available": True,
            "status": payload.get("status") or "unknown",
            "started_at": payload.get("started_at"),
            "finished_at": payload.get("finished_at"),
        }
        if kind == "monitoring":
            result["pending_windows"] = payload.get("pending_windows")
            result["source_summary_complete"] = payload.get("source_summary_complete")
            result["source_counts"] = {
                name: {key: data.get(key) for key in ("fetched", "inserted", "updated", "unchanged")}
                for name, data in (payload.get("sources") or {}).items()
                if isinstance(data, dict)
            }
        else:
            result["worker"] = payload.get("worker")
            result["classifier_version"] = payload.get("classifier_version")
            stats = payload.get("stats") or {}
            result["summary"] = {
                key: stats.get(key) for key in
                ("selected", "classified", "positive", "semantic_calls", "semantic_success", "retry")
            }
        return result
    except (OSError, ValueError, TypeError):
        return {"available": False, "status": "invalid_status_file"}


def create_app(root: Path | None = None, db_path: Path | None = None) -> FastAPI:
    root = Path(root or DEFAULT_ROOT).resolve()
    target = Path(db_path or os.getenv("INTELLIGENCE_DB_PATH") or root / "data" / "intelligence.db")
    if not target.is_absolute():
        target = root / target
    repo = IntelligenceRepository(target, root)

    app = FastAPI(
        title="AI Security Intelligence · B Module Query API",
        description=("只读查询 B 模块已融合的 CVE 和已完成的 AI 相关性分类。"
                     "不会启动采集、调用 DeepSeek、修改 SQLite。"),
        version="6.0.0",
    )
    origins = os.getenv("INTEL_API_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:3000,http://localhost:3000")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in origins.split(",") if origin.strip()],
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Content-Type"],
    )

    def handle_db_error(exc: Exception):
        if isinstance(exc, (FileNotFoundError, sqlite3.Error)):
            raise HTTPException(status_code=503, detail="本地 SQLite 暂不可用，请检查数据库路径和采集状态") from exc
        raise exc

    @app.get("/", tags=["API 信息"])
    def welcome():
        return {"service": "B-module intelligence query API", "version": "V6", "docs": "/docs"}

    @app.get("/api/intelligence", tags=["情报查询"])
    def list_intelligence(
        q: str | None = Query(default=None, max_length=120, description="搜索 CVE、标题、描述、厂商、产品"),
        source: str | None = Query(default=None, max_length=40, description="NVD / CISA_KEV / GITHUB_ADVISORY"),
        ai_related: bool | None = Query(default=None, description="只查已有有效分类的 AI / 非 AI 漏洞"),
        category: str | None = Query(default=None, max_length=80),
        state: FilterState | None = Query(default=None),
        sort: SortKey = Query(default="updated"),
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
    ):
        try:
            return repo.list_items(q=q, source=source, ai_related=ai_related,
                                   category=category, state=state, sort=sort,
                                   limit=limit, offset=offset)
        except (FileNotFoundError, sqlite3.Error) as exc:
            handle_db_error(exc)

    @app.get("/api/intelligence/stats", tags=["统计与健康"])
    def statistics():
        try:
            return repo.stats()
        except (FileNotFoundError, sqlite3.Error) as exc:
            handle_db_error(exc)

    @app.get("/api/intelligence/ai", tags=["情报查询"])
    def ai_intelligence(
        q: str | None = Query(default=None, max_length=120),
        source: str | None = Query(default=None, max_length=40),
        category: str | None = Query(default=None, max_length=80),
        sort: SortKey = Query(default="updated"),
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
    ):
        try:
            return repo.list_items(q=q, source=source, ai_related=True,
                                   category=category, limit=limit, offset=offset,
                                   sort=sort)
        except (FileNotFoundError, sqlite3.Error) as exc:
            handle_db_error(exc)

    @app.get("/api/intelligence/health", tags=["统计与健康"])
    def health():
        present = repo.db_path.is_file()
        response = {
            "service": "intelligence-query-v6",
            "database_available": present,
            "classifier_version": current_classifier_version(root),
            "monitoring": _public_status(root / "data" / "monitoring_status.json", "monitoring"),
            "classification": _public_status(root / "data" / "classification_status.json", "classification"),
            "latest_collectors": [],
        }
        if present:
            try:
                response["latest_collectors"] = repo.recent_collectors()
            except sqlite3.Error:
                response["database_available"] = False
                response["database_note"] = "数据库存在但查询失败"
        return response

    @app.get("/api/intelligence/{cve_id}", tags=["情报查询"])
    def detail(cve_id: str, include_raw: bool = Query(default=False, description="是否包含各来源原始响应")):
        if not CVE_PATTERN.fullmatch(cve_id):
            raise HTTPException(status_code=422, detail="CVE 编号格式应为 CVE-YYYY-NNNN...")
        try:
            item = repo.one(cve_id.upper(), include_raw=include_raw)
        except (FileNotFoundError, sqlite3.Error) as exc:
            handle_db_error(exc)
        if item is None:
            raise HTTPException(status_code=404, detail="CVE 不存在")
        return item

    return app


app = create_app()
