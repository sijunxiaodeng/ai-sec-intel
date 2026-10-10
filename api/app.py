import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from agents.conversation import sessions, SessionError

from agents.orchestrator import last_steps, run_answer, run_collect, run_enrich, run_documents
from automation.schedule import countable_latency, start as start_schedule, state as monitor_state
from config.llm import chat, configured
from config.settings import public_settings, save_settings
from rag.retrieve import get_record, knowledge_records, search
from enrichment.assets import AssetImport, AssetPreview, import_assets, load_assets, impact_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")

app = FastAPI(title="AI 安全知识情报")


@app.on_event("startup")
def _startup():
    start_schedule()


class CollectBody(BaseModel):
    # Broader AI-security default; comma-separated multi-keyword supported by monitor_agent.
    keyword: str = "llm"


class MonitorRunBody(BaseModel):
    """One-click auto monitor cycle. Empty keyword uses the built-in AI-security set."""
    keyword: str = ""
    sync_library: bool = True
    max_documents: int = Field(30, ge=1, le=200)


class AskBody(BaseModel):
    question: str = Field(..., max_length=4000)
    cve_id: str = Field("", regex=r"^(?:CVE-\d{4}-\d{4,7})?$", max_length=20)
    session_id: str = Field("", max_length=32)


class DocumentsBody(BaseModel):
    cve_id: str


class SettingsBody(BaseModel):
    base_url: str = ""
    model: str = ""
    api_key: str = ""


class LibrarySyncBody(BaseModel):
    per_source: int = Field(3, ge=1, le=8)
    include_seeds: bool = True


class TeamLibrarySyncBody(BaseModel):
    max_documents: int = Field(30, ge=1, le=200)


class LibraryAskBody(BaseModel):
    question: str = Field(..., min_length=1, max_length=4000)
    document_ids: list[str] = Field(default_factory=list, max_items=4)
    document_type: str = ""
    use_model: bool = True


class RelationCandidatesBody(BaseModel):
    topic: str = "model_supply_chain"
    document_ids: list[str] = Field(default_factory=list, max_items=4)
    use_model: bool = True


class RelationReviewBody(BaseModel):
    decision: str
    facet: str
    reviewer: str = Field(..., min_length=1, max_length=80)
    note: str = Field(..., min_length=10, max_length=1000)
    review_kind: str = "user_source_review"


def _summary(record):
    item = record.get("item") or {}
    cvss = record.get("cvss") or {}
    return {
        "cve_id": item.get("cve_id") or "",
        "title": item.get("title") or "",
        "description": item.get("description") or "",
        "source": item.get("source") or "",
        "url": item.get("url") or "",
        "published_at": item.get("published_at") or "",
        "collected_at": item.get("collected_at") or "",
        "product": item.get("product") or "",
        "sources": item.get("sources") or ([item.get("source")] if item.get("source") else []),
        "affected": item.get("affected") or [],
        "cvss": cvss.get("score"),
        "severity": cvss.get("severity"),
        "epss": record.get("epss"),
        "kev": record.get("kev"),
        "poc_count": len(record.get("poc") or []),
        "paper_count": len(record.get("papers") or []),
        "sample_mode": (item.get("raw_data") or {}).get("sample_mode"),
    }


def _team_intel_snapshot():
    """Best-effort B coverage / document stats for overview narrative (not a category claim)."""
    import json
    import urllib.error
    import urllib.request

    from collectors.intelligence import team_base_url

    base = team_base_url()
    out = {
        "reachable": False,
        "base_url": base,
        "database_available": None,
        "team_total": None,
        "document_total": None,
        "coverage": None,
        "error": None,
    }
    try:
        with urllib.request.urlopen(base + "/api/intelligence/health", timeout=3) as resp:
            health = json.load(resp)
        out["reachable"] = True
        out["database_available"] = bool(health.get("database_available"))
        out["knowledge_documents_available"] = bool(health.get("knowledge_documents_available"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        out["error"] = type(exc).__name__
        return out
    try:
        with urllib.request.urlopen(
            base + "/api/intelligence/team?q=&ai_only=true&limit=1", timeout=5
        ) as resp:
            team = json.load(resp)
        out["team_total"] = team.get("total")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    try:
        with urllib.request.urlopen(base + "/api/documents/stats", timeout=5) as resp:
            stats = json.load(resp)
        out["document_total"] = (
            stats.get("total_documents")
            or stats.get("total")
            or stats.get("documents")
        )
        cat_counts = stats.get("source_category_counts") or stats.get("source_record_counts")
        if isinstance(cat_counts, dict):
            out["document_categories"] = list(cat_counts.keys())
        elif isinstance(stats.get("categories"), list):
            out["document_categories"] = stats["categories"]
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    try:
        with urllib.request.urlopen(base + "/api/intelligence/coverage", timeout=5) as resp:
            cov = json.load(resp)
        out["coverage"] = {
            "configured_category_count": cov.get("configured_category_count"),
            "observed_ai_category_count": cov.get("observed_ai_category_count"),
            "observed_ai_categories": cov.get("observed_ai_categories"),
            "required_categories_observed": cov.get("required_categories_observed"),
            "sla_evidence": cov.get("sla_evidence"),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    return out


@app.get("/api/overview")
def overview():
    records = knowledge_records()
    names = []
    for record in records:
        if (record.get("item", {}).get("raw_data") or {}).get("sample_mode"):
            continue
        for name in (record.get("item") or {}).get("sources") or []:
            if name and name not in names:
                names.append(name)
    monitor = monitor_state()
    from rag.library import overview as library_overview
    library = library_overview()
    team = _team_intel_snapshot()
    return {
        "project": "智能体驱动的 AI 安全知识情报系统",
        "items": len(records),
        "source_count": len(names),
        "sources": names,
        "latency_count": countable_latency(records),
        "llm_ready": configured(),
        "monitor": monitor,
        "library": {"documents": library["documents"], "chunks": library["chunks"],
                    "source_categories": library["source_categories"]},
        "team_intel": team,
        "steps": last_steps(),
        "recent": [_summary(record) for record in records[:6]],
    }


@app.get("/api/items")
def items(q: str = ""):
    records = search(q, top_k=50) if q else knowledge_records()
    return {"items": [_summary(record) for record in records]}


_CATEGORY_LABELS = {
    "academic_paper": "学术论文",
    "security_blog": "安全博客",
    "security_community": "安全社区",
    "technical_standard": "技术标准",
    "policy_regulation": "政策法规",
    "vendor_advisory": "厂商公告",
    "government_alert": "政府告警",
    "vulnerability_database": "漏洞数据库",
    "academic": "学术",
    "policy": "政策",
    "research": "研究",
    "standard": "标准",
    "vendor": "厂商",
    "research_article": "研究文章",
    "vendor_guidance": "厂商指引",
}


def _fetch_team_documents(q="", limit=40):
    import json
    import urllib.error
    import urllib.parse
    import urllib.request

    from collectors.intelligence import team_base_url

    base = team_base_url()
    query = urllib.parse.urlencode({"q": q or "", "limit": min(limit, 100), "offset": 0})
    try:
        with urllib.request.urlopen(base + "/api/documents?" + query, timeout=8) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return [], {"reachable": False, "total": 0}
    rows = payload.get("items") or []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        category = row.get("source_category") or row.get("category") or ""
        title = row.get("title") or ""
        desc = row.get("description") or ""
        out.append({
            "kind": "document",
            "id": row.get("document_id") or row.get("id") or title,
            "document_id": row.get("document_id") or "",
            "title": title,
            "description": desc,
            "source": row.get("source") or "",
            "sources": [row.get("source")] if row.get("source") else [],
            "category": category,
            "category_label": _CATEGORY_LABELS.get(category, category or "资料"),
            "content_type": row.get("content_type") or "",
            "url": row.get("url") or "",
            "published_at": row.get("published_at") or row.get("first_seen_at") or "",
            "demo": bool((row.get("raw_data") or {}).get("demo_fixture"))
                or title.startswith("【演示】") or desc.startswith("演示用"),
            "origin": "team_documents",
        })
    return out, {"reachable": True, "total": payload.get("total", len(out))}


def _library_documents(q="", limit=40):
    from rag.library import documents as library_documents

    rows = library_documents()
    needle = (q or "").strip().lower()
    out = []
    for row in rows:
        title = row.get("title") or ""
        dtype = row.get("document_type") or ""
        blob = " ".join([title, dtype, row.get("publisher") or "", row.get("url") or ""]).lower()
        if needle and needle not in blob:
            continue
        out.append({
            "kind": "document",
            "id": row.get("document_id") or title,
            "document_id": row.get("document_id") or "",
            "title": title,
            "description": row.get("summary") or row.get("description") or "",
            "source": row.get("publisher") or row.get("source_id") or "",
            "sources": [row.get("publisher") or row.get("source_id") or "资料库"],
            "category": dtype,
            "category_label": _CATEGORY_LABELS.get(dtype, dtype or "资料"),
            "content_type": dtype,
            "url": row.get("url") or "",
            "published_at": row.get("published_at") or row.get("retrieved_at") or "",
            "demo": title.startswith("【演示】"),
            "origin": "library",
        })
        if len(out) >= limit:
            break
    return out


@app.get("/api/monitor/feed")
def monitor_feed(q: str = "", kind: str = "all"):
    """Monitor feed: CVE cards + non-CVE documents (B team docs + C library)."""
    kind = (kind or "all").strip().lower()
    if kind not in {"all", "cve", "document", "demo", "live"}:
        raise HTTPException(status_code=422, detail="kind 仅支持 all/cve/document/demo/live")

    cve_items = []
    if kind in {"all", "cve", "demo", "live"}:
        records = search(q, top_k=50) if q else knowledge_records()
        for record in records:
            summary = _summary(record)
            summary["kind"] = "cve"
            title = summary.get("title") or ""
            desc = summary.get("description") or ""
            summary["demo"] = bool(
                (summary.get("cve_id") or "").startswith("CVE-2099-")
                or title.startswith("【演示】")
                or "Demo offline" in (title + desc)
                or "合成" in (title + desc)
            )
            cve_items.append(summary)

    doc_items = []
    team_meta = {"reachable": False, "total": 0}
    if kind in {"all", "document", "demo", "live"}:
        team_docs, team_meta = _fetch_team_documents(q=q, limit=40)
        lib_docs = _library_documents(q=q, limit=40)
        # Prefer team docs; add library docs not already present by URL/title.
        seen = set()
        for row in team_docs + lib_docs:
            key = (row.get("url") or "") + "|" + (row.get("title") or "")
            if key in seen:
                continue
            seen.add(key)
            doc_items.append(row)

    if kind == "demo":
        cve_items = [row for row in cve_items if row.get("demo")]
        doc_items = [row for row in doc_items if row.get("demo")]
    elif kind == "live":
        cve_items = [row for row in cve_items if not row.get("demo")]
        doc_items = [row for row in doc_items if not row.get("demo")]
    elif kind == "cve":
        doc_items = []
    elif kind == "document":
        cve_items = []

    # Put non-CVE documents first on "all" so the monitor is not a CVE wall.
    if kind == "all":
        feed_items = doc_items + cve_items
    else:
        feed_items = cve_items + doc_items
    return {
        "kind": kind,
        "counts": {
            "cve": len(cve_items),
            "document": len(doc_items),
            "total": len(cve_items) + len(doc_items),
        },
        "team_documents": team_meta,
        "items": feed_items,
    }


@app.get("/api/items/{cve_id}")
def item_detail(cve_id: str):
    record = get_record(cve_id)
    if not record:
        raise HTTPException(status_code=404, detail="知识库里没有这条情报")
    payload = _summary(record)
    payload["references"] = record.get("references") or []
    payload["poc"] = record.get("poc") or []
    payload["papers"] = record.get("papers") or []
    payload["vector"] = (record.get("cvss") or {}).get("vector")
    payload["cvss_version"] = (record.get("cvss") or {}).get("version")
    from rag.ingest import document_status
    payload["documents"] = document_status(cve_id.upper())
    from enrichment.assessment import assess
    payload["assessment"] = (record["item"].get("raw_data") or {}).get("automatic_assessment") or assess(cve_id.upper())
    payload["related_guidance"] = (record["item"].get("raw_data") or {}).get("related_guidance")
    return payload


@app.get("/api/guidance/{cve_id}")
def related_guidance(cve_id: str):
    record = get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条漏洞")
    return record["item"].get("raw_data", {}).get("related_guidance") or {"status": "empty", "facets": {}, "evidence": []}


@app.post("/api/guidance/{cve_id}/refresh")
def refresh_guidance(cve_id: str):
    record = get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条漏洞")
    from enrichment.guidance import refresh
    return refresh(record)


@app.get("/api/assessment/{cve_id}")
def assessment(cve_id: str):
    record = get_record(cve_id)
    if not record:
        raise HTTPException(status_code=404, detail="知识库里没有这条情报")
    from enrichment.assessment import assess
    return (record["item"].get("raw_data") or {}).get("automatic_assessment") or assess(cve_id.upper())


def _asset_assessment(cve_id):
    record = get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="知识库里没有这条情报")
    from enrichment.assessment import assess
    return (record["item"].get("raw_data") or {}).get("automatic_assessment") or assess(cve_id.upper())


@app.get("/api/assets")
def assets():
    rows = load_assets()
    return {"items": rows, "count": len(rows), "demo_count": sum(bool(r.get("is_demo")) for r in rows)}


@app.post("/api/assets/import")
def assets_import(body: AssetImport):
    try:
        return import_assets(body.dict())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/assets/demo")
def assets_demo():
    import json
    with open(os.path.join(ROOT, "enrichment", "samples", "assets_demo.json"), encoding="utf-8") as stream:
        return json.load(stream)


@app.post("/api/assets/preview")
def assets_preview(body: AssetPreview):
    report = _asset_assessment(body.cve_id)
    return impact_report(report, [dict(r.dict(), inventory_source="preview") for r in body.assets], preview=True)


@app.get("/api/asset-impact/{cve_id}")
def asset_impact(cve_id: str):
    return impact_report(_asset_assessment(cve_id), load_assets())


# Built-in AI-security scope for one-click auto monitor (comma-separated).
AUTO_MONITOR_KEYWORDS = (
    "llm,vllm,langchain,huggingface,openai,ollama,adversarial,jailbreak,prompt injection"
)


@app.post("/api/monitor/run")
def monitor_run(body: MonitorRunBody):
    """One-click auto monitor: broad AI-security CVE collect + optional library team-sync."""
    keyword = (body.keyword or "").strip() or AUTO_MONITOR_KEYWORDS
    try:
        result = run_collect(keyword)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="自动监测没有完成：%s" % exc)
    library = None
    if body.sync_library:
        try:
            from rag.library import sync_team
            library = sync_team(max_documents=body.max_documents)
        except ValueError as exc:
            library = {"status": "busy", "error": str(exc)}
        except Exception as exc:
            library = {"status": "error", "error": type(exc).__name__}
    return {
        "mode": "auto",
        "keyword": keyword,
        "count": len(result["records"]),
        "steps": result["steps"],
        "library_sync": library,
        "items": [_summary(record) for record in result["records"][:10]],
        "notice": "本轮按 AI 安全范围采集 CVE，并尽力同步团队非 CVE 资料；列表见 /api/monitor/feed。",
    }


@app.post("/api/collect")
def collect(body: CollectBody):
    try:
        result = run_collect(body.keyword.strip() or AUTO_MONITOR_KEYWORDS)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="监测没有完成：%s" % exc)
    return {
        "count": len(result["records"]),
        "steps": result["steps"],
        "items": [_summary(record) for record in result["records"][:10]],
    }


@app.post("/api/enrich")
def enrich():
    try:
        result = run_enrich()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="富化没有完成：%s" % exc)
    return {"steps": result["steps"], "items": len(result["records"]), "documents": result["documents"]}


@app.post("/api/documents")
def documents(body: DocumentsBody):
    record = get_record(body.cve_id.strip().upper())
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条情报")
    return run_documents(record)


@app.get("/api/library")
def library_list(document_type: str = ""):
    from rag.library import DOCUMENT_TYPES, documents, overview
    if document_type and document_type not in DOCUMENT_TYPES:
        raise HTTPException(status_code=422, detail="未知资料类型")
    return {"items": documents(document_type=document_type), "overview": overview()}


@app.get("/api/library/search")
def library_search(q: str = "", document_type: str = "", cve_id: str = "", top_k: int = 8):
    from rag.library import search as search_library
    if len(q) > 4000:
        raise HTTPException(status_code=422, detail="检索内容过长")
    try:
        return search_library(q, top_k, document_type=document_type, cve_id=cve_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/library/sync")
def library_sync(body: LibrarySyncBody):
    from rag.library import sync
    try:
        return sync(per_source=body.per_source, include_seeds=body.include_seeds)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.post("/api/library/team-sync")
def library_team_sync(body: TeamLibrarySyncBody):
    from rag.library import sync_team
    try:
        return sync_team(max_documents=body.max_documents)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/api/library/{document_id}")
def library_detail(document_id: str):
    from rag.library import detail
    result = detail(document_id)
    if not result:
        raise HTTPException(status_code=404, detail="资料库里没有这份资料")
    return result


@app.post("/api/library/{document_id}/full-text")
def library_full_text(document_id: str):
    from rag.library import full_text
    try:
        return full_text(document_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/library/ask")
def library_ask(body: LibraryAskBody):
    from agents.library_qa import run
    try:
        return run(body.question, document_ids=body.document_ids, document_type=body.document_type, use_model=body.use_model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/library/analyze")
def library_analyze(body: LibraryAskBody):
    from agents.relations_qa import run
    try:
        return run(body.question, document_ids=body.document_ids, document_type=body.document_type, use_model=body.use_model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/library/relations/graph")
def library_relations_graph(topic: str = "indirect_prompt_injection"):
    from enrichment.relations import build_graph
    from enrichment.relation_candidates import reviewed_graph
    try:
        result = ({"topic": topic, "facts": [], "status": "reviewed_quotes_only"}
                  if topic == "article_relations" else build_graph(topic=topic))
        result["reviewed_quotes"] = reviewed_graph(topic=topic)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/library/relations/candidates")
def library_relation_candidates(topic: str = "model_supply_chain"):
    from enrichment.relation_candidates import list_candidates
    try:
        return list_candidates(topic=topic)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/library/relations/candidates")
def library_generate_candidates(body: RelationCandidatesBody):
    from enrichment.relation_candidates import generate
    try:
        return generate(topic=body.topic, document_ids=body.document_ids, use_model=body.use_model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/library/relations/candidates/{candidate_id}/review")
def library_review_candidate(candidate_id: str, body: RelationReviewBody):
    from enrichment.relation_candidates import review
    try:
        return review(candidate_id, **body.dict())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/ask")
def ask(body: AskBody):
    question = (body.question or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="请先写下问题")
    try:
        result = sessions.run(question, body.cve_id.strip(), body.session_id, run_answer)
    except SessionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {
        "answer": result["answer"],
        "session_id": result["session_id"],
        "turn": result["turn"],
        "context": result["context"],
        "history": result["history"],
        "used_model": result["used_model"],
        "model_attempted": bool(result.get("model_attempted", result["used_model"])),
        "verdict": {
            "passed": result["verdict"]["passed"],
            "notes": result["verdict"]["notes"],
        },
        "steps": result["steps"],
        "evidence": [_summary(record) for record in result["evidence"]],
        "evidence_chunks": [chunk for record in result["evidence"] for chunk in record.get("evidence_chunks") or []],
    }


@app.post("/api/sample")
def sample():
    from rag.prepare import prepare
    return prepare()  # 只载入人工历史样例；不下载模型、不运行采集。


@app.get("/api/settings")
def get_settings():
    return public_settings()


@app.put("/api/settings")
def put_settings(body: SettingsBody):
    save_settings(body.dict())
    return public_settings()


@app.post("/api/settings/test")
def test_settings():
    if not configured():
        raise HTTPException(status_code=400, detail="请先保存 API 地址、模型名和密钥")
    try:
        text = chat([
            {"role": "user", "content": "只回复：连接成功"},
        ], timeout=30)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="连接失败：%s" % exc)
    return {"ok": True, "reply": text[:80]}


@app.get("/")
def index():
    return FileResponse(os.path.join(WEB, "index.html"))


app.mount("/assets", StaticFiles(directory=WEB), name="assets")
