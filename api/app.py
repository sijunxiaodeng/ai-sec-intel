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
    keyword: str = "ollama"


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
    return {
        "project": "智能体驱动的 AI 安全知识情报系统",
        "items": len(records),
        "source_count": len(names),
        "sources": names,
        "latency_count": countable_latency(records),
        "llm_ready": configured(),
        "monitor": monitor,
        "steps": last_steps(),
        "recent": [_summary(record) for record in records[:6]],
    }


@app.get("/api/items")
def items(q: str = ""):
    records = search(q, top_k=50) if q else knowledge_records()
    return {"items": [_summary(record) for record in records]}


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
    return payload


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


@app.post("/api/collect")
def collect(body: CollectBody):
    try:
        result = run_collect(body.keyword.strip() or "ollama")
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
