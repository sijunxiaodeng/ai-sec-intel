import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agents.orchestrator import last_steps, run_answer, run_collect, run_enrich
from automation.schedule import countable_latency, start as start_schedule, state as monitor_state
from config.llm import chat, configured
from config.settings import public_settings, save_settings
from database.store import get_record, load_kb
from rag.retrieve import search

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")

app = FastAPI(title="AI 安全知识情报")


@app.on_event("startup")
def _startup():
    start_schedule()


class CollectBody(BaseModel):
    keyword: str = "ollama"


class AskBody(BaseModel):
    question: str
    cve_id: str = ""


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
    }


@app.get("/api/overview")
def overview():
    records = load_kb()
    names = []
    for record in records:
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
    records = search(q, top_k=50) if q else load_kb()
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
    return payload


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
    return {"steps": result["steps"], "items": len(result["records"])}


@app.post("/api/ask")
def ask(body: AskBody):
    question = (body.question or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="请先写下问题")
    result = run_answer(question, body.cve_id.strip())
    return {
        "answer": result["answer"],
        "used_model": result["used_model"],
        "verdict": {
            "passed": result["verdict"]["passed"],
            "notes": result["verdict"]["notes"],
        },
        "steps": result["steps"],
        "evidence": [_summary(record) for record in result["evidence"]],
    }


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
