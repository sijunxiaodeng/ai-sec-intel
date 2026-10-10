import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from agents.conversation import sessions, SessionError

from agents.orchestrator import last_steps, run_answer, run_collect, run_enrich, run_documents
from automation.schedule import countable_latency, start as start_schedule, state as monitor_state
from config.llm import chat, configured
from config.settings import public_settings, save_settings
from rag.retrieve import get_record, knowledge_records
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


def _enrichment_field_coverage(records):
    """Operational field presence — not independent enrichment accuracy."""
    keys = ("cvss", "epss", "kev", "papers", "affected", "poc")
    counts = {k: 0 for k in keys}
    live = 0
    for record in records:
        item = record.get("item") or {}
        if (item.get("raw_data") or {}).get("sample_mode"):
            continue
        live += 1
        if record.get("cvss") or item.get("cvss"):
            counts["cvss"] += 1
        if record.get("epss") is not None or (item.get("epss") is not None):
            counts["epss"] += 1
        if record.get("kev") or item.get("kev"):
            counts["kev"] += 1
        if record.get("papers") or item.get("papers"):
            counts["papers"] += 1
        if record.get("affected") or item.get("affected"):
            counts["affected"] += 1
        if record.get("poc") or item.get("poc"):
            counts["poc"] += 1
    present = [k for k, n in counts.items() if n > 0]
    return {"live_items": live, "counts": counts, "present_dimensions": present, "dimension_count": len(present)}


def _build_visibility(records, names, monitor, library, team, latency_count, llm_ready):
    """Honest module board: duty / standards / integration. Never invent competition_passed."""
    from enrichment.assets import load_assets

    cov = (team or {}).get("coverage") or {}
    observed_cats = int(cov.get("observed_ai_category_count") or 0)
    lib_cats = len((library or {}).get("source_categories") or [])
    # Prefer B observed categories for source-breadth narrative; fall back to library categories.
    source_breadth = max(observed_cats, lib_cats, len(names or []))
    if source_breadth >= 7:
        source_level, source_note = "良好～优秀（演示）", "类别观测≥7；优秀「实时」有调度但 SLA 样本不足，非自动判竞赛分"
    elif source_breadth >= 5:
        source_level, source_note = "良好（演示）", "类别观测≥5；非 competition_passed"
    elif source_breadth >= 3:
        source_level, source_note = "合格（演示）", "类别观测≥3；非自动判竞赛分"
    elif source_breadth > 0:
        source_level, source_note = "缺口", "来源类别不足合格线（≥3）"
    else:
        source_level, source_note = "缺口", "尚无可用类别观测"

    if latency_count and latency_count > 0:
        latency_level, latency_note = "部分可计", f"可计时效样本 {latency_count}；间隔≠发布→采集延迟；新鲜度看 feed.freshness（近7/30天）"
    else:
        latency_level, latency_note = "未达证", "latency_count=0 / sla_evidence 不足；勿用定时间隔或 CVE 年份冒充发布→采集延迟；列表已按 published_at 排序仅改善观感"

    enrich_cov = _enrichment_field_coverage(records)
    dim_n = enrich_cov["dimension_count"]
    if dim_n >= 5:
        enrich_dim_level, enrich_dim_note = "良好（可演示）", f"字段维度 {dim_n}：{', '.join(enrich_cov['present_dimensions'])}；缺互联网资产发现与独立准确率"
    elif dim_n >= 3:
        enrich_dim_level, enrich_dim_note = "合格（可演示）", f"字段维度 {dim_n}；独立准确率仍为空"
    else:
        enrich_dim_level, enrich_dim_note = "缺口", f"字段维度仅 {dim_n}，低于合格线≥3"

    assets = load_assets() or []
    asset_n = len(assets) if isinstance(assets, list) else 0

    b_reachable = bool((team or {}).get("reachable"))
    b_status = "接通" if b_reachable else "不可达"
    try:
        from api.b_proxy import public_b_base, team_intel_upstream, proxy_enabled
        b_public = public_b_base()
        b_up = team_intel_upstream()
        if proxy_enabled():
            b_detail = "经 8023 反代 · %s/api/intelligence/* → %s" % (b_public, b_up)
        else:
            b_detail = (team or {}).get("base_url") or b_up
    except Exception:
        b_detail = (team or {}).get("base_url") or "未配置 TEAM_INTEL_UPSTREAM"
    if b_reachable:
        b_detail += f" · AI CVE {(team or {}).get('team_total') if (team or {}).get('team_total') is not None else '—'} · 文档 {(team or {}).get('document_total') if (team or {}).get('document_total') is not None else '—'}"
    elif (team or {}).get("error"):
        b_detail += f" · {(team or {}).get('error')}"

    c_local = "接通"  # C capabilities run in-process on A
    llm_status = "接通" if llm_ready else "未配置"
    docs_n = int((library or {}).get("documents") or 0)
    chunks_n = int((library or {}).get("chunks") or 0)

    if "缺口" in source_level and latency_level == "未达证":
        monitor_std_level = "缺口"
    elif latency_level == "未达证":
        monitor_std_level = "部分"
    else:
        monitor_std_level = source_level

    modules = [
        {
            "id": "monitor",
            "title": "自动监测",
            "position": "管线 01 · 入口情报流",
            "duty": "宽范围 AI 安全情报流（CVE + 非 CVE）；默认自动持续采集，关键词仅可选收窄。",
            "standard": {
                "level": monitor_std_level,
                "summary": f"来源类别 {source_level}；延迟 {latency_level}",
                "detail": f"{source_note}。{latency_note}",
                "honest": True,
            },
            "integration": {
                "owner": "A 编排 · monitor 角色",
                "peers": [
                    {"party": "A", "role": "调度 / feed / status", "status": "接通"},
                    {"party": "B", "role": "团队情报（经 8023）", "status": b_status, "detail": b_detail},
                    {"party": "C", "role": "不经监测入口", "status": "跳过"},
                ],
            },
            "signals": {
                "items": len(records),
                "last_run": (monitor or {}).get("last_run"),
                "running": bool((monitor or {}).get("running")),
                "mode": (monitor or {}).get("mode") or "automatic",
            },
        },
        {
            "id": "enrich",
            "title": "情报富集",
            "position": "管线 02 · 单条补维度",
            "duty": "对单条漏洞补 EPSS / KEV / 论文等，并评估影响资产（登记匹配，非互联网发现）。",
            "standard": {
                "level": enrich_dim_level,
                "summary": f"富化维度 {enrich_dim_level}；准确率 空",
                "detail": f"{enrich_dim_note}。independent_enrichment_accuracy=null；互联网资产定位未实现；PoC 可用性未验收。已登记资产 {asset_n}。",
                "honest": True,
            },
            "integration": {
                "owner": "A 编排 · enrich 角色",
                "peers": [
                    {"party": "A", "role": "编排触发 /api/enrich", "status": "接通"},
                    {"party": "B", "role": "监测上游输入", "status": "跳过", "detail": "富集读本地库，不直连 B"},
                    {"party": "C", "role": "assessment / assets", "status": c_local},
                ],
            },
            "signals": enrich_cov,
        },
        {
            "id": "library",
            "title": "资料库沉淀",
            "position": "管线 03 · 可检索原文",
            "duty": "沉淀可检索原文与片段；监测是流，这里是存档与问答底座。",
            "standard": {
                "level": "可演示" if docs_n >= 1 else "缺口",
                "summary": f"文档 {docs_n} · 片段 {chunks_n} · 类别 {lib_cats}",
                "detail": "快照级检索/资料绑定可跑；独立语义质量不由此绿。",
                "honest": True,
            },
            "integration": {
                "owner": "A 壳 · C 资料检索",
                "peers": [
                    {"party": "A", "role": "资料库页 / 同步触发", "status": "接通"},
                    {"party": "B", "role": "团队文档同步", "status": b_status if b_reachable else "不可达", "detail": "可选 team-sync"},
                    {"party": "C", "role": "library / chunks / RAG 底座", "status": c_local},
                ],
            },
            "signals": {"documents": docs_n, "chunks": chunks_n, "categories": (library or {}).get("source_categories") or []},
        },
        {
            "id": "ask",
            "title": "证据问答",
            "position": "管线 04 · 先证据后答",
            "duty": "先检索证据再组织回答；编号与分数须来自证据；verifier 核对。",
            "standard": {
                "level": "部分（开发验证）" if docs_n >= 1 else "缺口",
                "summary": "问答质量待独立验收；competition_passed=null",
                "detail": ("大模型未配置，当前走原文摘录。" if not llm_ready else "大模型已配置；独立问答准确率仍为空。")
                + " 规则/开发题可过，不冒充赛题得分。",
                "honest": True,
            },
            "integration": {
                "owner": "A 编排 · qa + verifier",
                "peers": [
                    {"party": "A", "role": "会话 / 核对角色壳", "status": "接通"},
                    {"party": "B", "role": "不直连问答", "status": "跳过"},
                    {"party": "C", "role": "检索 / 证据组装", "status": c_local},
                    {"party": "LLM", "role": "国产模型接口", "status": llm_status},
                ],
            },
            "signals": {"llm_ready": llm_ready},
        },
    ]

    standards = [
        {"id": "source_categories", "metric": "来源类别数", "level": source_level, "note": source_note},
        {"id": "enrichment_dimensions", "metric": "富化维度数", "level": enrich_dim_level, "note": enrich_dim_note},
        {"id": "latency", "metric": "发布→采集延迟", "level": latency_level, "note": latency_note},
        {"id": "enrichment_accuracy", "metric": "富化准确率", "level": "空", "note": "independent_enrichment_accuracy=null"},
        {"id": "qa_quality", "metric": "问答质量", "level": "部分（开发验证）" if docs_n >= 1 else "缺口", "note": "独立准确率 null；勿把规则测试当竞赛分"},
        {"id": "internet_assets", "metric": "互联网资产定位", "level": "未实现", "note": "仅登记/预览匹配"},
        {"id": "poc_verify", "metric": "PoC 可用验证", "level": "未验收", "note": "候选未正式验收"},
    ]

    integration = [
        {"party": "A", "name": "本平台编排壳", "status": "接通", "detail": "monitor·enrich·qa·verifier · 对外只开 :8023"},
        {"party": "B", "name": "团队情报（反代）", "status": b_status, "detail": b_detail},
        {"party": "C", "name": "富集/资料/检索（进程内）", "status": c_local, "detail": f"资料 {docs_n} 份 · 富化字段维度 {dim_n}"},
        {"party": "LLM", "name": "问答模型", "status": llm_status, "detail": "未配置则摘录原文" if not llm_ready else "已配置"},
    ]

    gaps = [row for row in standards if row["level"] in ("缺口", "未达证", "空", "未实现", "未验收") or "部分" in str(row["level"])]

    return {
        "policy": {
            "competition_passed": None,
            "note": "对照验收包/acceptance_criteria 的工程自评；不自动判定竞赛通过。禁止假绿。",
        },
        "modules": modules,
        "standards": standards,
        "integration": integration,
        "gaps": gaps,
    }


@app.get("/api/visibility")
def visibility():
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
    return _build_visibility(
        records, names, monitor,
        {"documents": library["documents"], "chunks": library["chunks"],
         "source_categories": library["source_categories"]},
        team, countable_latency(records), configured(),
    )


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
    lib = {"documents": library["documents"], "chunks": library["chunks"],
           "source_categories": library["source_categories"]}
    latency = countable_latency(records)
    llm_ready = configured()
    return {
        "project": "智能体驱动的 AI 安全知识情报系统",
        "items": len(records),
        "source_count": len(names),
        "sources": names,
        "latency_count": latency,
        "llm_ready": llm_ready,
        "monitor": monitor,
        "library": lib,
        "team_intel": team,
        "visibility": _build_visibility(records, names, monitor, lib, team, latency, llm_ready),
        "steps": last_steps(),
        "recent": [_summary(record) for record in records[:6]],
    }


def _text_match(needle: str, *parts: str) -> bool:
    """Simple case-insensitive substring match for list filters (not RAG search)."""
    text = (needle or "").strip().lower()
    if not text:
        return True
    blob = " ".join(str(part or "") for part in parts).lower()
    # Support comma-separated OR terms (user keyword boxes often use llm,vllm).
    terms = [t.strip() for t in text.split(",") if t.strip()]
    if not terms:
        return True
    return any(term in blob for term in terms)


def _filter_cve_records(q: str = ""):
    records = knowledge_records()
    if not (q or "").strip():
        return records
    out = []
    for record in records:
        item = record.get("item") or record
        if _text_match(
            q,
            item.get("cve_id"),
            item.get("title"),
            item.get("description"),
            item.get("product"),
            " ".join(item.get("affected") or []),
            " ".join(item.get("sources") or []) or item.get("source"),
        ):
            out.append(record)
    return out


@app.get("/api/items")
def items(q: str = ""):
    # List filter must be substring match — RAG search() returns empty for many keywords.
    records = _filter_cve_records(q)
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
    # Fetch broad list; apply local OR-substring filter so comma keywords don't empty the feed.
    query = urllib.parse.urlencode({"q": "", "limit": min(max(limit * 3, 40), 100), "offset": 0})
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
        if not _text_match(q, title, desc, category, row.get("source") or "", row.get("url") or ""):
            continue
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
        if len(out) >= limit:
            break
    return out, {"reachable": True, "total": payload.get("total", len(out))}


def _library_documents(q="", limit=40):
    from rag.library import documents as library_documents

    rows = library_documents()
    out = []
    for row in rows:
        title = row.get("title") or ""
        dtype = row.get("document_type") or ""
        if not _text_match(q, title, dtype, row.get("publisher") or "", row.get("url") or "", row.get("summary") or ""):
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
        # Use substring filter, not RAG search — otherwise keyword clicks look empty.
        records = _filter_cve_records(q)
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

    def _pub_ts(row):
        raw = (row.get("published_at") or "").strip()
        if not raw:
            return 0.0
        text = raw.replace("Z", "+00:00")
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(text)
            return dt.timestamp()
        except Exception:
            # Date-only YYYY-MM-DD
            try:
                from datetime import datetime, timezone
                return datetime.fromisoformat(raw[:10]).replace(tzinfo=timezone.utc).timestamp()
            except Exception:
                return 0.0

    def _freshness_bucket(ts, now_ts):
        if not ts:
            return "unknown"
        age_days = (now_ts - ts) / 86400.0
        if age_days <= 7:
            return "days_7"
        if age_days <= 30:
            return "days_30"
        return "older"

    from datetime import datetime, timezone
    now_ts = datetime.now(timezone.utc).timestamp()

    # Recency-first across CVE + docs. CVE-2025 id ≠ old intel; sort by published_at.
    # Demo/synthetic sinks after live items with the same timestamp.
    feed_items = cve_items + doc_items
    feed_items.sort(key=lambda row: (-_pub_ts(row), 1 if row.get("demo") else 0, row.get("cve_id") or row.get("title") or ""))

    freshness = {"days_7": 0, "days_30": 0, "older": 0, "unknown": 0, "demo": 0}
    for row in feed_items:
        if row.get("demo"):
            freshness["demo"] += 1
        bucket = _freshness_bucket(_pub_ts(row), now_ts)
        freshness[bucket] = freshness.get(bucket, 0) + 1
    freshness["as_of"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    freshness["note"] = "按 published_at 新→旧；CVE 编号年份≠发布时间；近7/30天=监测新鲜度口径"

    return {
        "kind": kind,
        "counts": {
            "cve": len(cve_items),
            "document": len(doc_items),
            "total": len(cve_items) + len(doc_items),
        },
        "freshness": freshness,
        "team_documents": team_meta,
        "items": feed_items,
        "sort": "published_at_desc",
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


def _team_reachable_probe():
    """Fast probe so UI can warn when B upstream is down without freezing."""
    import json
    import urllib.error
    import urllib.request

    from collectors.intelligence import team_base_url
    from api.b_proxy import public_b_base, proxy_enabled

    base = team_base_url()
    public = public_b_base() if proxy_enabled() else base
    try:
        with urllib.request.urlopen(base + "/api/intelligence/health", timeout=3) as resp:
            payload = json.load(resp)
        return {
            "reachable": True,
            "base_url": base,
            "public_base": public,
            "via_proxy": proxy_enabled(),
            "database_available": bool(payload.get("database_available")),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {
            "reachable": False,
            "base_url": base,
            "public_base": public,
            "via_proxy": proxy_enabled(),
            "error": str(exc)[:160],
        }


@app.get("/api/monitor/status")
def monitor_status():
    st = monitor_state()
    team = _team_reachable_probe()
    return {
        "mode": "automatic",
        "interval_hours": st.get("interval_hours"),
        "auto_on_start": st.get("auto_on_start"),
        "running": bool(st.get("running")),
        "last_run": st.get("last_run") or "",
        "last_count": st.get("last_count") or 0,
        "last_error": st.get("last_error") or "",
        "last_keyword": st.get("last_keyword") or "",
        "team": team,
        "notice": "默认持续自动监测宽范围 AI 安全情报；手动按钮仅用于立即刷新一轮。",
    }


@app.post("/api/monitor/run")
def monitor_run(body: MonitorRunBody):
    """Manual refresh of the automatic monitor cycle (broad AI-security by default)."""
    keyword = (body.keyword or "").strip() or AUTO_MONITOR_KEYWORDS
    team = _team_reachable_probe()
    warnings = []
    if not team.get("reachable"):
        warnings.append("团队情报服务暂不可达（8023 反代后端），已跳过 B 源；仍采集 NVD/OSV 并刷新本地资料流。")
    try:
        result = run_collect(keyword)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="自动监测没有完成：%s" % exc)
    try:
        from automation.schedule import mark_run
        mark_run(count=len(result["records"]), keyword=keyword)
    except Exception:
        pass
    library = None
    if body.sync_library:
        if not team.get("reachable"):
            library = {"status": "skipped", "error": "team unreachable"}
            warnings.append("已跳过团队资料同步。")
        else:
            try:
                from rag.library import sync_team
                library = sync_team(max_documents=body.max_documents)
            except ValueError as exc:
                library = {"status": "busy", "error": str(exc)}
            except Exception as exc:
                library = {"status": "error", "error": type(exc).__name__}
                warnings.append("团队资料同步失败，CVE/公开源结果仍已刷新。")
    steps = result.get("steps") or []
    team_failed = any("团队情报" in (s.get("action") or "") and "失败" in (s.get("action") or "")
                      for s in steps)
    if team_failed and "团队情报服务（:8765）暂不可达" not in " ".join(warnings):
        warnings.append("团队情报源本轮失败或跳过；NVD/OSV 与本地库仍继续。")

    def _step_status(name):
        for step in steps:
            action = step.get("action") or ""
            if name not in action:
                continue
            if "失败" in action:
                return {"status": "失败", "detail": (step.get("detail") or "")[:200]}
            if "跳过" in action:
                return {"status": "跳过", "detail": (step.get("detail") or "")[:200]}
            return {"status": "成功", "detail": (step.get("detail") or "")[:200]}
        return {"status": "未跑", "detail": ""}

    nvd = _step_status("NVD")
    osv = _step_status("OSV")
    b_step = _step_status("团队情报")
    if not team.get("reachable"):
        b_src = {"status": "不可达", "detail": team.get("error") or team.get("base_url") or ":8765"}
    elif b_step["status"] == "失败":
        b_src = b_step
    else:
        b_src = {"status": b_step["status"] if b_step["status"] != "未跑" else "接通",
                 "detail": b_step.get("detail") or team.get("base_url") or ""}
    if library is None:
        c_sync = {"status": "未请求", "detail": "sync_library=false"}
    elif isinstance(library, dict) and library.get("status") == "skipped":
        c_sync = {"status": "跳过", "detail": library.get("error") or "team unreachable"}
    elif isinstance(library, dict) and library.get("status") in {"error", "busy"}:
        c_sync = {"status": "失败", "detail": library.get("error") or library.get("status")}
    else:
        c_sync = {"status": "成功", "detail": "已尽力同步团队/公开资料到资料库"}

    source_diag = {
        "nvd": nvd,
        "osv": osv,
        "b_team": b_src,
        "c_library_sync": c_sync,
        "written": len(result["records"]),
    }
    return {
        "mode": "auto",
        "keyword": keyword,
        "count": len(result["records"]),
        "steps": steps,
        "library_sync": library,
        "team": team,
        "warnings": warnings,
        "source_diag": source_diag,
        "items": [_summary(record) for record in result["records"][:10]],
        "notice": "本轮按 AI 安全范围采集 CVE，并尽力同步非 CVE 资料；列表见 /api/monitor/feed。",
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


# --- B reverse proxy (single public port :8023) ---
# A keeps POST /api/documents for CVE-linked ingest; only GET document routes proxy to B.
from api.b_proxy import forward_async, proxy_enabled  # noqa: E402


if proxy_enabled():
    @app.api_route("/api/intelligence", methods=["GET", "HEAD", "OPTIONS"])
    async def _proxy_intelligence_root(request: Request):
        return await forward_async(request, "/api/intelligence")

    @app.api_route("/api/intelligence/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def _proxy_intelligence(path: str, request: Request):
        return await forward_async(request, "/api/intelligence/" + path)

    @app.get("/api/documents/stats")
    async def _proxy_documents_stats(request: Request):
        return await forward_async(request, "/api/documents/stats")

    @app.get("/api/documents/{document_id}")
    async def _proxy_documents_one(document_id: str, request: Request):
        return await forward_async(request, "/api/documents/" + document_id)

    @app.get("/api/documents")
    async def _proxy_documents_list(request: Request):
        return await forward_async(request, "/api/documents")


app.mount("/assets", StaticFiles(directory=WEB), name="assets")
