import os
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictBool, StrictStr
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

from api.ui_version import web_version, versioned_html
WEB_VERSION = web_version(WEB)


@app.middleware("http")
async def fresh_ui_responses(request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif path.startswith("/assets/"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


@app.get("/api/version")
def client_version():
    return {"web_version": WEB_VERSION, "display_timezone": "Asia/Shanghai"}


@app.get("/api/admin/actions-consumption", tags=["actions-sync"])
def actions_consumption_status():
    from api.delivery_status import consumption_status
    return consumption_status()


@app.on_event("startup")
def _startup():
    # Optional: pull latest Actions intelligence snapshot before the monitor loop.
    try:
        from api.actions_ingest import maybe_pull_on_startup

        result = maybe_pull_on_startup()
        if result and result.get("status") == "ok":
            print("Actions sync on start: installed run_id=%s" % (
                (result.get("marker") or {}).get("run_id"),
            ), flush=True)
        elif result and result.get("status") == "error":
            print("Actions sync on start failed: %s" % result.get("error"), flush=True)
    except Exception as exc:
        print("Actions sync on start skipped: %s" % exc, flush=True)
    start_schedule()
    from automation.model_review import start as start_model_review
    start_model_review()
    from acceptance.worker import start as start_acceptance_observer
    start_acceptance_observer()
    from automation.asset_matching import start as start_asset_matching
    start_asset_matching()


@app.on_event("shutdown")
def _shutdown():
    from automation.schedule import stop
    stop()
    from automation.model_review import stop as stop_model_review
    stop_model_review()
    from acceptance.worker import stop as stop_acceptance_observer
    stop_acceptance_observer()
    from automation.asset_matching import stop as stop_asset_matching
    stop_asset_matching()


class CollectBody(BaseModel):
    # Keywords filter the displayed feed; synchronization always covers all valid AI records.
    keyword: str = "llm"


class MonitorRunBody(BaseModel):
    """One-click auto monitor cycle. Empty keyword uses the built-in AI-security set."""
    keyword: str = ""
    sync_library: bool = True
    max_documents: int = Field(30, ge=1, le=200)


class AskBody(BaseModel):
    question: str = Field(..., max_length=4000)
    cve_id: str = Field("", pattern=r"^(?:CVE-\d{4}-\d{4,7})?$", max_length=20)
    session_id: str = Field("", max_length=32)


class DocumentsBody(BaseModel):
    cve_id: str


class SettingsBody(BaseModel):
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    model_reasoning_effort: Literal["", "none", "low", "medium", "high"] = ""
    model_review_enabled: bool = False
    model_review_max_calls: int = Field(2, ge=0, le=10)
    model_review_daily_max_calls: int = Field(20, ge=0, le=1000)
    model_review_interval_seconds: int = Field(60, ge=30, le=3600)
    model_review_timeout_seconds: int = Field(90, ge=5, le=300)
    reasoning_budget_seconds: int = Field(30, ge=5, le=180)


class LibrarySyncBody(BaseModel):
    per_source: int = Field(3, ge=1, le=8)
    include_seeds: bool = True


class TeamLibrarySyncBody(BaseModel):
    max_documents: int = Field(30, ge=1, le=200)


class LibraryAskBody(BaseModel):
    question: str = Field(..., min_length=1, max_length=4000)
    document_ids: list[str] = Field(default_factory=list, max_length=4)
    document_type: str = ""
    use_model: bool = True
    mode: Literal["excerpts", "reasoning"] = "excerpts"


class RelationCandidatesBody(BaseModel):
    topic: str = "model_supply_chain"
    document_ids: list[str] = Field(default_factory=list, max_length=4)
    use_model: bool = True


class RelationReviewBody(BaseModel):
    decision: str
    facet: str
    reviewer: str = Field(..., min_length=1, max_length=80)
    note: str = Field(..., min_length=10, max_length=1000)
    review_kind: str = "user_source_review"


class AssetObservationBody(BaseModel):
    provider: Literal["shodan", "fofa"]
    content: StrictStr = Field(..., min_length=1, max_length=1024 * 1024)
    fields: list[StrictStr] = Field(default_factory=list, max_length=20)
    is_demo: StrictBool = False

    class Config:
        extra = "forbid"


class AssetObservationPreviewBody(AssetObservationBody):
    cve_id: str = Field("", pattern=r"^(?:CVE-\d{4}-\d{4,7})?$", max_length=20)


class PoCCodeCollectBody(BaseModel):
    class Config:
        extra = "forbid"


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

    from collectors.intelligence import team_intel_disabled
    if team_intel_disabled():
        return {"status": "skipped", "mode": "off", "enabled": False, "reachable": False,
                "base_url": "", "public_base": "", "via_proxy": False,
                "database_available": None, "knowledge_documents_available": None,
                "team_total": None, "document_total": None, "coverage": None}

    from api.b_embed import embed_enabled, inprocess_health, list_team_page, public_b_base

    if embed_enabled():
        health = inprocess_health()
        out = {
            "reachable": bool(health.get("reachable")),
            "base_url": health.get("public_base") or public_b_base(),
            "public_base": health.get("public_base") or public_b_base(),
            "mode": "embed",
            "via_proxy": False,
            "database_available": health.get("database_available"),
            "knowledge_documents_available": health.get("knowledge_documents_available"),
            "team_total": None,
            "document_total": None,
            "coverage": None,
            "error": health.get("error"),
        }
        if not out["reachable"]:
            return out
        try:
            out["team_total"] = list_team_page("", limit=1, ai_only=True).get("total")
        except Exception:
            pass
        try:
            from api.b_embed import ensure_intelligence_path, db_path, INTEL_ROOT
            ensure_intelligence_path()
            from api_v6.document_repository import DocumentRepository
            from api_v6.repository import IntelligenceRepository, current_classifier_version
            from monitoring.coverage import coverage_report
            from monitoring.source_registry import get_sources

            docs = DocumentRepository(db_path(), INTEL_ROOT)
            stats = docs.stats()
            out["document_total"] = stats.get("total_documents")
            cat_counts = stats.get("source_category_counts") or stats.get("source_record_counts")
            if isinstance(cat_counts, dict):
                out["document_categories"] = list(cat_counts.keys())
            repo = IntelligenceRepository(db_path(), INTEL_ROOT)
            with repo.read() as con:
                cov = coverage_report(
                    con, get_sources(),
                    poll_minutes=15, source_timeout_seconds=120, worker_count=4,
                    classifier_version=current_classifier_version(INTEL_ROOT),
                )
            out["coverage"] = {
                "configured_category_count": cov.get("configured_category_count"),
                "observed_ai_category_count": cov.get("observed_ai_category_count"),
                "observed_ai_categories": cov.get("observed_ai_categories"),
                "required_categories_observed": cov.get("required_categories_observed"),
                "sla_evidence": cov.get("sla_evidence"),
                "live_precise_samples": cov.get("live_precise_samples"),
                "violations_ge_6h": cov.get("violations_ge_6h"),
                "unknown_live_timing": cov.get("unknown_live_timing"),
            }
        except Exception as exc:
            out["error"] = "%s: %s" % (type(exc).__name__, exc)[:160]
        return out

    from collectors.intelligence import team_base_url

    base = team_base_url()
    out = {
        "reachable": False,
        "base_url": base,
        "public_base": public_b_base(),
        "mode": "sidecar",
        "via_proxy": True,
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
            "live_precise_samples": cov.get("live_precise_samples"),
            "violations_ge_6h": cov.get("violations_ge_6h"),
            "unknown_live_timing": cov.get("unknown_live_timing"),
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
    from api.visibility_metrics import category_observation, latency_observation
    source_breadth, category_basis = category_observation(cov, library or {})
    lib_cats = category_observation({}, library or {})[0]
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
    source_note += "；统计依据：" + category_basis

    latency_count, latency_basis = latency_observation(cov, latency_count)
    if latency_count and latency_count > 0:
        latency_level, latency_note = "部分可计", f"可计时效样本 {latency_count}；间隔≠发布→采集延迟；新鲜度看 feed.freshness（近7/30天）"
    else:
        latency_level, latency_note = "未达证", "latency_count=0 / sla_evidence 不足；勿用定时间隔或 CVE 年份冒充发布→采集延迟；列表已按 published_at 排序仅改善观感"
    latency_note += "；统计依据：" + latency_basis
    if cov.get("sla_evidence") == "breached":
        latency_level = "存在超时样本"
        latency_note += "；B 严格监测口径存在 ≥6 小时样本，不能认定全部达标"

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
    b_status = "已禁用" if (team or {}).get("enabled") is False else "接通" if b_reachable else "不可达"
    try:
        from api.b_embed import embed_enabled, public_b_base, sidecar_enabled
        from api.b_proxy import team_intel_upstream
        b_public = public_b_base()
        if embed_enabled() or (team or {}).get("mode") == "embed":
            b_detail = "同进程嵌入 · %s/api/intelligence/*（无需 :8765）" % b_public
        elif sidecar_enabled():
            b_detail = "遗留 sidecar · %s/api/intelligence/* → %s" % (b_public, team_intel_upstream())
        else:
            b_detail = (team or {}).get("base_url") or "TEAM_INTEL_MODE=off"
    except Exception:
        b_detail = (team or {}).get("base_url") or "未配置 TEAM_INTEL_MODE"
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
                    {"party": "B", "role": "多源情报（同进程）", "status": b_status, "detail": b_detail},
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
            "duty": "对单条漏洞补 EPSS / KEV / 论文等，筛选登记清单与平台观测；真实互联网发现待验收。",
            "standard": {
                "level": enrich_dim_level,
                "summary": f"富化维度 {enrich_dim_level}；准确率 空",
                "detail": f"{enrich_dim_note}。independent_enrichment_accuracy=null；被动观测导入已实现，真实互联网发现待验收；PoC 可用性未验收。已登记资产 {asset_n}。",
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
            "title": "资料存档",
            "position": "管线 03 · 可检索原文",
            "duty": "存档可检索原文与片段；监测是流，这里是资料存档与问答底座。来源仍是论文/博客/厂商等，不是「资料库沉淀」。",
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
                    {"party": "B", "role": "多源文档同步", "status": b_status, "detail": "可选 team-sync"},
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
        {"id": "internet_assets", "metric": "互联网资产定位", "level": "部分（导入流程）", "note": "登记/平台观测范围筛选；真实互联网发现待验收"},
        {"id": "poc_verify", "metric": "PoC 可用验证", "level": "部分（静态审查）", "note": "固定代码来源及开发审查已实现；运行可用性未验收"},
    ]

    integration = [
        {"party": "A", "name": "本平台编排壳", "status": "接通", "detail": "monitor·enrich·qa·verifier"},
        {"party": "B", "name": "多源情报（同进程嵌入）", "status": b_status, "detail": b_detail},
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


def _observed_item_source_names(records):
    """Distinct origin labels already present on knowledge-store cards.

    This is not the product source registry: CVE cards often only carry
    NVD/OSV/GitHub/CISA even when many more collectors are configured.
    """
    names = []
    for record in records:
        if (record.get("item", {}).get("raw_data") or {}).get("sample_mode"):
            continue
        for name in (record.get("item") or {}).get("sources") or []:
            if name and name not in names:
                names.append(name)
    return names


def _registered_source_catalog():
    """Enabled SourceSpec entries from the multi-source registry (real origins).

    Returns name list + category count. Never invents sources; empty on load failure.
    Product「来源」must use this catalog — not library ingest paths, not card tags alone.
    """
    try:
        from api.b_embed import ensure_intelligence_path
        ensure_intelligence_path()
        from monitoring.source_registry import get_sources
        specs = list(get_sources() or [])
    except Exception:
        return {
            "sources": [],
            "source_count": 0,
            "source_category_count": 0,
            "source_categories": [],
            "source_basis": "source_registry_unavailable",
            "registered_sources": [],
        }
    names = [spec.name for spec in specs if getattr(spec, "name", None)]
    categories = sorted({
        spec.category for spec in specs
        if isinstance(getattr(spec, "category", None), str) and spec.category
    })
    registered = [{
        "name": spec.name,
        "category": spec.category,
        "kind": spec.kind,
    } for spec in specs]
    return {
        "sources": names,
        "source_count": len(names),
        "source_category_count": len(categories),
        "source_categories": categories,
        "source_basis": "source_registry",
        "registered_sources": registered,
    }


@app.get("/api/visibility")
def visibility():
    records = knowledge_records()
    observed = _observed_item_source_names(records)
    catalog = _registered_source_catalog()
    # Prefer registry names for module board honesty; fall back to observed tags.
    names = catalog["sources"] or observed
    monitor = monitor_state()
    from rag.library import overview as library_overview
    library = library_overview()
    team = _team_intel_snapshot()
    board = _build_visibility(
        records, names, monitor,
        {"documents": library["documents"], "chunks": library["chunks"],
         "source_categories": library["source_categories"]},
        team, countable_latency(records), configured(),
    )
    board["source_registry"] = {
        "source_count": catalog["source_count"],
        "sources": catalog["sources"],
        "source_category_count": catalog["source_category_count"],
        "source_categories": catalog["source_categories"],
        "source_basis": catalog["source_basis"],
        "observed_source_count": len(observed),
        "observed_sources": observed,
    }
    return board


@app.get("/api/overview")
def overview():
    records = knowledge_records()
    observed = _observed_item_source_names(records)
    catalog = _registered_source_catalog()
    # Homepage「来源」= registered real origins (NVD/OSV/GitHub/…), not card-tag subset.
    names = catalog["sources"] or observed
    monitor = monitor_state()
    from rag.library import overview as library_overview
    library = library_overview()
    team = _team_intel_snapshot()
    lib = {"documents": library["documents"], "chunks": library["chunks"],
           "source_categories": library["source_categories"]}
    from api.visibility_metrics import latency_observation
    root_latency = countable_latency(records)
    latency, latency_basis = latency_observation((team or {}).get("coverage") or {}, root_latency)
    llm_ready = configured()
    return {
        "project": "智能体驱动的 AI 安全知识情报系统",
        "offline_demo": os.environ.get("OFFLINE_DEMO") == "1",
        "items": len(records),
        "source_count": len(names),
        "sources": names,
        "source_basis": catalog["source_basis"] if catalog["sources"] else "observed_item_tags",
        "source_category_count": catalog["source_category_count"],
        "registered_sources": catalog["registered_sources"],
        "observed_source_count": len(observed),
        "observed_sources": observed,
        "latency_count": latency,
        "latency_count_basis": latency_basis,
        "root_latency_count": root_latency,
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


from api.feed_mix import diversify_cves_by_product as _diversify_cves_by_product
from api.feed_mix import diversify_documents as _diversify_documents
from api.feed_mix import feed_composition as _feed_composition
from api.feed_mix import interleave_feed as _interleave_feed


def _fetch_team_documents(q="", limit=48):
    """List multi-source documents for the monitor feed.

    Embed mode must read the in-process DB — never HTTP :8765 (that false-fails
    after demo-up seed when no sidecar is running).

    The embed branch reads B repositories directly. Only the sidecar branch
    imports the root HTTP adapter. B collectors run in a private process and
    never replace A's ``collectors`` package.
    """
    import json
    import urllib.error
    import urllib.parse
    import urllib.request

    from collectors.intelligence import team_intel_disabled
    if team_intel_disabled():
        return [], {"status": "skipped", "mode": "off", "enabled": False,
                    "reachable": False, "total": None}

    from api.b_embed import embed_enabled, list_documents_page, prefer_root_packages

    # B's HTTP contract caps document pages at 100 in both deployment modes.
    page_limit = min(max(limit * 3, 60), 100)
    try:
        if embed_enabled():
            # list_documents_page reads api_v6 repos; avoids collectors.* clash.
            payload = list_documents_page("", limit=page_limit, offset=0)
        else:
            prefer_root_packages()
            from collectors.intelligence import team_base_url

            base = team_base_url()
            query = urllib.parse.urlencode({"q": "", "limit": page_limit, "offset": 0})
            with urllib.request.urlopen(base + "/api/documents?" + query, timeout=8) as resp:
                payload = json.load(resp)
    except Exception as exc:
        return [], {
            "reachable": False,
            "total": 0,
            "error": "%s: %s" % (type(exc).__name__, exc)[:160],
            "mode": "embed" if embed_enabled() else "sidecar",
        }
    if not isinstance(payload, dict):
        return [], {"reachable": False, "total": 0, "error": "invalid documents payload"}
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
        origin_name = _document_origin_name({
            "publisher": row.get("source") or "",
            "source": row.get("source") or "",
            "discovery_source_id": row.get("source") or "",
            "document_type": category or row.get("content_type") or "",
            "source_category": category,
        })
        out.append({
            "kind": "document",
            "id": row.get("document_id") or row.get("id") or title,
            "document_id": row.get("document_id") or "",
            "title": title,
            "description": desc,
            "source": origin_name,
            "sources": [origin_name] if origin_name else [],
            "category": category,
            "category_label": _CATEGORY_LABELS.get(category, category or "资料"),
            "content_type": row.get("content_type") or "",
            "url": row.get("url") or "",
            "published_at": row.get("published_at") or row.get("first_seen_at") or "",
            "demo": bool((row.get("raw_data") or {}).get("demo_fixture"))
                or title.startswith("【演示】") or desc.startswith("演示用"),
            "origin": "team_documents",  # ingest path, not product 来源
            "ingest_path": "multisource_db",
        })
        if len(out) >= limit:
            break
    return out, {
        "reachable": True,
        "total": payload.get("total", len(out)),
        "mode": "embed" if embed_enabled() else "sidecar",
    }


_INGEST_PATH_LABELS = frozenset({
    "资料库", "资料存档", "资料库沉淀", "资料沉淀", "本地资料库沉淀",
    "library", "team_documents", "多源情报资料", "多源情报", "聚合库",
})

_DISCOVERY_SOURCE_LABELS = {
    "arxiv": "arXiv",
    "arxiv_full_text": "arXiv",
    "arxiv_ai_security": "arXiv",
    "trail_of_bits": "Trail of Bits",
    "trail_of_bits_blog": "Trail of Bits",
    "hf_security_community": "Hugging Face",
    "huggingface": "Hugging Face",
    "vllm_vendor": "vLLM",
    "ollama_vendor": "Ollama",
    "langchain_vendor": "LangChain",
    "nist_csrc_ai_standards": "NIST",
    "nist": "NIST",
    "federal_register_ai_policy": "Federal Register",
    "federal_register": "Federal Register",
    "nvd": "NVD",
    "github_advisory": "GitHub Advisory",
    "github": "GitHub Advisory",
    "cisa_kev": "CISA KEV",
    "cisa": "CISA KEV",
    "team_source_text": "",  # not a product 来源
    "team_documents": "",
}

_TYPE_ORIGIN_FALLBACK = {
    "academic_paper": "学术论文源",
    "academic": "学术论文源",
    "security_blog": "安全博客源",
    "research_article": "安全研究/博客源",
    "research": "安全研究/博客源",
    "security_community": "安全社区源",
    "vendor_advisory": "厂商公告源",
    "vendor": "厂商公告源",
    "vendor_guidance": "厂商公告源",
    "technical_standard": "技术标准源",
    "standard": "技术标准源",
    "policy_regulation": "政策法规源",
    "policy": "政策法规源",
    "government_alert": "政府告警源",
    "vulnerability_database": "漏洞数据库",
}


def _map_collector_label(raw):
    text = (raw or "").strip()
    if not text or text in _INGEST_PATH_LABELS:
        return ""
    key = text.lower().replace("-", "_").replace(" ", "_")
    if key in _DISCOVERY_SOURCE_LABELS:
        return _DISCOVERY_SOURCE_LABELS[key]
    for mid, label in _DISCOVERY_SOURCE_LABELS.items():
        if label and mid and mid in key:
            return label
    # Human publisher names (not SCREAMING_COLLECTOR_IDS)
    if not text.isupper() or "_" not in text:
        return text
    return ""


def _document_origin_name(row):
    """Product「来源」= publisher / collector, never an ingest-path brand."""
    for candidate in (
        row.get("publisher"),
        row.get("source"),
        row.get("discovery_source_id"),
        row.get("source_id"),
    ):
        mapped = _map_collector_label(candidate)
        if mapped:
            return mapped
    dtype = (row.get("document_type") or row.get("source_category") or row.get("category") or "").strip()
    return _TYPE_ORIGIN_FALLBACK.get(dtype, "")


def _library_documents(q="", limit=40):
    from rag.library import documents as library_documents

    rows = library_documents()
    out = []
    for row in rows:
        title = row.get("title") or ""
        dtype = row.get("document_type") or ""
        if not _text_match(q, title, dtype, row.get("publisher") or "", row.get("url") or "", row.get("summary") or ""):
            continue
        origin_name = _document_origin_name(row)
        out.append({
            "kind": "document",
            "id": row.get("document_id") or title,
            "document_id": row.get("document_id") or "",
            "title": title,
            "description": row.get("summary") or row.get("description") or "",
            "source": origin_name,
            "sources": [origin_name] if origin_name else [],
            "category": dtype,
            "category_label": _CATEGORY_LABELS.get(dtype, dtype or "资料"),
            "content_type": dtype,
            "url": row.get("url") or "",
            "published_at": row.get("published_at") or row.get("retrieved_at") or "",
            "demo": title.startswith("【演示】"),
            "origin": "library",  # ingest path (技术细节), not product 来源
            "ingest_path": "library_sync",
        })
        if len(out) >= limit:
            break
    return out


@app.get("/api/monitor/feed")
def monitor_feed(q: str = "", kind: str = "all"):
    """Monitor feed: CVE cards + non-CVE documents (多源文档 + 资料库)."""
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
        team_docs, team_meta = _fetch_team_documents(q=q, limit=72)
        lib_docs = _library_documents(q=q, limit=72)
        # Prefer team docs; add library docs not already present by URL/title.
        seen = set()
        merged_docs = []
        for row in team_docs + lib_docs:
            key = (row.get("url") or "") + "|" + (row.get("title") or "")
            if key in seen:
                continue
            seen.add(key)
            merged_docs.append(row)
        # Category round-robin so blogs/papers/vendor are not starved by one lane.
        doc_items = _diversify_documents(merged_docs, limit=72)

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

    # Soft product balance for the monitor stream (KB still holds the full set).
    # Wider window so feed counts are less often mistaken for「知识库只有几十条」.
    cve_before_window = len(cve_items)
    if kind in {"all", "cve", "demo", "live"} and cve_items:
        cve_items = _diversify_cves_by_product(cve_items, per_product_limit=10, limit=120)

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

    # Soft-mix CVE + 资料 when showing "全部"；纯 CVE / 纯资料仍各自按发布时间。
    if kind in {"all", "demo", "live"} and doc_items:
        feed_items = _interleave_feed(cve_items, doc_items)
    else:
        feed_items = cve_items + doc_items
        feed_items.sort(
            key=lambda row: (
                -_pub_ts(row),
                1 if row.get("demo") else 0,
                row.get("cve_id") or row.get("title") or "",
            )
        )

    freshness = {"days_7": 0, "days_30": 0, "older": 0, "unknown": 0, "demo": 0}
    for row in feed_items:
        if row.get("demo"):
            freshness["demo"] += 1
        bucket = _freshness_bucket(_pub_ts(row), now_ts)
        freshness[bucket] = freshness.get(bucket, 0) + 1
    freshness["as_of"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    freshness["note"] = (
        "条目新鲜度按 published_at（近7/30天）；CVE 编号年份≠发布时间；"
        "采集节奏见定时间隔与最近一轮，非实时推流"
    )
    freshness["item_basis"] = "published_at"
    freshness["cadence"] = "periodic"

    composition = _feed_composition(feed_items)

    newest_pub = ""
    newest_collected = ""
    for row in feed_items:
        pub = (row.get("published_at") or "").strip()
        col = (row.get("collected_at") or "").strip()
        if pub and pub > newest_pub:
            newest_pub = pub
        if col and col > newest_collected:
            newest_collected = col

    freshness["newest_published_at"] = newest_pub
    freshness["newest_collected_at"] = newest_collected
    freshness["clock_note"] = (
        "条目「发布」= 原文公开日（常为昨天/更早）；监测是否在跑看上方「最近更新」。"
        "两者不是同一时钟。"
    )

    return {
        "kind": kind,
        "counts": {
            "cve": len(cve_items),
            "document": len(doc_items),
            "total": len(cve_items) + len(doc_items),
            "cve_before_window": cve_before_window if kind in {"all", "cve", "demo", "live"} else len(cve_items),
        },
        "composition": composition,
        "freshness": freshness,
        "team_documents": team_meta,
        "items": feed_items,
        "sort": "mixed_recency" if kind in {"all", "demo", "live"} and doc_items else "published_at_desc",
        "window_note": (
            "下方条数是情报流展示窗（按组件穿插截断），不是知识库全量；"
            "全量以总览「情报条目」/ 入库「库内共」为准。"
        ),
        "mix_note": (
            "情报流混排漏洞与已入库资料（博客/论文/厂商公告/社区等）；"
            "类型/分类与来源分两维看；多源情报=监测一并读入的多源 CVE，不是第二套监测/端口。"
            if doc_items else
            "当前几乎只有漏洞条目——请先监测刷新或同步资料库，资料类才会进入监测流。"
        ),
    }


@app.get("/api/items/{cve_id}")
def item_detail(cve_id: str):
    try:
        record = get_record(cve_id)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="加载情报详情失败：%s。若提示 lxml.html.clean，请安装 lxml_html_clean 后重启。"
            % exc,
        ) from exc
    if not record:
        raise HTTPException(status_code=404, detail="知识库里没有这条情报")
    payload = _summary(record)
    payload["references"] = record.get("references") or []
    payload["poc"] = record.get("poc") or []
    payload["papers"] = record.get("papers") or []
    from enrichment.research_associations import current as research_current
    from database.store import get_record as stored_record
    # The RAG view adds transient PoC/guidance fields. Revision-fenced research
    # must use the canonical source item, not that augmented display view.
    payload["research_associations"] = research_current(stored_record(cve_id.upper()) or record)
    payload["vector"] = (record.get("cvss") or {}).get("vector")
    payload["cvss_version"] = (record.get("cvss") or {}).get("version")
    from rag.ingest import document_status
    try:
        payload["documents"] = document_status(cve_id.upper())
    except Exception as exc:
        payload["documents"] = {"status": "error", "detail": str(exc)[:160]}
    from enrichment.assessment import assess
    try:
        payload["assessment"] = (record["item"].get("raw_data") or {}).get("automatic_assessment") or assess(cve_id.upper())
    except Exception as exc:
        payload["assessment"] = {"status": "error", "detail": "自动评估暂不可用：%s" % str(exc)[:160]}
    try:
        asset_report = impact_report(payload["assessment"], load_assets())
        payload["asset_summary"] = {key: asset_report[key] for key in ("asset_count", "demo_count", "counts")}
    except (ValueError, KeyError, OSError):
        payload["asset_summary"] = None
    payload["related_guidance"] = (record["item"].get("raw_data") or {}).get("related_guidance")
    payload["poc_code"] = (record["item"].get("raw_data") or {}).get("poc_code")
    return payload


def _poc_record(cve_id):
    from rag.evidence import CVE
    if not CVE.fullmatch(cve_id):
        raise HTTPException(status_code=422, detail="需要有效 CVE 编号")
    record = get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条漏洞")
    return record


@app.get("/api/poc-code/{cve_id}")
def poc_code_report(cve_id: str):
    from enrichment.poc_sources import report
    _poc_record(cve_id)
    try:
        return report(cve_id.upper())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="代码存档暂不可读取，请核对本机存储") from exc


@app.post("/api/poc-code/{cve_id}/collect")
def poc_code_collect(cve_id: str, body: PoCCodeCollectBody = PoCCodeCollectBody()):
    import sqlite3
    from enrichment.poc_sources import collect
    _poc_record(cve_id)
    try:
        return collect(cve_id.upper())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(status_code=503, detail="代码存档保存未完成，请核对本机存储；未确认成功") from exc


@app.get("/api/article-candidates/{cve_id}")
def article_candidates(cve_id: str, top_k: int = 4):
    from enrichment.article_candidates import CVE, report
    if not CVE.fullmatch(cve_id):
        raise HTTPException(status_code=422, detail="需要有效 CVE 编号")
    if not 1 <= top_k <= 8:
        raise HTTPException(status_code=422, detail="每类候选上限必须为 1 到 8")
    record = get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条漏洞")
    try:
        return report(record, top_k=top_k)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="本地论文与文章候选检索未完成，请稍后重试。") from exc


@app.get("/api/research-associations/{cve_id}")
def research_associations(cve_id: str):
    from enrichment.research_associations import current
    from database.store import get_record as stored_record
    record = stored_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="知识库中没有这条情报")
    return current(record)


@app.post("/api/research-associations/{cve_id}/refresh")
def refresh_research_associations(cve_id: str):
    from enrichment.research_associations import refresh_and_save
    from database.store import get_record as stored_record
    record = stored_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="知识库中没有这条情报")
    try:
        return refresh_and_save(record)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/guidance/{cve_id}")
def related_guidance(cve_id: str):
    try:
        record = get_record(cve_id.upper())
    except Exception as exc:
        raise HTTPException(status_code=502, detail="读取关联建议失败：%s" % exc) from exc
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条漏洞")
    return record["item"].get("raw_data", {}).get("related_guidance") or {"status": "empty", "facets": {}, "evidence": []}


@app.post("/api/guidance/{cve_id}/refresh")
def refresh_guidance(cve_id: str):
    record = get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="请先收录这条漏洞")
    from enrichment.guidance import refresh
    try:
        return refresh(record)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="补充关联建议失败：%s。若涉及 lxml.html.clean，请安装 lxml_html_clean。"
            % exc,
        ) from exc


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
    from automation.asset_matching import state as matching_state
    return {"items": rows, "count": len(rows), "demo_count": sum(bool(r.get("is_demo")) for r in rows),
            "automatic_matching": matching_state()}


@app.post("/api/assets/import")
def assets_import(body: AssetImport):
    try:
        result = import_assets(body.model_dump())
        from automation.investigation_queue import reconcile
        result["investigations_queued"] = reconcile(reason="assets_changed")
        from automation.asset_matching import run_batch as match_assets
        result["automatic_matches_completed"] = match_assets()
        from automation.processing import worker_state
        result["worker"] = worker_state()
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


class RiskDispositionBody(BaseModel):
    status: Literal["pending", "in_progress", "pending_review", "resolved", "accepted_risk"]
    note: str = Field("", max_length=1000)
    expected_fingerprint: str = Field(..., min_length=1, max_length=128)


@app.get("/api/risks")
def asset_risks(status: str = "", asset_id: str = "", cve_id: str = "",
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                actionable: bool = False):
    from enrichment.risk_register import list_risks
    try:
        result = list_risks(status=status or None, asset_id=asset_id or None,
                            cve_id=cve_id or None, limit=limit, offset=offset, actionable=actionable)
        from automation.asset_matching import state as matching_state
        result["automatic_matching"] = matching_state()
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/risks/assets")
def asset_risk_components(status: str = "", limit: int = Query(30, ge=1, le=200),
                          offset: int = Query(0, ge=0)):
    from enrichment.risk_register import list_risk_assets
    from automation.asset_matching import state as matching_state
    try:
        return dict(list_risk_assets(status=status or None, limit=limit, offset=offset),
                    automatic_matching=matching_state())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/risks/{asset_id}/{cve_id}")
def asset_risk_detail(asset_id: str, cve_id: str):
    from enrichment.risk_register import get_risk
    result = get_risk(asset_id, cve_id.upper())
    if not result:
        raise HTTPException(status_code=404, detail="未找到资产风险记录")
    return result


@app.post("/api/risks/reassess")
def reassess_assets():
    from automation.investigation_queue import reconcile
    return {"queued": reconcile(reason="manual_reassessment", force=True)}


@app.post("/api/risks/{asset_id}/{cve_id}/disposition")
def risk_disposition(asset_id: str, cve_id: str, body: RiskDispositionBody):
    from enrichment.risk_register import update_disposition
    try:
        return update_disposition(asset_id, cve_id.upper(), body.status,
            note=body.note, expected_fingerprint=body.expected_fingerprint)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/api/investigations")
def investigation_tasks(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    from automation.investigation_queue import tasks
    return tasks(limit=limit, offset=offset)


@app.get("/api/investigations/{job_id}/runs")
def investigation_history(job_id: int):
    from automation.investigation_queue import history
    return {"items": history(job_id)}


@app.post("/api/investigations/{cve_id}")
def request_investigation(cve_id: str):
    from database import store
    from automation.investigation_queue import reconcile
    record = store.get_record(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="知识库中没有这条情报")
    return {"queued": reconcile([record], reason="user_research", force=True, explicit=True)}


@app.get("/api/assets/demo")
def assets_demo():
    import json
    with open(os.path.join(ROOT, "enrichment", "samples", "assets_demo.json"), encoding="utf-8") as stream:
        return json.load(stream)


@app.post("/api/assets/preview")
def assets_preview(body: AssetPreview):
    report = _asset_assessment(body.cve_id)
    return impact_report(report, [dict(r.model_dump(), inventory_source="preview") for r in body.assets], preview=True)


@app.get("/api/asset-impact/{cve_id}")
def asset_impact(cve_id: str):
    return impact_report(_asset_assessment(cve_id), load_assets())


@app.post("/api/asset-impact/{cve_id}/save")
def asset_impact_save(cve_id: str):
    from enrichment.asset_workflow import evaluate_saved
    report = _asset_assessment(cve_id)
    try:
        return evaluate_saved(cve_id.upper(), report)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/assets/demo/evaluate")
def assets_demo_evaluate():
    from enrichment.asset_workflow import load_demo
    report = _asset_assessment("CVE-2024-37032")
    try:
        return load_demo("CVE-2024-37032", report)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/assets/demo/match")
def assets_demo_match():
    from enrichment.asset_workflow import match_demo_components
    try:
        return match_demo_components()
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/asset-observations/demo")
def asset_observations_demo():
    import json
    with open(os.path.join(ROOT, "enrichment", "samples", "passive_assets_demo.json"), encoding="utf-8") as stream:
        payload = json.load(stream)
    return dict(payload, is_demo=True)


@app.get("/api/asset-observations")
def asset_observations():
    from enrichment.asset_observations import load_observations
    try:
        rows = load_observations()
        return {"items": rows, "count": len(rows), "demo_count": sum(bool(row.get("is_demo")) for row in rows)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.post("/api/asset-observations/preview")
def asset_observations_preview(body: AssetObservationPreviewBody):
    from enrichment.asset_observations import preview_export, evaluate_observations
    try:
        result = preview_export(body.provider, body.content, body.fields, is_demo=body.is_demo)
        if body.cve_id:
            result["impact"] = evaluate_observations(_asset_assessment(body.cve_id), result["items"])
            result["impact"]["preview"] = True
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/asset-observations/import")
def asset_observations_import(body: AssetObservationBody):
    from enrichment.asset_observations import import_export
    try:
        return import_export(body.provider, body.content, body.fields, is_demo=body.is_demo)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/asset-observation-impact/{cve_id}")
def asset_observation_impact(cve_id: str):
    from enrichment.asset_observations import evaluate_observations, load_observations
    assessment = _asset_assessment(cve_id)
    try:
        report = evaluate_observations(assessment, load_observations())
        report["preview"] = False
        return report
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


# Built-in AI-security scope for one-click auto monitor (comma-separated).
# NVD uses concrete product terms (not only the leading llm); OSV expands packages.
AUTO_MONITOR_KEYWORDS = (
    "llm,vllm,transformers,langchain,llama-index,huggingface,openai,ollama,"
    "open-webui,open webui,adversarial,jailbreak,prompt injection"
)


def _team_reachable_probe():
    """Fast probe so UI can warn when B is unavailable without freezing."""
    import json
    import urllib.error
    import urllib.request

    from collectors.intelligence import team_intel_disabled
    if team_intel_disabled():
        return {"status": "skipped", "mode": "off", "enabled": False, "reachable": False,
                "base_url": "", "public_base": "", "via_proxy": False}

    from api.b_embed import embed_enabled, inprocess_health, public_b_base, sidecar_enabled

    if embed_enabled():
        return inprocess_health()

    from collectors.intelligence import team_base_url

    base = team_base_url()
    public = public_b_base()
    try:
        with urllib.request.urlopen(base + "/api/intelligence/health", timeout=3) as resp:
            payload = json.load(resp)
        return {
            "reachable": True,
            "base_url": base,
            "public_base": public,
            "mode": "sidecar",
            "via_proxy": sidecar_enabled(),
            "database_available": bool(payload.get("database_available")),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {
            "reachable": False,
            "base_url": base,
            "public_base": public,
            "mode": "sidecar",
            "via_proxy": sidecar_enabled(),
            "error": str(exc)[:160],
        }


@app.get("/api/monitor/status")
def monitor_status(light: int = 0):
    """Monitor schedule/progress.

    Use ``?light=1`` while a cycle is running — skip the embed health probe so
    progress polling is not blocked by the same-process multi-source work.
    """
    from automation.schedule import next_run_iso

    st = monitor_state()
    running = bool(st.get("running"))
    team = None
    from collectors.intelligence import team_intel_disabled
    if team_intel_disabled():
        # Configuration is known even while probes are omitted; never label a
        # deliberately disabled source as a reachable sidecar.
        team = _team_reachable_probe()
    elif not light and not running:
        team = _team_reachable_probe()
    elif not light and running:
        # Cheap stub so the UI keeps a team object without opening the intel DB.
        from api.b_embed import embed_enabled, public_b_base

        team = {
            "reachable": True,
            "mode": "embed" if embed_enabled() else "sidecar",
            "public_base": public_b_base(),
            "base_url": public_b_base(),
            "probe": "skipped_while_running",
        }
    from automation.pipeline import get_pipeline

    pipeline = get_pipeline()
    offline_demo = os.environ.get("OFFLINE_DEMO") == "1"
    automatic_enabled = not offline_demo and os.environ.get("AUTO_MONITOR_ENABLED", "1").lower() not in {"0", "false", "no", "off"}
    return {
        "mode": "automatic",
        "offline_demo": offline_demo,
        "automatic_enabled": automatic_enabled,
        "interval_hours": st.get("interval_hours"),
        "interval_minutes": st.get("interval_minutes"),
        "auto_on_start": st.get("auto_on_start"),
        "auto_enabled": st.get("auto_enabled"),
        "running": running,
        "run_phase": st.get("run_phase") or "",
        "run_started_at": st.get("run_started_at") or "",
        "last_run": st.get("last_run") or "",
        "next_run": next_run_iso(st) if automatic_enabled else "",
        "last_count": st.get("last_count") or 0,
        "collection_summary": st.get("collection_summary"),
        "last_error": st.get("last_error") or "",
        "last_status": st.get("last_status") or "",
        "last_warnings": st.get("last_warnings") or [],
        "source_results": st.get("source_results") or [],
        "last_keyword": st.get("last_keyword") or "",
        "team": team,
        "pipeline": pipeline,
        "freshness_policy": {
            "cadence": "periodic",
            "interval_hours": st.get("interval_hours"),
            "interval_minutes": st.get("interval_minutes"),
            "item_buckets": "published_at → 近7天 / 近30天 / 更早",
            "latency_sla": "需监测开始后新发布且可计 collected−published；间隔本身≠延迟达标",
            "realtime": False,
        },
        "notice": "定时轮询（默认每轮结束后等待 15 分钟，可配置）+ 手动「立即刷新」；进度来自真实任务状态，轮询间隔不等于发布到采集延迟。",
    }


@app.get("/api/processing/status")
def processing_status():
    from automation.processing import state
    return state()


@app.post("/api/processing/retry")
def retry_processing():
    from automation.processing import retry_failed
    return {"requeued": retry_failed()}


@app.get("/api/health")
def health():
    from automation.processing import state
    team = _team_reachable_probe()
    monitor = monitor_state()
    available = bool(team.get("reachable") and team.get("database_available"))
    return {"status": "ok" if available and monitor.get("last_status") != "failed" else "degraded",
            "team_database_available": available, "monitor_status": monitor.get("last_status", "not_run"),
            "processing": state(), "last_sync": monitor.get("last_run", "")}


@app.post("/api/monitor/b-cycle")
def monitor_b_cycle():
    """Run one isolated B collector cycle (partial/timeout OK)."""
    from api.b_monitor import run_b_monitor_cycle
    return run_b_monitor_cycle()


@app.post("/api/monitor/run")
def monitor_run(body: MonitorRunBody):
    from database.store import StoreBusy, collection_lock
    from automation.schedule import _RUN_LOCK

    if not _RUN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="已有采集或监测正在进行，请稍后重试")
    try:
        with collection_lock(timeout=0):
            return _monitor_run(body)
    except StoreBusy:
        raise HTTPException(status_code=409, detail="已有采集或监测正在进行，请稍后重试") from None
    finally:
        _RUN_LOCK.release()


def _monitor_run(body: MonitorRunBody):
    """Manual refresh of the automatic monitor cycle (broad AI-security by default)."""
    keyword = (body.keyword or "").strip() or AUTO_MONITOR_KEYWORDS
    from api.b_embed import embed_enabled
    from api.b_monitor import b_monitor_on_refresh, run_b_monitor_cycle
    from automation.pipeline import (
        begin_pipeline, bump_metrics, finish_pipeline, get_pipeline,
        set_tech_detail, update_stage,
    )
    from automation.schedule import combine_monitor_outcome, library_outcome, mark_run, mark_running

    try:
        begin_pipeline()
        mark_running(phase="监测刷新中", keyword=keyword)
    except Exception:
        try:
            mark_running(phase="监测刷新中", keyword=keyword)
        except Exception:
            pass

    def on_phase(stage_id, **fields):
        update_stage(stage_id, **fields)

    # One product stage「监测中」covers all collectors (incl. optional local refresh).
    b_cycle = None
    update_stage(
        "monitoring",
        status="running",
        did="多方面来源一并抓取中…",
        phase="监测刷新中",
    )
    if embed_enabled() and b_monitor_on_refresh():
        try:
            b_cycle = run_b_monitor_cycle()
        except Exception as exc:
            b_cycle = {"status": "failed", "error": "%s: %s" % (type(exc).__name__, exc)[:160]}

    team = _team_reachable_probe()
    warnings = []
    if team.get("enabled") is not False and not team.get("reachable"):
        warnings.append("多源情报暂不可用，本轮仍继续其它来源与资料刷新。")
    if b_cycle and b_cycle.get("status") in {"failed", "timeout"}:
        status_zh = {"failed": "失败", "timeout": "超时"}.get(b_cycle.get("status"), b_cycle.get("status"))
        warnings.append(
            "部分来源刷新%s（%s）；监测仍继续。"
            % (status_zh, (b_cycle.get("error") or "原因未详")[:120])
        )
    result = None
    library = None
    round_stats = {}
    try:
        try:
            result = run_collect(keyword, on_phase=on_phase)
        except Exception as exc:
            # Collection failure must not prevent independent document refresh,
            # or turn a recoverable source outage into a blank dashboard.
            error = "漏洞采集流程未完成（%s），已有资料保留。" % type(exc).__name__
            try:
                saved = knowledge_records()
            except Exception:
                saved = []
            result = {"status": "failed", "error": error, "warnings": [error],
                      "records": saved, "steps": [{"role": "监测", "action": "采集流程失败", "detail": error}],
                      "round_stats": {"inserted": 0, "merged": 0, "kept": 0}}
            update_stage("monitoring", status="error", did="采集流程未完成", note=error)
            update_stage("persist", status="skip", did="保留已有资料", note="不追加新的入库操作")
        round_stats = result.get("round_stats") or {}
        tech = result.get("tech_detail") or ""
        if b_cycle and b_cycle.get("status") in {"success", "partial"}:
            tech = (
                "本轮曾刷新多源情报（%s，%s/%s）；%s"
                % (
                    b_cycle.get("status"),
                    b_cycle.get("success_sources"),
                    b_cycle.get("configured_sources"),
                    tech,
                )
            ).strip("；")
        if tech:
            try:
                set_tech_detail(tech)
            except Exception:
                pass
        bump_metrics(
            hit=round_stats.get("hit"),
            kept=round_stats.get("kept"),
            inserted=round_stats.get("inserted"),
            merged=round_stats.get("merged"),
            external_fetches=round_stats.get("external_fetches"),
        )
        if body.sync_library:
            library = {"team": None, "public": {"status": "skipped", "enabled": False}}
            update_stage(
                "library_sync", status="running", did="同步已采集资料摘要", phase="资料同步",
            )
            # B already collected public research/vendor/paper sources. Import its
            # changes once; explicit /api/library/sync remains available for C.
            if team.get("enabled") is False:
                library["team"] = {"status": "skipped", "enabled": False}
            elif not team.get("reachable"):
                library["team"] = {"status": "skipped", "error": "team unreachable"}
                warnings.append("已跳过资料摘要同步。")
            else:
                try:
                    from rag.library import sync_team_drain
                    library["team"] = sync_team_drain(max_documents=body.max_documents)
                except ValueError as exc:
                    library["team"] = {"status": "busy", "error": str(exc)}
                except Exception as exc:
                    library["team"] = {"status": "error", "error": type(exc).__name__}
                    warnings.append("资料摘要同步失败，已入库情报仍保留。")
            team_st = library_outcome(library["team"])
            disabled = library["team"].get("enabled") is False
            library["status"] = "success" if disabled or team_st == "success" else "partial"
            update_stage(
                "library_sync", status="skip" if disabled else "ok" if team_st == "success" else "error",
                did="同步资料到资料库", got="资料摘要 %s" % team_st,
                produced="资料可供监测流展示", impact="无 CVE 资料进入情报流",
                note="失败不回滚已入库情报", phase="资料同步",
            )
        else:
            update_stage(
                "library_sync",
                status="skip",
                did="本轮未请求资料同步",
                got="sync_library=false",
                produced="—",
                impact="本轮以 CVE 监测结果为主",
                phase="资料同步",
            )
        libraries = (("公开资料同步", library.get("public")), ("资料摘要同步", library.get("team"))) if library else ()
        outcome = combine_monitor_outcome(result, b_cycle=b_cycle, libraries=libraries)
        if outcome["status"] == "failed":
            update_stage("monitoring", status="error", note=outcome["error"])
        warnings = list(dict.fromkeys(warnings + outcome["warnings"]))
        inserted = int(round_stats.get("inserted") or 0)
        finish_pipeline(
            ok=outcome["status"] != "failed",
            metrics={
                "hit": round_stats.get("hit"),
                "kept": round_stats.get("kept"),
                "inserted": round_stats.get("inserted"),
                "merged": round_stats.get("merged"),
                "external_fetches": round_stats.get("external_fetches"),
            },
            tech_detail=(result.get("tech_detail") or tech or "")[:500],
        )
        # Persist the semantic outcome after the generic pipeline finalizer.
        # In particular, partial/failed cannot be overwritten by a done state.
        mark_run(count=inserted, keyword=keyword, source_results=result.get("source_results"),
                 collection_summary=(b_cycle or {}).get("collection_summary"),
                 received=result.get("fetched", round_stats.get("kept", 0)), **outcome)
    except HTTPException:
        try:
            finish_pipeline(ok=False, summary="监测未完成")
        except Exception:
            pass
        raise
    except Exception as exc:
        try:
            mark_run(count=0, keyword=keyword, error=str(exc)[:200],
                     collection_summary=(b_cycle or {}).get("collection_summary"))
            finish_pipeline(ok=False, summary="监测失败：%s" % str(exc)[:160])
        except Exception:
            pass
        raise HTTPException(status_code=502, detail="自动监测没有完成：%s" % exc)
    steps = result.get("steps") or []
    team_failed = any(
        (
            "多源情报" in (s.get("action") or "")
            or "聚合库" in (s.get("action") or "")
            or "本机库" in (s.get("action") or "")  # 旧步骤名兼容
            or "团队情报" in (s.get("action") or "")
        )
        and "失败" in (s.get("action") or "")
        for s in steps
    )
    if team_failed and "多源情报" not in " ".join(warnings) and "聚合库" not in " ".join(warnings):
        warnings.append("多源情报本轮失败或跳过；NVD/OSV 与已有资料仍继续。")

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
    if (result.get("source_outcomes") or {}).get("nvd") == "skipped":
        nvd["status"] = "跳过"
    osv = _step_status("OSV")
    if (result.get("source_outcomes") or {}).get("osv") == "skipped":
        osv["status"] = "跳过"
    b_step = _step_status("多源情报")
    if b_step["status"] == "未跑":
        b_step = _step_status("聚合库")
    if b_step["status"] == "未跑":
        b_step = _step_status("本机库")  # 旧步骤名兼容
    if b_step["status"] == "未跑":
        b_step = _step_status("团队情报")
    if team.get("enabled") is False:
        b_src = {"status": "跳过", "detail": "多源情报已按配置禁用"}
    elif not team.get("reachable"):
        b_src = {
            "status": "不可达",
            "detail": team.get("error") or team.get("base_url") or "embed/db",
        }
    elif b_step["status"] == "失败":
        b_src = b_step
    else:
        b_src = {
            "status": b_step["status"] if b_step["status"] != "未跑" else "接通",
            "detail": b_step.get("detail") or team.get("mode") or team.get("base_url") or "embed",
        }
    if library is None:
        c_sync = {"status": "未请求", "detail": "sync_library=false"}
    elif isinstance(library, dict) and library.get("status") == "skipped":
        c_sync = {"status": "跳过", "detail": library.get("error") or "team unreachable"}
    elif isinstance(library, dict) and library.get("status") in {"error", "busy", "failed"}:
        c_sync = {"status": "失败", "detail": library.get("error") or library.get("status")}
    elif isinstance(library, dict) and library.get("status") == "partial":
        c_sync = {"status": "部分", "detail": "已保留成功同步资料，未完成来源可重试"}
    else:
        c_sync = {"status": "成功", "detail": "已同步已采集资料摘要到资料库"}

    if b_cycle is None:
        b_mon = {"status": "未请求", "detail": "本轮未另刷多源情报"}
    elif b_cycle.get("status") in {"success", "partial"}:
        b_mon = {
            "status": "成功" if b_cycle.get("status") == "success" else "部分",
            "detail": "多源情报刷新 %s/%s 路成功"
            % (b_cycle.get("success_sources"), b_cycle.get("configured_sources")),
        }
    elif b_cycle.get("status") == "skipped":
        b_mon = {"status": "跳过", "detail": "已有监测锁或禁用"}
    elif b_cycle.get("status") == "timeout":
        b_mon = {"status": "超时", "detail": b_cycle.get("error") or "overall timeout"}
    elif b_cycle.get("status") == "disabled":
        b_mon = {"status": "禁用", "detail": "多源情报刷新已关闭"}
    else:
        b_mon = {"status": "失败", "detail": b_cycle.get("error") or b_cycle.get("status")}

    from automation.pipeline import get_pipeline

    source_diag = {
        "nvd": nvd,
        "osv": osv,
        "b_monitor": b_mon,
        "b_team": b_src,
        "c_library_sync": c_sync,
        "written": int(round_stats.get("inserted") or 0),
        "merged": int(round_stats.get("merged") or 0),
        "hit": int(round_stats.get("hit") or 0),
        "kept": int(round_stats.get("kept") or 0),
        "kb_total": len(result["records"]),
    }
    return {
        "status": outcome["status"],
        "error": outcome["error"],
        "source_outcomes": result.get("source_outcomes") or {},
        "mode": "auto",
        "keyword": keyword,
        "count": int(round_stats.get("inserted") or 0),
        "fetched": int(result.get("fetched", round_stats.get("kept", 0)) or 0),
        "kb_total": len(result["records"]),
        "round_stats": round_stats,
        "pipeline": get_pipeline(),
        "steps": steps,
        "library_sync": library,
        "team": team,
        "b_monitor": b_cycle,
        "collection_summary": (b_cycle or {}).get("collection_summary"),
        "warnings": warnings,
        "source_diag": source_diag,
        "items": [_summary(record) for record in result["records"][:10]],
        "notice": "本轮监测刷新：round_stats.hit=查询返回（水位前原始行），kept=水位后保留，inserted/merged=新增/合并；count=本轮新增 CVE，不是整库条数。",
    }


@app.post("/api/collect")
def collect(body: CollectBody):
    from database.store import StoreBusy, collection_lock

    try:
        with collection_lock(timeout=0):
            result = run_collect(body.keyword.strip() or AUTO_MONITOR_KEYWORDS)
    except StoreBusy:
        raise HTTPException(status_code=409, detail="已有采集或监测正在进行，请稍后重试") from None
    except Exception as exc:
        raise HTTPException(status_code=502, detail="监测没有完成：%s" % exc)
    return {
        "count": len(result["records"]),
        "status": result.get("status", "success"),
        "error": result.get("error", ""),
        "warnings": result.get("warnings", []),
        "source_outcomes": result.get("source_outcomes", {}),
        "round_stats": result.get("round_stats", {}),
        "notice": "count 兼容旧接口表示库内记录数；本轮新增请读取 round_stats.inserted。",
        "steps": result["steps"],
        "items": [_summary(record) for record in result["records"][:10]],
    }


@app.post("/api/enrich")
def enrich():
    try:
        result = run_enrich()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="富化没有完成：%s" % exc)
    return {"steps": result["steps"], "items": len(result["records"]), "documents": result["documents"], "feed": result.get("feed", {})}


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
        options = {"document_ids": body.document_ids, "document_type": body.document_type,
                   "use_model": body.use_model}
        if body.mode == "reasoning":
            options["mode"] = body.mode
        return run(body.question, **options)
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
        return review(candidate_id, **body.model_dump())
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
    return prepare(demo=True)  # 显式样例入口；生产索引入口不导入演示数据。


@app.get("/api/settings")
def get_settings():
    return public_settings()


@app.put("/api/settings")
def put_settings(body: SettingsBody):
    save_settings(body.model_dump(exclude_unset=True))
    return public_settings()


@app.get("/api/model-review/status")
def model_review_status():
    from automation.model_review import state
    return state()


@app.get("/api/retrieval/status")
def retrieval_status():
    from config.paths import DATA_ROOT
    from rag.semantic import status
    return {"results": [status(DATA_ROOT / "task_c.sqlite3"), status(DATA_ROOT / "library.sqlite3")],
            "notice": "只读检查当前证据与向量是否一致；不下载模型，不调用问答模型。"}


@app.post("/api/settings/test")
def test_settings():
    if not configured():
        raise HTTPException(status_code=400, detail="请先保存完整模型配置；公网 HTTPS 接口需要密钥，本机回环接口可不填密钥")
    try:
        text = chat([
            {"role": "user", "content": "只回复：连接成功"},
        ], timeout=30)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="连接失败：%s" % exc)
    return {"ok": True, "reply": text[:80]}


@app.get("/")
def index():
    return HTMLResponse(versioned_html(WEB, WEB_VERSION))


# Secure Actions → deploy ingest (must NOT live under /api/intelligence — that is B).
from api.actions_ingest import router as actions_ingest_router  # noqa: E402

app.include_router(actions_ingest_router)

# --- B integration on :8023 ---
# Default: ASGI-embed B in this process (TEAM_INTEL_MODE=embed).
# Legacy: TEAM_INTEL_MODE=sidecar keeps HTTP reverse-proxy to :8765.
from api.b_embed import EmbedBMiddleware, embed_enabled, sidecar_enabled  # noqa: E402
from api.b_proxy import forward_async  # noqa: E402

if embed_enabled():
    app.add_middleware(EmbedBMiddleware)
elif sidecar_enabled():
    @app.get("/api/team/changes")
    async def _proxy_team_changes(request: Request):
        return await forward_async(request, "/api/team/changes")

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


from api.acceptance import router as acceptance_router
app.include_router(acceptance_router)

app.mount("/assets", StaticFiles(directory=WEB), name="assets")
