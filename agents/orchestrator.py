# Ownership: A (integration / orchestration). C must not change step order
# without an A-reviewed PR. Optional document ingest after collect/enrich is
# controlled by AUTO_INGEST_ON_COLLECT (default "1" keeps prior behavior).
import os

from agents.enrichment_agent import run as enrich_run
from agents.monitor_agent import run as monitor_run
from agents.qa_agent import run as qa_run
from agents.verifier_agent import run as verify_run
from database.store import append_run, latest_run, load_kb, upsert, upsert_stats
from enrichment.papers import fetch_papers
from enrichment.service import apply_public_feeds
from models import enriched_record
from rag.ingest import ingest


def _auto_ingest_enabled():
    return os.environ.get("AUTO_INGEST_ON_COLLECT", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _documents_step(records, limit=3):
    if not _auto_ingest_enabled():
        return [], [{"role": "编排", "action": "跳过自动抓取关联资料",
                     "detail": "AUTO_INGEST_ON_COLLECT 已关闭；可在详情页或 /api/documents 单独处理。"}]
    results = [ingest(record, max_sources=4) for record in records[:limit]]
    return results, [{"role": "富化", "action": "抓取关联资料并更新证据索引",
                      "detail": "本次处理 %d 条情报，抓取成功 %d 个来源；失败状态已保留。其余情报可在详情中单独处理。" %
                      (len(results), sum(row["ok"] for row in results))}]


def run_documents(record):
    result = ingest(record)
    steps = [{"role": "富化", "action": "抓取关联资料并更新证据索引",
              "detail": "%s：尝试 %d 个来源，成功 %d 个，新增/更新 %d 段。" %
              (result["cve_id"], result["attempted"], result["ok"], result["chunks"])}]
    append_run(steps, "documents")
    return dict(result, steps=steps)


def run_collect(keyword="llm", *, on_phase=None):
    """Run monitor → normalize → upsert.

    ``on_phase(stage_id, **fields)`` optional callback for live pipeline UI.
    """
    def phase(stage_id, **fields):
        if on_phase:
            try:
                on_phase(stage_id, **fields)
            except Exception:
                pass

    phase("fetch_nvd", status="running", did="开始查询 NVD…")
    phase("fetch_osv", status="pending")
    phase("fetch_aggregate", status="pending")
    monitored = monitor_run(keyword)
    stats = monitored.get("stats") or {}
    steps_in = monitored.get("steps") or []

    def _fill_from_step(stage_id, step, ok_flag):
        if not step:
            phase(stage_id, status="skip", note="未跑")
            return
        status = "ok" if ok_flag and "失败" not in (step.get("action") or "") else "error"
        if "失败" in (step.get("action") or ""):
            status = "error"
        phase(
            stage_id,
            status=status,
            did=step.get("did") or step.get("action") or "",
            got=step.get("got") or step.get("detail") or "",
            produced=step.get("produced") or "",
            impact=step.get("impact") or "",
            note=step.get("note") or "",
        )

    nvd_step = next((s for s in steps_in if "NVD" in (s.get("action") or "")), None)
    osv_step = next((s for s in steps_in if "OSV" in (s.get("action") or "")), None)
    agg_step = next(
        (
            s for s in steps_in
            if "聚合库" in (s.get("action") or "")
            or "多源情报" in (s.get("action") or "")
            or "团队情报" in (s.get("action") or "")
        ),
        None,
    )
    _fill_from_step("fetch_nvd", nvd_step, stats.get("nvd_ok", True))
    _fill_from_step("fetch_osv", osv_step, stats.get("osv_ok", True))
    _fill_from_step("fetch_aggregate", agg_step, stats.get("aggregate_ok", True))

    phase(
        "normalize",
        status="running",
        did="统一来源字段名为系统标准格式",
        got="待整理 %d 条" % len(monitored.get("items") or []),
    )
    enriched = enrich_run(monitored["items"], online=False)
    enrich_step = (enriched.get("steps") or [{}])[0]
    phase(
        "normalize",
        status="ok",
        did=enrich_step.get("action") or "整理情报字段",
        got="整理 %d 条" % len(enriched.get("records") or []),
        produced="规范化记录 %d 条" % len(enriched.get("records") or []),
        impact="进入入库合并；本步不查外网 EPSS/KEV",
        note=enrich_step.get("detail") or "",
    )

    phase(
        "upsert",
        status="running",
        did="按 CVE 编号合并写入知识库",
        got="待写入 %d 条" % len(enriched.get("records") or []),
    )
    write = upsert_stats(enriched["records"])
    saved = write["records"]
    # Advance OSV/NVD watermarks only after a successful upsert path.
    collectors = monitored.get("collectors") or {}
    for key in ("nvd", "osv"):
        coll = collectors.get(key)
        if coll is not None and hasattr(coll, "commit_cursor"):
            try:
                coll.commit_cursor()
            except Exception:
                pass
    phase(
        "upsert",
        status="ok",
        did="按 CVE 编号合并写入知识库",
        got="本轮参与合并 %d 条" % write.get("fetched", 0),
        produced="新增 %d · 合并已有 %d · 库内共 %d"
        % (write.get("inserted", 0), write.get("merged", 0), write.get("total", len(saved))),
        impact="情报监测流将反映库内最新合并结果",
        note="「库内共 N」不是本轮新增；0 新增时请看命中/合并",
    )

    documents, document_steps = _documents_step(enriched["records"])
    steps = monitored["steps"] + enriched["steps"] + [{
        "role": "编排",
        "action": "写入知识库",
        "detail": "新增 %d，合并 %d，库内共 %d"
        % (write.get("inserted", 0), write.get("merged", 0), write.get("total", len(saved))),
        "did": "合并写入 knowledge.json",
        "got": "参与 %d 条" % write.get("fetched", 0),
        "produced": "新增 %d / 合并 %d" % (write.get("inserted", 0), write.get("merged", 0)),
        "impact": "列表展示以监测 feed 为准",
    }]
    steps += document_steps
    append_run(steps, "collect")
    round_stats = {
        "hit": stats.get("hit", 0),
        "kept": stats.get("kept", 0),
        "inserted": write.get("inserted", 0),
        "merged": write.get("merged", 0),
        "skipped_dup": write.get("skipped_dup", 0),
        "total": write.get("total", len(saved)),
        "external_fetches": stats.get("external_fetches", 0),
        "nvd": stats.get("nvd") or {},
        "osv": stats.get("osv") or {},
    }
    return {
        "records": saved,
        "steps": steps,
        "documents": documents,
        "round_stats": round_stats,
        "write": write,
    }


def run_enrich():
    records = load_kb()
    feed = apply_public_feeds(records)
    cve_ids = [(record.get("item") or {}).get("cve_id") for record in records]
    papers, paper_error = fetch_papers(cve_ids)
    attached = 0
    for record in records:
        cve_id = (record.get("item") or {}).get("cve_id")
        found = papers.get(cve_id) or []
        if found:
            record["papers"] = found
            attached += len(found)
    saved = upsert([enriched_record(record) for record in records])
    detail = "已查询 EPSS、CISA KEV，并按编号检索论文。对上编号的论文 %d 篇。" % attached
    if feed.get("epss_error") or feed.get("kev_error") or paper_error:
        detail = "部分公开源没有连通，失败项已跳过，已有字段仍保留。"
    steps = [{
        "role": "富化",
        "action": "补充 EPSS、KEV 与论文",
        "detail": detail,
    }]
    documents, document_steps = _documents_step(saved)
    steps += document_steps
    append_run(steps, "enrich")
    return {"records": saved, "steps": steps, "feed": feed, "documents": documents}


def run_answer(question, cve_id="", *, cve_ids=None, db_path=None):
    options = {"cve_id": cve_id}
    if cve_ids is not None:
        options["cve_ids"] = cve_ids
    if db_path is not None:
        options["db_path"] = db_path
    answered = qa_run(question, **options)
    verdict = verify_run(answered["answer"], answered["evidence"])
    answer = answered["answer"]
    if not verdict["passed"]:
        answer = "核对没有通过，下面保留模型原文，请以证据列表为准。\n" + answer
    steps = answered["steps"] + verdict["steps"]
    append_run(steps, "ask")
    return {
        "answer": answer,
        "evidence": answered["evidence"],
        "used_model": answered["used_model"],
        "model_attempted": bool(answered.get("model_attempted", answered["used_model"])),
        "verdict": verdict,
        "steps": steps,
    }


def last_steps():
    run = latest_run()
    if not run:
        return []
    return run.get("steps") or []
