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
    Product stages are coarse: monitoring → persist (not per-source).
    """
    def phase(stage_id, **fields):
        if on_phase:
            try:
                on_phase(stage_id, **fields)
            except Exception:
                pass

    phase(
        "monitoring",
        status="running",
        did="多方面来源一并抓取中…",
        phase="监测刷新中",
    )
    monitored = monitor_run(keyword)
    stats = monitored.get("stats") or {}
    steps_in = monitored.get("steps") or []

    failed_bits = []
    for step in steps_in:
        action = step.get("action") or ""
        if "失败" in action:
            failed_bits.append(action.replace("调用 ", "").strip())
    # Soft-fail: any source failure alone is not a whole-stage error if others worked.
    all_failed = bool(failed_bits) and not (
        stats.get("nvd_ok") or stats.get("osv_ok") or stats.get("aggregate_ok")
    )
    phase(
        "monitoring",
        status="error" if all_failed else "ok",
        did="多方面来源抓取已完成",
        got="命中 %d，保留 %d" % (stats.get("hit", 0), stats.get("kept", 0)),
        produced="进入整理入库 %d 条" % len(monitored.get("items") or []),
        impact="本轮监测结果将规范化并写入知识库",
        note=("部分来源未通：" + "、".join(failed_bits[:4]) if failed_bits else "多方面来源已尽力查询"),
        phase="监测刷新中",
    )
    # Compact tech line for optional UI disclosure (not a stage checklist).
    tech_bits = []
    for step in steps_in:
        action = step.get("action") or ""
        detail = (step.get("detail") or "")[:80]
        if action:
            tech_bits.append("%s：%s" % (action.replace("调用 ", ""), detail))
    monitored["tech_detail"] = "；".join(tech_bits)[:480]

    phase(
        "persist",
        status="running",
        did="规范化字段并合并写入知识库",
        got="待处理 %d 条" % len(monitored.get("items") or []),
        phase="整理入库",
    )
    enriched = enrich_run(monitored["items"], online=False)
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
        "persist",
        status="ok",
        did="规范化并合并写入知识库",
        got="本轮参与 %d 条" % write.get("fetched", 0),
        produced="新增 %d · 合并 %d · 库内共 %d"
        % (write.get("inserted", 0), write.get("merged", 0), write.get("total", len(saved))),
        impact="情报流将反映最新合并结果",
        note="0 新增时请看命中/合并——不等于没搜到",
        phase="整理入库",
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
        "tech_detail": monitored.get("tech_detail") or "",
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
