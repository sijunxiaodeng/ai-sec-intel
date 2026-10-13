# Ownership: A (integration / orchestration). C must not change step order
# without an A-reviewed PR. Optional document ingest after collect/enrich is
# controlled by AUTO_INGEST_ON_COLLECT (default "1" keeps prior behavior).
import os

from agents.enrichment_agent import run as enrich_run
from agents.monitor_agent import run as monitor_run
from agents.qa_agent import run as qa_run
from agents.verifier_agent import run as verify_run
from database.store import (
    append_run,
    apply_enrichment,
    apply_sync_page,
    collection_lock,
    latest_run,
    load_kb,
    upsert_stats,
)
from enrichment.papers import fetch_papers
from enrichment.service import apply_public_feeds
from models import enriched_record
from rag.ingest import ingest


def _auto_ingest_enabled():
    return os.environ.get("AUTO_INGEST_ON_COLLECT", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _documents_step(records):
    if not _auto_ingest_enabled():
        return [], [{"role": "编排", "action": "跳过自动抓取关联资料",
                     "detail": "AUTO_INGEST_ON_COLLECT 已关闭；可在详情页或 /api/documents 单独处理。"}]
    from automation.processing import enqueue
    count = enqueue(records)
    return [], [{"role": "富化", "action": "加入富化与证据索引队列",
                 "detail": "%d 个任务已持久化；所有新记录及变更均会处理，失败自动重试。" % count}]


def run_documents(record):
    result = ingest(record)
    steps = [{"role": "富化", "action": "抓取关联资料并更新证据索引",
              "detail": "%s：尝试 %d 个来源，成功 %d 个，新增/更新 %d 段。" %
              (result["cve_id"], result["attempted"], result["ok"], result["chunks"])}]
    append_run(steps, "documents")
    return dict(result, steps=steps)


def _monitor_outcome(monitored):
    """A successful empty poll is different from unavailable collection sources."""
    stats = monitored.get("stats") or {}
    labels = {"nvd": "NVD", "osv": "OSV", "aggregate": "多源情报"}
    sources, warnings = {}, []
    for name, label in labels.items():
        if name in {"nvd", "osv"} and stats.get(name + "_disabled_duplicate"):
            sources[name] = "skipped"
        elif name == "aggregate" and stats.get("aggregate_disabled"):
            sources[name] = "skipped"
        elif name + "_ok" in stats:
            sources[name] = "success" if stats[name + "_ok"] else "failed"
            if sources[name] == "failed":
                warnings.append(label + " 本轮采集失败")
    # Preserve callers using the older items/steps contract without source flags.
    if not sources:
        warnings = [(s.get("action") or "") for s in monitored.get("steps", []) if "失败" in (s.get("action") or "")]
        failed = bool(warnings) and not monitored.get("items")
    else:
        active = [value for value in sources.values() if value != "skipped"]
        failed = not active or all(value == "failed" for value in active)
    if (stats.get("osv") or {}).get("packages_failed"):
        warnings.append("OSV 部分包查询失败，未完成包会重试")
        if sources.get("osv") == "success":
            sources["osv"] = "partial"
    if (stats.get("nvd") or {}).get("pending_windows"):
        warnings.append("NVD 仍有历史窗口待续采")
        if sources.get("nvd") == "success":
            sources["nvd"] = "partial"
    if stats.get("aggregate_partial") or any("部分关键词失败" in (s.get("detail") or "") for s in monitored.get("steps", [])):
        warnings.append("多源情报部分关键词查询失败")
        if sources.get("aggregate") == "success":
            sources["aggregate"] = "partial"
    status = "failed" if failed else "partial" if warnings else "success"
    error = "本轮可用采集来源全部失败；已有情报已保留。" if failed else "；".join(dict.fromkeys(warnings))
    return {"status": status, "error": error, "warnings": list(dict.fromkeys(warnings)), "source_outcomes": sources}


def run_collect(keyword="llm", *, on_phase=None):
    # Also guard direct callers, not just the HTTP/scheduled entry points.
    # A busy round performs no fetch/write/ack and is safe to retry.
    with collection_lock(timeout=0):
        return _run_collect(keyword, on_phase=on_phase)


def _run_collect(keyword="llm", *, on_phase=None):
    """Run monitor → normalize → upsert.

    ``on_phase(stage_id, **fields)`` optional callback for live pipeline UI.
    Product stages are coarse: monitoring → persist (not per-source).
    """
    def phase(stage_id, **fields):
        if on_phase:
            try:
                on_phase(stage_id, **fields)
            except Exception:
                pass  # Presentation cannot invalidate a committed sync.

    phase(
        "monitoring",
        status="running",
        did="多方面来源一并抓取中…",
        phase="监测刷新中",
    )
    monitored = monitor_run(keyword)
    stats = monitored.get("stats") or {}
    steps_in = monitored.get("steps") or []

    outcome = _monitor_outcome(monitored)
    all_failed = outcome["status"] == "failed"
    phase(
        "monitoring",
        status="error" if all_failed else "ok",
        did="多方面来源抓取已完成",
        got="查询返回 %d，水位后保留 %d" % (stats.get("hit", 0), stats.get("kept", 0)),
        produced="进入整理入库 %d 条" % len(monitored.get("items") or []),
        impact="本轮监测结果将规范化并写入知识库",
        note=outcome["error"] or "多方面来源已尽力查询（查询返回含水位前历史；成功空轮也会保留查询状态）",
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

    if all_failed:
        saved = load_kb()
        phase("persist", status="skip", did="采集未完成，保留已有知识库",
              produced="本轮不写入、不推进游标", note=outcome["error"], phase="整理入库")
        steps = steps_in + [{"role": "编排", "action": "保留已有知识库", "detail": outcome["error"]}]
        append_run(steps, "collect")
        write = {"records": saved, "fetched": 0, "inserted": 0, "merged": 0, "skipped_dup": 0, "total": len(saved)}
        return dict(outcome, records=saved, steps=steps, documents=[], write=write,
                    round_stats={"hit": stats.get("hit", 0), "kept": 0, "inserted": 0, "merged": 0,
                                 "skipped_dup": 0, "total": len(saved), "external_fetches": stats.get("external_fetches", 0),
                                 "nvd": stats.get("nvd") or {}, "osv": stats.get("osv") or {}},
                    tech_detail=monitored["tech_detail"])

    phase(
        "persist",
        status="running",
        did="规范化字段并合并写入知识库",
        got="待处理 %d 条" % len(monitored.get("items") or []),
        phase="整理入库",
    )
    enriched = enrich_run(monitored["items"], online=False)
    changes = monitored.get("team_changes")
    if changes is not None:
        write = apply_sync_page(
            enriched["records"],
            source=changes["source"],
            cursor=changes["cursor"],
            retracted_ids=changes["retracted_ids"],
            return_stats=True,
        )
    else:
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
                outcome["status"] = "partial"
                outcome["warnings"].append(key.upper() + " 位点未保存，下轮将重试；本轮情报已入库")
                outcome["error"] = "；".join(outcome["warnings"])
    phase(
        "persist",
        status="ok",
        did="规范化并合并写入知识库",
        got="本轮参与 %d 条" % write.get("fetched", 0),
        produced="新增 %d · 合并 %d · 库内共 %d"
        % (write.get("inserted", 0), write.get("merged", 0), write.get("total", len(saved))),
        impact="新增与变更进入后续持久处理队列",
        note="0 新增时请看查询返回/水位后保留/合并——不等于没搜到",
        phase="整理入库",
    )

    try:
        documents, document_steps = _documents_step(enriched["records"])
    except Exception:
        outcome["status"] = "partial"
        outcome["warnings"].append("关联资料补充未完成；已入库情报保留，独立资料同步仍可继续")
        outcome["error"] = "；".join(outcome["warnings"])
        documents = []
        document_steps = [{"role": "富化", "action": "关联资料补充失败", "detail": outcome["warnings"][-1]}]
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
    result = {
        **outcome,
        "records": saved,
        "steps": steps,
        "documents": documents,
        "round_stats": round_stats,
        "write": write,
        "tech_detail": monitored.get("tech_detail") or "",
        "fetched": len(monitored.get("items") or []),
    }
    if monitored.get("source_results") is not None:
        result["source_results"] = monitored.get("source_results")
    return result


def run_enrich():
    records = load_kb()
    from automation.processing import revision
    expected = {record["item"]["cve_id"]: revision(record) for record in records}
    feed = apply_public_feeds(records)
    cve_ids = [(record.get("item") or {}).get("cve_id") for record in records]
    papers, paper_error = fetch_papers(cve_ids)
    paper_status = dict(getattr(papers, "metadata", {}) or {})
    if paper_status:
        feed["papers"] = paper_status
    feed["paper_error"] = paper_error
    attached = 0
    for record in records:
        cve_id = (record.get("item") or {}).get("cve_id")
        found = papers.get(cve_id) or []
        if found:
            record["papers"] = found
            attached += len(found)
    apply_enrichment([enriched_record(record) for record in records], expected_revisions=expected)
    saved = load_kb()
    detail = "已查询 EPSS、CISA KEV，并按编号检索论文。对上编号的论文 %d 篇。" % attached
    paper_source_error = paper_error and (
        not paper_status or any(batch.get("status") == "error" for batch in paper_status.get("batches", []))
    )
    if feed.get("epss_error") or feed.get("kev_error") or paper_source_error:
        detail = "部分公开源没有连通，失败项已跳过，已有字段仍保留。"
    if paper_error:
        detail += " 论文查询状态：" + str(paper_error)[:500]
    if paper_status:
        detail += " 论文查询覆盖 %d/%d 个编号（有界轮转，非全量论文召回）。" % (
            len(paper_status.get("queried_cve_ids") or []), len(paper_status.get("requested_cve_ids") or []))
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
