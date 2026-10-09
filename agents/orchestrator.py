# Ownership: A (integration / orchestration). C must not change step order
# without an A-reviewed PR. Optional document ingest after collect/enrich is
# controlled by AUTO_INGEST_ON_COLLECT (default "1" keeps prior behavior).
import os

from agents.enrichment_agent import run as enrich_run
from agents.monitor_agent import run as monitor_run
from agents.qa_agent import run as qa_run
from agents.verifier_agent import run as verify_run
from database.store import append_run, latest_run, load_kb, upsert
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


def run_collect(keyword="llm"):
    monitored = monitor_run(keyword)
    enriched = enrich_run(monitored["items"], online=False)
    saved = upsert(enriched["records"])
    documents, document_steps = _documents_step(enriched["records"])
    steps = monitored["steps"] + enriched["steps"] + [{
        "role": "编排",
        "action": "写入知识库",
        "detail": "当前共 %d 条" % len(saved),
    }]
    steps += document_steps
    append_run(steps, "collect")
    return {"records": saved, "steps": steps, "documents": documents}


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
