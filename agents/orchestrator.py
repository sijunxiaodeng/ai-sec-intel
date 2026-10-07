from agents.enrichment_agent import run as enrich_run
from agents.monitor_agent import run as monitor_run
from agents.qa_agent import run as qa_run
from agents.verifier_agent import run as verify_run
from database.store import append_run, latest_run, load_kb, upsert
from enrichment.papers import fetch_papers
from enrichment.service import apply_public_feeds
from models import enriched_record


def run_collect(keyword="ollama"):
    monitored = monitor_run(keyword)
    enriched = enrich_run(monitored["items"], online=False)
    saved = upsert(enriched["records"])
    steps = monitored["steps"] + enriched["steps"] + [{
        "role": "编排",
        "action": "写入知识库",
        "detail": "当前共 %d 条" % len(saved),
    }]
    append_run(steps, "collect")
    return {"records": saved, "steps": steps}


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
    append_run(steps, "enrich")
    return {"records": saved, "steps": steps, "feed": feed}


def run_answer(question, cve_id=""):
    answered = qa_run(question, cve_id=cve_id)
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
        "verdict": verdict,
        "steps": steps,
    }


def last_steps():
    run = latest_run()
    if not run:
        return []
    return run.get("steps") or []
