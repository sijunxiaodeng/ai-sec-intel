"""运行独立问答题单；自动检查只作辅助，人工质量评分单独汇总。"""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
DATASET = Path(__file__).with_name("qa_evaluation.json")


def pointer(value, path):
    for key in path.strip("/").split("/"):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def source_manifest(db, dataset):
    """对直接存档的 JSON 校验人工题单前提，不从生产评估函数生成标准答案。"""
    from rag.evidence import _connection
    from enrichment.documents import digest
    if not db.exists():
        raise ValueError("评测证据库不存在，请先运行 --prepare")
    manifest = []
    with _connection(db) as conn:
        for source in dataset["sources"]:
            sid = digest(source["url"])[:16]
            row = conn.execute("SELECT digest, body FROM source_snapshots WHERE cve_id=? AND source_id=?",
                               (source["cve_id"], sid)).fetchone()
            if not row or hashlib.sha256(row[1]).hexdigest() != row[0]:
                raise ValueError("缺少有效来源快照：" + source["cve_id"])
            payload = json.loads(row[1])["vulnerabilities"][0]["cve"]
            if payload["id"] != source["cve_id"]:
                raise ValueError("来源编号不一致")
            for fact in source["preconditions"]:
                if pointer(payload, fact["pointer"]) != fact["value"]:
                    raise ValueError("来源已变化，请人工复核题单：" + source["cve_id"] + " " + fact["pointer"])
            manifest.append({"cve_id": source["cve_id"], "url": source["url"],
                             "response_sha256": row[0], "last_modified": payload.get("lastModified")})
        # 附上关联修复等来源的快照摘要，便于复核一整次评测的证据版本。
        for cve, sid, sha, body, doc in conn.execute(
                "SELECT s.cve_id,s.source_id,s.digest,s.body,d.payload FROM source_snapshots s JOIN documents d ON s.cve_id=d.cve_id AND s.source_id=d.source_id ORDER BY s.cve_id,s.source_id"):
            if cve not in {s["cve_id"] for s in dataset["sources"]}:
                continue
            metadata = json.loads(doc)
            if metadata["url"] in {m["url"] for m in manifest}:
                continue
            if hashlib.sha256(body).hexdigest() != sha:
                raise ValueError("关联来源快照校验失败：" + metadata["url"])
            manifest.append({"cve_id": cve, "url": metadata["url"], "response_sha256": sha,
                             "retrieved_at": metadata.get("retrieved_at")})
    return manifest


def check_case(case, payload):
    answer = payload.get("answer", "")
    failures = []
    if {r["cve_id"] for r in payload.get("evidence", [])} != set(case["expected_cves"]):
        failures.append("召回的漏洞范围不符")
    for regex in case.get("required_patterns", []):
        if not re.search(regex, answer, re.I):
            failures.append("未包含预期表达：" + regex)
    for regex in case.get("forbidden_patterns", []):
        if re.search(regex, answer, re.I):
            failures.append("出现不支持的结论：" + regex)
    chunks = payload.get("evidence_chunks", [])
    for req in case.get("required_evidence", []):
        matched = [c for c in chunks if c.get("cve_id") == req["cve_id"] and
                   req["locator_contains"] in c.get("locator", "") and
                   c.get("url", "").startswith(req["url_prefix"])]
        if not any("[%s]" % c["citation_id"] in answer for c in matched):
            failures.append("关键事实缺少预期字段引用：" + req["cve_id"] + " " + req["locator_contains"])
    if case["expected_cves"] and not payload.get("verdict", {}).get("passed"):
        failures.append("引用/编号/显式评分核对未通过")
    # 这些规则不能判断完整语义正确性；完整答案必须在 report 中另行人工复核。
    return failures


def prepare(db, dataset):
    from enrichment.sample import load_sample
    from rag.ingest import ingest
    template, _ = load_sample()
    import copy
    for source in dataset["sources"]:
        record = copy.deepcopy(template)
        cve = source["cve_id"]
        record.update(cvss=None, poc=[], papers=[], references=source.get("extra_urls", []), epss=None, kev=None)
        record["item"].update(id=cve, cve_id=cve, title=cve, description="", affected=[],
                              url=source["url"], source="NVD", references=[], raw_data={"sample_mode": "evaluation"})
        result = ingest(record, db, max_sources=2 if source.get("extra_urls") else 1)
        print(cve, "成功来源", result["ok"])


def run(db, dataset, mode):
    from fastapi.testclient import TestClient
    from api.app import app
    from agents.conversation import SessionStore
    from agents.orchestrator import run_answer
    from config.llm import chat, configured
    manifest = source_manifest(db, dataset)
    rows = []
    with ExitStack() as stack:
        # 隔离评测库、空资产清单和会话，不写业务库或运行日志。
        stack.enter_context(patch("rag.retrieve.load_kb", return_value=[]))
        stack.enter_context(patch("enrichment.assets.load_assets", return_value=[]))
        stack.enter_context(patch("agents.orchestrator.append_run"))
        stack.enter_context(patch("api.app.sessions", SessionStore(capacity=100)))
        stack.enter_context(patch("api.app.run_answer", partial(run_answer, db_path=db)))
        if mode == "rules":
            stack.enter_context(patch("agents.qa_agent.configured", return_value=False))
        else:
            if not configured():
                raise ValueError("模型未配置，不能生成模型模式的评测结果")
        drafts = []
        def capture(messages, **kwargs):
            draft = {"answer": None, "error": None}
            drafts.append(draft)
            try:
                draft["answer"] = chat(messages, **kwargs)
                return draft["answer"]
            except Exception as exc:
                draft["error"] = type(exc).__name__
                raise
        stack.enter_context(patch("agents.qa_agent.chat", side_effect=capture))
        client = TestClient(app)  # 不运行 startup 监测任务。
        for case in dataset["cases"]:
            sid = ""
            for previous in case.get("history", []):
                response = client.post("/api/ask", json={"question": previous, "session_id": sid})
                response.raise_for_status()
                sid = response.json()["session_id"]
            drafts.clear()
            start = time.perf_counter()
            response = client.post("/api/ask", json={"question": case["question"], "session_id": sid})
            elapsed = time.perf_counter() - start
            if response.status_code != 200:
                payload, failures = response.json(), ["HTTP " + str(response.status_code)]
            else:
                payload = response.json()
                failures = check_case(case, payload)
            rows.append({"id": case["id"], "category": case["category"], "question": case["question"],
                         "history": case.get("history", []), "seconds": round(elapsed, 4),
                         "automatic_passed": not failures, "failures": failures,
                         "manual_review": {"correct": None, "citations_supported": None, "notes": ""},
                         "model_attempted": bool(drafts), "model_drafts": list(drafts),
                         "review_checklist": case["review_checklist"], "response": payload})
            print("%s %s %.3fs %s" % (case["id"], "自动检查通过" if not failures else "需复核", elapsed,
                                          "模型回答" if payload.get("used_model") else "规则或回退"), flush=True)
    times = sorted(r["seconds"] for r in rows)
    from config.settings import public_settings
    settings = public_settings()
    return {"schema_version": 1, "run_at": datetime.now(timezone.utc).isoformat(), "mode": mode,
            "model": settings["model"] if mode == "model" else None,
            "endpoint_type": ("local" if settings["base_url"].startswith("http://127.0.0.1:") else "configured") if mode == "model" else None,
            "dataset_sha256": hashlib.sha256(DATASET.read_bytes()).hexdigest(), "source_manifest": manifest,
            "summary": {"cases": len(rows), "automatic_passed": sum(r["automatic_passed"] for r in rows),
                        "used_model_cases": sum(bool(r["response"].get("used_model")) for r in rows),
                        "accepted_model_automatic_passed": sum(r["automatic_passed"] and bool(r["response"].get("used_model")) for r in rows),
                        "model_attempted_cases": sum(r["model_attempted"] for r in rows),
                        "model_fallback_cases": sum(r["model_attempted"] and not r["response"].get("used_model") for r in rows),
                        "median_seconds": statistics.median(times), "p95_seconds": times[math.ceil(len(times)*.95)-1],
                        "max_seconds": max(times), "over_5_seconds": sum(t > 5 for t in times),
                        "manual_accuracy": None, "manual_citation_support_rate": None,
                        "accepted_model_manual_accuracy": None},
            "limits": ["题单是公开的开发评测集，开发者已看过；不是独立盲测成绩。",
                       "自动规则检查关键词、范围和字段引用，不能代替语义质量评审。",
                       "耗时覆盖本机 TestClient 完整 HTTP 响应及检索/组织/核对，不包括浏览器、外网、并发和首次模型下载。",
                       "模型模式的比较及资产拒答仍可使用规则；每题分别记录 used_model。"], "cases": rows}


def summarize_review(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    rows = report["cases"]
    if any(not isinstance(r["manual_review"][key], bool) for r in rows for key in ("correct", "citations_supported")):
        raise ValueError("请先逐题填写全部人工复核字段 true/false；未复核项不能按通过计分")
    report["summary"]["manual_accuracy"] = sum(r["manual_review"]["correct"] for r in rows) / len(rows)
    accepted = [r for r in rows if r["response"].get("used_model")]
    report["summary"]["accepted_model_manual_accuracy"] = sum(r["manual_review"]["correct"] for r in accepted) / len(accepted) if accepted else None
    cited = [r for r in rows if r["response"].get("evidence")]
    report["summary"]["manual_citation_support_rate"] = sum(r["manual_review"]["citations_supported"] for r in cited) / len(cited) if cited else None
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report["summary"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "qa_evaluation.sqlite3")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--mode", choices=["rules", "model"], default="rules")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "qa-evaluation-report.json")
    parser.add_argument("--summarize-review", type=Path)
    args = parser.parse_args()
    try:
        if args.summarize_review:
            print(json.dumps(summarize_review(args.summarize_review), ensure_ascii=False))
            return
        dataset = json.loads(DATASET.read_text(encoding="utf-8"))
        if args.prepare:
            prepare(args.db, dataset)
        report = run(args.db, dataset, args.mode)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report["summary"], ensure_ascii=False))
        print("报告：", args.output)
    except (ValueError, KeyError) as exc:
        parser.exit(2, str(exc) + "\n")


if __name__ == "__main__":
    main()
