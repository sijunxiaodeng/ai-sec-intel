"""真实本机 HTTP 开发评测，来源前提独立于生产关系文件；人工质量待填。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

DATASET = Path(__file__).with_name("relations_evaluation.json")


def request_json(base, route, body=None):
    request = urllib.request.Request(base.rstrip("/") + route,
                                    data=json.dumps(body).encode("utf-8") if body is not None else None,
                                    headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("评测响应超出预算")
        return json.loads(raw)


def source_manifest(base, dataset):
    docs = request_json(base, "/api/library")["items"]
    sources = {}
    for source in dataset["sources"]:
        matches = [d for d in docs if d["url"] == source["url"] and d.get("version") == source["version"]
                   and d["content_scope"] == source["content_scope"]]
        if len(matches) != 1:
            raise ValueError("缺少题单预期版本：" + source["id"])
        doc = request_json(base, "/api/library/" + matches[0]["document_id"])
        if doc["integrity_status"] != "ok":
            raise ValueError("题单来源完整性异常：" + source["id"])
        for probe in source["probes"]:
            if not any(probe["locator"] in r["locator"] and probe["contains"] in r["text"] for r in doc["evidence"]):
                raise ValueError("题单来源前提已变化，须复核：" + source["id"])
        sources[source["id"]] = {k: doc[k] for k in ("document_id", "url", "version", "content_scope", "source_response_sha256", "retrieved_at")}
    return sources


def check_case(case, result, sources):
    failures = []
    if result.get("status") != case["expected_status"]:
        failures.append("回答状态不符")
    answer = result.get("answer", "")
    for pattern in case["required_patterns"]:
        if not re.search(pattern, answer, re.I | re.S):
            failures.append("缺少预期表达：" + pattern)
    for pattern in case["forbidden_patterns"]:
        if re.search(pattern, answer, re.I | re.S):
            failures.append("出现不支持的断言：" + pattern)
    rows = result.get("evidence", [])
    returned_citations = {row["citation_id"] for row in rows}
    if any(not set(edge["evidence_ids"]) <= returned_citations for edge in result.get("graph", {}).get("edges", [])):
        failures.append("关系图的边缺少返回的原文证据")
    for requirement in case["required_evidence"]:
        expected = sources[requirement["source"]]
        if not any(r["document_id"] == expected["document_id"] and r["url"] == expected["url"]
                   and requirement["locator"] in r["locator"] and "[%s]" % r["citation_id"] in answer for r in rows):
            failures.append("缺少所需来源及定位引用：" + requirement["source"] + " " + requirement["locator"])
    if case["expected_status"] == "answered":
        if not result.get("verdict", {}).get("passed") or len({r["document_id"] for r in rows}) < 2:
            failures.append("缺少跨文档绑定结果")
        if not result.get("analyses"):
            failures.append("没有综合路径")
    elif result.get("analyses"):
        failures.append("证据不足/不支持的问题生成了综合结论")
    return failures


def run(base, dataset, mode, case_ids=None):
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.username or parsed.password:
        raise ValueError("评测只允许本机系统地址")
    sources = source_manifest(base, dataset)
    cases = [c for c in dataset["cases"] if not case_ids or c["id"] in case_ids]
    if case_ids and set(case_ids) - {c["id"] for c in cases}:
        raise ValueError("题号不存在")
    rows = []
    for case in cases:
        body = {"question": case["question"], "use_model": mode == "model",
                "document_ids": [sources[k]["document_id"] for k in case["selected_sources"]]}
        started = time.perf_counter()
        result = request_json(base, "/api/library/analyze", body)
        elapsed = time.perf_counter() - started
        failures = check_case(case, result, sources)
        rows.append({"case_id": case["id"], "question": case["question"], "elapsed_http_seconds": round(elapsed, 4),
                     "status": result.get("status"), "automatic_passed": not failures, "failures": failures,
                     "model_attempted": result.get("model_attempted", False), "used_model": result.get("used_model", False),
                     "analysis_ids": [a["id"] for a in result.get("analyses", [])],
                     "citation_ids": [r["citation_id"] for r in result.get("evidence", [])],
                     "answer": result["answer"], "evidence": result.get("evidence", []),
                     "manual_review": {"reviewer": None, "independent_human": None,
                                       "source_supported": None, "relevant": None, "conditions_preserved": None,
                                       "synthesis_correct": None, "notes": ""}})
    return {"schema_version": 1, "recorded_at": datetime.now(timezone.utc).isoformat(), "mode": mode,
            "purpose": dataset["purpose"], "source_manifest": sources, "rows": rows,
            "summary": {"cases": len(rows), "automatic_passed": sum(r["automatic_passed"] for r in rows),
                        "model_attempted": sum(r["model_attempted"] for r in rows),
                        "model_accepted": sum(r["used_model"] for r in rows),
                        "http_under_5s": sum(r["elapsed_http_seconds"] <= 5 for r in rows),
                        "timing_scope": "Local HTTP request serialization, server work, full response read; excludes browser rendering; one run, no load benchmark",
                        "independent_semantic_accuracy": None, "competition_multihop_accuracy": None}}


def public_report(report):
    return dict(report, rows=[{k: v for k, v in r.items() if k not in ("answer", "evidence")} for r in report["rows"]])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8023")
    parser.add_argument("--mode", choices=("rules", "model"), default="rules")
    parser.add_argument("--case", action="append")
    parser.add_argument("--output", type=Path, default=Path("data/relations-evaluation.json"))
    parser.add_argument("--public-output", type=Path)
    args = parser.parse_args()
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    report = run(args.url, dataset, args.mode, args.case)
    report["dataset_sha256"] = hashlib.sha256(DATASET.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.public_output:
        args.public_output.parent.mkdir(parents=True, exist_ok=True)
        args.public_output.write_text(json.dumps(public_report(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False))
    if not all(r["automatic_passed"] for r in report["rows"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
