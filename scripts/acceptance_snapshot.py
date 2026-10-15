"""Capture a selected CVE's existing investigation/evidence/risk chain over localhost.

No collection, asset import, job enqueue or retry is requested. --ask explicitly
requests one answer using the server's model settings (possibly a paid provider).
GET handlers may reconcile derived records; this is not a database forensic copy.
The report proves observable bindings, never semantic accuracy or contest scores.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def validate_base(base):
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("只允许本机服务根地址，不允许凭据、路径或重定向")
    return base.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("验收请求不跟随重定向")


def request_json(base, route, body=None):
    request = urllib.request.Request(validate_base(base) + route,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    with opener.open(request, timeout=90) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("响应超出验收预算")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("响应不是对象")
    return payload


def capture(base, cve_id, *, asset_id="", ask=False, declared_commit="", requester=request_json):
    base = validate_base(base)
    cve_id = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        raise ValueError("需要规范 CVE 编号")
    if asset_id and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", asset_id):
        raise ValueError("资产编号格式无效")
    if declared_commit and not re.fullmatch(r"[a-f0-9]{40}", declared_commit):
        raise ValueError("提交号需为完整40位SHA；该字段仅是运行者声明")
    checks, requests = [], []

    def get(name, route, body=None):
        started = time.perf_counter()
        row = {"name": name, "method": "POST" if body is not None else "GET"}
        try:
            result = requester(base, route, body)
            row["status"] = "observed"
            return result
        except Exception as exc:
            row.update(status="error", error_type=type(exc).__name__)
            checks.append({"id": name + "_request", "status": "error"})
            return {}
        finally:
            row["elapsed_http_seconds"] = round(time.perf_counter() - started, 4)
            requests.append(row)

    def check(name, condition, detail):
        checks.append({"id": name, "status": "pass" if condition else "waiting", "detail": detail})

    monitor = get("monitor", "/api/monitor/status")
    processing = get("processing", "/api/processing/status")
    assessment = get("assessment", "/api/assessment/" + cve_id)
    query = urllib.parse.urlencode({"cve_id": cve_id, "asset_id": asset_id, "limit": 200})
    risk_page = get("risks", "/api/risks?" + query)
    risks = [r for r in risk_page.get("items", []) if r.get("cve_id") == cve_id]
    # A specific asset makes the selected chain unambiguous. Otherwise prefer a
    # currently valid record, but do not silently claim that every asset was checked.
    risks.sort(key=lambda r: (r.get("lifecycle") == "invalidated", str(r.get("asset_id"))))
    risk = risks[0] if risks else {}
    job_id = risk.get("job_id")
    jobs, complete = [], False
    for offset in range(0, 2000, 200):
        page = get("investigations", "/api/investigations?limit=200&offset=" + str(offset))
        rows = page.get("items", [])
        jobs += [j for j in rows if j.get("cve_id") == cve_id]
        if job_id and any(j.get("id") == job_id for j in jobs):
            break
        if not rows or offset + len(rows) >= page.get("total", 0):
            complete = True
            break
    job = next((j for j in jobs if j.get("id") == job_id), jobs[0] if jobs and not job_id else {})
    history = get("investigation_runs", "/api/investigations/%s/runs" % job["id"]) if job else {}
    run = next((r for r in history.get("items", []) if r.get("run_id") == risk.get("run_id")), {})
    trace = run.get("trace") or {}
    source_hash = (assessment.get("source") or {}).get("sha256")
    evidence_ids = {e.get("citation_id") for e in assessment.get("evidence", []) if e.get("citation_id")}
    risk_ids = set(risk.get("evidence_ids") or [])
    check("assessment_archive", assessment.get("cve_id") == cve_id and
          assessment.get("status") in {"ok", "partial"} and bool(source_hash and evidence_ids),
          "已存档来源与引用绑定；字段缺失仍可为partial，不等于全部富化完成")
    check("current_risk", bool(risk) and risk.get("lifecycle") != "invalidated" and
          bool(risk.get("source_revision") and risk.get("fingerprint")),
          "仅选择一个资产/CVE；unknown是有效待确认结论，不等于安全")
    check("investigation_commit", bool(run) and job.get("status") == "done" and
          run.get("status") == "done" and trace.get("committed") is True and
          job.get("revision") == risk.get("source_revision") == trace.get("revision"),
          "风险run_id、持久任务修订和已提交运行记录相同；尚在重试/执行则等待")
    check("tool_trace", bool(trace.get("calls")) and bool(trace.get("stop_reason")),
          "实际持久工具轨迹及停止原因；没有调用时不据角色名称判成功")
    check("risk_evidence_binding", bool(source_hash and risk_ids) and risk_ids <= evidence_ids and
          (risk.get("source") or {}).get("sha256") == source_hash,
          "资产版本依据的引用和来源摘要与当前评估相同；不是语义准确率")

    qa = {}
    if ask:
        answer = get("qa", "/api/ask", {"question": cve_id + " 的受影响版本范围是什么？",
                                        "cve_id": cve_id, "session_id": ""})
        chunks = answer.get("evidence_chunks") or []
        # Extractive answers prefix record headings with [1]; those are list
        # ordinals, not evidence identifiers. Other bracket references must bind.
        used = {value for value in re.findall(r"\[([^\[\]\n]+)\]", answer.get("answer") or "")
                if not value.isdigit()}
        returned = {e.get("citation_id") or cve_id + "/" + str(e.get("evidence_id")) for e in chunks}
        relevant = {e.get("citation_id") or cve_id + "/" + str(e.get("evidence_id")) for e in chunks
                    if e.get("cve_id") == cve_id and e.get("source_response_sha256") == source_hash}
        qa = {"requested": True, "used_model": answer.get("used_model"),
              "model_attempted": answer.get("model_attempted"),
              "verifier_passed": (answer.get("verdict") or {}).get("passed"),
              "answer_sha256": digest(answer.get("answer", "")),
              "answer_characters": len(answer.get("answer") or ""),
              "cited_ids": sorted(used), "bound_version_citations": sorted(used & risk_ids & relevant),
              "semantic_correctness": None}
        check("qa_same_evidence", (answer.get("verdict") or {}).get("passed") is True and
              bool(used & risk_ids & relevant) and used <= returned,
              "回答引用与同CVE风险版本证据交集；真实HTTP耗时另列，语义仍需人工复核")
    else:
        check("qa_same_evidence", False, "未请求问答；使用--ask才请求当前配置，可能调用付费模型")

    after = get("assessment_after", "/api/assessment/" + cve_id)
    risk_after = get("risk_after", "/api/risks/%s/%s" % (risk["asset_id"], cve_id)) if risk else {}
    check("capture_stable", bool(source_hash and risk) and
          (after.get("source") or {}).get("sha256") == source_hash and
          risk_after.get("fingerprint") == risk.get("fingerprint") and
          risk_after.get("run_id") == risk.get("run_id") and risk_after.get("lifecycle") != "invalidated",
          "采集前后来源摘要、风险指纹和run_id稳定；HTTP多请求并非原子数据库快照")
    summary = monitor.get("collection_summary") or {}
    source_counts = {k: summary.get(k) for k in ("status", "finished_at", "raw_inserted", "raw_updated",
        "raw_fetched", "counts_complete", "source_total", "source_success", "source_partial", "source_failed", "source_skipped")}
    return {"schema_version": 1, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "evidence_kind": "live_capture", "declared_commit": declared_commit or None,
            "commit_verified_by_server": False, "cve_id": cve_id,
            "scope": {"collection_requested": False, "asset_import_requested": False,
                      "investigation_requested": False, "qa_requested": bool(ask),
                      "model_call_possible": bool(ask), "full_answers_exported": False,
                      "asset_addresses_exported": False, "selected_risks": 1 if risk else 0},
            "monitor": source_counts, "processing_counts": processing.get("counts"),
            "investigation": {"job_id": job.get("id"), "status": job.get("status"),
                "revision": job.get("revision"), "run_id": run.get("run_id"),
                "search_complete": complete, "stop_reason": trace.get("stop_reason"),
                "remaining_gaps": trace.get("remaining_gaps"), "model_calls": trace.get("model_calls"),
                "calls": [{k: c.get(k) for k in ("tool", "status", "resolved_gaps", "remaining_gaps")}
                          for c in trace.get("calls", [])]},
            "risk": {"asset_id_sha256": digest(risk.get("asset_id")) if risk else None,
                **{k: risk.get(k) for k in ("status", "lifecycle", "disposition", "source_revision", "fingerprint", "run_id", "job_id")},
                "evidence_ids": sorted(risk_ids)}, "source_sha256": source_hash, "qa": qa,
            "requests": requests, "checks": checks,
            "summary": {"chain_bindings_verified": all(c["status"] == "pass" for c in checks),
                "waiting": [c["id"] for c in checks if c["status"] == "waiting"],
                "errors": [c["id"] for c in checks if c["status"] == "error"],
                "semantic_accuracy": None, "enrichment_accuracy": None, "monitor_sla": None,
                "semantic_index_verified": None, "competition_passed": None},
            "limits": ["只有所选一条资产/CVE绑定，不是全库完成率或准确率。",
                       "未核对源站漏采、全部任务完成、语义索引或人工答案正确性。",
                       "普通GET可能校正派生风险；--ask会写问答历史，并可能调用当前配置模型。"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8023")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--asset-id", default="")
    parser.add_argument("--commit", default="", help="运行者声明的完整部署SHA，不自动认证")
    parser.add_argument("--ask", action="store_true", help="显式请求一次版本问答，可能调用当前付费模型")
    parser.add_argument("--output", type=Path, required=True, help="新JSON报告，不覆盖已有文件")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("报告已存在，请使用新的文件名")
    try:
        report = capture(args.url, args.cve, asset_id=args.asset_id, ask=args.ask, declared_commit=args.commit)
    except ValueError as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 1 if report["summary"]["errors"] else 0 if report["summary"]["chain_bindings_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
