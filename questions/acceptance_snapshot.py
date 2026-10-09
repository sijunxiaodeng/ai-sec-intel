"""本机验收现状快照：不采集、不导入资产、不调用模型，不判定比赛达标。"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
TOPICS = ("indirect_prompt_injection", "model_supply_chain")


def validate_base(base):
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("仅允许本机系统根地址，不允许外部地址、凭据或查询参数")
    return base.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("验收请求不跟随重定向")


def request_json(base, route, body=None):
    base = validate_base(base)
    request = urllib.request.Request(base + route,
              data=json.dumps(body).encode("utf-8") if body is not None else None,
              headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("响应超过 4 MiB 验收预算")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("接口未返回对象")
    return payload


def closed_citations(result):
    rows = result.get("evidence", [])
    returned = {r["citation_id"] for r in rows}
    return (bool(result.get("analyses")) and len({r["document_id"] for r in rows}) >= 2
            and bool(result.get("graph", {}).get("edges"))
            and all(set(edge["evidence_ids"]) <= returned for edge in result.get("graph", {}).get("edges", []))
            and all(a["evidence_ids"] and set(a["evidence_ids"]) <= returned for a in result["analyses"]))


def capture(base="http://127.0.0.1:8023", cve_id="CVE-2024-37032", requester=request_json):
    base = validate_base(base)
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("无效 CVE 编号")
    checks, inventory = [], {}

    def check(cid, route, summarize, body=None):
        started = time.perf_counter()
        try:
            payload = requester(base, route, body)
            state, summary = summarize(payload)
            inventory[cid] = summary
            checks.append({"id": cid, "status": state, "elapsed_http_seconds": round(time.perf_counter() - started, 4)})
        except Exception as exc:
            # 不记录异常原文，避免把服务器错误、配置或原始响应带入可提交报告。
            checks.append({"id": cid, "status": "error", "error_kind": type(exc).__name__,
                           "elapsed_http_seconds": round(time.perf_counter() - started, 4)})

    def overview(p):
        return ("pass" if p["items"] > 0 else "needs_data"), {
            "stored_cve_records": p["items"], "vulnerability_source_names": p["sources"],
            "source_name_count_is_category_count": False, "llm_configured": bool(p["llm_ready"]),
            "eligible_monitor_latency_samples": p["latency_count"],
            "interval_hours": p["monitor"].get("interval_hours")}

    def library(p):
        o = p["overview"]
        return ("pass" if o["documents"] > 0 else "needs_data"), {
            "documents": o["documents"], "chunks": o["chunks"], "types": o["types"],
            "source_categories": o["source_categories"], "scope_counts": o["scope_counts"],
            "failed_documents": len(o["failed_documents"])}

    def assessment(p):
        return ("pass" if p["status"] == "ok" else "needs_data"), {
            "status": p["status"], "cvss_available": bool(p.get("cvss")),
            "affected_ranges": len(p.get("affected_ranges", [])), "poc_candidate_links": len(p.get("poc_candidates", [])),
            "poc_validation_states": sorted({v["validation"] for v in p.get("poc_candidates", [])}),
            "fix_records": len(p.get("fix_records", [])),
            "fix_validation_states": sorted({v["validation"] for v in p.get("fix_records", [])})}

    check("overview", "/api/overview", overview)
    check("library", "/api/library", library)
    check("assessment", "/api/assessment/" + cve_id, assessment)
    check("assets", "/api/assets", lambda p: ("observed", {"registered": p["count"], "demo": p["demo_count"], "internet_asset_discovery_tested": False}))
    check("retrieval", "/api/library/search?q=" + urllib.parse.quote("间接提示注入"),
          lambda p: ("pass" if p["evidence"] else "needs_data", {"mode": p["mode"], "returned_chunks": len(p["evidence"])}))
    for topic in TOPICS:
        check(topic + "_graph", "/api/library/relations/graph?topic=" + topic,
              lambda p: ("pass" if p["status"] == "ready" else "needs_review", {
                  "status": p["status"], "curated_facts": len(p["facts"]), "unavailable_facts": len(p["unavailable_facts"]),
                  "reviewed_quotes": len(p.get("reviewed_quotes", {}).get("facts", []))}))
        check(topic + "_queue", "/api/library/relations/candidates?topic=" + topic,
              lambda p: ("observed", {"displayed_candidates": len(p["items"]),
                "effective_states": {state: sum(i["effective_state"] == state for i in p["items"])
                   for state in ("pending", "approved", "rejected", "revoked", "stale")}}))
    questions = {TOPICS[0]: "间接提示注入的机制、防护建议与局限是什么？",
                 TOPICS[1]: "模型供应链的加载风险、防护建议与扫描局限是什么？"}
    for topic, question in questions.items():
        check(topic + "_analysis", "/api/library/analyze",
              lambda p: ("pass" if p["status"] == "answered" and not p.get("model_attempted") and not p.get("used_model") and closed_citations(p) else "needs_review", {
                 "status": p["status"], "analysis_paths": len(p.get("analyses", [])),
                 "model_attempted": bool(p.get("model_attempted")), "used_model": bool(p.get("used_model")),
                 "citation_binding_passed": closed_citations(p) if p["status"] == "answered" else False}),
              {"question": question, "use_model": False})
    return {"schema_version": 1, "recorded_at": datetime.now(timezone.utc).isoformat(), "cve_id": cve_id,
            "purpose": "当前本机演示资料和接口绑定快照，不是独立语义验收或比赛评分",
            "scope": {"collection_triggered": False, "asset_import_triggered": False, "model_calls_requested": False,
                      "original_answers_or_asset_details_exported": False},
            "inventory": inventory, "checks": checks,
            "summary": {"checks": len(checks), "errors": sum(c["status"] == "error" for c in checks),
                        "needs_data_or_review": sum(c["status"] in {"needs_data", "needs_review"} for c in checks),
                        "independent_enrichment_accuracy": None, "independent_enrichment_recall": None,
                        "independent_qa_accuracy": None, "competition_passed": None}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8023")
    parser.add_argument("--cve", default="CVE-2024-37032")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "task-c-acceptance-snapshot.json")
    args = parser.parse_args()
    try:
        report = capture(args.url, args.cve)
    except ValueError as exc:
        parser.exit(2, str(exc) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False))
    if report["summary"]["errors"] or report["summary"]["needs_data_or_review"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
