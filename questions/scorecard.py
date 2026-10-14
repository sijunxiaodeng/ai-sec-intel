"""汇总冻结问答报告；未完成独立人工复核时不生成竞赛准确率。"""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics

KINDS = {"single_fact", "comparison", "multi_hop", "refusal", "multi_turn", "other"}
RELATION_CHECKS = ("source_supported", "relevant", "conditions_preserved", "synthesis_correct")


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _manifest_valid(manifest):
    values = list(manifest.values()) if isinstance(manifest, dict) else manifest
    return isinstance(values, list) and bool(values) and all(
        isinstance(source, dict) and _sha(source.get("response_sha256", source.get("source_response_sha256")))
        for source in values)


def _row(row, report):
    review = row.get("manual_review") or {}
    relation = "case_id" in row
    checks = RELATION_CHECKS if relation else ("correct", "citations_supported")
    complete = all(isinstance(review.get(key), bool) for key in checks)
    independent = complete and review.get("independent_human") is True and isinstance(review.get("reviewer"), str) and bool(review["reviewer"].strip())
    correct = all(review[key] for key in checks) if complete else None
    seconds = row.get("elapsed_http_seconds" if relation else "seconds")
    if seconds is not None and (isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds < 0):
        raise ValueError("逐题耗时须为有限非负数")
    response = row.get("response") or {}
    kind = review.get("reasoning_kind")
    return {"id": row.get("case_id" if relation else "id"),
            "automatic_passed": row.get("automatic_passed") is True,
            "manual_complete": complete, "independent_reviewed": independent, "correct": correct,
            "reasoning_kind": kind if kind in KINDS else "unclassified",
            "reasoning_explained": review.get("reasoning_explained"),
            "seconds": seconds, "timing_scope": "local_http" if relation and seconds is not None else "in_process_testclient",
            "used_model": (row.get("used_model") if relation else response.get("used_model")) is True,
            "model_attempted": row.get("model_attempted") is True,
            "reproducible": _sha(report.get("dataset_sha256")) and _manifest_valid(report.get("source_manifest"))
                and report.get("dataset_cases") == len(report.get("cases", report.get("rows", [])))}


def _metrics(rows):
    independent = [row for row in rows if row["independent_reviewed"]]
    complete = bool(rows) and len(independent) == len(rows) and all(row["reproducible"] for row in rows)
    times = sorted(row["seconds"] for row in rows if row["seconds"] is not None)
    http = [row for row in rows if row["timing_scope"] == "local_http" and row["seconds"] is not None]
    return {"cases": len(rows), "automatic_passed": sum(row["automatic_passed"] for row in rows),
            "manual_reviewed": sum(row["manual_complete"] for row in rows), "independent_reviewed": len(independent),
            "unreviewed_cases": len(rows) - len(independent),
            "independent_accuracy": sum(row["correct"] for row in rows) / len(rows) if complete else None,
            "reviewed_subset_accuracy": sum(row["correct"] for row in independent) / len(independent) if independent else None,
            "model_attempted": sum(row["model_attempted"] for row in rows),
            "model_accepted": sum(row["used_model"] for row in rows),
            "model_fallback": sum(row["model_attempted"] and not row["used_model"] for row in rows),
            "timed_cases": len(times), "median_seconds": statistics.median(times) if times else None,
            "p95_seconds": times[math.ceil(len(times) * .95) - 1] if times else None,
            "max_seconds": max(times) if times else None,
            "local_http_cases": len(http), "local_http_under_5s": sum(row["seconds"] <= 5 for row in http),
            "all_cases_local_http_under_5s": len(http) == len(rows) and bool(rows) and all(row["seconds"] <= 5 for row in http),
            "independent_explanation_rate": sum(row["reasoning_explained"] for row in rows) / len(rows)
                if complete and all(isinstance(row["reasoning_explained"], bool) for row in rows) else None}


def compile_scorecard(reports):
    if not reports:
        raise ValueError("至少提供一份评测报告")
    modes = {report.get("mode") for report in reports}
    if len(modes) != 1 or next(iter(modes)) not in {"rules", "model"}:
        raise ValueError("请分别汇总 rules 与 model 模式，不混合计算准确率")
    rows, seen, manifests = [], set(), []
    for report in reports:
        cases = report.get("cases", report.get("rows"))
        if not isinstance(cases, list) or not cases:
            raise ValueError("每份报告须包含非空 cases 或 rows")
        digest = report.get("dataset_sha256")
        count = report.get("summary", {}).get("cases")
        if count is not None and count != len(cases):
            raise ValueError("报告题目数与逐题记录不一致")
        local_ids = set()
        for case in cases:
            row = _row(case, report)
            if not isinstance(row["id"], str) or not row["id"].strip() or row["id"] in local_ids:
                raise ValueError("报告内题号须非空且唯一")
            local_ids.add(row["id"])
            # 同一冻结题单中的同一道题不能通过合并重复运行扩大样本数。
            identity = (digest.lower(), row["id"]) if _sha(digest) else (None, row["id"])
            if identity in seen:
                raise ValueError("重复题目不能重复计分：" + row["id"])
            seen.add(identity)
            rows.append(row)
        manifests.append({"dataset_sha256": digest, "mode": report["mode"], "cases": len(cases),
                          "report_sha256": hashlib.sha256(json.dumps(report, ensure_ascii=False, sort_keys=True).encode()).hexdigest()})
    summary = _metrics(rows)
    return {"schema_version": 1, "mode": next(iter(modes)), "reports": manifests, "summary": summary,
            "reasoning_kinds": dict(Counter(row["reasoning_kind"] for row in rows)),
            "by_reasoning_kind": {kind: _metrics([row for row in rows if row["reasoning_kind"] == kind])
                                  for kind in sorted({row["reasoning_kind"] for row in rows})},
            "accepted_model": _metrics([row for row in rows if row["used_model"]]),
            "measurement_complete": summary["independent_accuracy"] is not None,
            "competition_passed": None,
            "limits": ["人工身份与独立性来自复核者声明；程序不能证明其身份或未参与开发。",
                       "independent_accuracy 须整份题单完成独立人审并保存题单摘要、完整题数和来源响应摘要；选题子集不能作为整套达标成绩。",
                       "跨文档回答不自动算多跳；题型及推理解释须由复核者按题目和实际答案标注。",
                       "自动检查通过率不代表语义准确率；公开开发题单不因独立人审而成为盲测题单。",
                       "local_http 覆盖完整本机 HTTP 返回；TestClient、浏览器、外网、并发及冷启动的范围分别看待。",
                       "本工具不按题目数量或准确率自动给比赛打分；样本代表性与评审规则仍需复核。"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compile_scorecard([json.loads(path.read_text(encoding="utf-8")) for path in args.reports])
    except (ValueError, KeyError, TypeError) as exc:
        parser.exit(2, str(exc) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
