"""冻结来源的新题预验收：真实 HTTP 捕获、逐题复核包；不自动认定语义正确。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import sqlite3
import statistics
import time
import uuid

from questions.acceptance_snapshot import request_json, validate_base

ROOT = Path(__file__).resolve().parent.parent
DATASET = Path(__file__).with_name("acceptance_round1.json")
KINDS = {"assessment", "qa", "excerpt", "relations", "reviewed_graph"}
PRODUCTION_DIRS = {"agents", "api", "automation", "collectors", "config", "database", "enrichment", "rag", "web"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_baseline(dataset, root=ROOT):
    baseline = dataset["baseline"]
    if not re.fullmatch(r"[a-f0-9]{40}", baseline["commit"]):
        raise ValueError("无效冻结版本")
    paths = baseline["production_sha256"]
    for name, expected in paths.items():
        path = (root / name).resolve()
        if root.resolve() not in path.parents or not path.is_file() or sha(path.read_bytes().replace(b"\r\n", b"\n")) != expected:
            raise ValueError("生产代码与冻结版本不一致，需建立新一轮评测")
    for dirname in PRODUCTION_DIRS:
        for path in (root / dirname).rglob("*"):
            name = path.relative_to(root).as_posix()
            if path.is_file() and path.suffix in {".py", ".js", ".html", ".css", ".json"} and name != "config/local.json" and name not in paths:
                raise ValueError("冻结清单之外存在生产文件")


def validate_dataset(dataset):
    sources = {s["id"] for s in dataset["sources"]}
    cases = dataset["cases"]
    if not cases or len({c["id"] for c in cases}) != len(cases) or len(sources) != len(dataset["sources"]):
        raise ValueError("题号/来源重复或题单为空")
    for source in dataset["sources"]:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", source["id"]):
            raise ValueError("来源存档编号无效")
        key, pattern = ("document_id", r"DOC-[a-f0-9]{16}") if source["kind"] == "library" else ("cve_id", r"CVE-\d{4}-\d{4,7}")
        if source["kind"] not in {"library", "nvd"} or not re.fullmatch(pattern, source[key]):
            raise ValueError("来源类型或编号无效")
    for case in cases:
        if case["kind"] not in KINDS or not set(case.get("sources", [])) <= sources or not case["expected_points"]:
            raise ValueError("未知操作、来源或缺少参考要点")
        if any(not isinstance(q, str) or not 1 <= len(q) <= 4000 for q in [case.get("question", "检查"), *case.get("history", [])]):
            raise ValueError("问题长度无效")
        if case["kind"] == "assessment" and not re.fullmatch(r"CVE-\d{4}-\d{4,7}", case["cve_id"]):
            raise ValueError("无效漏洞编号")


def source_signature(doc):
    return sha(json.dumps([doc["url"], doc.get("version"), doc["content_scope"],
        sorted((r["citation_id"], r["text_sha256"], r["locator"]) for r in doc["evidence"])], ensure_ascii=False).encode())


def queue_signature(payload):
    return sha(json.dumps(sorted((i["id"], i["state"], i["effective_state"], i["source_fingerprint"],
        sha(json.dumps(i["reviews"], ensure_ascii=False, sort_keys=True).encode())) for i in payload["items"]), ensure_ascii=False).encode())


def source_manifest(base, dataset, requester=request_json):
    manifest = {}
    for source in dataset["sources"]:
        if source["kind"] == "library":
            doc = requester(base, "/api/library/" + source["document_id"])
            if (doc["integrity_status"] != "ok" or doc["url"] != source["url"] or
                doc["content_scope"] != source["content_scope"] or doc.get("version") != source.get("version") or
                source_signature(doc) != source["evidence_signature"]):
                raise ValueError("资料来源或版本已变化，需重新核对标签")
            manifest[source["id"]] = {k: source.get(k) for k in ("document_id", "url", "version", "content_scope", "evidence_signature")}
        else:
            report = requester(base, "/api/assessment/" + source["cve_id"])
            if report["status"] != "ok" or report.get("source", {}).get("sha256") != source["response_sha256"]:
                raise ValueError("漏洞来源缺失或已变化，需重新核对标签")
            manifest[source["id"]] = {k: source[k] for k in ("cve_id", "url", "response_sha256")}
    if dataset.get("review_queue_sha256"):
        signature = queue_signature(requester(base, "/api/library/relations/candidates?topic=article_relations"))
        if signature != dataset["review_queue_sha256"]: raise ValueError("审核队列与冻结状态不一致")
        manifest["review_queue"] = {"sha256": signature}
    return manifest


def archive_sources(dataset, target, *, timing="before_capture", library_db=None, evidence_db=None, library_reader=None):
    """只复制题单选中的原始来源；校验失败时保留现场，不冒充已有存档。"""
    from rag.library import LIBRARY_DB, detail
    from rag.evidence import DEFAULT_DB
    validate_dataset(dataset)
    if timing not in {"before_capture", "verified_after_capture"}:
        raise ValueError("未知存档时点")
    sources_dir = target / "sources"
    if sources_dir.exists(): raise ValueError("不覆盖已有来源存档")
    collected = []
    for source in dataset["sources"]:
        if source["kind"] == "library":
            metadata = (library_reader or detail)(source["document_id"], library_db or LIBRARY_DB)
            if (metadata.get("integrity_status") != "ok" or source_signature(metadata) != source["evidence_signature"]):
                raise ValueError("资料存档与冻结证据不一致")
            db, sql, args = library_db or LIBRARY_DB, "SELECT digest,body FROM library_snapshots WHERE document_id=?", (source["document_id"],)
            expected = metadata["source_response_sha256"]
        else:
            metadata = {"cve_id": source["cve_id"], "url": source["url"], "source_pointer_labels": [
                f for c in dataset["cases"] if c.get("cve_id") == source["cve_id"] for f in c.get("gold_facts", [])]}
            db, sql, args = evidence_db or DEFAULT_DB, "SELECT digest,body FROM source_snapshots WHERE cve_id=? AND source_id=?", (source["cve_id"], sha(source["url"].encode())[:16])
            expected = source["response_sha256"]
        # 只读连接，不复制整个数据库，也不读取模型配置或资产。
        conn = sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True)
        try: row = conn.execute(sql, args).fetchone()
        finally: conn.close()
        if not row or row[0] != expected or sha(row[1]) != expected:
            raise ValueError("来源快照缺失、变化或校验失败")
        collected.append((source, bytes(row[1]), metadata))
    sources_dir.mkdir(parents=True)
    manifest = {"schema_version": 1, "archived_at": datetime.now(timezone.utc).isoformat(), "timing": timing,
                "dataset_sha256": sha(json.dumps(dataset, ensure_ascii=False, sort_keys=True).encode()), "sources": []}
    for source, body, metadata in collected:
        raw_name, metadata_name = source["id"] + ".snapshot", source["id"] + ".json"
        metadata_bytes = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode()
        (sources_dir / raw_name).write_bytes(body)
        (sources_dir / metadata_name).write_bytes(metadata_bytes)
        manifest["sources"].append({"id": source["id"], "url": source["url"], "snapshot": "sources/" + raw_name,
            "snapshot_sha256": sha(body), "snapshot_bytes": len(body), "metadata": "sources/" + metadata_name,
            "metadata_sha256": sha(metadata_bytes), "evidence_signature": source.get("evidence_signature")})
    (target / "dataset.json").write_text(json.dumps(dataset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (target / "archive_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def predictions(payload):
    """只计预先声明的 CVSS、CPE 范围、向量条件/影响维度；不以全部字段数充当召回分母。"""
    result = []
    def add(dimension, field, value, path, row, **context):
        result.append({"id": "P%d" % (len(result) + 1), "dimension": dimension, "field": field, "value": value,
                       "response_pointer": path, "evidence_ids": row.get("evidence_ids", []), **context})
    for i, row in enumerate(payload.get("cvss_candidates", [])):
        for field in ("score", "severity", "version", "vector", "source", "metric_type"):
            add("cvss", field, row.get(field), f"/cvss_candidates/{i}/{field}", row, provider=row.get("source"))
    for i, row in enumerate(payload.get("affected_ranges", [])):
        for field in ("criteria", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
            if field in row:
                add("affected_range", field, row[field], f"/affected_ranges/{i}/{field}", row, criteria=row.get("criteria"))
    for group in ("attack_conditions", "technical_impact"):
        for i, row in enumerate(payload.get(group, [])):
            add(group, row.get("metric"), row.get("value"), f"/{group}/{i}/value", row)
    return result


def suggested_match(prediction, facts):
    matches = [f["id"] for f in facts if all(prediction.get(k) == v for k, v in f["expected"].items())]
    return matches[0] if len(matches) == 1 else None


def check_case(case, payload, dataset):
    failures = []
    if "expected_status" in case and payload.get("status") != case["expected_status"]:
        failures.append("返回状态不符")
    rows = payload.get("evidence_chunks" if case["kind"] == "qa" else "evidence", [])
    if case["kind"] == "qa":
        if {r["cve_id"] for r in payload.get("evidence", [])} != set(case["expected_cves"]):
            failures.append("漏洞范围不符")
    if case["kind"] == "excerpt":
        sources = {s["id"]: s for s in dataset["sources"]}
        expected = {sources[s]["document_id"] for s in case["sources"]}
        if {r["document_id"] for r in rows} != expected:
            failures.append("摘录未覆盖且仅覆盖指定资料")
    answer = payload.get("answer", "")
    for pattern in case.get("required_patterns", []):
        if not re.search(pattern, answer, re.I | re.S): failures.append("缺少题单约定表达")
    for pattern in case.get("forbidden_patterns", []):
        if re.search(pattern, answer, re.I | re.S): failures.append("出现题单禁止的表达")
    cited = set(re.findall(r"\[((?:CVE-\d{4}-\d{4,7}|DOC-[a-f0-9]{16})/[^\]\s]+)\]", answer))
    returned = {r["citation_id"] for r in rows if "citation_id" in r}
    if not cited <= returned: failures.append("答案引用未随原文返回")
    if case.get("requires_citations") and not cited: failures.append("缺少回答引用")
    if case["kind"] == "assessment":
        returned = {r["citation_id"] for r in rows}
        for pred in predictions(payload):
            if not pred["evidence_ids"] or not set(pred["evidence_ids"]) <= returned:
                failures.append("富化事实缺少返回的引用"); break
    if case["kind"] == "reviewed_graph":
        graph = payload["reviewed_quotes"]
        returned = {r["citation_id"] for r in graph["evidence"]}
        if any(not set(e["evidence_ids"]) <= returned for e in graph["graph"]["edges"]):
            failures.append("复核关系边缺少返回原文")
        if any(f["review"]["decision"] != "approved" for f in graph["facts"]):
            failures.append("未通过项进入有效图")
    return failures


def route_body(case, dataset, mode):
    kind = case["kind"]
    if kind == "assessment": return "/api/assessment/" + case["cve_id"], None
    if kind == "reviewed_graph": return "/api/library/relations/graph?topic=article_relations", None
    if kind == "qa": return "/api/ask", {"question": case["question"], "session_id": ""}
    sources = {s["id"]: s for s in dataset["sources"]}
    return "/api/library/" + ("ask" if kind == "excerpt" else "analyze"), {
        "question": case["question"], "document_ids": [sources[s]["document_id"] for s in case["sources"]],
        "use_model": mode == "model"}


def run(base, dataset, mode="rules", case_ids=None, requester=request_json, baseline_verifier=verify_baseline):
    base = validate_base(base); validate_dataset(dataset); baseline_verifier(dataset)
    if mode not in {"rules", "model"}: raise ValueError("未知评测模式")
    cases = [c for c in dataset["cases"] if not case_ids or c["id"] in case_ids]
    if case_ids and set(case_ids) - {c["id"] for c in cases}: raise ValueError("未知题号")
    before = source_manifest(base, dataset, requester)
    rows = []
    for case in cases:
        row = {"id": case["id"], "kind": case["kind"], "category": case["category"], "stratum": case["stratum"], "question": case.get("question"),
               "expected_points": case["expected_points"], "history": [], "status": "skipped", "failures": []}
        if case["kind"] == "assessment": row["gold_facts"] = case["gold_facts"]
        rows.append(row)
        if mode == "rules" and case["kind"] == "qa":
            row["skip_reason"] = "漏洞问答 HTTP 接口无规则开关；避免通过改全局模型配置伪造纯规则运行"
            continue
        route, body = route_body(case, dataset, mode)
        try:
            for question in case.get("history", []):
                started = time.perf_counter()
                response = requester(base, route, {"question": question, "session_id": body["session_id"]})
                row["history"].append({"question": question, "response": response,
                                       "elapsed_http_seconds": round(time.perf_counter() - started, 4)})
                body["session_id"] = response["session_id"]
            started = time.perf_counter()
            response = requester(base, route, body)
            row.update(status="captured", response=response, elapsed_http_seconds=round(time.perf_counter() - started, 4))
            row["failures"] = check_case(case, response, dataset)
            row["automatic_checks_passed"] = not row["failures"]
            if case["kind"] == "assessment":
                row["predictions"] = predictions(response)
                for pred in row["predictions"]: pred["suggested_gold_id"] = suggested_match(pred, case["gold_facts"])
        except Exception as exc:
            row.update(status="error", error_kind=type(exc).__name__, automatic_checks_passed=False)
            if isinstance(getattr(exc, "code", None), int): row["http_status"] = exc.code
            # 异常正文不带进报告；失败题仍保留，不缩小分母。
        print(case["id"], row["status"], row.get("automatic_checks_passed"), flush=True)
    source_stable, after_error = False, None
    try:
        baseline_verifier(dataset)
        source_stable = before == source_manifest(base, dataset, requester)
    except Exception as exc: after_error = type(exc).__name__
    try:
        model_name = requester(base, "/api/settings").get("model")
    except Exception:
        model_name = None
    return {"schema_version": 1, "run_id": uuid.uuid4().hex, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "baseline_commit": dataset["baseline"]["commit"], "dataset_sha256": sha(json.dumps(dataset, ensure_ascii=False, sort_keys=True).encode()),
            "mode": mode, "configured_model_name": model_name, "source_manifest": before, "source_stable": source_stable, "after_check_error": after_error,
            "environment": {"python": platform.python_version(), "platform": platform.system(), "concurrency": 1,
                            "index_temperature": "未控制；复用本机进程，不作为冷启动测试", "background_monitoring": "生产定时任务仍可能运行"},
            "rows": rows, "independent_semantic_accuracy": None, "competition_passed": None}


def review_template(report, dataset):
    cases = {c["id"]: c for c in dataset["cases"]}
    rows = []
    for r in report["rows"]:
        if r["status"] == "skipped": continue
        row = {"id": r["id"], "decision": "pending", "reviewer": "", "review_kind": None,
               "participated_in_development": None, "had_seen_questions_before_run": None, "gold_labels_validated": None,
               "correct": None, "relevant": None, "conditions_preserved": None, "citations_supported": None,
               "synthesis_correct": None, "notes": ""}
        if r["kind"] == "assessment":
            row["gold_fact_ids"] = [f["id"] for f in cases[r["id"]]["gold_facts"]]
            row["prediction_judgments"] = [{"prediction_id": p["id"], "supported": None, "gold_fact_id": None, "notes": ""} for p in r.get("predictions", [])]
        rows.append(row)
    return {"run_id": report["run_id"], "dataset_sha256": report["dataset_sha256"],
            "results_sha256": sha(json.dumps(report, ensure_ascii=False, sort_keys=True).encode()), "rows": rows}


def independent(row):
    return (row["decision"] == "reviewed" and isinstance(row.get("reviewer"), str) and bool(row["reviewer"].strip()) and
            row.get("review_kind") == "independent_human" and row.get("participated_in_development") is False and
            row.get("had_seen_questions_before_run") is False and row.get("gold_labels_validated") is True)


def timing(rows):
    times = sorted(r["elapsed_http_seconds"] for r in rows if r["status"] == "captured")
    return {"captured": len(times), "errors": sum(r["status"] == "error" for r in rows),
            "p50_seconds": statistics.median(times) if times else None,
            "p95_seconds_nearest_rank": times[math.ceil(.95 * len(times)) - 1] if times else None,
            "http_at_most_5s": sum(t <= 5 for t in times),
            "scope": "完整本机 HTTP 请求及响应读取；逐题计时不含历史轮次，历史另记；错误不计入低延迟成功样本"}


def summarize(report, reviews):
    if reviews["run_id"] != report["run_id"] or reviews["dataset_sha256"] != report["dataset_sha256"]:
        raise ValueError("复核文件与本轮结果不一致")
    if reviews.get("results_sha256") != sha(json.dumps(report, ensure_ascii=False, sort_keys=True).encode()):
        raise ValueError("结果内容已改变，不能沿用旧复核文件")
    if len({r["id"] for r in reviews["rows"]}) != len(reviews["rows"]): raise ValueError("复核题号重复")
    reviewed = {r["id"]: r for r in reviews["rows"]}
    active = [r for r in report["rows"] if r["status"] != "skipped"]
    if set(reviewed) != {r["id"] for r in active}: raise ValueError("复核题号与执行题单不一致")
    qa_rows = [r for r in active if r["kind"] in {"qa", "excerpt", "relations"}]
    dimensions = ("correct", "relevant", "conditions_preserved", "citations_supported", "synthesis_correct")
    eligible_qa = [r for r in qa_rows if independent(reviewed[r["id"]]) and all(isinstance(reviewed[r["id"]].get(k), bool) for k in dimensions)]
    qa_accuracy = None
    if report["source_stable"] and qa_rows and len(eligible_qa) == len(qa_rows):
        qa_accuracy = sum(r["status"] == "captured" and all(reviewed[r["id"]][k] for k in dimensions) for r in qa_rows) / len(qa_rows)
    # TP 要匹配经独立核对的金标事实；重复返回不能重复获得 TP。
    enrich_rows = [r for r in active if r["kind"] == "assessment"]
    tp = fp = fn = 0; enrich_complete = bool(enrich_rows)
    for r in enrich_rows:
        review = reviewed[r["id"]]; gold = {f["id"] for f in r["gold_facts"]}; matched = set()
        if set(review.get("gold_fact_ids", [])) != gold:
            raise ValueError("复核金标分母与冻结题单不一致")
        judgments = review.get("prediction_judgments", [])
        ids = {p["id"] for p in r.get("predictions", [])}
        if (not independent(review) or not gold or len(gold) != len(review.get("gold_fact_ids", [])) or
            len(judgments) != len(ids) or {j["prediction_id"] for j in judgments} != ids):
            enrich_complete = False; continue
        for j in judgments:
            if not isinstance(j["supported"], bool): enrich_complete = False; continue
            if j["supported"]:
                if j.get("gold_fact_id") not in gold or j["gold_fact_id"] in matched:
                    raise ValueError("金标映射未知或重复，不能重复计 TP")
                matched.add(j["gold_fact_id"]); tp += 1
            else: fp += 1
        fn += len(gold - matched)
    complete = report["source_stable"] and enrich_complete
    responses = [p for r in active for p in [r.get("response", {}), *[h["response"] for h in r["history"]]]]
    return {"run_id": report["run_id"], "baseline_commit": report["baseline_commit"], "mode": report["mode"],
            "configured_model_name": report.get("configured_model_name"),
            "model_attempted_requests_including_history": sum(bool(p.get("model_attempted")) for p in responses),
            "model_adopted_requests_including_history": sum(bool(p.get("used_model")) for p in responses),
            "source_stable": report["source_stable"], "planned_cases": len(report["rows"]), "captured_cases": sum(r["status"] == "captured" for r in active),
            "skipped_cases": len(report["rows"]) - len(active), "errors": sum(r["status"] == "error" for r in active),
            "automatic_checks_passed": sum(r.get("automatic_checks_passed", False) for r in active),
            "cases_needing_attention": [{"id": r["id"], "status": r["status"], "failures": r["failures"]} for r in active if not r.get("automatic_checks_passed")],
            "timing_by_kind": {k: timing([r for r in active if r["kind"] == k]) for k in sorted(KINDS)},
            "independent_qa_reviewed": len(eligible_qa), "qa_executed_denominator": len(qa_rows), "independent_qa_accuracy": qa_accuracy,
            "qa_by_stratum": {s: {"executed": len([r for r in qa_rows if r["stratum"] == s]),
                "independent_accuracy": (sum(r["status"] == "captured" and all(reviewed[r["id"]][k] for k in dimensions) for r in qa_rows if r["stratum"] == s) /
                    len([r for r in qa_rows if r["stratum"] == s])) if qa_accuracy is not None else None}
                for s in sorted({r["stratum"] for r in qa_rows})},
            "enrichment_scope": "仅本题单 CVSS/CPE 范围/向量条件与影响，不包括 PoC、资产或论文关联召回",
            "independent_enrichment_tp": tp if complete else None, "independent_enrichment_fp": fp if complete else None,
            "independent_enrichment_fn": fn if complete else None,
            "independent_enrichment_precision": tp / (tp + fp) if complete and tp + fp else None,
            "independent_enrichment_recall": tp / (tp + fn) if complete and tp + fn else None,
            "competition_passed": None}


def review_markdown(report, dataset):
    sources = {s["id"]: s for s in dataset["sources"]}; cases = {c["id"]: c for c in dataset["cases"]}
    lines = ["# 本轮来源与答案核对包", "", f"冻结版本：{report['baseline_commit']}；运行编号：{report['run_id']}", "",
             "参考要点由开发者编写；自动检查不等于语义正确。请核对原文和限定条件后填写同目录 manual_review.json。", ""]
    for row in report["rows"]:
        case = cases[row["id"]]
        lines += [f"## {row['id']} · {row['category']} · {row['status']}", "", case.get("question", "检查富化字段或审核图"), "", "参考核对要点：", ""]
        lines += ["- " + point for point in case["expected_points"]]
        lines += ["", "来源：", ""]
        lines += [f"- [{s}]({sources[s]['url']})；" + str(sources[s].get("content_scope", "NVD 存档字段")) for s in case["sources"]]
        lines += [f"- {s}：本轮[证据元数据](sources/{s}.json)及[原始快照](sources/{s}.snapshot)，摘要见 archive_manifest.json。" for s in case["sources"]]
        if row.get("predictions"):
            lines += ["", "从独立 NVD 快照投影并核对的金标候选（仍待独立验收）：", "", "```json", json.dumps(row["gold_facts"], ensure_ascii=False, indent=2), "```",
                      "", "富化事实与建议金标匹配（建议需复核）：", "", "```json", json.dumps(row["predictions"], ensure_ascii=False, indent=2), "```"]
        for turn in row["history"]:
            lines += ["", "历史轮问题：" + turn["question"], "", turn["response"].get("answer", "")]
        if "response" in row:
            lines += ["", "实际回答：", "", row["response"].get("answer", "本题为结构化接口，完整返回见 results.json。"), "", "原文证据：", ""]
            for e in row["response"].get("evidence_chunks" if row["kind"] == "qa" else "evidence", []):
                lines += ["[" + e["citation_id"] + "] · " + e.get("locator", ""), "", e.get("text", ""), ""]
        lines += ["", "自动检查提示：" + ("；".join(row["failures"]) or row.get("skip_reason", row.get("error_kind", "未发现结构性失败，语义仍待核对"))), ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--url", default="http://127.0.0.1:8023")
    parser.add_argument("--mode", choices=("rules", "model"), default="rules")
    parser.add_argument("--case", action="append")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--summarize", type=Path, help="既有结果目录；读取人工复核并汇总，不再次运行或调用模型")
    args = parser.parse_args()
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    if args.summarize:
        report = json.loads((args.summarize / "results.json").read_text(encoding="utf-8"))
        reviews = json.loads((args.summarize / "manual_review.json").read_text(encoding="utf-8"))
        print(json.dumps(summarize(report, reviews), ensure_ascii=False, indent=2)); return
    target = args.output_dir or ROOT / "data" / "acceptance-round1" / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + args.mode)
    if target.exists() and any(target.iterdir()): raise ValueError("输出目录非空，不覆盖既有评测/复核记录")
    validate_base(args.url); validate_dataset(dataset); verify_baseline(dataset)
    source_manifest(args.url, dataset)
    archive_sources(dataset, target)
    report = run(args.url, dataset, args.mode, args.case)
    reviews = review_template(report, dataset); summary = summarize(report, reviews)
    target.mkdir(parents=True, exist_ok=True)
    for name, data in (("results.json", report), ("manual_review.json", reviews), ("summary.json", summary)):
        (target / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (target / "来源与答案核对.md").write_text(review_markdown(report, dataset), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    if not report["source_stable"] or any(r["status"] == "error" or r.get("automatic_checks_passed") is False for r in report["rows"]):
        raise SystemExit(1)


if __name__ == "__main__": main()
