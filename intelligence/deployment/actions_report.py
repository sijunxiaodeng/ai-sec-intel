"""Read-only cloud facts: acquisition latency, classification and model execution.

The immutable first-cloud-run boundary is an additional report, never a new
monitoring baseline. Public notices contain only allowlisted states and numbers.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unicodedata
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api_v6.repository import current_classifier_version
from deployment.actions_state import GitHubClient
from monitoring.coverage import coverage_report
from monitoring.metrics import baseline, latency_report, parse_timestamp
from monitoring.source_registry import get_sources

DEFAULT_CLOUD_STARTED_AT = "2026-10-09T12:05:16Z"
REPORT_FILE = "actions_report.json"
MODEL_FILE = "deepseek_status.json"
MAX_JSON_BYTES = 1024 * 1024
MODEL_STATUSES = frozenset({"success", "partial", "failed", "timeout", "skipped"})
MODEL_REASONS = frozenset({
    "completed", "no_candidates", "disabled", "missing_api_key", "classification_locked",
    "wall_timeout", "authentication_failed", "rate_limited", "request_timeout",
    "provider_unavailable", "invalid_response", "request_error", "processing_error",
    "invalid_configuration", "progress_unavailable", "progress_invalid",
})
STEP_OUTCOMES = frozenset({"success", "failure", "cancelled", "skipped", "unknown"})
SOURCE_STATUSES = frozenset({"success", "partial", "failed", "skipped"})
SOURCE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")


def _number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _timestamp(value):
    stamp = parse_timestamp(value)
    return stamp.isoformat() if stamp else None


def _json(path):
    if path.is_symlink() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("Invalid report input file")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Report input must be an object")
    return data


def _atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".actions_report_", delete=False) as output:
            temporary = Path(output.name)
            json.dump(data, output, ensure_ascii=False, indent=2)
            output.write("\n")
        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def escape_workflow_data(value):
    """Escape GitHub command data, including control characters and percent signs."""
    value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return "".join("".join(f"%{byte:02X}" for byte in char.encode("utf-8"))
                   if unicodedata.category(char) == "Cc" else char for char in value)


def model_facts(directory, run_id):
    """A restored old model status is never evidence of this run's execution."""
    result = {"status": "not_executed", "provider": "deepseek", "model": None,
              "run_id": str(run_id), "has_current_run_record": False,
              "semantic_calls": 0, "semantic_success": 0, "retry": 0,
              "max_llm_calls": None, "started_at": None, "finished_at": None,
              "committed_classifications": None, "committed_retries": None,
              "reason_category": "missing_status_file"}
    try:
        status = _json(Path(directory) / MODEL_FILE)
    except FileNotFoundError:
        return result
    except (OSError, ValueError, TypeError):
        result["reason_category"] = "invalid_status_file"
        return result
    if str(status.get("run_id")) != str(run_id):
        result["reason_category"] = "stale_run"
        return result
    if status.get("status") not in MODEL_STATUSES or status.get("provider") != "deepseek":
        result["reason_category"] = "invalid_status_file"
        return result
    result["has_current_run_record"] = True
    result["status"] = status["status"]
    result["reason_category"] = (status.get("reason_category")
                                 if status.get("reason_category") in MODEL_REASONS else "unknown_reason")
    model = status.get("model")
    if isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", model) and not model.startswith(("sk-", "ghp_", "github_pat_")):
        result["model"] = model
    for name in ("semantic_calls", "semantic_success", "retry", "max_llm_calls",
                 "committed_classifications", "committed_retries"):
        result[name] = _number(status.get(name))
    result["started_at"] = _timestamp(status.get("started_at"))
    result["finished_at"] = _timestamp(status.get("finished_at"))
    return result


class _LatencyRows:
    """Read-only projection guards malformed/future rows before existing metrics."""
    def __init__(self, connection, now):
        self.rows = []
        self.excluded = {"invalid_payload": 0, "future_timestamp": 0}
        for row in connection.execute("SELECT payload_json, first_seen_at FROM unified_vulnerabilities"):
            try:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict):
                    raise ValueError("Invalid payload")
            except (ValueError, TypeError):
                self.excluded["invalid_payload"] += 1
                continue
            source = payload.get("publication_source")
            seen = parse_timestamp(row["first_seen_at"])
            published = (None if source == "CISA_KEV" or payload.get("sources") == ["CISA_KEV"]
                         else parse_timestamp(payload.get("published_at"), nvd_utc=source == "NVD"))
            if (seen is not None and seen > now) or (published is not None and published > now):
                self.excluded["future_timestamp"] += 1
                continue
            self.rows.append({"payload_json": row["payload_json"], "first_seen_at": row["first_seen_at"]})

    def execute(self, query):
        if query != "SELECT payload_json, first_seen_at FROM unified_vulnerabilities":
            raise ValueError("Latency projection only permits its read-only query")
        return iter(self.rows)


def _period(rows, start, *, rolling=False):
    report = latency_report(rows, start)
    summary = report["continuous_monitoring"]
    evidence = ("breached" if summary["breached_6h"] else "insufficient_samples"
                if not summary["samples"] else "observed_samples_under_6h")
    return {"monitored_since": report["monitored_since"], "summary": summary,
            "excluded": {**report["excluded"], **rows.excluded}, "evidence": evidence,
            "rolling_window": rolling}


def classification_facts(connection, version):
    total = connection.execute("SELECT COUNT(*) FROM unified_vulnerabilities").fetchone()[0]
    fields = {"total_cves": total, "valid_current": 0, "classified": 0, "review": 0,
              "rule": 0, "semantic": 0, "semantic_classified": 0, "semantic_review": 0,
              "pending_llm": 0, "retry": 0, "unclassified_or_stale": total,
              "classified_ai_positive": 0, "classifier_version": version, "status": "ok"}
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "ai_classifications" not in tables or version is None:
        return fields
    for row in connection.execute("""
        SELECT a.state, a.decision_source, a.ai_related, COUNT(*) AS n
        FROM unified_vulnerabilities v JOIN ai_classifications a ON a.cve_id=v.cve_id
        WHERE a.content_sha256=v.content_sha256 AND a.classifier_version=?
        GROUP BY a.state, a.decision_source, a.ai_related
    """, (version,)):
        state, source, n = row["state"], row["decision_source"], row["n"]
        if state not in {"classified", "review", "pending_llm", "retry"}:
            continue
        fields["valid_current"] += n
        fields[state] += n
        if state == "classified" and source in {"rule_positive", "rule_negative", "rule"}:
            fields["rule"] += n
        if state in {"classified", "review"} and source == "semantic_judge":
            fields["semantic"] += n
            fields["semantic_" + state] += n
        if state == "classified" and row["ai_related"] == 1:
            fields["classified_ai_positive"] += n
    fields["unclassified_or_stale"] = total - fields["valid_current"]
    return fields


def schedule_facts(client, run_id, *, workflow="intelligence-collect.yml", branch="main"):
    result = {"status": "unknown", "reason_category": "github_metadata_unavailable",
              "configured_interval_seconds": 900, "current_run": None, "previous_completed_run": None,
              "creation_interval_seconds": None, "start_interval_seconds": None,
              "current_start_delay_seconds": None}
    if client is None:
        result["reason_category"] = "github_metadata_not_configured"
        return result
    try:
        current = client.run(int(run_id))
        if str(current.get("id")) != str(run_id) or current.get("head_branch") != branch:
            result["reason_category"] = "github_metadata_invalid"
            return result
        def safe_run(value):
            return {"run_id": _number(value.get("id")),
                    "event": value.get("event") if value.get("event") in {"schedule", "workflow_dispatch"} else "unknown",
                    "created_at": _timestamp(value.get("created_at")),
                    "run_started_at": _timestamp(value.get("run_started_at"))}
        result["current_run"] = safe_run(current)
        current_created = parse_timestamp(result["current_run"]["created_at"])
        current_started = parse_timestamp(result["current_run"]["run_started_at"])
        if current_created is None:
            result["reason_category"] = "github_metadata_invalid"
            return result
        if current_started and current_started >= current_created:
            result["current_start_delay_seconds"] = (current_started - current_created).total_seconds()
        candidates = []
        for index, item in enumerate(client.runs(workflow, branch)):
            if index >= 100:
                break
            created = parse_timestamp(item.get("created_at"))
            if (str(item.get("id")) != str(run_id) and item.get("head_branch") == branch
                    and item.get("event") in {"schedule", "workflow_dispatch"}
                    and created is not None and created < current_created):
                candidates.append(item)
                # GitHub returns runs newest first. Only one page is needed.
                break
        if candidates:
            previous = safe_run(candidates[0])
            result["previous_completed_run"] = previous
            result["creation_interval_seconds"] = (current_created - parse_timestamp(previous["created_at"])).total_seconds()
            previous_started = parse_timestamp(previous["run_started_at"])
            if current_started and previous_started and current_started >= previous_started:
                result["start_interval_seconds"] = (current_started - previous_started).total_seconds()
        result.update(status="ok", reason_category="observed" if candidates else "no_previous_completed_run")
    except Exception:
        # Metadata failure must not interrupt collection backups or leak an API body.
        result["status"] = "unknown"
        result["reason_category"] = "github_metadata_unavailable"
    return result


def source_facts(directory, specs, coverage, schedule):
    try:
        status = _json(Path(directory) / "monitoring_status.json")
    except (OSError, ValueError, TypeError):
        status = {}
    finished = _timestamp(status.get("finished_at"))
    current_started = _timestamp(os.getenv("COLLECTION_STARTED_AT")) or (
        (schedule.get("current_run") or {}).get("run_started_at"))
    scope = "latest_completed_collection"
    if finished and current_started:
        scope = "current_run" if parse_timestamp(finished) >= parse_timestamp(current_started) else "previous_run"
    raw_sources = status.get("sources") if isinstance(status.get("sources"), dict) else {}
    values = {}
    for spec in specs:
        if not SOURCE_NAME.fullmatch(spec.name) or not spec.enabled:
            continue
        item = raw_sources.get(spec.name)
        item = item if isinstance(item, dict) else {}
        values[spec.name] = {
            "category": spec.category,
            "status": item.get("status") if item.get("status") in SOURCE_STATUSES else "unknown",
            "recent_success": item.get("recent_success") if isinstance(item.get("recent_success"), bool) else None,
            "pending_backfill": item.get("pending") if isinstance(item.get("pending"), bool) else None,
            "source_records": (coverage.get("counts_by_source", {}).get(spec.name) or {}).get("source_records"),
            "ai_candidate_records": (coverage.get("counts_by_source", {}).get(spec.name) or {}).get("ai_records"),
        }
    return {"status": status.get("status") if status.get("status") in SOURCE_STATUSES else "unknown",
            "observation_scope": scope, "started_at": _timestamp(status.get("started_at")), "finished_at": finished,
            "failed": sum(row["status"] == "failed" for row in values.values()),
            "partial": sum(row["status"] == "partial" for row in values.values()),
            "unknown": sum(row["status"] == "unknown" for row in values.values()), "by_source": values}


def _code_sha(root):
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                                text=True, timeout=3, check=True)
        value = result.stdout.strip()
        return value if re.fullmatch(r"[0-9a-f]{40}", value) else None
    except (OSError, subprocess.SubprocessError):
        return None


def build_report(directory, *, run_id, root=ROOT, now=None, cloud_started_at=DEFAULT_CLOUD_STARTED_AT,
                 version=None, specs=None, client=None, workflow="intelligence-collect.yml"):
    now = now or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("Report time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    directory, root = Path(directory), Path(root)
    specs = list(get_sources() if specs is None else specs)
    version = current_classifier_version(root) if version is None else version
    schedule = schedule_facts(client, run_id, workflow=workflow)
    report = {"format_version": 1, "run_id": str(run_id), "recorded_at": now.isoformat(),
              "collector_sha": _code_sha(root), "schedule": schedule,
              "model": model_facts(directory, run_id),
              "latency": {"status": "unavailable", "reason_category": "database_unavailable",
                          "unit": "unique_cve", "strict_deadline_seconds": 21600},
              "classification": {"status": "unavailable"}, "coverage": {"status": "unavailable"}}
    coverage = {}
    try:
        uri = (directory / "intelligence.db").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            rows = _LatencyRows(connection, now)
            cloud_start = _timestamp(cloud_started_at)
            report["latency"] = {
                "status": "ok", "reason_category": "observed", "unit": "unique_cve",
                "strict_deadline_seconds": 21600,
                "full_observation_period": _period(rows, baseline(root, state_dir=directory)),
                "since_cloud_deployment": _period(rows, cloud_start),
                "last_24h": _period(rows, (now - timedelta(hours=24)).isoformat(), rolling=True),
                "cloud_boundary_valid": cloud_start is not None and parse_timestamp(cloud_start) <= now,
            }
            report["classification"] = classification_facts(connection, version)
            coverage = coverage_report(connection, specs, now=now, classifier_version=version)
            report["coverage"] = {
                "status": "ok", "unit": "source_records_including_duplicates_and_documents",
                "configured_category_count": coverage["configured_category_count"],
                "observed_ai_category_count": coverage["observed_ai_category_count"],
                "per_source_precise_samples": coverage["live_precise_samples"],
                "per_source_delayed_records": coverage["violations_ge_6h"],
                "unknown_source_timing": coverage["unknown_live_timing"],
            }
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError):
        # Failed diagnostics do not initialize a DB or block its durable snapshot.
        pass
    report["sources"] = source_facts(directory, specs, coverage, schedule)
    return report


def _period_number(report, period, field):
    return _number(((report.get("latency") or {}).get(period) or {}).get("summary", {}).get(field))


def notice_line(report):
    model = report.get("model") or {}
    sources = report.get("sources") or {}
    fields = {
        "cve_samples": _period_number(report, "full_observation_period", "samples"),
        "breach": _period_number(report, "full_observation_period", "breached_6h"),
        "cloud_samples": _period_number(report, "since_cloud_deployment", "samples"),
        "cloud_breach": _period_number(report, "since_cloud_deployment", "breached_6h"),
        "recent_samples": _period_number(report, "last_24h", "samples"),
        "recent_breach": _period_number(report, "last_24h", "breached_6h"),
        "pending_llm": _number((report.get("classification") or {}).get("pending_llm")),
        "deepseek_status": model.get("status") if model.get("status") in MODEL_STATUSES | {"not_executed"} else "unknown",
        "model_attempts": _number(model.get("semantic_calls")),
        "model_accepted": _number(model.get("semantic_success")),
        "model_committed": _number(model.get("committed_classifications")),
        "model_retries": _number(model.get("committed_retries")),
        "model_reason": model.get("reason_category") if model.get("reason_category") in MODEL_REASONS | {
            "missing_status_file", "invalid_status_file", "stale_run", "unknown_reason"} else "unknown_reason",
        "source_failed": _number(sources.get("failed")),
        "source_partial": _number(sources.get("partial")),
        "source_unknown": _number(sources.get("unknown")),
        "source_scope": sources.get("observation_scope") if sources.get("observation_scope") in {
            "current_run", "previous_run", "latest_completed_collection"} else "unknown",
        "schedule_gap_s": (report.get("schedule") or {}).get("creation_interval_seconds"),
        "collector_sha": report.get("collector_sha") if isinstance(report.get("collector_sha"), str)
                         and re.fullmatch(r"[0-9a-f]{40}", report["collector_sha"]) else None,
    }
    if not isinstance(fields["schedule_gap_s"], (int, float)) or isinstance(fields["schedule_gap_s"], bool):
        fields["schedule_gap_s"] = None
    message = " ".join(f"{key}={value if value is not None else 'unknown'}" for key, value in fields.items())
    return "::notice title=B cloud facts::" + escape_workflow_data(message)


def render_summary(report, *, run_id, collection_outcome="unknown", snapshot_outcome="unknown"):
    collection = collection_outcome if collection_outcome in STEP_OUTCOMES else "unknown"
    snapshot = snapshot_outcome if snapshot_outcome in STEP_OUTCOMES else "unknown"
    lines = ["## B 云端事实报告", f"采集步骤：{collection}；状态备份：{snapshot}。"]
    if (not isinstance(report, dict) or report.get("format_version") != 1
            or str(report.get("run_id")) != str(run_id)):
        lines.append("当前运行的事实报告缺失、无效或属于旧运行；本轮时效、分类和模型执行均为未知，未复用上一轮结果。")
        return "\n\n".join(lines) + "\n"
    lines.append(f"报告生成时间（UTC）：{_timestamp(report.get('recorded_at')) or '未知'}。")
    sha = report.get("collector_sha")
    if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha):
        lines.append(f"实际 B 代码提交：`{sha}`。")
    rows = ["| 独立 CVE 统计范围 | 起点（UTC） | 精确样本 | 延迟 ≥6h |", "|---|---|---:|---:|"]
    for label, key in [("原始全观察期（保留历史）", "full_observation_period"),
                       ("首次云端部署后", "since_cloud_deployment"), ("最近24小时（滚动子集）", "last_24h")]:
        period = (report.get("latency") or {}).get(key) or {}
        start = _timestamp(period.get("monitored_since")) or "未知"
        samples, breach = _period_number(report, key, "samples"), _period_number(report, key, "breached_6h")
        rows.append(f"| {label} | {start} | {samples if samples is not None else '未知'} | {breach if breach is not None else '未知'} |")
    lines.append("\n".join(rows))
    lines.append("时效从来源发布到首次实际入库计时，按去重后的 CVE 统计，严格要求 <6h；不包括模型分类耗时。首次云端部署后和最近24小时是附加子集，不替代整体指标，也不删除历史超限；零超限样本不能证明漏采、未知时间或未来均达标。")
    classification = report.get("classification") or {}
    def count(field):
        value = _number(classification.get(field))
        return value if value is not None else "未知"
    lines.append(f"当前内容哈希及分类器版本匹配的结果：classified={count('classified')}，规则完成={count('rule')}，语义已接受（含待复核）={count('semantic')}，review={count('review')}，pending_llm={count('pending_llm')}，retry={count('retry')}，未分类或过期={count('unclassified_or_stale')}。规则完成和 DeepSeek 执行是不同事实。")
    model = report.get("model") or {}
    status = model.get("status") if model.get("status") in MODEL_STATUSES | {"not_executed"} else "unknown"
    reason = model.get("reason_category") if model.get("reason_category") in MODEL_REASONS | {
        "missing_status_file", "invalid_status_file", "stale_run", "unknown_reason"} else "unknown_reason"
    attempted, accepted = _number(model.get("semantic_calls")), _number(model.get("semantic_success"))
    lines.append(f"本轮 DeepSeek 状态：{status}；原因类别：{reason}；尝试={attempted if attempted is not None else '未知'}，通过响应校验={accepted if accepted is not None else '未知'}。只使用本轮 run_id 的模型记录；通过响应校验不等于所有结果已落库或免人工复核。模型失败不等于采集迟于六小时。")
    coverage = report.get("coverage") or {}
    lines.append(f"独立来源/文档覆盖：配置类别={_number(coverage.get('configured_category_count'))}；已有 AI 内容候选类别={_number(coverage.get('observed_ai_category_count'))}；逐源精确记录={_number(coverage.get('per_source_precise_samples'))}；逐源延迟记录={_number(coverage.get('per_source_delayed_records'))}。此栏目包含跨源重复 CVE、论文及其他文档，不能当作独立 CVE 违约数或分类准确率。")
    sources = report.get("sources") or {}
    scope = sources.get("observation_scope")
    scope_text = {"current_run": "已核对为当前运行", "previous_run": "上一轮完整结果，不能冒充本轮",
                  "latest_completed_collection": "最近完整结果，运行归属尚未核实"}.get(scope, "未知")
    rows = [f"最新完整采集状态：{scope_text}，完成时间（UTC）：{_timestamp(sources.get('finished_at')) or '未知'}。",
            "| 来源 | 状态 | 近期发布阶段成功 | 历史回填待处理 |", "|---|---|---|---|"]
    for name, item in sorted((sources.get("by_source") or {}).items()):
        if not isinstance(name, str) or not SOURCE_NAME.fullmatch(name) or not isinstance(item, dict):
            continue
        source_status = item.get("status") if item.get("status") in SOURCE_STATUSES else "unknown"
        boolean = lambda value: "是" if value is True else "否" if value is False else "未知/不适用"
        rows.append(f"| {name} | {source_status} | {boolean(item.get('recent_success'))} | {boolean(item.get('pending_backfill'))} |")
    lines.append("\n".join(rows))
    lines.append("NVD/GitHub 的 partial + 近期发布成功 + 回填待处理，表示近期采集已完成而历史补采尚未完成，不能直接解释为新漏洞采集失败。")
    schedule = report.get("schedule") or {}
    current, previous = schedule.get("current_run") or {}, schedule.get("previous_completed_run") or {}
    gap = schedule.get("creation_interval_seconds")
    if isinstance(gap, (int, float)) and not isinstance(gap, bool) and gap >= 0:
        lines.append(f"实际运行创建间隔：{gap} 秒；当前事件={current.get('event') if current.get('event') in {'schedule', 'workflow_dispatch'} else 'unknown'}（{_timestamp(current.get('created_at')) or '未知'}），上一次完成运行事件={previous.get('event') if previous.get('event') in {'schedule', 'workflow_dispatch'} else 'unknown'}（{_timestamp(previous.get('created_at')) or '未知'}）。手动运行间隔不能当作定时调度表现。")
    else:
        lines.append("实际运行间隔尚无可用 GitHub 元数据，记为未知；不会用配置的15分钟代替实测。")
    lines.append("GitHub 任务可能排队、延迟或被平台停用；本报告描述已观察事实，不保证连续在线或未来六小时时效。")
    return "\n\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("record", "summary"))
    parser.add_argument("--directory", default=str(ROOT / "data"))
    parser.add_argument("--run-id", default=os.getenv("GITHUB_RUN_ID"))
    parser.add_argument("--workflow", default="intelligence-collect.yml")
    parser.add_argument("--cloud-started-at", default=os.getenv("CLOUD_COLLECTION_STARTED_AT", DEFAULT_CLOUD_STARTED_AT))
    args = parser.parse_args(argv)
    if not args.run_id or not re.fullmatch(r"[0-9]+", str(args.run_id)):
        parser.error("A numeric current run ID is required")
    directory = Path(args.directory)
    if args.command == "record":
        client = None
        try:
            if os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPOSITORY"):
                client = GitHubClient(os.getenv("GITHUB_TOKEN"), os.getenv("GITHUB_REPOSITORY"),
                                      os.getenv("GITHUB_API_URL", "https://api.github.com"))
            report = build_report(directory, run_id=args.run_id, client=client,
                                  cloud_started_at=args.cloud_started_at, workflow=args.workflow)
            _atomic_json(directory / REPORT_FILE, report)
        except Exception:
            report = {"run_id": str(args.run_id), "reason_category": "report_unavailable"}
        print(notice_line(report), flush=True)
        return 0  # Diagnostics never prevent preserving already collected state.
    try:
        report = _json(directory / REPORT_FILE)
    except (OSError, ValueError, TypeError):
        report = None
    summary = render_summary(report, run_id=args.run_id,
                             collection_outcome=os.getenv("COLLECTION_OUTCOME", "unknown"),
                             snapshot_outcome=os.getenv("SNAPSHOT_OUTCOME", "unknown"))
    destination = os.getenv("GITHUB_STEP_SUMMARY")
    if destination:
        with open(destination, "a", encoding="utf-8") as output:
            output.write(summary)
    else:
        print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
