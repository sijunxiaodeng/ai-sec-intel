"""Read-only source/category coverage and observed strict six-hour evidence.

Polling health, content coverage and publication latency are independent facts.
No successful empty poll, historical backfill or imprecise date proves an SLA.
"""
from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime, timezone

from .metrics import parse_timestamp

REQUIRED_CATEGORY_COUNT = 7
STRICT_DEADLINE_SECONDS = 6 * 3600
SOURCE_CATEGORIES = frozenset({
    "vulnerability_database", "security_community", "vendor_advisory", "security_blog",
    "academic_paper", "technical_standard", "policy_regulation", "government_alert",
})


def _rows(con, sql, params=()):
    cursor = con.execute(sql, params)
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _summary(seconds):
    values = sorted(seconds)
    def percentile(fraction):
        return round(values[math.ceil(len(values) * fraction) - 1] / 3600, 6) if values else None
    return {
        "samples": len(values),
        "p50_hours": percentile(.50),
        "p95_hours": percentile(.95),
        "max_hours": round(values[-1] / 3600, 6) if values else None,
        "max_seconds": values[-1] if values else None,
        "under_6h": sum(value < STRICT_DEADLINE_SECONDS for value in values),
        "breached_6h": sum(value >= STRICT_DEADLINE_SECONDS for value in values),
    }


def _latency(records, source, baseline, now):
    live, historical = [], []
    excluded = {"missing_or_imprecise_time": 0, "negative_delay": 0,
                "future_timestamp": 0, "missing_baseline": 0, "invalid_payload": 0}
    unknown_live = 0
    for row in records:
        try:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                raise ValueError("payload is not an object")
        except (ValueError, TypeError):
            excluded["invalid_payload"] += 1
            unknown_live += 1
            continue
        seen = parse_timestamp(row.get("first_seen_at"))
        published = None if source == "CISA_KEV" else parse_timestamp(
            row.get("published_at", payload.get("published_at")), nvd_utc=source == "NVD")
        if published is None or seen is None:
            excluded["missing_or_imprecise_time"] += 1
            if baseline is None or seen is None or seen >= baseline:
                unknown_live += 1
            continue
        if seen > now or published > now:
            excluded["future_timestamp"] += 1
            unknown_live += 1
            continue
        delay = (seen - published).total_seconds()
        if delay < 0:
            excluded["negative_delay"] += 1
            unknown_live += 1
            continue
        historical.append(delay)
        if baseline is None:
            excluded["missing_baseline"] += 1
            unknown_live += 1
        elif published >= baseline and seen >= baseline:
            live.append(delay)
    summary = _summary(live)
    if summary["breached_6h"]:
        evidence = "breached"
    elif not live or unknown_live:
        evidence = "insufficient_samples"
    else:
        evidence = "observed_samples_under_6h"
    return {
        "monitored_since": baseline.isoformat() if baseline else None,
        "live": summary,
        "all_observed_including_backfill": _summary(historical),
        "excluded": excluded,
        "unknown_live_timing": unknown_live,
        "sla_evidence": evidence,
    }


def _freshness(runs, now, threshold):
    # A failure may reuse the whole source/cycle's start timestamp, while its
    # preceding successful window started later. In each table the committed
    # row ID, rather than attempt time, identifies the last terminal event.
    # For sources present in both tables, compare their latest completion times.
    def latest_terminal(candidates):
        by_table = {}
        for row in candidates:
            table = row.get("run_table", "default")
            if table not in by_table or row["id"] > by_table[table]["id"]:
                by_table[table] = row
        return max(by_table.values(), key=lambda row: (
            parse_timestamp(row.get("finished_at")) or datetime.max.replace(tzinfo=timezone.utc),
            row["id"])) if by_table else None
    latest = latest_terminal(runs)
    latest_success = latest_terminal([row for row in runs if row.get("status") == "success"])
    last_success_at = (latest_success or {}).get("finished_at")
    stamp = parse_timestamp(last_success_at)
    age = (now - stamp).total_seconds() if stamp else None
    status = (latest or {}).get("status") or "never_run"
    timed_out = "timeout" in str((latest or {}).get("error_text") or "").lower() or "timed out" in str((latest or {}).get("error_text") or "").lower()
    if latest is None:
        health = "never_run"
    elif status != "success":
        health = "timeout" if timed_out else "failed" if status == "failed" else "unknown"
    elif age is None or age < 0:
        health = "unknown"
    elif age > threshold:
        health = "stale"
    else:
        health = "fresh"
    return {
        "status": health,
        "healthy": health == "fresh",
        "latest_run_status": status,
        "last_attempt_at": (latest or {}).get("started_at"),
        "last_finished_at": (latest or {}).get("finished_at"),
        "last_success_at": last_success_at,
        "seconds_since_success": age,
        "freshness_limit_seconds": threshold,
        "latest_fetched_count": (latest or {}).get("fetched_count"),
        "timed_out": timed_out,
    }


def coverage_report(con: sqlite3.Connection, specs, *, now=None, poll_minutes=15,
                    source_timeout_seconds=120, worker_count=4, classifier_version=None) -> dict:
    """Describe enabled source specs using persisted evidence, without writes.

    CVE AI coverage requires a current hash/version-matched classified positive.
    Documents are locally filtered topical candidates; this is not a measured
    AI classification accuracy. Explicit negative admission metadata is honored.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif isinstance(now, str):
        now = parse_timestamp(now)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if (isinstance(poll_minutes, bool) or isinstance(source_timeout_seconds, bool)
            or not math.isfinite(poll_minutes) or poll_minutes <= 0
            or not math.isfinite(source_timeout_seconds) or source_timeout_seconds < 0):
        raise ValueError("poll interval must be positive and timeout nonnegative")
    if isinstance(worker_count, bool) or not isinstance(worker_count, int) or worker_count <= 0:
        raise ValueError('worker_count must be a positive integer')
    tables = {row["name"] for row in _rows(con, "SELECT name FROM sqlite_master WHERE type='table'")}
    configured, skipped = {}, []
    for spec in specs:
        name = getattr(spec, "name", None)
        category = getattr(spec, "category", None)
        if not getattr(spec, "enabled", True):
            skipped.append({"source": name, "category": category, "reason": "disabled"})
            continue
        if not isinstance(name, str) or not name.strip() or not isinstance(category, str) or not category.strip():
            skipped.append({"source": name, "category": category, "reason": "invalid_identity"})
            continue
        name, category = name.strip(), category.strip().lower()
        if category not in SOURCE_CATEGORIES:
            skipped.append({"source": name, "category": category, "reason": "unknown_category"})
            continue
        if name in configured:
            skipped.append({"source": name, "category": category, "reason": "duplicate_source_spec"})
            continue
        configured[name] = category

    records = {name: [] for name in configured}
    runs = {name: [] for name in configured}
    counts = {name: {"source_records": 0, "ai_records": 0} for name in configured}
    unregistered, mismatched = set(), 0
    positive_cves = set()
    if classifier_version and {"ai_classifications", "unified_vulnerabilities"} <= tables:
        positive_cves = {row["cve_id"] for row in _rows(con, """
            SELECT v.cve_id FROM unified_vulnerabilities v
            JOIN ai_classifications a ON a.cve_id=v.cve_id
              AND a.content_sha256=v.content_sha256
            WHERE a.classifier_version=? AND a.state='classified' AND a.ai_related=1
        """, (classifier_version,))}
    ai_cves_by_source = {name: set() for name in configured}
    if "source_items" in tables:
        for row in _rows(con, "SELECT source,cve_id,payload_json,first_seen_at FROM source_items"):
            name = row["source"]
            if name not in configured:
                unregistered.add(name)
                continue
            counts[name]["source_records"] += 1
            records[name].append(row)
            if row["cve_id"] in positive_cves:
                ai_cves_by_source[name].add(row["cve_id"])
    for name, cves in ai_cves_by_source.items():
        counts[name]["ai_records"] += len(cves)
    if "knowledge_documents" in tables:
        for row in _rows(con, """SELECT source,source_category,payload_json,published_at,first_seen_at
                               FROM knowledge_documents"""):
            name = row["source"]
            if name not in configured:
                unregistered.add(name)
                continue
            if row["source_category"] != configured[name]:
                mismatched += 1
                continue
            counts[name]["source_records"] += 1
            records[name].append(row)
            try:
                payload = json.loads(row["payload_json"])
                raw = payload.get("raw_data") or {}
                if not isinstance(payload, dict) or not isinstance(raw, dict):
                    raise ValueError("invalid document payload")
                if raw.get("ai_security_related") is not False:
                    counts[name]["ai_records"] += 1
            except (ValueError, TypeError, AttributeError):
                pass
    if "collector_runs" in tables:
        for row in _rows(con, """SELECT 'collector_runs' AS run_table,id,collector AS source,started_at,finished_at,status,
                                        fetched_count,error_text FROM collector_runs"""):
            if row["source"] in configured:
                runs[row["source"]].append(row)
    if "document_source_runs" in tables:
        for row in _rows(con, """SELECT 'document_source_runs' AS run_table,id,source,source_category,started_at,finished_at,status,
                                        fetched_count,error_text FROM document_source_runs"""):
            if row["source"] in configured and row["source_category"] == configured[row["source"]]:
                runs[row["source"]].append(row)
    baselines = {}
    if "source_observation_baselines" in tables:
        for row in _rows(con, "SELECT source,source_category,started_at FROM source_observation_baselines"):
            if row["source"] in configured and row["source_category"] == configured[row["source"]]:
                baselines[row["source"]] = parse_timestamp(row["started_at"])
    categories = sorted(set(configured.values()))
    cycle_budget = math.ceil(len(configured) / worker_count) * source_timeout_seconds + 90
    threshold = poll_minutes * 60 + cycle_budget + 60
    observed = sorted({configured[name] for name, count in counts.items() if count["source_records"]})
    ai_observed = sorted({configured[name] for name, count in counts.items() if count["ai_records"]})
    freshness = {name: _freshness(runs[name], now, threshold) for name in configured}
    latency = {name: _latency(records[name], name, baselines.get(name), now) for name in configured}
    total_samples = sum(data["live"]["samples"] for data in latency.values())
    violations = sum(data["live"]["breached_6h"] for data in latency.values())
    unknown = sum(data["unknown_live_timing"] for data in latency.values())
    evidence = "breached" if violations else "insufficient_samples" if not total_samples or unknown else "observed_samples_under_6h"
    return {
        "checked_at": now.isoformat(),
        "polling_configuration": {"interval_minutes": poll_minutes, "worker_count": worker_count,
                                  "source_timeout_seconds": source_timeout_seconds,
                                  "worst_case_cycle_seconds": cycle_budget},
        "required_category_count": REQUIRED_CATEGORY_COUNT,
        "configured_categories": categories,
        "configured_category_count": len(categories),
        "observed_source_categories": observed,
        "observed_source_category_count": len(observed),
        "observed_ai_categories": ai_observed,
        "observed_ai_category_count": len(ai_observed),
        "missing_categories": sorted(set(categories) - set(ai_observed)),
        "required_categories_configured": len(categories) >= REQUIRED_CATEGORY_COUNT,
        "required_categories_observed": len(ai_observed) >= REQUIRED_CATEGORY_COUNT,
        "counts_by_source": counts,
        "freshness_by_source": freshness,
        "all_sources_fresh": bool(freshness) and all(item["healthy"] for item in freshness.values()),
        "per_source_live_latency": latency,
        "strict_deadline_seconds": STRICT_DEADLINE_SECONDS,
        "live_precise_samples": total_samples,
        "violations_ge_6h": violations,
        "unknown_live_timing": unknown,
        "sla_evidence": evidence,
        "all_sources_have_precise_live_samples": bool(latency) and all(item["live"]["samples"] for item in latency.values()),
        "skipped_sources": skipped,
        "skipped_categories": sorted({item["category"] for item in skipped if isinstance(item["category"], str)}),
        "unregistered_sources": sorted(unregistered),
        "mismatched_document_categories": mismatched,
        "missing_evidence_tables": sorted({"source_items", "knowledge_documents", "collector_runs",
                                            "document_source_runs", "source_observation_baselines"} - tables),
        "note": ("类别按真实内容来源计数，空轮询不增加覆盖。CVE AI 覆盖仅计当前有效已完成分类正例；"
                 "文档为来源采集器本地过滤的主题候选，未表示测得的准确率。严格时效使用原始秒数 <21600，"
                 "时效按每源首次入库记录计算，包含未完成 AI 分类记录，不衡量分类或问答可用时间。"
                 "历史回填和不精确时间不能证明实时达标。基线只是观察起点，不证明连续运行；"
                 "已观察样本不能保证所有未知、漏采或上游迟发布内容以及未来时效。"),
    }
