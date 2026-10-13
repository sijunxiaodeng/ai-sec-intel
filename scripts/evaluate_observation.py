"""Read-only, fixed-window collection evidence and independent label metrics.

This program does not collect data, call models, migrate databases, or certify
an SLA. A database only contains observed records; missing upstream records
require a separately frozen upstream sample to measure recall.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import sqlite3

DEADLINE_SECONDS = 21600


def timestamp(value, *, nvd_utc=False):
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        if not nvd_utc:
            return None
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def required_timestamp(value, name):
    stamp = timestamp(value)
    if stamp is None:
        raise ValueError(f"{name} requires a precise timestamp with timezone")
    return stamp


def distribution(values):
    values = sorted(values)
    def percentile(fraction):
        return values[math.ceil(len(values) * fraction) - 1] if values else None
    return {
        "samples": len(values),
        "p50_seconds": percentile(.5), "p95_seconds": percentile(.95),
        "max_seconds": values[-1] if values else None,
        "strict_under_6h": sum(value < DEADLINE_SECONDS for value in values),
        "strict_breaches_ge_6h": sum(value >= DEADLINE_SECONDS for value in values),
        "contest_within_6h": sum(value <= DEADLINE_SECONDS for value in values),
        "contest_breaches_gt_6h": sum(value > DEADLINE_SECONDS for value in values),
    }


def _table_records(connection, table):
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if table not in tables:
        return None
    if table == "source_items":
        query = "SELECT source,source_id AS record_id,payload_json,first_seen_at FROM source_items"
    elif table == "knowledge_documents":
        query = "SELECT source,document_id AS record_id,payload_json,published_at,first_seen_at FROM knowledge_documents"
    else:
        query = "SELECT cve_id AS record_id,payload_json,first_seen_at FROM unified_vulnerabilities"
    return [dict(row) for row in connection.execute(query)]


def _table_report(rows, start, end, as_of, *, unified=False):
    if rows is None:
        return {"available": False, "window": distribution([]), "historical_backfill": distribution([]),
                "all_observed": distribution([]), "excluded": {}, "window_samples": [],
                "historical_breaches": [], "other_observed_breaches": [], "by_source": {}}
    live, historical, observed, samples, history_breaches, other_breaches = [], [], [], [], [], []
    by_source = {}
    excluded = Counter()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                raise ValueError("not an object")
        except (ValueError, TypeError):
            excluded["invalid_payload"] += 1
            continue
        source = payload.get("publication_source") if unified else row["source"]
        if source is not None and not isinstance(source, str):
            excluded["invalid_publication_source"] += 1
            continue
        sources = payload.get("sources")
        kev_only = unified and sources == ["CISA_KEV"]
        if source == "CISA_KEV" or kev_only:
            excluded["kev_listing_is_not_original_publication"] += 1
            continue
        published = timestamp(row.get("published_at", payload.get("published_at")), nvd_utc=source == "NVD")
        seen = timestamp(row["first_seen_at"])
        if published is None or seen is None:
            excluded["missing_or_imprecise_time"] += 1
            continue
        if published > as_of or seen > as_of:
            excluded["after_as_of"] += 1
            continue
        seconds = (seen - published).total_seconds()
        if seconds < 0:
            excluded["negative_delay"] += 1
            continue
        record = {"record_id": row["record_id"], "source": source or "unknown_publication_source",
                  "published_at": published.isoformat(), "first_seen_at": seen.isoformat(),
                  "delay_seconds": seconds, "strict_under_6h": seconds < DEADLINE_SECONDS,
                  "contest_within_6h": seconds <= DEADLINE_SECONDS}
        observed.append(seconds)
        if published < start:
            historical.append(seconds)
            if seconds >= DEADLINE_SECONDS:
                history_breaches.append(record)
        elif published < end:
            live.append(seconds)
            samples.append(record)
            by_source.setdefault(record["source"], []).append(seconds)
        elif seconds >= DEADLINE_SECONDS:
            other_breaches.append(record)
    return {"available": True, "records": len(rows), "window": distribution(live),
            "historical_backfill": distribution(historical), "all_observed": distribution(observed),
            "excluded": dict(excluded), "window_samples": samples,
            "historical_breaches": history_breaches, "other_observed_breaches": other_breaches,
            "by_source": {name: distribution(values) for name, values in sorted(by_source.items())}}


def observation_report(db, *, start, end, as_of):
    start, end, as_of = (required_timestamp(value, name) for value, name in
                          ((start, "start"), (end, "end"), (as_of, "as_of")))
    if not start < end <= as_of:
        raise ValueError("require start < end <= as_of")
    path = Path(db).resolve(strict=True)
    if not path.is_file():
        raise ValueError("db must be an existing SQLite file")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")  # One coherent read snapshot, including WAL commits.
        reports = {table: _table_report(_table_records(connection, table), start, end, as_of,
                                       unified=table == "unified_vulnerabilities")
                   for table in ("source_items", "knowledge_documents", "unified_vulnerabilities")}
    return {"schema_version": 1,
            "window": {"published_start_inclusive": start.isoformat(), "published_end_exclusive": end.isoformat(),
                       "observed_as_of": as_of.isoformat(), "duration_seconds": (end - start).total_seconds(),
                       "as_of_elapsed": as_of <= datetime.now(timezone.utc)},
            "database": str(path), "metrics": reports,
            "sla_verified": None,
            "limits": ["Only records present in this read snapshot are measurable; uncollected upstream items are unknown.",
                       "The window selects publication time, not a new/reset first-seen baseline; later ingestion remains counted.",
                       "Historical strict-six-hour breaches remain listed and are never deleted or re-timestamped.",
                       "CISA KEV dateAdded and date-only timestamps do not prove publication-to-ingestion latency.",
                       "Per-source observations and deduplicated CVEs are different denominators and must not be added together.",
                       "Use a consistent snapshot frozen at as_of: this database does not reconstruct historical payload versions.",
                       "A fixed report does not establish continuous uptime, successful classification, or question-answer availability."]}


def _cases(labels, name):
    rows = labels.get(name, [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"{name} must be a list of objects")
    ids = [row.get("id") for row in rows]
    if any(not isinstance(value, str) or not value.strip() for value in ids) or len(set(ids)) != len(ids):
        raise ValueError(f"{name} requires unique nonempty case ids")
    return rows


def _boolean(row, key):
    value = row.get(key)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{key} must be true, false or null")
    return value


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _confusion(tp, fp, fn, tn, total, complete):
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": _ratio(tp, tp + fp) if complete else None,
            "recall": _ratio(tp, tp + fn) if complete else None,
            "accuracy": _ratio(tp + tn, total) if complete else None}


def quality_report(labels):
    if not isinstance(labels, dict) or type(labels.get("schema_version")) is not int or labels.get("schema_version") != 1:
        raise ValueError("labels requires an object with schema_version=1")
    metadata = labels.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    result = {"metadata_declaration": metadata,
              "independence_verified": None,
              "note": "Metrics summarize supplied labels; this program cannot verify reviewer independence or evidence correctness."}
    rows = _cases(labels, "classification")
    labelled = [(row, _boolean(row, "expected"), _boolean(row, "predicted")) for row in rows]
    measured = [(expected, predicted) for _, expected, predicted in labelled if expected is not None and predicted is not None]
    tp = sum(expected and predicted for expected, predicted in measured)
    fp = sum(not expected and predicted for expected, predicted in measured)
    fn = sum(expected and not predicted for expected, predicted in measured)
    tn = sum(not expected and not predicted for expected, predicted in measured)
    complete = bool(rows) and len(measured) == len(rows)
    result["classification"] = dict(cases=len(rows), scored_cases=len(measured), complete=complete,
                                      **_confusion(tp, fp, fn, tn, len(rows), complete))
    rows = _cases(labels, "enrichment")
    tp = fp = fn = exact = measured = 0
    for row in rows:
        expected, predicted = row.get("expected_facts"), row.get("predicted_facts")
        if any(value is not None and (not isinstance(value, list) or any(not isinstance(fact, str) for fact in value))
               for value in (expected, predicted)):
            raise ValueError("enrichment facts must be lists of canonical strings or null")
        if expected is None or predicted is None:
            continue
        expected, predicted = set(expected), set(predicted)
        tp += len(expected & predicted)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        exact += expected == predicted
        measured += 1
    complete = bool(rows) and measured == len(rows)
    result["enrichment"] = {"cases": len(rows), "scored_cases": measured, "complete": complete,
                            "tp_facts": tp, "fp_facts": fp, "fn_facts": fn,
                            "precision": _ratio(tp, tp + fp) if complete else None,
                            "recall": _ratio(tp, tp + fn) if complete else None,
                            "exact_record_accuracy": _ratio(exact, len(rows)) if complete else None}
    rows = _cases(labels, "qa")
    correct = [_boolean(row, "correct") for row in rows]
    citations = [_boolean(row, "citations_supported") for row in rows]
    used_model = [_boolean(row, "used_model") for row in rows]
    times = []
    for row in rows:
        value = row.get("latency_seconds")
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
            raise ValueError("latency_seconds must be finite, nonnegative or null")
        times.append(value)
    complete = bool(rows) and all(value is not None for value in correct)
    timing_complete = bool(rows) and len(times) == len(rows)
    timing = distribution(times)
    result["qa"] = {"cases": len(rows), "reviewed_cases": sum(value is not None for value in correct),
                    "complete": complete, "accuracy": _ratio(sum(value is True for value in correct), len(rows)) if complete else None,
                    "citation_support_rate": _ratio(sum(value is True for value in citations), len(rows))
                        if rows and all(value is not None for value in citations) else None,
                    "used_model_cases": sum(value is True for value in used_model),
                    "model_mode_unknown_cases": sum(value is None for value in used_model),
                    "latency_samples": len(times), "timing_complete": timing_complete,
                    "p50_seconds": timing["p50_seconds"], "p95_seconds": timing["p95_seconds"],
                    "max_seconds": timing["max_seconds"], "over_5_seconds": sum(value > 5 for value in times),
                    "all_responses_within_5_seconds": all(value <= 5 for value in times) if timing_complete else None}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--start", required=True, help="inclusive publication time; timezone required")
    parser.add_argument("--end", required=True, help="exclusive publication time; timezone required")
    parser.add_argument("--as-of", required=True, help="freeze observation cutoff; must be >= end")
    parser.add_argument("--labels", type=Path, help="optional independent human-label JSON")
    parser.add_argument("--output", type=Path, help="new report file; existing files are not overwritten")
    args = parser.parse_args()
    try:
        report = observation_report(args.db, start=args.start, end=args.end, as_of=args.as_of)
        report["quality"] = None
        if args.labels:
            label_bytes = args.labels.read_bytes()
            report["quality"] = quality_report(json.loads(label_bytes))
            report["quality"]["labels_sha256"] = hashlib.sha256(label_bytes).hexdigest()
        text = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as output:
                output.write(text)
            print(f"Observation report: {args.output}")
        else:
            print(text, end="")
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(2, f"Observation failed: {exc}\n")


if __name__ == "__main__":
    main()
