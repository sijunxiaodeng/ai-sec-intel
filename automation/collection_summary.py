"""Keep raw source writes separate from AI knowledge-base insertions."""
from datetime import datetime, timezone


def summarize_collection(cycle):
    if not isinstance(cycle, dict):
        return None
    sources = cycle.get("sources")
    sources = sources if isinstance(sources, dict) else {}
    rows = []
    totals = {key: 0 for key in ("inserted", "updated", "fetched")}
    reported = {key: False for key in totals}
    complete = bool(sources)
    for name, source in sources.items():
        if not isinstance(source, dict):
            complete = False
            continue
        # A CVE source has recent + publication recovery + modification phases.
        # OSV may also write advisories without a CVE as documents.
        phases = [source] + [source[key] for key in ("publication_recovery", "backfill", "documents")
                             if isinstance(source.get(key), dict)]
        counts = {}
        for key in totals:
            values = [p[key] for p in phases if type(p.get(key)) is int and p[key] >= 0]
            counts[key] = sum(values) if values else None
            if values:
                totals[key] += sum(values)
                reported[key] = True
        complete = complete and source.get("status") == "success" and all(value is not None for value in counts.values())
        recovery = source.get("publication_recovery")
        recovery = recovery if isinstance(recovery, dict) else {}
        backfill = source.get("backfill")
        backfill = backfill if isinstance(backfill, dict) else {}
        rows.append({"source": name, "status": source.get("status", "unknown"), **counts,
                     "error": source.get("error") or source.get("recent_error") or recovery.get("error"),
                     "recent_success": source.get("recent_success"), "pending": source.get("pending"),
                     "lag_seconds": backfill.get("lag_seconds"),
                     "publication_lag_seconds": recovery.get("lag_seconds")})
    total = cycle.get("configured_sources")
    if type(total) is not int:
        total = len(rows) or None
    complete = complete and total == len(rows)
    return {"status": cycle.get("status", "unknown"),
            "finished_at": cycle.get("finished_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            **{"raw_" + key: totals[key] if reported[key] else None for key in totals},
            "counts_complete": bool(complete), "source_total": total,
            **{"source_" + status: sum(row["status"] == status for row in rows) if rows else None
               for status in ("success", "partial", "failed", "skipped")},
            "sources": rows,
            "count_scope": "source_records_including_documents; not_unique_cves; reported_committed_writes"}
