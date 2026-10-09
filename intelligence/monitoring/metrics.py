"""Publication-to-first-ingestion latency, separate from historical backfill."""
from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def parse_timestamp(value, *, nvd_utc: bool = False) -> datetime | None:
    if not isinstance(value, str) or "T" not in value:
        return None  # Date-only records cannot substantiate an hourly SLA.
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        if not nvd_utc:
            return None
        dt = dt.replace(tzinfo=timezone.utc)  # NVD's documented UTC timestamps.
    return dt.astimezone(timezone.utc)


def baseline(root: Path, *, state_dir: Path | None = None) -> str | None:
    try:
        data = json.loads(((state_dir or root / "data") / "monitoring_baseline.json").read_text(encoding="utf-8"))
        value = data.get("started_at")
        return value if parse_timestamp(value) else None
    except (OSError, ValueError, AttributeError):
        return None


def _summary(values: list[float]) -> dict:
    values = sorted(values)
    def percentile(p):
        return round(values[max(0, math.ceil(len(values) * p) - 1)], 3) if values else None
    return {
        "samples": len(values),
        "p50_hours": percentile(0.50),
        "p95_hours": percentile(0.95),
        "max_hours": round(values[-1], 3) if values else None,
        "within_6h": sum(v <= 6 for v in values),
        "under_6h": sum(v * 3600 < 21600 for v in values),
        "breached_6h": sum(v * 3600 >= 21600 for v in values),
        "max_seconds": values[-1] * 3600 if values else None,
        "within_12h": sum(v <= 12 for v in values),
        "within_24h": sum(v <= 24 for v in values),
        "over_24h": sum(v > 24 for v in values),
    }


def latency_report(con: sqlite3.Connection, monitored_since: str | None) -> dict:
    start = parse_timestamp(monitored_since)
    historical, live = [], []
    excluded = {"missing_or_imprecise_time": 0, "negative_delay": 0}
    for row in con.execute("SELECT payload_json, first_seen_at FROM unified_vulnerabilities"):
        data = json.loads(row["payload_json"])
        source = data.get("publication_source")
        # Legacy KEV-only rows incorrectly called dateAdded a publication date.
        published = None if source == "CISA_KEV" or data.get("sources") == ["CISA_KEV"] else parse_timestamp(
            data.get("published_at"), nvd_utc=(source == "NVD")
        )
        seen = parse_timestamp(row["first_seen_at"])
        if published is None or seen is None:
            excluded["missing_or_imprecise_time"] += 1
            continue
        delay = (seen - published).total_seconds() / 3600
        if delay < 0:
            excluded["negative_delay"] += 1
            continue
        historical.append(delay)
        if start is not None and published >= start and seen >= start:
            live.append(delay)
    return {
        "monitored_since": monitored_since if start else None,
        "continuous_monitoring": _summary(live),
        "all_observed_including_backfill": _summary(historical),
        "excluded": excluded,
        "note": "按 CVE 计数；历史回填与持续监测分开。无监测基线或无新发布样本时，不能据此声称达到赛题时效指标。",
    }
