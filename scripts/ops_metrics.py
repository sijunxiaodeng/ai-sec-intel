#!/usr/bin/env python3
"""Read-only operational Prometheus exporter; unknown observations stay absent."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

MAX_BODY = 4 * 1024 * 1024
QUEUE_STATES = ("pending", "retry", "running", "failed", "done", "skipped")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def read_json(base, path, *, timeout=3):
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API base must be HTTP(S) without credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("API base cannot contain a query or fragment")
    request = Request(base.rstrip("/") + path, headers={"Accept": "application/json"})
    with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
        payload = response.read(MAX_BODY + 1)
        if len(payload) > MAX_BODY:
            raise ValueError("API response exceeds size limit")
        if response.headers.get_content_type() != "application/json":
            raise ValueError("API response is not JSON")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("API response is not an object")
        return data


def read_queue(database):
    """Never create a database/table and never return zero for missing evidence."""
    path = Path(database).resolve()
    if not path.is_file():
        raise FileNotFoundError("Main database unavailable")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='processing_jobs'").fetchone():
            raise ValueError("Processing queue unavailable")
        counts = dict(connection.execute("SELECT status,count(*) FROM processing_jobs GROUP BY status"))
    return {state: counts.get(state, 0) for state in QUEUE_STATES}


class Metrics:
    def __init__(self):
        self.lines = []
        self.described = set()

    def add(self, name, value, help_text, **labels):
        if isinstance(value, bool):
            value = int(value)
        if not isinstance(value, (int, float)) or not math.isfinite(value):
            return
        if name not in self.described:
            self.lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} gauge"])
            self.described.add(name)
        label_text = "{" + ",".join(f"{key}={json.dumps(str(val), ensure_ascii=False)}" for key, val in sorted(labels.items())) + "}" if labels else ""
        self.lines.append(f"{name}{label_text} {value:g}")

    def text(self):
        return "\n".join(self.lines) + "\n"


def render_metrics(observations, queue):
    """Inputs are observed dictionaries or None after a failed probe."""
    metrics = Metrics()
    for endpoint in ("health", "coverage", "latency"):
        metrics.add("ai_sec_probe_success", isinstance(observations.get(endpoint), dict),
                    "Whether an operational endpoint returned a valid JSON object.", endpoint=endpoint)
    health = observations.get("health") or {}
    available = health.get("database_available")
    if isinstance(available, bool):
        metrics.add("ai_sec_intelligence_database_available", available, "B reports its database is present; not a freshness guarantee.")
    coverage = observations.get("coverage") or {}
    metrics.add("ai_sec_observed_ai_source_categories", coverage.get("observed_ai_category_count"),
                "Source categories with current classified AI records, not configured sources.")
    for source, item in mapping(coverage.get("counts_by_source")).items():
        if isinstance(item, dict):
            metrics.add("ai_sec_source_ai_records", item.get("ai_records"), "Current classified AI records per source.", source=source)
    for source, item in mapping(coverage.get("freshness_by_source")).items():
        if not isinstance(item, dict):
            continue
        healthy = item.get("healthy")
        if isinstance(healthy, bool):
            metrics.add("ai_sec_source_fresh", healthy, "One means source evidence is fresh under its configured policy.", source=source)
        metrics.add("ai_sec_source_seconds_since_success", item.get("seconds_since_success"),
                    "Age of last successful source run; missing if never successful.", source=source)
        status = item.get("latest_run_status")
        if isinstance(status, str):
            # An empty successful fetch is a successful poll, not proof of coverage.
            metrics.add("ai_sec_source_latest_run_success", status == "success",
                        "One means the latest persisted source attempt succeeded.", source=source)
    for field, population in (("per_source_live_latency", "all_records"), ("per_source_ai_live_latency", "current_ai_positive")):
        for source, item in mapping(coverage.get(field)).items():
            if not isinstance(item, dict):
                continue
            live = mapping(item.get("live"))
            metrics.add("ai_sec_source_live_latency_samples", live.get("samples"), "Precisely timed new records after the source baseline.", source=source, population=population)
            metrics.add("ai_sec_source_live_latency_p95_seconds", seconds(live.get("p95_hours")),
                        "Observed P95 publication to first source ingestion; not an SLA guarantee.", source=source, population=population)
            metrics.add("ai_sec_source_live_latency_max_seconds", live.get("max_seconds"),
                        "Observed maximum publication to first source ingestion.", source=source, population=population)
    metrics.add("ai_sec_live_timing_unknown_records", coverage.get("unknown_live_timing"), "Records without sufficient timing evidence.")
    latency = mapping((observations.get("latency") or {}).get("continuous_monitoring"))
    metrics.add("ai_sec_cve_live_latency_samples", latency.get("samples"), "Precisely timed new CVEs after the global baseline.")
    metrics.add("ai_sec_cve_live_latency_p95_seconds", seconds(latency.get("p95_hours")), "Observed CVE publication to first ingestion P95.")
    metrics.add("ai_sec_queue_observation_available", isinstance(queue, dict), "Queue exists and was read without initialization.")
    if isinstance(queue, dict):
        for state in QUEUE_STATES:
            metrics.add("ai_sec_processing_jobs", queue.get(state), "Durable processing tasks by status.", status=state)
    metrics.add("ai_sec_qa_metrics_available", 0, "QA requests are not instrumented by this exporter; QPS and answer latency are unavailable.")
    return metrics.text()


def seconds(hours):
    return hours * 3600 if isinstance(hours, (int, float)) and not isinstance(hours, bool) and math.isfinite(hours) else None


def mapping(value):
    return value if isinstance(value, dict) else {}


def collect_metrics(base, database, *, reader=read_json):
    paths = {"health": "/api/intelligence/health", "coverage": "/api/intelligence/coverage", "latency": "/api/intelligence/metrics"}
    observations = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {name: pool.submit(reader, base, path) for name, path in paths.items()}
        for name, future in futures.items():
            try:
                observations[name] = future.result()
            except Exception:
                # Never emit request URLs, body excerpts, secrets or exception strings.
                observations[name] = None
    try:
        queue = read_queue(database)
    except (OSError, ValueError, sqlite3.Error):
        queue = None
    return render_metrics(observations, queue)


def serve(host, port, base, database):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in {"/metrics", "/healthz"}:
                self.send_error(404)
                return
            body = b"ok\n" if self.path == "/healthz" else collect_metrics(base, database).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    ThreadingHTTPServer((host, port), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9108)
    parser.add_argument("--b-base", default="http://127.0.0.1:8765")
    parser.add_argument("--main-db", default="data/knowledge.sqlite3")
    args = parser.parse_args()
    serve(args.host, args.port, args.b_base, args.main_db)


if __name__ == "__main__":
    main()
