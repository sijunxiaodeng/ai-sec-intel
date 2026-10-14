#!/usr/bin/env python3
"""Wait for an expected Actions generation and prove both durable imports."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import time
import urllib.request

SPEC = importlib.util.spec_from_file_location("actions_delivery_check", Path(__file__).with_name("verify-actions-delivery.py"))
DELIVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELIVERY)

PROGRESS_REASONS = frozenset({
    "unverified", "invalid_response", "invalid_endpoint_configuration",
    "redirect_not_allowed", "response_too_large", "endpoint_unavailable_or_invalid_response",
    "expected_generation_not_served", "main_and_b_generations_differ",
    "feed_generation_unverified", "generation_changed_during_verification",
    "consumer_upstream_generation_unverified", "durable_import_verified",
    "consumer_import_pending", "actions_pull_and_durable_import_verified",
    "import_verified_recent_pull_unverified",
})
PROGRESS_POLLERS = frozenset({"ready", "degraded", "stale", "not_observed", "generation_mismatch"})


def progress_summary(facts, *, phase, elapsed_seconds):
    """Expose only fixed categories and booleans, never response or error text."""
    consumers = facts.get("consumers") or {}
    return {
        "phase": phase,
        "elapsed_seconds": round(elapsed_seconds, 1),
        "reason_category": facts.get("reason_category") if facts.get("reason_category") in PROGRESS_REASONS else "unverified",
        "snapshot_serving_verified": facts.get("snapshot_serving_verified") is True,
        "poller_observation": facts.get("poller_observation") if facts.get("poller_observation") in PROGRESS_POLLERS else "unverified",
        "cve_caught_up": (consumers.get("cve") or {}).get("caught_up") is True,
        "document_caught_up": (consumers.get("document") or {}).get("caught_up") is True,
    }


def print_progress(summary):
    # stdout avoids PowerShell 5.1 treating native stderr as a terminating error.
    print("[deployment-check] " + json.dumps(summary, ensure_ascii=True), flush=True)


def post_json(url, body):
    """Import from configured B only; no cloud collection or model invocation."""
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "ai-sec-intel-deployment-check"})
    try:
        with urllib.request.build_opener(DELIVERY.NoRedirect()).open(request, timeout=30) as response:
            payload = response.read(DELIVERY.MAX_JSON_BYTES + 1)
        if len(payload) > DELIVERY.MAX_JSON_BYTES or not isinstance(json.loads(payload), dict):
            raise ValueError("Invalid response")
    except Exception:
        # Existing running imports can return 409. Recheck durable state rather
        # than trusting success text or leaking authenticated exception details.
        return False
    return True


def check(*, b_base, main_base, run_id, collector_commit, wait_seconds=180,
          synchronize=False, reader=DELIVERY.request_json, poster=post_json,
          clock=time.monotonic, sleeper=time.sleep, progress=None):
    if type(wait_seconds) is not int or not 5 <= wait_seconds <= 3600:
        raise ValueError("wait_seconds must be 5..3600")
    if type(run_id) is not int or run_id <= 0 or not re.fullmatch(r"[0-9a-f]{40}", collector_commit):
        raise ValueError("A real run ID and full collector commit are required")
    b_base, main_base = DELIVERY.validate_base(b_base), DELIVERY.validate_base(main_base)
    started = clock()
    deadline = started + wait_seconds
    attempts, imports = 0, 0
    sync_failure = False
    last_progress_at, last_progress_state = None, None

    def report(facts, phase, *, force=False):
        nonlocal last_progress_at, last_progress_state
        if progress is None:
            return
        now = clock()
        summary = progress_summary(facts, phase=phase, elapsed_seconds=now - started)
        state = {key: value for key, value in summary.items() if key != "elapsed_seconds"}
        if force or state != last_progress_state or last_progress_at is None or now - last_progress_at >= 10:
            progress(summary)
            last_progress_at, last_progress_state = now, state

    report({}, "verification_started", force=True)
    while True:
        attempts += 1
        facts = DELIVERY.verify(b_base=b_base, main_base=main_base, run_id=run_id,
                                collector_commit=collector_commit, reader=reader)
        pull = facts.get("snapshot_serving_verified") is True and facts.get("poller_observation") == "ready"
        complete = pull and facts.get("consumption_verified") is True
        facts.update(schema_version=1, expected_run_id=run_id, expected_collector_commit=collector_commit,
                     pull_verified=pull, deployment_import_loop_verified=complete,
                     synchronization_requested=bool(synchronize), synchronization_rounds=imports,
                     verification_attempts=attempts, synchronization_request_failed=sync_failure,
                     elapsed_seconds=round(clock() - started, 3), checked_at=datetime.now(timezone.utc).isoformat(),
                     verification_scope="main_proxy_and_durable_consumers" if b_base == main_base else "b_api_main_proxy_and_durable_consumers",
                     limits=["Verifies this expected Actions generation, recent mirror observation and committed CVE/document cursors.",
                             "Does not verify asynchronous enrichment/index completion, semantic accuracy, collection SLA or unattended uptime.",
                             "A cloud/container proof does not establish deployment on a separate Windows computer."])
        if complete or clock() >= deadline:
            if complete:
                facts["reason_category"] = "actions_pull_and_durable_import_verified"
            elif facts.get("consumption_verified") and not pull:
                facts["reason_category"] = "import_verified_recent_pull_unverified"
            report(facts, "verified" if complete else "wait_expired", force=True)
            return facts
        report(facts, "waiting")
        # Do not write until both B and the main proxy serve the expected run.
        if synchronize and facts.get("snapshot_serving_verified") and not facts.get("consumption_verified"):
            imports += 1
            consumers = facts.get("consumers") or {}
            cve_ok, document_ok = True, True
            if not (consumers.get("cve") or {}).get("caught_up"):
                report(facts, "cve_import_started", force=True)
                cve_ok = poster(main_base + "/api/collect", {"keyword": ""})
                report(facts, "cve_import_returned", force=True)
            if not (consumers.get("document") or {}).get("caught_up"):
                report(facts, "document_import_started", force=True)
                document_ok = poster(main_base + "/api/library/team-sync", {"max_documents": 200})
                report(facts, "document_import_returned", force=True)
            sync_failure = sync_failure or not cve_ok or not document_ok
        remaining = deadline - clock()
        if remaining > 0:
            sleeper(min(2, remaining))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    # Inside main-app its loopback API forwards both B delivery and changefeed
    # requests to b-api. No exposed Docker daemon or extra Python installation.
    parser.add_argument("--b-base", default="http://127.0.0.1:8023")
    parser.add_argument("--main-base", default="http://127.0.0.1:8023")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--collector-commit", required=True)
    parser.add_argument("--wait-seconds", type=int, default=180)
    parser.add_argument("--synchronize", action="store_true")
    parser.add_argument("--progress", action="store_true", help="Print safe progress summaries to stdout before the final JSON proof")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        facts = check(b_base=args.b_base, main_base=args.main_base, run_id=args.run_id,
                      collector_commit=args.collector_commit, wait_seconds=args.wait_seconds,
                      synchronize=args.synchronize, progress=print_progress if args.progress else None)
    except (ValueError, TypeError):
        parser.error("Invalid endpoint, expected generation or waiting period; no import was started")
    body = json.dumps(facts, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(body, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(args.output)
    print(body, end="")
    return 0 if facts["deployment_import_loop_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
