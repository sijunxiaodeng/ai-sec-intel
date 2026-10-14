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
          clock=time.monotonic, sleeper=time.sleep):
    if type(wait_seconds) is not int or not 5 <= wait_seconds <= 3600:
        raise ValueError("wait_seconds must be 5..3600")
    if type(run_id) is not int or run_id <= 0 or not re.fullmatch(r"[0-9a-f]{40}", collector_commit):
        raise ValueError("A real run ID and full collector commit are required")
    b_base, main_base = DELIVERY.validate_base(b_base), DELIVERY.validate_base(main_base)
    started = clock()
    deadline = started + wait_seconds
    attempts, imports = 0, 0
    sync_failure = False
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
            return facts
        # Do not write until both B and the main proxy serve the expected run.
        if synchronize and facts.get("snapshot_serving_verified") and not facts.get("consumption_verified"):
            imports += 1
            consumers = facts.get("consumers") or {}
            cve_ok = True if (consumers.get("cve") or {}).get("caught_up") else poster(main_base + "/api/collect", {"keyword": ""})
            document_ok = True if (consumers.get("document") or {}).get("caught_up") else poster(main_base + "/api/library/team-sync", {"max_documents": 200})
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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        facts = check(b_base=args.b_base, main_base=args.main_base, run_id=args.run_id,
                      collector_commit=args.collector_commit, wait_seconds=args.wait_seconds,
                      synchronize=args.synchronize)
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
