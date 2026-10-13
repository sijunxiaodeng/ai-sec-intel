#!/usr/bin/env python3
"""Read-only proof of an expected Actions generation and committed consumers."""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from team_change_protocol import validate_page

MAX_JSON_BYTES = 4 * 1024 * 1024


class VerificationError(ValueError):
    pass


def validate_base(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or any(ord(char) < 33 or ord(char) == 127 for char in value)
                or parsed.scheme not in {"http", "https"} or (parsed.scheme == "http" and not local)):
            raise ValueError
    except ValueError:
        raise VerificationError("invalid_endpoint_configuration") from None
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise VerificationError("redirect_not_allowed")


def request_json(url):
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-delivery-verifier"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            body = response.read(MAX_JSON_BYTES + 1)
        if len(body) > MAX_JSON_BYTES:
            raise VerificationError("response_too_large")
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise VerificationError("invalid_response")
        return payload
    except VerificationError:
        raise
    except Exception:
        # URLs, credentials, response bodies and source content remain private.
        raise VerificationError("endpoint_unavailable_or_invalid_response") from None


def _generation(payload, run_id, collector_commit):
    generation = payload.get("generation") if isinstance(payload, dict) else None
    if (not isinstance(generation, dict) or payload.get("status") != "serving_verified_generation"
            or payload.get("database_available") is not True
            or (payload.get("compatibility") or {}).get("ready") is not True
            or generation.get("run_id") != run_id or generation.get("collector_commit") != collector_commit):
        raise VerificationError("expected_generation_not_served")
    return {key: generation.get(key) for key in
            ("repository", "branch", "workflow", "run_id", "run_number", "collector_commit")}


def verify(*, b_base, main_base, run_id, collector_commit, reader=request_json):
    evidence = {"snapshot_serving_verified": False, "consumption_verified": False,
                "processing_verified": False, "reason_category": "unverified"}
    try:
        b_base, main_base = validate_base(b_base), validate_base(main_base)
        observed = reader(b_base + "/api/intelligence/delivery")
        generation = _generation(observed, run_id, collector_commit)
        proxied = reader(main_base + "/api/intelligence/delivery")
        if _generation(proxied, run_id, collector_commit) != generation:
            raise VerificationError("main_and_b_generations_differ")
        high = observed.get("changefeed")
        if (not isinstance(high, dict) or not isinstance(high.get("epoch"), str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", high["epoch"])
                or type(high.get("through")) is not int or high["through"] < 0
                or proxied.get("changefeed") != high):
            raise VerificationError("feed_generation_unverified")
        for kind in ("cve", "document"):
            page = validate_page(reader(b_base + "/api/team/changes?kind=" + kind + "&cursor=0&limit=1"), 0)
            if {"epoch": page["epoch"], "through": page["through"]} != high:
                raise VerificationError("generation_changed_during_verification")
        evidence.update(snapshot_serving_verified=True, generation=generation, changefeed=high,
                        poller_observation=observed.get("poller_observation") if observed.get("poller_observation")
                        in {"ready", "degraded", "stale", "not_observed", "generation_mismatch"} else "unverified")
        consumed = reader(main_base + "/api/admin/actions-consumption")
        consumers = consumed.get("consumers")
        if consumed.get("upstream") != high or not isinstance(consumers, dict):
            raise VerificationError("consumer_upstream_generation_unverified")
        checkpoints = {}
        for kind in ("cve", "document"):
            item = consumers.get(kind)
            cursor = item.get("checkpoint") if isinstance(item, dict) else None
            caught_up = (isinstance(cursor, dict) and item.get("status") == "caught_up"
                         and cursor.get("epoch") == high["epoch"]
                         and type(cursor.get("seq")) is int and cursor["seq"] == high["through"]
                         and cursor.get("through") is None)
            checkpoints[kind] = {"caught_up": caught_up}
        evidence["consumers"] = checkpoints
        # Recheck after all requests; a new atomic generation needs a fresh proof.
        final = reader(b_base + "/api/intelligence/delivery")
        if _generation(final, run_id, collector_commit) != generation or final.get("changefeed") != high:
            evidence["snapshot_serving_verified"] = False
            raise VerificationError("generation_changed_during_verification")
        evidence["consumption_verified"] = (consumed.get("status") == "caught_up"
                                             and consumers.get("all_caught_up") is True
                                             and all(item["caught_up"] for item in checkpoints.values()))
        evidence["reason_category"] = "durable_import_verified" if evidence["consumption_verified"] else "consumer_import_pending"
    except (VerificationError, ValueError, TypeError, KeyError, AttributeError) as exc:
        evidence["reason_category"] = str(exc) if isinstance(exc, VerificationError) else "invalid_response"
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--b-base", default="http://127.0.0.1:8765")
    parser.add_argument("--main-base", default="http://127.0.0.1:8023")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--collector-commit", required=True)
    args = parser.parse_args(argv)
    if args.run_id <= 0 or not re.fullmatch(r"[0-9a-f]{40}", args.collector_commit):
        parser.error("Use a positive real workflow run ID and its full collector commit SHA")
    evidence = verify(b_base=args.b_base, main_base=args.main_base,
                      run_id=args.run_id, collector_commit=args.collector_commit)
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0 if evidence["snapshot_serving_verified"] and evidence["consumption_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
