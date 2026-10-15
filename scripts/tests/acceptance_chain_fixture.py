"""Subprocess-only synthetic chain: real localhost HTTP/SQLite, no external IO.

Run by test_acceptance_snapshot.py with an empty temporary directory. Only the
external evidence/feed/paper providers are substituted, not the investigation,
assessment, version matcher, queue, risk persistence, retriever or answer logic.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def run(directory):
    directory = Path(directory).resolve()
    if not directory.is_dir() or any(directory.iterdir()):
        raise ValueError("Fixture requires an empty temporary directory")
    os.environ.update({"MAIN_DATA_DIR": str(directory), "MAIN_KB_DB_PATH": str(directory / "main.sqlite3"),
        "APP_SETTINGS_PATH": str(directory / "model.json"), "MAIN_IMPORT_DEMO_CARDS": "0", "PYTHONUTF8": "1",
        "INTELLIGENCE_DB_PATH": str(directory / "b.sqlite3"), "OFFLINE_DEMO": "1",
        "AUTO_MONITOR_ENABLED": "0", "AUTO_MONITOR_ON_START": "0", "AUTO_INGEST_ON_COLLECT": "0",
        "B_MONITOR_ENABLED": "0", "B_MONITOR_ON_REFRESH": "0", "ACTIONS_SYNC_ON_START": "0",
        "ACTIONS_SYNC_PULL": "0", "INVESTIGATION_USE_MODEL": "0", "TEAM_INTEL_MODE": "embed"})
    from config.offline import install_guard
    install_guard()
    from api.app import app
    from agents import investigation
    from automation import investigation_queue as queue
    from database import store
    from models import enriched_record
    from rag.ingest import ingest
    from scripts.acceptance_snapshot import capture, request_json
    import uvicorn

    cve = "CVE-2099-90099"
    record = enriched_record({"cve_id": cve, "title": "Synthetic acceptance fixture only",
        "description": "Synthetic AI component version fixture, not a real vulnerability.",
        "product": "ai_fixture", "source": "NVD", "raw_data": {"synthetic_fixture": True}})
    store.upsert([record])
    asset = {"asset_id": "fixture-only", "name": "Synthetic component", "vendor": "fixture",
             "product": "ai_fixture", "version": "1.0.0", "exposure": "isolated", "is_demo": True}
    nvd = {"id": cve, "lastModified": "2099-01-01T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "Synthetic acceptance version fixture."}],
        "metrics": {"cvssMetricV31": [{"source": "fixture@example.invalid", "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}]},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True,
            "criteria": "cpe:2.3:a:fixture:ai_fixture:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.2.0"}]}]}]}

    def fetch(url):
        if url != "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve:
            raise AssertionError("Unexpected fixture URL")
        return {"body": json.dumps({"vulnerabilities": [{"cve": nvd}]}).encode(),
                "content_type": "application/json", "url": url}

    def feeds(records):
        for row in records:
            row["epss"] = {"status": "empty"}
            row["kev"] = {"status": "not_listed"}
        return {}

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = "http://127.0.0.1:%s" % sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    try:
        while not server.started:
            if time.monotonic() > deadline or not thread.is_alive():
                raise RuntimeError("Fixture HTTP server did not start")
            time.sleep(.02)
        with ExitStack() as stack:
            stack.enter_context(patch.object(investigation, "ingest",
                side_effect=lambda row, **kwargs: ingest(row, fetcher=fetch, **kwargs)))
            stack.enter_context(patch.object(investigation, "apply_public_feeds", side_effect=feeds))
            stack.enter_context(patch.object(investigation, "fetch_papers", return_value=({}, None)))
            imported = request_json(base, "/api/assets/import", {"assets": [asset]})
            assert imported["investigations_queued"] == 1
            assert queue.run_pending() == 1
            risk = request_json(base, "/api/risks/fixture-only/" + cve)
            assert risk["status"] == "matched_version" and risk["validation"] == "not_tested"
            first = capture(base, cve, asset_id=asset["asset_id"], ask=True)
            assert first["summary"]["chain_bindings_verified"], json.dumps(first["checks"], ensure_ascii=True)
            assert first["qa"]["used_model"] is False and first["qa"]["model_attempted"] is False
            assert first["investigation"]["calls"][0]["tool"] == "evidence.fetch"
            assert "affected_versions" in first["investigation"]["calls"][0]["resolved_gaps"]
            assert "research_evidence" in first["investigation"]["remaining_gaps"]

            # Upgrade via the real API invalidates old state and triggers new work.
            imported = request_json(base, "/api/assets/import", {"assets": [dict(asset, version="1.2.0")]})
            assert imported["investigations_queued"] == 1
            assert request_json(base, "/api/risks/fixture-only/" + cve)["status"] == "invalidated"
            assert queue.run_pending() == 1
            risk = request_json(base, "/api/risks/fixture-only/" + cve)
            assert risk["status"] == "not_matched" and risk["disposition"] != "resolved"
            closed = request_json(base, "/api/risks/fixture-only/" + cve + "/disposition",
                {"status": "resolved", "note": "Synthetic declared version no longer matches cited range.",
                 "expected_fingerprint": risk["fingerprint"]})
            assert closed["disposition"] == "resolved"
            second = capture(base, cve, asset_id=asset["asset_id"], ask=True)
            assert second["summary"]["chain_bindings_verified"], second["checks"]
            assert len(request_json(base, "/api/investigations/%s/runs" % risk["job_id"])["items"]) == 2

            # Unknown version must reopen review and may not be marked resolved.
            request_json(base, "/api/assets/import", {"assets": [dict(asset, version="")]})
            queue.run_pending()
            risk = request_json(base, "/api/risks/fixture-only/" + cve)
            assert risk["status"] == "unknown" and risk["disposition"] == "pending_review"
            from urllib.error import HTTPError
            try:
                request_json(base, "/api/risks/fixture-only/" + cve + "/disposition",
                    {"status": "resolved", "note": "Must be rejected", "expected_fingerprint": risk["fingerprint"]})
                raise AssertionError("Unknown risk was resolved")
            except HTTPError as exc:
                assert exc.code == 409
            # A new source revision fences the old risk before re-evaluation.
            updated = store.get_record(cve)
            updated["item"]["description"] += " Source revision changed."
            store.upsert([updated])
            assert request_json(base, "/api/risks/fixture-only/" + cve)["status"] == "invalidated"
            assert queue.reconcile() == 1
            queue.run_pending()
            store.retract([cve])
            assert request_json(base, "/api/risks/fixture-only/" + cve)["status"] == "invalidated"
        # Persist only the sanitized successful synthetic report, with honest scope.
        first["evidence_kind"] = "offline_fixture"
        first["scope"].update(external_network=False, model_call_possible=False,
                              external_providers_substituted=True, transport="localhost_http",
                              synthetic_data=True)
        first["fixture_checks"] = {"upgrade_reassessed": True, "unknown_close_rejected": True,
                                    "source_revision_invalidated": True, "withdrawal_invalidated": True}
        (directory / "report.json").write_text(json.dumps(first, ensure_ascii=False), encoding="utf-8")
        return first
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


if __name__ == "__main__":
    result = run(sys.argv[1])
    print(json.dumps({"evidence_kind": result["evidence_kind"], "summary": result["summary"]}))
