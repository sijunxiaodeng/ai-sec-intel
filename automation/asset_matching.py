"""Independent automatic inventory matching; local archived evidence only."""
import json
import logging
import os
import threading

from automation import processing
from enrichment.assessment import assess
from enrichment.risk_register import evaluate_record, inventory_fingerprint, StaleInventory

_STOP = threading.Event()
_THREAD = None


def run_batch(limit=10):
    completed = 0
    for job in processing._claim("asset_match", max(1, min(int(limit), 20))):
        trace = {"framework": "automatic-local-asset-match-v1", "cve_id": job["cve_id"],
                 "mode": "automatic_rules", "calls": [], "model_calls": 0}
        try:
            record = processing._current(job)
            if record is None:
                continue
            expected = json.loads(job["context_json"])["inventory_fingerprint"]
            if inventory_fingerprint() != expected:
                raise processing.StaleWork("Inventory changed")
            assessment = assess(job["cve_id"])
            run_id = str(job["id"]) + "-" + job["lease_token"]
            result = evaluate_record(record, assessment=assessment, run_id=run_id, job_id=job["id"],
                                     expected_inventory_fingerprint=expected, evaluation_mode="automatic_rules")
            if result.get("status") == "skipped":
                raise processing.StaleWork("Source changed")
            trace.update(risks_saved=result["evaluated"], stop_reason="local_matching_complete",
                         source_status=assessment.get("status"), trigger=json.loads(job["context_json"]).get("reason"))
            processing._finish(job, trace=trace)
            completed += 1
        except (processing.StaleWork, StaleInventory):
            processing._finish(job, skipped=True, trace=trace)
        except Exception as exc:
            processing._finish(job, type(exc).__name__, trace=trace)
    return completed


def _loop():
    from automation.investigation_queue import reconcile
    while not _STOP.is_set():
        try:
            reconcile()
            run_batch()
        except Exception:
            logging.getLogger(__name__).exception("Automatic asset matching failed")
        _STOP.wait(10)


def start():
    global _THREAD
    if os.environ.get("ASSET_AUTO_MATCH_ENABLED", "1").lower() in {"0", "false", "off"}:
        return
    if _THREAD and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, name="automatic-asset-matching", daemon=True)
    _THREAD.start()


def stop():
    _STOP.set()


def state():
    return {"running": bool(_THREAD and _THREAD.is_alive() and not _STOP.is_set()),
            "interval_seconds": 10, "mode": "local_rules"}
