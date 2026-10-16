"""Immediate, source-backed asset results through the existing risk register."""
import json
from pathlib import Path

from automation.processing import worker_state
from database import store
from enrichment.assets import import_assets, load_assets, impact_report
from enrichment.risk_register import evaluate_record, inventory_fingerprint


def evaluate_saved(cve_id, assessment):
    record = store.get_record(cve_id)
    if not record:
        raise ValueError("知识库中没有这条情报，请先收录")
    fingerprint = inventory_fingerprint()
    result = evaluate_record(record, assessment=assessment,
                             expected_inventory_fingerprint=fingerprint, evaluation_mode="immediate_rules")
    if result.get("status") == "skipped":
        raise ValueError("情报或资产已变化，旧结果未保存，请重新评估")
    report = impact_report(assessment, load_assets())
    report.update(risks_saved=result["evaluated"], worker=worker_state(),
                  persistence="asset_risks", evaluation_mode="immediate_rules")
    return report


def _demo_inventory():
    # Demo IDs cannot overwrite real components, even on repeated imports.
    payload = json.loads((Path(__file__).parent / "samples/assets_demo.json").read_text(encoding="utf-8"))
    existing = {r["asset_id"]: r for r in load_assets()}
    if any(row["asset_id"] in existing and not existing[row["asset_id"]].get("is_demo") for row in payload["assets"]):
        raise ValueError("演示编号与真实资产冲突，请先调整真实资产编号；本次未覆盖")
    return payload


def match_demo_components():
    """Start from components and match all relevant stored intelligence locally."""
    from automation.investigation_queue import reconcile
    from automation.asset_matching import run_batch
    from enrichment.risk_register import list_risks
    payload = _demo_inventory()
    saved = import_assets(payload)
    queued = reconcile(reason="assets_changed")
    completed = run_batch(limit=20)
    return {"demo_loaded": True, "demo_assets": payload["assets"], "inventory": saved,
            "investigations_queued": queued, "automatic_matches_completed": completed,
            "risks_saved": sum(list_risks(asset_id=row["asset_id"], limit=1)["total"] for row in payload["assets"]),
            "worker": worker_state(), "persistence": "asset_risks", "view": "components"}


def load_demo(cve_id, assessment):
    # Retain the existing single-CVE endpoint for API clients.
    if cve_id != "CVE-2024-37032" or not store.get_record(cve_id):
        raise ValueError("请先收录 CVE-2024-37032，再载入资产风险演示")
    payload = _demo_inventory()
    saved = import_assets(payload)
    result = evaluate_saved(cve_id, assessment)
    from automation.investigation_queue import reconcile
    result.update(inventory=saved, investigations_queued=reconcile(reason="assets_changed"),
                  demo_loaded=True, demo_assets=payload["assets"])
    return result
