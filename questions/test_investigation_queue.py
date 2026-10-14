"""Integration of durable triggers, real risk persistence and stale-work fences."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import processing, investigation_queue as queue
from database import store
from enrichment import assets, risk_register
from enrichment.assessment import _walk_config
from models import enriched_record


class InvestigationQueueTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        changes = {name: self.root / filename for name, filename in {
            "DB_PATH": "main.sqlite3", "KB_PATH": "old.json", "RUNS_PATH": "runs.json",
            "CARDS_PATH": "cards.json", "CARDS_JS_PATH": "cards.js", "SEED_CARDS_PATH": "seed.json"}.items()}
        self.enterContext(patch.multiple(store, DATA=self.root, **changes))
        self.enterContext(patch.dict(os.environ, {"MAIN_KB_DB_PATH": str(changes["DB_PATH"]), "MAIN_IMPORT_DEMO_CARDS": "0"}))
        self.enterContext(patch.object(assets, "DEFAULT_ASSET_DB", self.root / "assets.sqlite3"))
        self.asset = {"asset_id": "ai-1", "name": "test", "vendor": "ollama", "product": "ollama", "version": "0.1.30", "exposure": "internet"}
        self.record = enriched_record({"cve_id": "CVE-2024-37032", "title": "fixture", "product": "ollama", "source": "NVD"})
        store.upsert([self.record])
        self.record = store.get_record("CVE-2024-37032")
        row = next(_walk_config({"cpeMatch": [{"vulnerable": True,
            "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.1.34"}]}, "configurations/0"))
        row["evidence_ids"] = ["CVE-2024-37032/FIXTURE"]
        self.report = {"cve_id": "CVE-2024-37032", "status": "partial", "affected_ranges": [row],
                       "evidence": [{"citation_id": "CVE-2024-37032/FIXTURE", "text": "Synthetic range fixture"}]}

    def result(self, record, **kwargs):
        return {"record": copy.deepcopy(record), "assessment": self.report,
                "trace": {"stop_reason": "available_tools_exhausted", "remaining_gaps": ["cvss"]},
                "retryable": False, "errors": [], "documents_changed": False}

    def test_asset_import_api_enqueues_existing_intelligence_and_preserves_preview(self):
        from fastapi.testclient import TestClient
        from api.app import app
        client = TestClient(app)
        result = client.post("/api/assets/import", json={"assets": [self.asset]})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["investigations_queued"], 1)
        with patch("agents.investigation.run", side_effect=self.result):
            self.assertEqual(queue.run_pending(), 1)
        response = client.get("/api/risks")
        self.assertEqual(response.status_code, 200)
        risk = response.json()["items"][0]
        self.assertEqual(risk["status"], "matched_version")
        self.assertEqual(client.post("/api/risks/ai-1/CVE-2024-37032/disposition", json={
            "status": "resolved", "note": "cannot close affected fixture", "expected_fingerprint": risk["fingerprint"]}).status_code, 409)
        self.assertEqual(client.get("/api/risks?status=invalid-value").status_code, 422)
        self.assertEqual(client.get("/api/risks?limit=10000").status_code, 422)
        self.assertEqual(client.get("/api/investigations").json()["total"], 1)

    def test_new_intelligence_is_reconciled_after_restart_without_manual_cve(self):
        assets.import_assets({"assets": [self.asset]})
        self.assertEqual(queue.reconcile(), 1)
        with patch("agents.investigation.run", side_effect=self.result):
            queue.run_pending()
        self.assertEqual(queue.reconcile(), 0)
        risk = risk_register.list_risks()["items"][0]
        job = queue.tasks()["items"][0]
        self.assertEqual(risk["job_id"], job["id"])
        self.assertEqual(queue.history(job["id"])[0]["run_id"], risk["run_id"])

    def test_inventory_upgrade_reopens_task_and_clears_only_with_evidence(self):
        assets.import_assets({"assets": [self.asset]})
        queue.reconcile()
        with patch("agents.investigation.run", side_effect=self.result):
            queue.run_pending()
            assets.import_assets({"assets": [dict(self.asset, version="0.1.34")]})
            self.assertEqual(risk_register.list_risks()["items"][0]["status"], "invalidated")
            self.assertEqual(queue.reconcile(reason="assets_changed"), 1)
            queue.run_pending()
        risk = risk_register.list_risks()["items"][0]
        self.assertEqual(risk["status"], "not_matched")
        self.assertNotEqual(risk["disposition"], "resolved")
        self.assertEqual(len(queue.history(risk["job_id"])), 2)

    def test_unchanged_import_does_not_repeat_investigation(self):
        assets.import_assets({"assets": [self.asset]})
        queue.reconcile()
        assets.import_assets({"assets": [self.asset]})
        self.assertEqual(queue.reconcile(reason="assets_changed"), 0)

    def test_explicit_research_works_without_assets(self):
        self.assertEqual(queue.reconcile(), 0)
        self.assertEqual(queue.reconcile(explicit=True, reason="user_research"), 1)
        with patch("agents.investigation.run", side_effect=self.result):
            queue.run_pending()
        self.assertEqual(queue.tasks()["items"][0]["status"], "done")
        self.assertEqual(risk_register.list_risks()["total"], 0)

    def test_inventory_change_during_tool_call_skips_old_task(self):
        assets.import_assets({"assets": [self.asset]})
        queue.reconcile()
        def change(record, **kwargs):
            assets.import_assets({"assets": [dict(self.asset, version="0.1.34")]})
            return self.result(record)
        with patch("agents.investigation.run", side_effect=change):
            queue.run_pending()
        self.assertEqual(queue.tasks()["items"][0]["status"], "skipped")
        self.assertEqual(risk_register.list_risks()["total"], 0)
        self.assertEqual(queue.reconcile(), 1)

    def test_withdrawal_during_investigation_cannot_publish_risk(self):
        assets.import_assets({"assets": [self.asset]})
        queue.reconcile()
        def retract(record, **kwargs):
            store.retract([record["item"]["cve_id"]])
            return self.result(record)
        with patch("agents.investigation.run", side_effect=retract):
            queue.run_pending()
        self.assertEqual(queue.tasks()["items"][0]["status"], "skipped")
        self.assertEqual(risk_register.list_risks()["total"], 0)

    def test_initial_documents_and_feeds_precede_research_but_failure_does_not_starve_it(self):
        assets.import_assets({"assets": [self.asset]})
        processing.enqueue([self.record])
        self.assertEqual(processing._claim("investigate"), [])
        for stage in ("enrich", "documents"):
            job = processing._claim(stage)[0]
            processing._finish(job, "synthetic_network_failure")
        self.assertEqual(len(processing._claim("investigate")), 1)

    def test_running_task_cannot_be_stolen_by_manual_retry(self):
        assets.import_assets({"assets": [self.asset]})
        queue.reconcile()
        job = processing._claim("investigate")[0]
        self.assertEqual(queue.reconcile(force=True), 0)
        assets.import_assets({"assets": [dict(self.asset, version="0.1.34")]})
        self.assertEqual(queue.reconcile(), 1)
        processing._finish(job, trace={"committed": True})
        self.assertEqual(queue.tasks()["items"][0]["status"], "pending")
        self.assertEqual(queue.history(job["id"]), [])

    def test_deferred_index_waits_and_resumes_without_exhausting_retry_budget(self):
        job = {"cve_id": self.record["item"]["cve_id"], "revision": processing.revision(self.record)}
        processing._enqueue_index(job)
        claimed = processing._claim("index")[0]
        processing._finish(claimed, deferred=True)
        self.assertEqual(processing._claim("index"), [])
        with processing._connection() as conn:
            row = conn.execute("SELECT status,attempts FROM processing_jobs WHERE stage='index'").fetchone()
            self.assertEqual(tuple(row), ("deferred", 0))
            conn.execute("UPDATE processing_jobs SET available_at=0 WHERE stage='index'")
        resumed = processing._claim("index")[0]
        processing._finish(resumed)
        self.assertEqual(processing.state()["counts"], {"done": 1})

    def test_new_evidence_requeues_finished_and_fences_running_research(self):
        assets.import_assets({"assets": [self.asset]})
        queue.reconcile()
        with patch("agents.investigation.run", side_effect=self.result):
            queue.run_pending()
        with patch("enrichment.assessment.assess", return_value=self.report):
            self.assertEqual(queue.evidence_updated(self.record), 1)
            self.assertEqual(risk_register.list_risks()["items"][0]["status"], "invalidated")
            old = processing._claim("investigate")[0]
            self.assertEqual(queue.evidence_updated(self.record), 1)
        processing._finish(old, trace={"committed": True})
        self.assertEqual(queue.tasks()["items"][0]["status"], "pending")
        self.assertEqual(len(queue.history(old["id"])), 1)

    def test_archived_cpe_routes_productless_record_after_evidence_update(self):
        assets.import_assets({"assets": [self.asset]})
        record = copy.deepcopy(self.record)
        record["item"]["product"] = ""
        store.upsert([record])
        current = store.get_record(record["item"]["cve_id"])
        # The source store may preserve a prior nonempty product, so create a fresh CVE.
        current["item"]["cve_id"] = "CVE-2026-12345"
        current["item"]["product"] = ""
        store.upsert([current])
        current = store.get_record("CVE-2026-12345")
        self.assertEqual(queue.reconcile([current]), 0)
        report = dict(self.report, cve_id="CVE-2026-12345")
        with patch("enrichment.assessment.assess", return_value=report):
            self.assertEqual(queue.evidence_updated(current), 1)

    def test_processing_can_start_with_public_monitoring_disabled(self):
        from automation import schedule
        with patch.object(schedule, "AUTO_ENABLED", False), patch.object(schedule, "_STARTED", False), \
             patch.object(schedule, "ensure_state"), patch.object(processing, "start") as worker:
            schedule.start()
        worker.assert_called_once()


if __name__ == "__main__":
    unittest.main()
