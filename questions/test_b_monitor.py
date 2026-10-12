"""Offline process isolation, deadlines and API responsiveness regressions."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sqlite3
from datetime import datetime, timezone
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from api import b_monitor


class WorkerTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.script = self.directory / "worker.py"
        self.db = self.directory / "intelligence.db"
        self.ready = self.directory / "ready"
        self.environment = patch.dict(os.environ, {
            "B_MONITOR_ENABLED": "1", "TEAM_INTEL_MODE": "embed",
            "INTELLIGENCE_DB_PATH": str(self.db), "AUDIT_READY": str(self.ready),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.command = patch.object(b_monitor, "_worker_command", side_effect=self.command_for)
        self.command.start()
        self.addCleanup(self.command.stop)

    def command_for(self, root, db, result, source_timeout, workers, poll_minutes):
        return [sys.executable, str(self.script), "--result", str(result), "--db", str(db)]

    def worker(self, body):
        self.script.write_text(
            "import argparse,json,os,sys,time,subprocess\nfrom pathlib import Path\n"
            "p=argparse.ArgumentParser();p.add_argument('--result');p.add_argument('--db');a=p.parse_args()\n" + body,
            encoding="utf-8",
        )

    def wait_ready(self):
        deadline = time.monotonic() + 3
        while not self.ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.ready.exists(), "fake worker did not start")

    def test_summary_keeps_default_mode_and_source_diagnostics(self):
        self.worker("Path(a.result).write_text(json.dumps({'status':'partial','configured_sources':2,'success_sources':1,'failed_sources':1,'sources':{'z':{},'a':{}}}),encoding='utf-8')\n")
        result = b_monitor.run_b_monitor_cycle()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["mode"], "embed")
        self.assertEqual(result["execution"], "subprocess")
        self.assertEqual(result["source_names"], ["a", "z"])
        self.assertEqual(result["configured_sources"], 2)
        self.assertEqual(result["overall_timeout_seconds"], 180)
        self.assertEqual(result["db_path"], str(self.db))

    def test_disabled_does_not_spawn(self):
        with patch.dict(os.environ, {"B_MONITOR_ENABLED": "0"}), patch.object(b_monitor.subprocess, "Popen") as spawn:
            self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "disabled")
            spawn.assert_not_called()

    def test_failed_worker_releases_cycle_lock(self):
        self.worker("raise SystemExit(2)\n")
        self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "failed")
        self.worker("Path(a.result).write_text(json.dumps({'status':'success','sources':{}}),encoding='utf-8')\n")
        self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "success")

    def test_malformed_result_is_not_accepted(self):
        self.worker("Path(a.result).write_text('[]',encoding='utf-8')\n")
        result = b_monitor.run_b_monitor_cycle()
        self.assertEqual(result["status"], "failed")
        self.assertIn("ValueError", result["error"])

    def test_nonzero_worker_cannot_claim_success(self):
        self.worker("Path(a.result).write_text(json.dumps({'status':'success','sources':{}}),encoding='utf-8');raise SystemExit(1)\n")
        result = b_monitor.run_b_monitor_cycle()
        self.assertEqual(result["status"], "failed")

    def test_deadline_terminates_worker_and_its_descendant(self):
        heartbeat = self.directory / "heartbeat"
        descendant = (
            "import time\nfrom pathlib import Path\np=Path(%r)\n"
            "while True:\n p.write_text(str(time.time()),encoding='utf-8');time.sleep(0.02)\n"
        ) % str(heartbeat)
        self.worker("subprocess.Popen([sys.executable,'-c',%r]);Path(os.environ['AUDIT_READY']).write_text('ready');time.sleep(30)\n" % descendant)
        started = time.monotonic()
        result = b_monitor.run_b_monitor_cycle(overall_timeout=1)
        elapsed = time.monotonic() - started
        self.assertEqual(result["status"], "timeout")
        self.assertTrue(result["termination_confirmed"])
        self.assertLess(elapsed, 4, "deadline waited for the 30-second worker")
        self.assertTrue(heartbeat.exists())
        previous = heartbeat.read_bytes()
        time.sleep(0.15)
        self.assertEqual(heartbeat.read_bytes(), previous, "descendant kept running after timeout")
        self.worker("Path(a.result).write_text(json.dumps({'status':'success','sources':{}}),encoding='utf-8')\n")
        self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "success")

    def test_overlapping_cycle_is_skipped_and_parent_imports_stay_root(self):
        root_collectors = importlib.import_module("collectors")
        root_nvd = importlib.import_module("collectors.nvd")
        self.worker("Path(os.environ['AUDIT_READY']).write_text('ready');time.sleep(30)\n")
        results = []
        thread = threading.Thread(target=lambda: results.append(b_monitor.run_b_monitor_cycle(overall_timeout=1)))
        thread.start()
        self.addCleanup(lambda: thread.join(5))
        self.wait_ready()
        started = time.monotonic()
        self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "skipped")
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertIs(importlib.import_module("collectors"), root_collectors)
        self.assertIs(importlib.import_module("collectors.nvd"), root_nvd)
        cursors = importlib.import_module("collectors.cursors")
        self.assertNotIn("intelligence", str(Path(cursors.__file__).parent))
        thread.join(5)
        self.assertEqual(results[0]["status"], "timeout")

    def test_overview_visibility_and_status_remain_responsive_during_worker(self):
        from fastapi.testclient import TestClient
        appmod = importlib.import_module("api.app")
        library = importlib.import_module("rag.library")
        self.worker("Path(os.environ['AUDIT_READY']).write_text('ready');time.sleep(30)\n")
        results = []
        thread = threading.Thread(target=lambda: results.append(b_monitor.run_b_monitor_cycle(overall_timeout=1)))
        thread.start()
        self.addCleanup(lambda: thread.join(5))
        self.wait_ready()
        with patch.object(appmod, "knowledge_records", return_value=[]), \
             patch.object(appmod, "monitor_state", return_value={}), \
             patch.object(appmod, "configured", return_value=False), \
             patch.object(appmod, "countable_latency", return_value=0), \
             patch.object(appmod, "last_steps", return_value=[]), \
             patch("automation.pipeline.get_pipeline", return_value={}), \
             patch("automation.schedule.next_run_iso", return_value=""), \
             patch.object(library, "overview", return_value={"documents":0,"chunks":0,"source_categories":[]}), \
             patch("urllib.request.urlopen", side_effect=AssertionError("network disabled")):
            client = TestClient(appmod.app, raise_server_exceptions=True)
            started = time.monotonic()
            for route in ["/api/overview", "/api/visibility", "/api/monitor/status", "/api/monitor/status?light=1"]:
                self.assertEqual(client.get(route).status_code, 200, route)
            self.assertLess(time.monotonic() - started, 0.7, "API waited for the collector deadline")
        thread.join(5)
        self.assertEqual(results[0]["status"], "timeout")

    def test_seven_source_names_in_one_category_do_not_claim_breadth_or_latency(self):
        from fastapi.testclient import TestClient
        from intelligence.monitoring.coverage import coverage_report
        from intelligence.monitoring.source_registry import SourceSpec
        appmod = importlib.import_module("api.app")
        library = importlib.import_module("rag.library")
        names = ["TEST_VENDOR_%d" % n for n in range(7)]
        con = sqlite3.connect(":memory:")
        self.addCleanup(con.close)
        con.row_factory = sqlite3.Row
        con.execute("CREATE TABLE knowledge_documents(source TEXT,source_category TEXT,payload_json TEXT,published_at TEXT,first_seen_at TEXT)")
        for name in names:
            con.execute("INSERT INTO knowledge_documents VALUES (?,?,?,?,?)",
                        (name, "vendor_advisory", json.dumps({"raw_data":{"ai_security_related":True}}),
                         "2020-01-01T00:00:00Z", "2020-01-01T01:00:00Z"))
        specs = [SourceSpec(name, "vendor_advisory", "feed", "https://example.org/" + name) for name in names]
        coverage = coverage_report(con, specs, now=datetime.now(timezone.utc))
        self.assertEqual(coverage["observed_ai_category_count"], 1)
        self.assertEqual(coverage["live_precise_samples"], 0)
        records = [{"item":{"cve_id":"CVE-2099-99999", "title":"Synthetic API regression fixture",
                            "sources":names, "raw_data":{}}, "cvss":None}]
        self.worker("Path(os.environ['AUDIT_READY']).write_text('ready');time.sleep(30)\n")
        results = []
        thread = threading.Thread(target=lambda: results.append(b_monitor.run_b_monitor_cycle(overall_timeout=1)))
        thread.start()
        self.addCleanup(lambda: thread.join(5))
        self.wait_ready()
        with patch.object(appmod, "knowledge_records", return_value=records), \
             patch.object(appmod, "monitor_state", return_value={}), \
             patch.object(appmod, "configured", return_value=False), \
             patch.object(appmod, "countable_latency", return_value=7), \
             patch.object(appmod, "last_steps", return_value=[]), \
             patch.object(appmod, "_team_intel_snapshot", return_value={"reachable":True,"coverage":coverage}), \
             patch.object(library, "overview", return_value={"documents":7,"chunks":7,"source_categories":["vendor","vendor_advisory"]}), \
             patch("urllib.request.urlopen", side_effect=AssertionError("network disabled")):
            client = TestClient(appmod.app, raise_server_exceptions=True)
            overview = client.get("/api/overview").json()
            self.assertEqual(overview["source_count"], 7)
            self.assertEqual(overview["root_latency_count"], 7)
            self.assertEqual(overview["latency_count"], 0)
            self.assertIn("按来源", overview["latency_count_basis"])
            direct = client.get("/api/visibility").json()
            for view in [overview["visibility"], direct]:
                standards = {row["id"]:row for row in view["standards"]}
                self.assertEqual(standards["source_categories"]["level"], "缺口")
                self.assertIn("B 当前有效", standards["source_categories"]["note"])
                self.assertEqual(standards["latency"]["level"], "未达证")
                self.assertIsNone(view["policy"]["competition_passed"])
        thread.join(5)
        self.assertEqual(results[0]["status"], "timeout")

    def test_query_adapter_does_not_evict_existing_package_modules(self):
        from api.b_embed import ensure_intelligence_path
        package = importlib.import_module("collectors")
        cursors = importlib.import_module("collectors.cursors")
        ensure_intelligence_path()
        self.assertIs(sys.modules["collectors"], package)
        self.assertIs(sys.modules["collectors.cursors"], cursors)

    def test_posix_cleanup_targets_only_the_workers_process_group(self):
        child = Mock(pid=12345)
        child.poll.return_value = None
        with patch.object(b_monitor.os, "name", "posix"), \
             patch.object(b_monitor.signal, "SIGKILL", 9, create=True), \
             patch.object(b_monitor.os, "killpg", create=True) as kill_group:
            self.assertTrue(b_monitor._stop_process_tree(child))
        kill_group.assert_called_once_with(12345, 9)
        child.wait.assert_called_once_with(timeout=b_monitor._CLEANUP_TIMEOUT)

    def test_cleanup_failure_is_reported_as_unconfirmed(self):
        child = Mock(pid=12345)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("worker", 3)
        with patch.object(b_monitor.os, "name", "posix"), \
             patch.object(b_monitor.signal, "SIGKILL", 9, create=True), \
             patch.object(b_monitor.os, "killpg", create=True, side_effect=PermissionError):
            self.assertFalse(b_monitor._stop_process_tree(child))
        child.kill.assert_called_once()

    def test_worker_entry_publishes_an_atomic_result(self):
        from api.b_embed import INTEL_ROOT
        result_path = self.directory / "published.json"
        driver = self.directory / "entry_driver.py"
        driver.write_text(
            "import sys,types,runpy\n"
            "pkg=types.ModuleType('monitoring');pkg.__path__=[]\n"
            "mod=types.ModuleType('monitoring.multisource');mod.run_cycle=lambda *a,**kw:{'status':'skipped','sources':{},'poll':kw['poll_interval_minutes']}\n"
            "sys.modules.update({'monitoring':pkg,'monitoring.multisource':mod})\n"
            "sys.argv=[%r,'--db',%r,'--result',%r,'--timeout','5','--workers','1','--poll-minutes','7']\n"
            "runpy.run_path(sys.argv[0],run_name='__main__')\n"
            % (str(INTEL_ROOT / "deployment/run_embedded_cycle.py"), str(self.db), str(result_path)),
            encoding="utf-8",
        )
        done = subprocess.run([sys.executable, str(driver)], capture_output=True, timeout=5)
        self.assertEqual(done.returncode, 0, done.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(result_path.read_text(encoding="utf-8"))["poll"], 7)
        self.assertFalse(result_path.with_suffix(".tmp").exists())


if __name__ == "__main__":
    unittest.main()
