"""Durable JSON RMW/cycle locking regressions; only synthetic temporary state."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from agents import orchestrator
from database import store
from models import enriched_record


ROOT = Path(__file__).resolve().parents[1]
CHILD_SETUP = """
import json, os, sys, time
from pathlib import Path
from database import store
from models import enriched_record
root = Path(sys.argv[1])
store.DATA = root / 'data'
store.KB_PATH = store.DATA / 'knowledge.json'
store.CARDS_PATH = root / 'cards.json'
store.CARDS_JS_PATH = root / 'cards.js'
store.RUNS_PATH = store.DATA / 'runs.json'
"""


def record(number, *, source="OSV", epss=None, kev=None):
    return enriched_record({"item": {
        "cve_id": "CVE-2099-%04d" % number, "title": "Offline %d" % number,
        "description": "Synthetic fixture", "source": source, "sources": [source],
        "published_at": "2026-10-10T00:00:00Z", "collected_at": "2026-10-11T00:00:00Z",
        "references": ["https://example.invalid/" + source]}, "epss": epss, "kev": kev})


class StoreFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for key, path in {"DATA": self.root / "data", "KB_PATH": self.root / "data/knowledge.json",
                          "CARDS_PATH": self.root / "cards.json", "CARDS_JS_PATH": self.root / "cards.js",
                          "RUNS_PATH": self.root / "data/runs.json"}.items():
            self.stack.enter_context(patch.object(store, key, path))
        self.stack.enter_context(patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected live network")))
        self.stack.enter_context(patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected live network")))
        store.save_kb([record(1)])

    def snapshots(self):
        return {path: path.read_bytes() for path in (store.KB_PATH, store.CARDS_PATH, store.CARDS_JS_PATH)}

    def assert_ids(self, expected):
        self.assertEqual({r["item"]["cve_id"] for r in store.load_kb()}, expected)
        self.assertEqual({r["cve_id"] for r in json.loads(store.CARDS_PATH.read_text(encoding="utf-8"))}, expected)

    def spawn(self, body, *args):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", AUTO_MONITOR_ON_START="0",
                   AUTO_MONITOR_ENABLED="0", B_MONITOR_ENABLED="0")
        process = subprocess.Popen([sys.executable, "-c", CHILD_SETUP + body, str(self.root), *map(str, args)],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.addCleanup(self.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def finish(self, process):
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr.decode("utf-8", errors="replace"))
        return stdout.decode("utf-8")

    def wait_file(self, path):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(path.exists(), "Child did not acquire its temporary lock")


class DurableStoreTest(StoreFixture):
    def test_thread_rmw_keeps_all_batches_and_run_history(self):
        barrier = threading.Barrier(8)
        read_list = store._read_list

        def slow_read(path):
            rows = read_list(path)
            if path == store.KB_PATH:
                time.sleep(0.025)  # Amplify the original unlocked load/save race.
            return rows

        def write(number):
            barrier.wait(timeout=3)
            result = store.upsert_stats([record(number)])
            store.append_run([{"number": number}], "offline")
            return result

        with patch.object(store, "_read_list", side_effect=slow_read), ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(2, 10)))
        self.assertEqual(sum(r["inserted"] for r in results), 8)
        self.assertEqual(sum(r["merged"] for r in results), 0)
        self.assert_ids({"CVE-2099-%04d" % i for i in range(1, 10)})
        runs = json.loads(store.RUNS_PATH.read_text(encoding="utf-8"))
        self.assertEqual({r["steps"][0]["number"] for r in runs}, set(range(2, 10)))

    def test_real_process_rmw_keeps_all_batches(self):
        body = """
number = int(sys.argv[2])
ready = root / ('ready-%d' % number)
ready.write_text('ready')
deadline = time.monotonic() + 5
while not (root / 'go').exists():
    if time.monotonic() > deadline: raise RuntimeError('test barrier expired')
    time.sleep(.02)
for i in range(4):
    value = number * 10 + i
    store.upsert_stats([enriched_record({'item': {'cve_id': 'CVE-2099-%04d' % value, 'source': 'OSV'}})])
store.append_run([{'number': number}], 'offline-process')
"""
        children = [self.spawn(body, number) for number in range(2, 6)]
        for number in range(2, 6):
            self.wait_file(self.root / ("ready-%d" % number))
        (self.root / "go").write_text("go")
        for child in children:
            self.finish(child)
        expected = {"CVE-2099-0001"} | {"CVE-2099-%04d" % (number * 10 + i) for number in range(2, 6) for i in range(4)}
        self.assert_ids(expected)
        self.assertEqual(len(json.loads(store.RUNS_PATH.read_text(encoding="utf-8"))), 4)

    def test_same_cve_concurrent_feed_updates_preserve_history(self):
        old = record(1, source="NVD", epss={"status": "ok", "score": "0.25",
            "queried_at": "2026-10-11T00:00:00Z", "last_success_at": "2026-10-11T00:00:00Z"})
        store.save_kb([old])
        barrier = threading.Barrier(2)
        def update(value):
            barrier.wait(timeout=3)
            return store.upsert([value])
        incoming = [record(1, source="OSV", epss={"status": "error", "queried_at": "2026-10-12T00:00:00Z"}),
                    record(1, source="厂商公告", kev={"status": "listed", "queried_at": "2026-10-12T00:00:00Z"})]
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(update, incoming))
        final = store.get_record("CVE-2099-0001")
        self.assertEqual(set(final["item"]["sources"]), {"NVD", "OSV", "厂商公告"})
        self.assertEqual(final["item"]["published_at"], old["item"]["published_at"])
        self.assertEqual(final["item"]["collected_at"], old["item"]["collected_at"])
        self.assertEqual(final["epss"]["score"], "0.25")
        self.assertEqual(final["epss"]["last_success_at"], "2026-10-11T00:00:00Z")
        self.assertEqual(final["epss"]["latest_attempt"]["status"], "error")
        self.assertTrue(final["epss"]["retained_previous"])
        self.assertEqual(final["kev"]["status"], "listed")
        self.assertEqual(len(final["references"]), 3)

    def test_replace_failure_restores_all_original_files(self):
        replace = os.replace
        for target in (store.CARDS_PATH, store.CARDS_JS_PATH, store.KB_PATH):
            with self.subTest(target=target.name):
                before = self.snapshots()
                def fail_pending(src, dst):
                    if Path(dst) == target and ".pending-" in Path(src).name:
                        raise OSError("offline injected publication failure")
                    return replace(src, dst)
                with patch.object(store.os, "replace", side_effect=fail_pending), self.assertRaises(OSError):
                    store.upsert_stats([record(2)])
                self.assertEqual(self.snapshots(), before)
                self.assertFalse(list(self.root.rglob("*.pending-*")))
                self.assertFalse(list(self.root.rglob("*.backup-*")))

    def test_fsync_failure_does_not_publish_or_acknowledge(self):
        before = self.snapshots()
        with patch.object(store.os, "fsync", side_effect=OSError("offline full disk")), self.assertRaises(OSError):
            store.upsert([record(2)])
        self.assertEqual(self.snapshots(), before)
        self.assertFalse(list(self.root.rglob("*.pending-*")))

    def test_rollback_failure_retains_old_backup_for_recovery(self):
        replace = os.replace
        old_cards = store.CARDS_PATH.read_bytes()
        def fail(src, dst):
            if Path(dst) == store.KB_PATH or (Path(dst) == store.CARDS_PATH and ".backup-" in Path(src).name):
                raise OSError("offline restore failed")
            return replace(src, dst)
        with patch.object(store.os, "replace", side_effect=fail), self.assertRaises(store.StoreWriteError):
            store.upsert([record(2)])
        backups = list(self.root.glob(".cards.json.backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), old_cards)
        self.assertEqual({r["item"]["cve_id"] for r in store.load_kb()}, {"CVE-2099-0001"})

    def test_unlocked_readers_only_see_complete_atomic_json(self):
        finished = threading.Event()
        def writer():
            try:
                for number in range(2, 22):
                    row = record(number)
                    row["item"]["description"] = "synthetic " * 1000
                    store.upsert([row])
            finally:
                finished.set()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(writer)
            reads = 0
            while not finished.is_set():
                try:
                    text = store.KB_PATH.read_text(encoding="utf-8")
                except PermissionError:
                    # Windows can reject a non-cooperating reader during replace;
                    # store.load_kb instead holds the same read/write lock.
                    if os.name != "nt":
                        raise
                    time.sleep(0.001)
                    continue
                rows = json.loads(text)
                reads += 1
                self.assertGreaterEqual(len(rows), 1)
                time.sleep(0.001)
            future.result(timeout=5)
            self.assertGreater(reads, 0)
        self.assertEqual(len(store.load_kb()), 21)

    def test_corrupt_existing_json_is_preserved_not_replaced_by_cards(self):
        before_cards = store.CARDS_PATH.read_bytes()
        store.KB_PATH.write_bytes(b'{"incomplete":')
        with self.assertRaises(store.StoreCorruptError):
            store.upsert([record(2)])
        self.assertEqual(store.KB_PATH.read_bytes(), b'{"incomplete":')
        self.assertEqual(store.CARDS_PATH.read_bytes(), before_cards)

    def test_valid_empty_kb_does_not_reimport_stale_cards(self):
        store.KB_PATH.write_text("[]", encoding="utf-8")
        self.assertEqual(store.load_kb(), [])
        self.assertEqual(store.KB_PATH.read_text(encoding="utf-8"), "[]")

    def test_missing_kb_can_bootstrap_old_cards_once(self):
        store.KB_PATH.unlink()
        self.assertEqual(len(store.load_kb()), 1)
        store.upsert([record(2)])
        self.assert_ids({"CVE-2099-0001", "CVE-2099-0002"})


class PersistentLockTest(StoreFixture):
    def test_thread_busy_has_finite_wait_and_owner_can_reenter(self):
        with store._write_lock():
            with store._write_lock(timeout=0):
                self.assertEqual(len(store.load_kb()), 1)
            start = time.monotonic()
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(lambda: store._write_lock(timeout=0.1).__enter__())
                with self.assertRaises(store.StoreBusy):
                    future.result(timeout=2)
            self.assertLess(time.monotonic() - start, 1.0)

    def test_process_wait_timeout_and_lock_release_after_owner_crash(self):
        child = self.spawn("""
with store._write_lock():
    (root / 'locked').write_text('ready')
    time.sleep(30)
""")
        self.wait_file(self.root / "locked")
        start = time.monotonic()
        with self.assertRaises(store.StoreBusy), store._write_lock(timeout=0.12):
            self.fail("Competing process admitted")
        self.assertLess(time.monotonic() - start, 1.0)
        child.kill()
        child.communicate(timeout=5)
        with store._write_lock(timeout=1):
            store.upsert([record(2)])
        self.assert_ids({"CVE-2099-0001", "CVE-2099-0002"})

    def test_process_collection_gate_rejects_overlapping_direct_collect(self):
        child = self.spawn("""
with store.collection_lock():
    (root / 'locked').write_text('ready')
    time.sleep(30)
""")
        self.wait_file(self.root / "locked")
        with patch("agents.orchestrator.monitor_run") as fetch, self.assertRaises(store.StoreBusy):
            orchestrator.run_collect("offline")
        fetch.assert_not_called()
        child.kill()
        child.communicate(timeout=5)

    def test_windows_sharing_conflict_retries_but_has_finite_budget(self):
        if os.name != "nt":
            self.skipTest("Windows-specific sharing conflict")
        replace = os.replace
        target = self.root / "share-conflict.json"
        pending = self.root / "pending.json"
        pending.write_text("[]")
        attempts = []
        def transient(src, dst):
            attempts.append(True)
            if len(attempts) <= 2:
                raise PermissionError("offline transient sharing conflict")
            return replace(src, dst)
        with patch.object(store.os, "replace", side_effect=transient):
            store._replace(pending, target)
        self.assertEqual(len(attempts), 3)
        pending.write_text("[]")
        start = time.monotonic()
        with patch.object(store.os, "replace", side_effect=PermissionError("offline persistent denial")), \
                self.assertRaises(PermissionError):
            store._replace(pending, target)
        self.assertLess(time.monotonic() - start, 1.5)


class CollectionAckTest(StoreFixture):
    def monitor(self, number, collector):
        return {"items": [record(number)["item"]], "steps": [], "collectors": {"osv": collector},
                "stats": {"osv_ok": True, "nvd_disabled_duplicate": True, "aggregate_disabled": True,
                          "hit": 1, "kept": 1}}

    def mock_steps(self):
        self.stack.enter_context(patch("agents.orchestrator.enrich_run", side_effect=lambda items, **kw:
            {"records": [enriched_record(item) for item in items], "steps": []}))
        self.stack.enter_context(patch("agents.orchestrator._documents_step", return_value=([], [])))

    def test_failed_persistence_never_advances_cursor_and_retry_is_safe(self):
        self.mock_steps()
        collector = Mock()
        before = self.snapshots()
        with patch("agents.orchestrator.monitor_run", return_value=self.monitor(2, collector)), \
             patch.object(store.os, "replace", side_effect=OSError("offline failed replace")), self.assertRaises(OSError):
            orchestrator.run_collect("offline")
        collector.commit_cursor.assert_not_called()
        self.assertEqual(self.snapshots(), before)
        def ack_after_durable_save():
            self.assert_ids({"CVE-2099-0001", "CVE-2099-0002"})
        collector.commit_cursor.side_effect = ack_after_durable_save
        with patch("agents.orchestrator.monitor_run", return_value=self.monitor(2, collector)):
            self.assertEqual(orchestrator.run_collect("offline")["status"], "success")
        collector.commit_cursor.assert_called_once()

    def test_overlapping_thread_round_is_busy_then_retry_keeps_both_acknowledged_batches(self):
        self.mock_steps()
        entered, release = threading.Event(), threading.Event()
        first, second = Mock(), Mock()
        def fetch(keyword):
            if keyword == "first":
                entered.set()
                if not release.wait(3):
                    raise RuntimeError("test release missing")
                return self.monitor(2, first)
            return self.monitor(3, second)
        with patch("agents.orchestrator.monitor_run", side_effect=fetch), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(orchestrator.run_collect, "first")
            self.assertTrue(entered.wait(2))
            try:
                with self.assertRaises(store.StoreBusy):
                    orchestrator.run_collect("second")
                second.commit_cursor.assert_not_called()
            finally:
                release.set()
            self.assertEqual(future.result(timeout=5)["status"], "success")
            self.assertEqual(orchestrator.run_collect("second")["status"], "success")
        first.commit_cursor.assert_called_once()
        second.commit_cursor.assert_called_once()
        self.assert_ids({"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"})


class CollectionEntryGateTest(StoreFixture):
    def setUp(self):
        super().setUp()
        from api.app import app
        from automation import schedule
        from fastapi.testclient import TestClient
        self.schedule = schedule
        self.stack.enter_context(patch.object(schedule, "STATE_PATH", self.root / "monitor.json"))
        self.stack.enter_context(patch.object(schedule, "LOG_PATH", self.root / "collect.log"))
        self.stack.enter_context(patch("api.b_monitor.b_monitor_on_refresh", return_value=False))
        self.stack.enter_context(patch("api.app._team_reachable_probe", return_value={"reachable": True, "enabled": True}))
        self.client = TestClient(app)

    def held_in_thread(self, callback):
        entered, release = threading.Event(), threading.Event()
        def hold():
            with store.collection_lock():
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("Missing test release")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(hold)
            self.assertTrue(entered.wait(2))
            try:
                callback()
            finally:
                release.set()
            future.result(timeout=3)

    def test_both_api_entries_busy_before_fetch_or_pipeline_changes(self):
        self.schedule.mark_running(phase="current live round", keyword="first")
        before = self.schedule.STATE_PATH.read_bytes()
        with patch("api.app.run_collect") as fetch, patch("automation.pipeline.begin_pipeline") as begin:
            def check():
                for path, body in (("/api/monitor/run", {"sync_library": False}), ("/api/collect", {"keyword": "offline"})):
                    response = self.client.post(path, json=body)
                    self.assertEqual(response.status_code, 409, response.text)
                    self.assertIn("正在进行", response.json()["detail"])
                self.assertEqual(self.schedule.STATE_PATH.read_bytes(), before)
            self.held_in_thread(check)
        fetch.assert_not_called()
        begin.assert_not_called()

    def test_scheduled_busy_preserves_live_pipeline_state(self):
        self.schedule.mark_running(phase="live manual round", keyword="first")
        before = self.schedule.STATE_PATH.read_bytes()
        with patch("agents.orchestrator.run_collect") as fetch, patch("rag.library.sync") as library, patch("rag.library.sync_team") as team:
            def check():
                result = self.schedule.run_once("second")
                self.assertEqual(result["status"], "busy")
                self.assertTrue(result["running"])
                self.assertEqual(self.schedule.STATE_PATH.read_bytes(), before)
            self.held_in_thread(check)
        fetch.assert_not_called()
        library.assert_not_called()
        team.assert_not_called()
        self.assertFalse(self.schedule._RUN_LOCK.locked())

    def test_manual_round_blocks_legacy_collect_until_pipeline_finalizes(self):
        entered, release = threading.Event(), threading.Event()
        def fetch(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Missing test release")
            return {"status": "success", "records": store.load_kb(), "steps": [], "round_stats": {"inserted": 0}}
        with patch("api.app.run_collect", side_effect=fetch), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.client.post, "/api/monitor/run", json={"sync_library": False})
            self.assertTrue(entered.wait(2))
            try:
                response = self.client.post("/api/collect", json={"keyword": "second"})
                self.assertEqual(response.status_code, 409)
                self.assertTrue(self.schedule.state()["running"])
                self.assertEqual(self.schedule.state()["pipeline"]["status"], "running")
            finally:
                release.set()
            first = future.result(timeout=5)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["status"], "success")
        self.assertFalse(self.schedule.state()["running"])
        self.assertEqual(self.schedule.state()["pipeline"]["status"], "done")

    def test_scheduler_blocks_manual_entry_through_document_sync(self):
        entered, release = threading.Event(), threading.Event()
        def sync(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Missing test release")
            return {"attempted": 0, "ok": 0, "sources": []}
        result = {"status": "success", "records": store.load_kb(), "steps": [], "round_stats": {"inserted": 0}}
        with patch("agents.orchestrator.run_collect", return_value=result), patch("rag.library.sync", side_effect=sync), \
                patch("rag.library.sync_team", return_value={"attempted": 0, "ok": 0, "sources": []}), \
                ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.schedule.run_once, "first")
            self.assertTrue(entered.wait(2))
            try:
                response = self.client.post("/api/monitor/run", json={"sync_library": False})
                self.assertEqual(response.status_code, 409)
                self.assertTrue(self.schedule.state()["running"])
            finally:
                release.set()
            completed = future.result(timeout=5)
        self.assertEqual(completed["last_status"], "success")
        self.assertFalse(completed["running"])
        self.assertFalse(self.schedule._RUN_LOCK.locked())


if __name__ == "__main__":
    unittest.main()
