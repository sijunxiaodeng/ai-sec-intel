"""Offline tests for collect pipeline state, cursors, and upsert round stats."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collectors import cursors as cursors_mod
from collectors.osv import OSVCollector
from database import store as store_mod
from models import enriched_record, intelligence_item


class TestCollectCursors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "collect_cursors.json"
        self._old = cursors_mod.CURSOR_PATH
        cursors_mod.CURSOR_PATH = self.path

    def tearDown(self):
        cursors_mod.CURSOR_PATH = self._old
        self.tmp.cleanup()

    def test_monotonic_advance(self):
        cursors_mod.set_cursor("osv", "2024-01-01T00:00:00Z")
        cursors_mod.set_cursor("osv", "2023-01-01T00:00:00Z")
        self.assertEqual(cursors_mod.get_cursor("osv"), "2024-01-01T00:00:00Z")
        cursors_mod.set_cursor("osv", "2025-06-01T12:00:00Z")
        self.assertEqual(cursors_mod.get_cursor("osv"), "2025-06-01T12:00:00Z")


class TestOSVIncremental(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "collect_cursors.json"
        self._old = cursors_mod.CURSOR_PATH
        cursors_mod.CURSOR_PATH = self.path

    def tearDown(self):
        cursors_mod.CURSOR_PATH = self._old
        self.tmp.cleanup()

    def test_saved_package_revisions_filter_kept_but_count_fetched(self):
        cursors_mod.set_cursor("osv", "2024-06-01T00:00:00Z")

        def fake_post(eco, name):
            return {
                "vulns": [
                    {
                        "id": "CVE-2023-0001",
                        "summary": "old",
                        "published": "2023-01-01T00:00:00Z",
                        "modified": "2023-02-01T00:00:00Z",
                    },
                    {
                        "id": "CVE-2024-9999",
                        "summary": "new",
                        "published": "2024-07-01T00:00:00Z",
                        "modified": "2024-07-02T00:00:00Z",
                    },
                ]
            }

        coll = OSVCollector(keyword="vllm", per_package_limit=10)
        with patch("collectors.osv._post", side_effect=fake_post):
            with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]):
                first = coll.collect()
                # An old global timestamp cannot prove either record was saved.
                self.assertEqual(len(first), 2)
                coll.commit_cursor()
                changed = fake_post("PyPI", "vllm")
                changed["vulns"][1]["summary"] = "new revision"
                with patch("collectors.osv._post", return_value=changed):
                    items = coll.collect()
        self.assertEqual(coll.last_stats["fetched"], 2)
        self.assertEqual(coll.last_stats["kept"], 1)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cve_id"], "CVE-2024-9999")
        self.assertTrue(coll.last_stats["incremental"])

    def test_second_run_can_keep_zero(self):
        cursors_mod.set_cursor("osv", "2025-01-01T00:00:00Z")

        def fake_post(eco, name):
            return {
                "vulns": [
                    {
                        "id": "CVE-2024-1111",
                        "summary": "older",
                        "published": "2024-01-01T00:00:00Z",
                        "modified": "2024-06-01T00:00:00Z",
                    }
                ]
            }

        coll = OSVCollector(keyword="vllm", per_package_limit=10)
        with patch("collectors.osv._post", side_effect=fake_post):
            with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]):
                self.assertEqual(len(coll.collect()), 1)
                coll.commit_cursor()
                items = coll.collect()
        self.assertEqual(items, [])
        self.assertEqual(coll.last_stats["fetched"], 1)
        self.assertEqual(coll.last_stats["kept"], 0)


class TestUpsertStats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self._paths = (
            store_mod.DATA,
            store_mod.KB_PATH,
            store_mod.CARDS_PATH,
            store_mod.CARDS_JS_PATH,
            store_mod.RUNS_PATH,
        )
        store_mod.DATA = root / "data"
        store_mod.KB_PATH = store_mod.DATA / "knowledge.json"
        store_mod.CARDS_PATH = root / "cards.json"
        store_mod.CARDS_JS_PATH = root / "cards.js"
        store_mod.RUNS_PATH = store_mod.DATA / "runs.json"
        store_mod.DATA.mkdir(parents=True, exist_ok=True)
        store_mod.KB_PATH.write_text("[]", encoding="utf-8")

    def tearDown(self):
        (
            store_mod.DATA,
            store_mod.KB_PATH,
            store_mod.CARDS_PATH,
            store_mod.CARDS_JS_PATH,
            store_mod.RUNS_PATH,
        ) = self._paths
        self.tmp.cleanup()

    def _rec(self, cve, title="t"):
        return enriched_record(intelligence_item({
            "cve_id": cve,
            "title": title,
            "description": "d",
            "source": "OSV",
            "sources": ["OSV"],
            "published_at": "2024-01-01T00:00:00Z",
            "collected_at": "2024-01-02T00:00:00Z",
            "product": "vllm",
        }))

    def test_inserted_vs_merged(self):
        first = store_mod.upsert_stats([self._rec("CVE-2024-1")])
        self.assertEqual(first["inserted"], 1)
        self.assertEqual(first["merged"], 0)
        second = store_mod.upsert_stats([self._rec("CVE-2024-1", "again"), self._rec("CVE-2024-2")])
        self.assertEqual(second["inserted"], 1)
        self.assertEqual(second["merged"], 1)
        self.assertEqual(second["total"], 2)


class TestPipelineState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        from automation import schedule as schedule_mod
        from automation import pipeline as pipeline_mod

        self.schedule_mod = schedule_mod
        self.pipeline_mod = pipeline_mod
        self._state = schedule_mod.STATE_PATH
        schedule_mod.STATE_PATH = Path(self.tmp.name) / "monitor.json"
        schedule_mod.STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.schedule_mod.STATE_PATH = self._state
        self.tmp.cleanup()

    def test_migrates_old_per_source_stages(self):
        # Simulate leftover monitor.json from earlier UI (抓取·NVD 等).
        stale = {
            "started_at": "2026-10-11T08:40:00Z",
            "interval_hours": 6,
            "running": False,
            "pipeline": {
                "status": "done",
                "stages": [
                    {"id": "fetch_multisource", "title": "抓取 · 多路采集", "status": "skip"},
                    {"id": "fetch_nvd", "title": "抓取 · NVD", "status": "ok"},
                    {"id": "fetch_osv", "title": "抓取 · OSV", "status": "ok"},
                ],
                "metrics": {"hit": 1942, "inserted": 0, "merged": 18},
                "summary": "旧摘要",
            },
        }
        self.schedule_mod.STATE_PATH.write_text(
            json.dumps(stale, ensure_ascii=False), encoding="utf-8"
        )
        pipe = self.pipeline_mod.get_pipeline()
        self.assertEqual([s["id"] for s in pipe["stages"]], ["monitoring", "persist", "library_sync"])
        self.assertFalse(any("fetch_nvd" == s["id"] for s in pipe["stages"]))
        self.assertEqual(pipe["metrics"].get("hit"), 1942)

    def test_begin_update_finish(self):
        pipe = self.pipeline_mod.begin_pipeline()
        self.assertEqual(pipe["status"], "running")
        ids = [s["id"] for s in pipe["stages"]]
        self.assertEqual(ids, ["monitoring", "persist", "library_sync"])
        # Mid-run: metrics stay 0 until collectors finish and update_stage passes metrics.
        mid = self.pipeline_mod.get_pipeline()
        self.assertEqual(mid["metrics"].get("hit"), 0)
        self.pipeline_mod.update_stage(
            "monitoring",
            status="ok",
            did="多方面来源抓取已完成",
            got="命中 10，保留 0",
            produced="进入整理入库 0 条",
            note="多方面来源已尽力查询",
            metrics={"hit": 10, "kept": 0, "external_fetches": 3},
        )
        after_mon = self.pipeline_mod.get_pipeline()
        self.assertEqual(after_mon["metrics"].get("hit"), 10)
        self.assertEqual(after_mon["metrics"].get("external_fetches"), 3)
        self.pipeline_mod.update_stage(
            "persist",
            status="ok",
            did="规范化并合并写入",
            got="参与 0",
            produced="新增 0 · 合并 0",
            metrics={"inserted": 0, "merged": 0},
        )
        done = self.pipeline_mod.finish_pipeline(
            ok=True,
            metrics={"hit": 10, "kept": 0, "inserted": 0, "merged": 0, "external_fetches": 3},
        )
        self.assertEqual(done["status"], "done")
        self.assertIn("命中 10", done["summary"])
        self.assertEqual(done["metrics"]["inserted"], 0)
        self.assertNotIn("fetch_osv", [s["id"] for s in done["stages"]])
        raw = json.loads(self.schedule_mod.STATE_PATH.read_text(encoding="utf-8"))
        self.assertFalse(raw.get("running"))


if __name__ == "__main__":
    unittest.main()
