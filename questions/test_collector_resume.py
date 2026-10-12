"""Independent offline regressions for missed records and unsafe checkpoints."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collectors import cursors
from collectors.nvd import NVDCollector, fetch_nvd, query_cursor_key
from collectors.osv import OSVCollector, _post, package_cursor_key


NOW = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


def osv_record(number, day, *, modified=None):
    return {"id": "CVE-2026-%04d" % number, "summary": "Synthetic component vulnerability",
            "published": "2026-09-%02dT00:00:00Z" % day,
            "modified": modified or "2026-09-%02dT00:00:00Z" % day}


def nvd_record(number, modified=None):
    return {"cve": {"id": "CVE-2026-%04d" % number,
                    "published": "2026-10-10T00:00:00Z",
                    "lastModified": modified or "2026-10-11T00:00:00Z",
                    "descriptions": [{"lang": "en", "value": "Synthetic LLM issue"}]}}


def nvd_page(rows, total=None, offset=0, declared=None):
    return {"vulnerabilities": rows, "totalResults": len(rows) if total is None else total,
            "startIndex": offset, "resultsPerPage": len(rows) if declared is None else declared}


class CursorFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "state" / "cursors.json"
        patcher = patch.object(cursors, "CURSOR_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)


class OSVResumeTests(CursorFixture):
    def test_cap_preserves_every_unsaved_record_for_following_runs(self):
        upstream = [osv_record(4101, 1), osv_record(4102, 2), osv_record(4103, 3)]
        saved, batches = set(), []
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": upstream}):
            for _ in range(4):
                collector = OSVCollector(per_package_limit=1)
                items = collector.collect()
                batches.append([row["cve_id"] for row in items])
                saved.update(row["cve_id"] for row in items)
                collector.commit_cursor()  # Successful storage of exactly this emitted batch.
        self.assertEqual(batches, [["CVE-2026-4103"], ["CVE-2026-4102"], ["CVE-2026-4101"], []])
        self.assertEqual(saved, {row["id"] for row in upstream})

    def test_failed_package_recovers_older_record_after_other_package_saves_newer(self):
        packages = [("PyPI", "vllm"), ("PyPI", "langchain")]
        older, newer = osv_record(4201, 2), osv_record(4202, 4)
        def flaky(ecosystem, name):
            if name == "vllm":
                raise TimeoutError("Synthetic source outage")
            return {"vulns": [newer]}
        with patch("collectors.osv.resolve_packages", return_value=packages), \
                patch("collectors.osv._post", side_effect=flaky):
            first = OSVCollector()
            self.assertEqual([r["cve_id"] for r in first.collect()], [newer["id"]])
            first.commit_cursor()
        self.assertEqual(cursors.get_state(package_cursor_key("PyPI", "vllm")), {})
        with patch("collectors.osv.resolve_packages", return_value=packages), \
                patch("collectors.osv._post", side_effect=lambda ecosystem, name: {"vulns": [older if name == "vllm" else newer]}):
            recovered = OSVCollector()
            self.assertEqual([r["cve_id"] for r in recovered.collect()], [older["id"]])

    def test_changing_product_does_not_reuse_another_packages_position(self):
        first, second = osv_record(4301, 20), osv_record(4302, 1)
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": [first]}):
            collector = OSVCollector(keyword="vllm")
            collector.collect()
            collector.commit_cursor()
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "langchain")]), \
                patch("collectors.osv._post", return_value={"vulns": [second]}):
            collector = OSVCollector(keyword="langchain")
            self.assertEqual([r["cve_id"] for r in collector.collect()], [second["id"]])
            self.assertFalse(collector.last_stats["incremental"])

    def test_legacy_global_position_replays_old_records_instead_of_claiming_them_saved(self):
        cursors.set_cursor("osv", "2026-10-12T12:00:00Z")
        old = osv_record(4401, 1)
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": [old]}):
            collector = OSVCollector()
            self.assertEqual([r["cve_id"] for r in collector.collect()], [old["id"]])
            self.assertTrue(collector.last_stats["legacy_global_replayed"])
            collector.commit_cursor()
            self.assertEqual(OSVCollector().collect(), [])
        self.assertEqual(cursors.get_cursor("osv"), "2026-10-12T12:00:00Z")

    def test_uncommitted_collection_repeats_after_storage_failure(self):
        record = osv_record(4501, 1)
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": [record]}):
            first = OSVCollector()
            self.assertEqual(len(first.collect()), 1)
            self.assertFalse(self.path.exists())
            self.assertEqual(len(OSVCollector().collect()), 1)

    def test_same_timestamp_revision_and_late_old_record_are_not_lost(self):
        original = osv_record(4601, 20)
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": [original]}):
            first = OSVCollector()
            first.collect()
            first.commit_cursor()
        revised = dict(original, summary="Changed fact without timestamp advance")
        late = osv_record(4602, 1)
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": [revised, late]}):
            self.assertEqual({r["cve_id"] for r in OSVCollector().collect()}, {original["id"], late["id"]})

    def test_osv_follows_pagination_before_acknowledging_package(self):
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", side_effect=[
                    {"vulns": [osv_record(4701, 1)], "next_page_token": "page-2"},
                    {"vulns": [osv_record(4702, 2)]},
                ]) as request:
            collector = OSVCollector()
            self.assertEqual(len(collector.collect()), 2)
            self.assertEqual(request.call_args_list[1].kwargs, {"page_token": "page-2"})
            self.assertFalse(self.path.exists())
            collector.commit_cursor()
        self.assertEqual(len(cursors.get_state(package_cursor_key("PyPI", "vllm"))["record_revisions"]), 2)

    def test_osv_page_failure_discards_partial_package_and_can_retry(self):
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", side_effect=[
                    {"vulns": [osv_record(4801, 1)], "next_page_token": "page-2"}, TimeoutError(),
                ]):
            collector = OSVCollector()
            with self.assertRaises(RuntimeError):
                collector.collect()
            collector.commit_cursor()
        self.assertFalse(self.path.exists())

    def test_osv_page_limit_and_repeated_token_do_not_commit_partial_records(self):
        for pages, payload in [(1, {"vulns": [osv_record(4901, 1)], "next_page_token": "next"}),
                               (3, {"vulns": [], "next_page_token": "same"})]:
            with self.subTest(pages=pages), patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                    patch("collectors.osv._post", return_value=payload):
                collector = OSVCollector(max_pages=pages)
                with self.assertRaises(RuntimeError):
                    collector.collect()
                collector.commit_cursor()
                self.assertFalse(self.path.exists())

    def test_invalid_nonstring_page_token_cannot_look_like_a_complete_page(self):
        with patch("collectors.osv.resolve_packages", return_value=[("PyPI", "vllm")]), \
                patch("collectors.osv._post", return_value={"vulns": [osv_record(4921, 1)], "next_page_token": 0}):
            collector = OSVCollector()
            with self.assertRaises(RuntimeError):
                collector.collect()
            collector.commit_cursor()
        self.assertFalse(self.path.exists())

    def test_duplicate_cve_in_other_package_is_deferred_until_its_payload_was_emitted(self):
        one = osv_record(4951, 1)
        two = dict(one, id="GHSA-test-pypi", aliases=[one["id"]], summary="Other package evidence")
        def response(ecosystem, name):
            return {"vulns": [one if ecosystem == "PyPI" else two]}
        packages = [("PyPI", "vllm"), ("GIT", "github.com/vllm-project/vllm")]
        with patch("collectors.osv.resolve_packages", return_value=packages), patch("collectors.osv._post", side_effect=response):
            first = OSVCollector()
            batch = first.collect()
            self.assertEqual(len(batch), 1)
            first.commit_cursor()
            saved_counts = [len(cursors.get_state(package_cursor_key(*p))["record_revisions"]) for p in packages]
            self.assertEqual(sum(saved_counts), 1)
            second = OSVCollector()
            self.assertEqual(len(second.collect()), 1)
            second.commit_cursor()
            self.assertEqual(OSVCollector().collect(), [])

    def test_page_token_is_in_osv_http_body(self):
        with patch("collectors.osv.urllib.request.urlopen") as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = b'{"vulns":[]}'
            _post("PyPI", "vllm", page_token="continuation")
        body = json.loads(open_url.call_args.args[0].data)
        self.assertEqual(body, {"package": {"ecosystem": "PyPI", "name": "vllm"}, "page_token": "continuation"})


class NVDResumeTests(CursorFixture):
    def setUp(self):
        super().setUp()
        clock = patch("collectors.nvd.datetime", FrozenDateTime)
        clock.start()
        self.addCleanup(clock.stop)

    def collector(self, **kwargs):
        return NVDCollector(request_interval=0, settle_minutes=0, **kwargs)

    def seed(self, keyword, stamp):
        cursors.set_cursor(query_cursor_key(keyword), stamp, meta={"protocol": "nvd_query_windows_v2", "keyword": keyword})

    def test_all_pages_share_fixed_window_and_all_ids_are_emitted(self):
        with patch("collectors.nvd.fetch_nvd", side_effect=[
            nvd_page([nvd_record(5101)], total=2), nvd_page([nvd_record(5102)], total=2, offset=1),
        ]) as request:
            collector = self.collector(limit=1)
            self.assertEqual({r["cve_id"] for r in collector.collect()}, {"CVE-2026-5101", "CVE-2026-5102"})
            calls = request.call_args_list
            self.assertEqual([c.kwargs["start_index"] for c in calls], [0, 1])
            self.assertEqual(calls[0].kwargs["start"], NOW - timedelta(days=30))
            self.assertEqual(calls[0].kwargs["end"], NOW)
            self.assertEqual(calls[0].kwargs["start"], calls[1].kwargs["start"])
            self.assertEqual(calls[0].kwargs["end"], calls[1].kwargs["end"])
            self.assertFalse(self.path.exists())
            collector.commit_cursor()
        self.assertEqual(cursors.parse_utc(cursors.get_cursor(query_cursor_key("llm"))), NOW)

    def test_page_error_never_advances_or_leaves_previous_success_pending(self):
        self.seed("llm", "2026-10-10T00:00:00Z")
        original = self.path.read_bytes()
        with patch("collectors.nvd.fetch_nvd", side_effect=[nvd_page([nvd_record(5201)], total=2), TimeoutError()]):
            collector = self.collector(limit=1)
            with self.assertRaises(TimeoutError):
                collector.collect()
            collector.commit_cursor()
        self.assertEqual(self.path.read_bytes(), original)

    def test_bad_pagination_or_duplicate_identity_never_commits(self):
        cases = [
            [nvd_page([nvd_record(5301)], total=2), nvd_page([], total=2, offset=1, declared=1)],
            [nvd_page([nvd_record(5301)], total=2), nvd_page([nvd_record(5302)], total=3, offset=1)],
            [nvd_page([nvd_record(5301)], total=2), nvd_page([nvd_record(5302)], total=2, offset=0)],
            [nvd_page([nvd_record(5301)], total=2), nvd_page([nvd_record(5301)], total=2, offset=1)],
            [{"vulnerabilities": [], "startIndex": 0, "resultsPerPage": 0}],
        ]
        for payloads in cases:
            with self.subTest(payloads=payloads), patch("collectors.nvd.fetch_nvd", side_effect=payloads):
                collector = self.collector(limit=1)
                with self.assertRaises((RuntimeError, ValueError)):
                    collector.collect()
                collector.commit_cursor()
                self.assertFalse(self.path.exists())

    def test_page_budget_refuses_to_acknowledge_first_page(self):
        with patch("collectors.nvd.fetch_nvd", return_value=nvd_page([nvd_record(5401)], total=2)) as request:
            collector = self.collector(limit=1, max_pages=1)
            with self.assertRaises(RuntimeError):
                collector.collect()
            collector.commit_cursor()
            self.assertEqual(request.call_count, 1)
        self.assertFalse(self.path.exists())

    def test_legacy_global_cursor_replays_old_records_without_date_cut(self):
        cursors.set_cursor("nvd", "2026-10-12T12:00:00Z")
        with patch("collectors.nvd.fetch_nvd", return_value=nvd_page([nvd_record(5501, "2001-01-01T00:00:00Z")])) as request:
            collector = self.collector()
            self.assertEqual(len(collector.collect()), 1)
            self.assertIsNone(request.call_args.kwargs["start"])
            self.assertIsNone(request.call_args.kwargs["end"])
            self.assertTrue(collector.last_stats["legacy_global_replayed"])
            collector.commit_cursor()
        self.assertEqual(cursors.get_cursor("nvd"), "2026-10-12T12:00:00Z")
        self.assertTrue(cursors.get_cursor(query_cursor_key("llm")))

    def test_keyword_scope_and_incremental_overlap_are_independent(self):
        self.seed("vllm", "2026-10-10T00:00:00Z")
        with patch("collectors.nvd.fetch_nvd", return_value=nvd_page([nvd_record(5601)])) as request:
            narrow = self.collector(keyword="vllm")
            narrow.collect()
            self.assertEqual(request.call_args.kwargs["start"], datetime(2026, 10, 9, 23, 30, tzinfo=timezone.utc))
            self.assertTrue(narrow.last_stats["incremental"])
        with patch("collectors.nvd.fetch_nvd", return_value=nvd_page([nvd_record(5602)])) as request:
            fresh = self.collector(keyword="langchain")
            fresh.collect()
            self.assertEqual(request.call_args.kwargs["start"], NOW - timedelta(days=30))
            self.assertFalse(fresh.last_stats["incremental"])

    def test_long_gap_uses_legal_windows_and_commits_only_completed_prefix(self):
        self.seed("llm", "2025-01-01T00:00:00Z")
        with patch("collectors.nvd.fetch_nvd", return_value=nvd_page([])) as request:
            collector = self.collector(max_windows=1)
            self.assertEqual(collector.collect(), [])
            start, end = request.call_args.kwargs["start"], request.call_args.kwargs["end"]
            self.assertEqual(end - start, timedelta(days=119))
            self.assertTrue(collector.last_stats["pending_windows"])
            collector.commit_cursor()
        self.assertEqual(cursors.parse_utc(cursors.get_cursor(query_cursor_key("llm"))), end)
        self.assertLess(end, NOW)

    def test_out_of_window_or_missing_modified_time_refuses_checkpoint(self):
        for modified in ["2020-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "invalid"]:
            with self.subTest(modified=modified), patch("collectors.nvd.fetch_nvd", return_value=nvd_page([nvd_record(5701, modified)])):
                collector = self.collector()
                with self.assertRaises(ValueError):
                    collector.collect()
                collector.commit_cursor()
                self.assertFalse(self.path.exists())

    def test_first_empty_windows_can_finish_complete_unrestricted_query(self):
        with patch("collectors.nvd.fetch_nvd", side_effect=[nvd_page([]), nvd_page([]), nvd_page([nvd_record(5801, "2001-01-01T00:00:00Z")])]) as request:
            collector = self.collector(max_pages=3)
            self.assertEqual(len(collector.collect()), 1)
            self.assertEqual(request.call_count, 3)
            self.assertIsNone(request.call_args.kwargs["start"])

    def test_disabled_cursors_do_not_write(self):
        with patch("collectors.nvd.fetch_nvd", return_value=nvd_page([nvd_record(5901)])):
            collector = self.collector(use_cursor=False)
            collector.collect()
            collector.commit_cursor()
        self.assertFalse(self.path.exists())

    def test_http_window_is_explicit_utc_and_pagination_offset_is_sent(self):
        start = datetime(2026, 10, 10, 8, tzinfo=timezone(timedelta(hours=8)))
        with patch("collectors.nvd.urllib.request.urlopen") as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = b'{}'
            fetch_nvd("llm", 100, start_index=100, start=start, end=NOW)
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(open_url.call_args.args[0].full_url).query)
        self.assertEqual(query["startIndex"], ["100"])
        self.assertEqual(query["lastModStartDate"], ["2026-10-10T00:00:00.000Z"])
        self.assertEqual(query["lastModEndDate"], ["2026-10-12T12:00:00.000Z"])


class CursorPersistenceTests(CursorFixture):
    def test_mixed_fractional_precision_and_offsets_compare_real_utc_time(self):
        cursors.set_cursor("nvd", "2026-10-12T00:00:00Z")
        cursors.set_cursor("nvd", "2026-10-12T00:00:00.500Z")
        self.assertEqual(cursors.get_cursor("nvd"), "2026-10-12T00:00:00.500Z")
        cursors.set_cursor("nvd", "2026-10-12T08:00:00+08:00")
        self.assertEqual(cursors.get_cursor("nvd"), "2026-10-12T00:00:00.500Z")

    def test_atomic_replacement_failure_keeps_previous_file(self):
        cursors.set_cursor("nvd", "2026-10-11T00:00:00Z")
        previous = self.path.read_bytes()
        with patch("collectors.cursors.os.replace", side_effect=OSError("Synthetic disk failure")):
            with self.assertRaises(OSError):
                cursors.set_cursor("nvd", "2026-10-12T00:00:00Z")
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(list(self.path.parent.glob(".collect_cursors_*")), [])

    def test_invalid_multi_scope_update_cannot_partially_write(self):
        with self.assertRaises(ValueError):
            cursors.commit_states({"first": {"window_end_at": "2026-10-12T00:00:00Z"}, "bad": {"window_end_at": "2026-10-12"}})
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
