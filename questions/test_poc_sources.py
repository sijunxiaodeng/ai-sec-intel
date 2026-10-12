"""Own synthetic source fixtures only: no foreign PoC is run or committed."""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from enrichment import poc_sources as sources


class PoCSourcesTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.db = self.root / "poc.sqlite3"
        self.catalog = self.root / "catalog.json"
        self.bodies = {
            "README.md": b"# Synthetic fixture\nExample environment: version 0.1.33\n",
            # Valid syntax with observable side effects if somebody imports it.
            "main.py": b"import subprocess\nsubprocess.run(['fixture-must-never-run'])\nraise RuntimeError('source was executed')\n",
            "server.py": b"from fixture_missing_module import Thing\ndef create_example():\n    return 'example'\n",
            "requirements.txt": b"fixture-package==1.2.3\nfixture-web>=2.0\n",
            "LICENSE": b"Own test fixture; no third party source code.\n",
        }
        self.candidate = {
            "cve_id": "CVE-2024-37032", "candidate_id": "fixture-source",
            "repository": "fixture-owner/fixture-source", "commit_sha": "a" * 40,
            "parent_repository": "fixture-parent/fixture-source", "license": "Fixture license",
            "copyright": "Fixture author",
            "files": [self.metadata(path, body) for path, body in self.bodies.items()],
            "review": {"reviewed_by": "development_agent", "review_method": "manual_source_read_and_ast",
                       "runtime_validation": "not_run", "summary": "这是用于完整性回归的合成来源，不代表真实 PoC。",
                       "capability": "fixture_only", "dependencies_file": "requirements.txt",
                       "findings": [{"text": "测试 Python 文件包含副作用；本模块只解析其 AST。", "file": "main.py", "lines": [1, 3]}],
                       "target_version_claim": {"version": "0.1.33", "file": "README.md", "lines": [2, 2]},
                       "notes": ["未执行合成来源代码。"]},
        }
        self.write_catalog()
        catalog_patch = patch.object(sources, "CATALOG_PATH", self.catalog)
        catalog_patch.start()
        self.addCleanup(catalog_patch.stop)
        for target in ("socket.socket", "socket.getaddrinfo"):
            blocker = patch(target, side_effect=AssertionError("network is forbidden in offline PoC source tests"))
            blocker.start()
            self.addCleanup(blocker.stop)
        self.urls = []

    @staticmethod
    def metadata(path, body):
        return {"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                "git_blob_sha": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()}

    def write_catalog(self, candidates=None):
        self.catalog.write_text(json.dumps({"candidates": candidates if candidates is not None else [self.candidate]}, ensure_ascii=False), encoding="utf-8")

    def fetch(self, url):
        self.urls.append(url)
        prefix = "https://raw.githubusercontent.com/fixture-owner/fixture-source/" + "a" * 40 + "/"
        self.assertTrue(url.startswith(prefix))
        return self.bodies[url[len(prefix):]]

    def collect(self, **kwargs):
        return sources.collect("CVE-2024-37032", db_path=self.db, fetcher=kwargs.get("fetcher", self.fetch))

    def report(self):
        return sources.report("CVE-2024-37032", db_path=self.db)

    def mutate(self, statement, params=()):
        with self.database() as conn:
            conn.execute(statement, params)

    @contextmanager
    def database(self):
        conn = sqlite3.connect(self.db)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def test_missing_report_is_read_only_and_has_pending_candidate(self):
        result = self.report()
        self.assertEqual(result["status"], "not_collected")
        self.assertEqual(result["items"][0]["validation"], "not_run")
        self.assertEqual(result["items"][0]["availability"], "pending")
        self.assertFalse(self.db.exists())
        self.assertFalse(self.urls)

    def test_complete_snapshot_is_pinned_source_not_runtime_verification(self):
        result = self.collect()
        item = result["items"][0]
        self.assertEqual(result["status"], "static_reviewed")
        self.assertEqual(item["review"]["status"], "development_static_review")
        self.assertFalse(item["review"]["independent_validation"])
        self.assertEqual(item["validation"], "not_run")
        self.assertEqual(item["availability"], "pending")
        self.assertEqual(item["parent_repository"], "fixture-parent/fixture-source")
        self.assertEqual(item["license"], "Fixture license")
        self.assertEqual(item["copyright"], "Fixture author")
        self.assertEqual(len(item["files"]), 5)
        self.assertEqual(item["dependencies"][0]["specifier"], "==1.2.3")
        self.assertEqual(item["files"][1]["imports"], ["subprocess"])
        self.assertEqual(item["files"][1]["syntax_status"], "valid")
        self.assertEqual(result["latest_attempt"]["files_fetched"], 5)
        self.assertEqual(len(self.urls), 5)
        for evidence in result["evidence"]:
            self.assertTrue(evidence["citation_id"].startswith("CVE-2024-37032/POC-"))
            self.assertEqual(evidence["text_sha256"], hashlib.sha256(evidence["text"].encode()).hexdigest())
            self.assertEqual(evidence["validation"], "not_run")
        texts = {row["citation_id"]: row["text"] for row in result["evidence"]}
        for fact in result["facts"]:
            self.assertEqual(fact["text"], texts[fact["evidence_ids"][0]])
        self.assertFalse(list(self.root.glob("*.py")))
        # Sources stay in SQLite, never materialize as importable Python files.
        self.assertEqual(self.report()["evidence"], result["evidence"])

    def test_read_only_report_does_not_fetch_import_install_or_execute(self):
        with patch("subprocess.run", side_effect=AssertionError("source execution is forbidden")), \
                patch.object(sources, "_fetch", side_effect=AssertionError("default network forbidden")):
            self.collect()
            before = self.db.read_bytes()
            report = self.report()
            self.assertEqual(report["status"], "static_reviewed")
            self.assertEqual(before, self.db.read_bytes())
        self.assertNotIn("fixture_missing_module", __import__("sys").modules)

    def test_repeated_collection_does_not_duplicate_snapshot_files_or_evidence(self):
        first = self.collect()
        second = self.collect()
        self.assertEqual(first["items"][0]["evidence_ids"], second["items"][0]["evidence_ids"])
        with self.database() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM poc_files").fetchone()[0], 5)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM poc_snapshots").fetchone()[0], 1)

    def test_partial_failure_never_publishes_any_source(self):
        def failing(url):
            if url.endswith("server.py"):
                raise TimeoutError("fixture error")
            return self.fetch(url)
        result = self.collect(fetcher=failing)
        self.assertEqual(result["status"], "error")
        self.assertIn("最近来源采集失败", result["detail"])
        self.assertTrue(result["items"][0]["collection_failed"])
        self.assertEqual(result["latest_attempt"]["status"], "error")
        self.assertEqual(result["latest_attempt"]["files_fetched"], 2)
        self.assertFalse(result["evidence"])
        with self.database() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM poc_files").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM poc_snapshots").fetchone()[0], 0)

    def test_failed_refresh_preserves_complete_snapshot_with_separate_latest_attempt(self):
        first = self.collect()
        at = first["items"][0]["retrieved_at"]
        result = self.collect(fetcher=Mock(side_effect=TimeoutError("fixture error")))
        self.assertEqual(result["status"], "static_reviewed")
        self.assertEqual(result["items"][0]["retrieved_at"], at)
        self.assertTrue(result["items"][0]["retained_previous"])
        self.assertEqual(result["latest_attempt"]["status"], "error")
        self.assertNotEqual(result["latest_attempt"]["queried_at"], at)
        self.assertIn("最近采集失败", result["detail"])
        self.assertEqual(first["evidence"], result["evidence"])

    def test_hash_mismatch_nonbytes_invalid_utf8_fail_closed(self):
        for body in (b"different body", "not bytes", b"\xff" * len(self.bodies["README.md"])):
            with self.subTest(body=repr(body)[:20]):
                result = self.collect(fetcher=Mock(return_value=body))
                self.assertFalse(result["evidence"])
                self.assertEqual(result["latest_attempt"]["status"], "error")

    def test_same_size_body_and_recomputed_storage_hash_cannot_forge_pinned_evidence(self):
        self.collect()
        original = self.bodies["main.py"]
        tampered = original.replace(b"fixture-must-never-run", b"fixture-will-run-here!")
        self.assertEqual(len(tampered), len(original))
        meta = self.metadata("main.py", tampered)
        self.mutate("UPDATE poc_files SET body=?,sha256=?,git_blob_sha=?,size=? WHERE path='main.py'",
                    (tampered, meta["sha256"], meta["git_blob_sha"], meta["size"]))
        report = self.report()
        self.assertEqual(report["status"], "error")
        self.assertFalse(report["evidence"])
        self.assertEqual(report["items"][0]["validation"], "not_run")

    def test_body_only_tamper_is_rejected(self):
        self.collect()
        self.mutate("UPDATE poc_files SET body=? WHERE path='main.py'", (b"raise Exception('forged')",))
        self.assertEqual(self.report()["status"], "error")
        self.assertFalse(self.report()["facts"])

    def test_missing_extra_or_cross_cve_file_cannot_pass_complete_snapshot(self):
        changes = (("DELETE FROM poc_files WHERE path='LICENSE'", ()),
                   ("UPDATE poc_files SET path='unexpected.txt' WHERE path='LICENSE'", ()),
                   ("UPDATE poc_files SET cve_id='CVE-2025-0312' WHERE path='LICENSE'", ()))
        for statement, params in changes:
            with self.subTest(statement=statement):
                self.collect()
                self.mutate(statement, params)
                self.assertEqual(self.report()["status"], "error")
                self.assertFalse(self.report()["evidence"])
                # Clean orphan rows to exercise each attack independently.
                with self.database() as conn:
                    conn.execute("DELETE FROM poc_files")

    def test_orphan_file_rows_do_not_count_as_collected(self):
        self.collect()
        self.mutate("DELETE FROM poc_snapshots")
        self.assertEqual(self.report()["status"], "error")
        self.assertFalse(self.report()["evidence"])

    def test_catalog_commit_review_and_filelist_changes_invalidate_old_review(self):
        original = copy.deepcopy(self.candidate)
        for mutate in (lambda row: row.update(commit_sha="b" * 40),
                       lambda row: row["review"].update(summary="changed review"),
                       lambda row: row["files"].pop()):
            self.candidate = copy.deepcopy(original)
            self.write_catalog()
            self.collect()
            mutate(self.candidate)
            self.write_catalog()
            with self.subTest(candidate=self.candidate):
                self.assertEqual(self.report()["status"], "error")
                self.assertFalse(self.report()["evidence"])

    def test_snapshot_catalog_or_attempt_binding_tamper_fails_closed(self):
        self.collect()
        self.mutate("UPDATE poc_snapshots SET catalog='{}'")
        self.assertEqual(self.report()["status"], "error")
        self.collect()
        self.mutate("UPDATE poc_attempts SET payload=?", (json.dumps({"cve_id": "CVE-2025-0312", "candidate_id": "fixture-source", "status": "ok"}),))
        self.assertEqual(self.report()["status"], "error")

    def test_valid_catalogued_source_with_syntax_error_is_collected_but_never_static_reviewed(self):
        self.bodies["main.py"] = b"def broken(:\n"
        self.candidate["files"] = [self.metadata(path, body) for path, body in self.bodies.items()]
        self.write_catalog()
        result = self.collect()
        item = result["items"][0]
        self.assertEqual(result["status"], "collected")
        self.assertEqual(item["files"][1]["syntax_status"], "invalid")
        self.assertEqual(item["review"]["status"], "attention_required")
        self.assertEqual(item["validation"], "not_run")
        self.assertFalse(any(row["text_kind"] == "development_static_review" for row in result["evidence"]))

    def test_invalid_review_locator_or_mismatched_readme_version_suppresses_review_claims(self):
        for change in (lambda row: row["review"]["findings"][0].update(lines=[1, 999]),
                       lambda row: row["review"]["target_version_claim"].update(version="9.9.9")):
            candidate = copy.deepcopy(self.candidate)
            change(candidate)
            self.write_catalog([candidate])
            result = self.collect()
            self.assertEqual(result["status"], "collected")
            self.assertFalse(any(row["text_kind"] == "development_static_review" for row in result["evidence"]))

    def test_requirements_directives_are_only_recorded_not_followed_or_installed(self):
        self.bodies["requirements.txt"] = b"# test\n-r https://malicious.invalid/include\nfixture-package==1.2.3\n"
        self.candidate["files"] = [self.metadata(path, body) for path, body in self.bodies.items()]
        self.write_catalog()
        result = self.collect()
        self.assertEqual(len(self.urls), 5)
        dependencies = result["items"][0]["dependencies"]
        self.assertEqual(dependencies[0]["status"], "unresolved")
        self.assertIsNone(dependencies[0]["name"])
        self.assertEqual(dependencies[1]["status"], "plain_declaration")
        self.assertIn("未安装", result["facts"][6]["text"])

    def test_bad_paths_mutable_commits_file_counts_and_false_runtime_claims_are_rejected_before_fetch(self):
        for change in (lambda row: row.update(commit_sha="main"),
                       lambda row: row.update(repository="https://other.invalid/repo"),
                       lambda row: row["files"][0].update(path="../secret.txt"),
                       lambda row: row["files"].append(copy.deepcopy(row["files"][0])),
                       lambda row: row["files"][0].update(size=sources.MAX_FILE_BYTES + 1),
                       lambda row: row["review"].update(runtime_validation="verified")):
            candidate = copy.deepcopy(self.candidate)
            change(candidate)
            self.write_catalog([candidate])
            fetch = Mock()
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                sources.collect("CVE-2024-37032", db_path=self.db, fetcher=fetch)
            fetch.assert_not_called()
        self.assertFalse(self.db.exists())

    def test_unsupported_cve_and_invalid_identifier_do_not_write_or_fetch(self):
        fetch = Mock()
        result = sources.collect("CVE-2025-0312", db_path=self.db, fetcher=fetch)
        self.assertEqual(result["status"], "unconfigured")
        self.assertFalse(self.db.exists())
        fetch.assert_not_called()
        for identifier in ("CVE-2024-37032-extra", "CVE-2024-37032/CVE-2025-0312", "", None):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                sources.report(identifier, db_path=self.db)

    def test_default_fetch_rejects_arbitrary_hosts_before_opening_network(self):
        for url in ("http://raw.githubusercontent.com/a/b/c/main.py", "https://other.invalid/a/main.py",
                    "https://raw.githubusercontent.com@other.invalid/a.py", "https://raw.githubusercontent.com/a.py?target=123"):
            with self.subTest(url=url), patch.object(sources, "build_opener") as opener, self.assertRaises(ValueError):
                sources._fetch(url, 1e12)
            opener.assert_not_called()

    def test_default_http_fetch_checks_final_url_and_declared_and_actual_byte_limits(self):
        url = sources._file_url(self.candidate, "main.py", raw=True)
        for headers, chunks, final_url in (({"Content-Length": str(sources.MAX_FILE_BYTES + 1)}, [], url),
                                          ({}, [b"x" * (sources.MAX_FILE_BYTES + 1)], url),
                                          ({}, [], "https://other.invalid/main.py")):
            response = Mock(status=200, headers=headers)
            response.read1 = None
            response.geturl.return_value = final_url
            response.read.side_effect = chunks
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = response
            with self.subTest(headers=headers, final_url=final_url), patch.object(sources, "build_opener", return_value=opener), \
                    self.assertRaises(ValueError):
                sources._fetch(url, 1e12)

    def test_dripping_http_response_returns_to_shared_soft_budget_between_raw_reads(self):
        url = sources._file_url(self.candidate, "main.py", raw=True)
        timer = [0.0]
        timeout_values = []

        class DrippingResponse:
            status = 200
            headers = {}
            fp = None

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return url

            def read1(self, size):
                timer[0] += sources.FETCH_BUDGET / 3
                timeout_values.append(size)
                return b"x"

            def read(self, size):
                raise AssertionError("read(n) can hide multiple internal raw reads")

        opener = Mock()
        opener.open.return_value = DrippingResponse()
        with patch.object(sources, "build_opener", return_value=opener), \
                patch.object(sources.time, "monotonic", side_effect=lambda: timer[0]), self.assertRaises(TimeoutError):
            sources._fetch(url, sources.FETCH_BUDGET)
        self.assertEqual(len(timeout_values), 3)

    def test_older_started_failure_finishing_after_new_success_cannot_overwrite_latest_attempt(self):
        now = datetime(2026, 10, 12, 20, tzinfo=timezone.utc)
        older_at = now - timedelta(seconds=2)
        newer_at = now - timedelta(seconds=1)
        old_started, finish_old = threading.Event(), threading.Event()
        results, errors = [], []
        thread_first_call = set()

        def clock():
            name = threading.current_thread().name
            if name in ("old-collection", "new-collection") and name not in thread_first_call:
                thread_first_call.add(name)
                return older_at if name == "old-collection" else newer_at
            return now

        def old_fetch(url):
            old_started.set()
            if not finish_old.wait(3):
                raise AssertionError("newer collection did not complete")
            raise TimeoutError("older collection failed later")

        def worker(fetch):
            try:
                results.append(self.collect(fetcher=fetch))
            except Exception as exc:
                errors.append(exc)

        old_thread = threading.Thread(target=worker, args=(old_fetch,), name="old-collection")
        new_thread = threading.Thread(target=worker, args=(self.fetch,), name="new-collection")
        with patch.object(sources, "_now", side_effect=clock):
            old_thread.start()
            try:
                self.assertTrue(old_started.wait(3))
                new_thread.start()
                new_thread.join(3)
                self.assertFalse(new_thread.is_alive())
            finally:
                finish_old.set()
                old_thread.join(3)
                if new_thread.ident is not None:
                    new_thread.join(3)
            self.assertFalse(old_thread.is_alive())
            self.assertFalse(errors)
            report = self.report()
            self.assertEqual(report["status"], "static_reviewed")
            self.assertEqual(report["latest_attempt"]["status"], "ok")
            self.assertEqual(report["latest_attempt"]["queried_at"], newer_at.isoformat())
            self.assertEqual(report["items"][0]["retrieved_at"], newer_at.isoformat())
            self.assertFalse(report["items"][0]["retained_previous"])

    def test_future_snapshot_or_attempt_times_are_rejected_and_explicit_refresh_can_repair(self):
        self.collect()
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        self.mutate("UPDATE poc_snapshots SET retrieved_at=?", (future,))
        self.assertEqual(self.report()["status"], "error")
        self.assertFalse(self.report()["evidence"])
        self.assertEqual(self.collect()["status"], "static_reviewed")
        payload = {"cve_id": "CVE-2024-37032", "candidate_id": "fixture-source", "status": "ok", "queried_at": future}
        self.mutate("UPDATE poc_attempts SET payload=?", (json.dumps(payload),))
        self.assertEqual(self.report()["status"], "error")
        self.assertEqual(self.collect()["status"], "static_reviewed")

    def test_malformed_catalog_rows_raise_configuration_error_before_network(self):
        for row in (None, {}, {"cve_id": None}, {"cve_id": 1234}):
            self.write_catalog([row])
            fetch = Mock()
            with self.subTest(row=row), self.assertRaises(ValueError):
                sources.collect("CVE-2024-37032", db_path=self.db, fetcher=fetch)
            fetch.assert_not_called()
        self.assertFalse(self.db.exists())

    def test_default_fetch_no_redirect_handler_refuses_even_github_redirects(self):
        request = Mock(full_url="https://raw.githubusercontent.com/fixture/path.py")
        with self.assertRaises(HTTPError):
            sources._NoRedirect().redirect_request(request, None, 302, "redirect", {},
                                                    "https://raw.githubusercontent.com/different/path.py")

    def test_default_fetch_honors_user_proxy_without_changing_pinned_destination(self):
        url = sources._file_url(self.candidate, "main.py", raw=True)
        response = Mock(status=200, headers={})
        response.geturl.return_value = url
        response.read1.return_value = b""
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        proxies = {"https": "http://127.0.0.1:3128"}
        with patch("urllib.request.getproxies", return_value=proxies), patch.object(sources, "build_opener", return_value=opener) as build:
            self.assertEqual(sources._fetch(url, 1e12), b"")
        self.assertEqual(build.call_args.args[0].proxies, proxies)
        self.assertIsInstance(build.call_args.args[1], sources._NoRedirect)
        self.assertEqual(opener.open.call_args.args[0].full_url, url)

    def test_bad_database_is_preserved_and_never_shown_as_source_evidence(self):
        self.db.write_bytes(b"not a database: preserve me")
        before = self.db.read_bytes()
        result = self.report()
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["evidence"])
        self.assertEqual(before, self.db.read_bytes())

    def test_shared_collection_budget_prevents_partial_publish(self):
        ticks = iter([0.0, 0.1, 1.0, sources.FETCH_BUDGET + 1])
        with patch.object(sources.time, "monotonic", side_effect=lambda: next(ticks)):
            result = self.collect()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["latest_attempt"]["error_type"], "TimeoutError")
        self.assertFalse(result["evidence"])

    def test_invalid_utf8_even_with_catalogue_matching_hash_does_not_publish(self):
        self.bodies["LICENSE"] = b"\xff\xfe"
        self.candidate["files"] = [self.metadata(path, body) for path, body in self.bodies.items()]
        self.write_catalog()
        result = self.collect()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["latest_attempt"]["status"], "error")

    def test_record_adapter_preserves_input_and_only_collects_explicitly(self):
        record = {"item": {"cve_id": "CVE-2024-37032"}, "extension": {"poc": {"validation": "not_run"}}}
        before = copy.deepcopy(record)
        result = sources.refresh_record(record, db_path=self.db, fetcher=self.fetch)
        self.assertEqual(record, before)
        self.assertEqual(result["status"], "static_reviewed")


if __name__ == "__main__":
    unittest.main()
