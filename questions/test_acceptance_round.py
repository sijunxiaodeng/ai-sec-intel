"""检查评测分母、来源冻结和隐私边界，不给生产问答打语义分。"""
import copy
from contextlib import closing
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest

from questions.acceptance_round import (archive_sources, review_template, run, sha, source_manifest,
                                        summarize, verify_baseline)


class AcceptanceRoundTest(unittest.TestCase):
    def setUp(self):
        self.report = {"run_id": "fixture", "dataset_sha256": "fixture", "baseline_commit": "a" * 40,
            "mode": "model", "source_stable": True, "rows": [
                {"id": "E1", "kind": "assessment", "category": "fixture", "stratum": "new_questions", "status": "captured",
                 "history": [], "failures": [], "automatic_checks_passed": True, "elapsed_http_seconds": .2,
                 "gold_facts": [{"id": "F1"}, {"id": "F2"}], "predictions": [{"id": "P1"}, {"id": "P2"}]},
                {"id": "Q1", "kind": "qa", "category": "fixture", "stratum": "new_questions", "status": "captured",
                 "history": [], "failures": [], "automatic_checks_passed": True, "elapsed_http_seconds": .5,
                 "response": {"answer": "private output", "api_key": "private credential", "used_model": True, "model_attempted": True}}]}
        self.dataset = {"cases": [{"id": "E1", "gold_facts": [{"id": "F1"}, {"id": "F2"}]}, {"id": "Q1"}]}
        self.review = review_template(self.report, self.dataset)

    def complete(self):
        for r in self.review["rows"]:
            r.update(decision="reviewed", reviewer="Fixture independent reviewer", review_kind="independent_human",
                     participated_in_development=False, had_seen_questions_before_run=False, gold_labels_validated=True,
                     correct=True, relevant=True, conditions_preserved=True, citations_supported=True, synthesis_correct=True)
        judgments = self.review["rows"][0]["prediction_judgments"]
        judgments[0].update(supported=True, gold_fact_id="F1")
        judgments[1].update(supported=False, gold_fact_id=None)

    def test_pending_reviews_cannot_become_accuracy(self):
        s = summarize(self.report, self.review)
        self.assertIsNone(s["independent_qa_accuracy"])
        self.assertIsNone(s["independent_enrichment_precision"])
        self.assertIsNone(s["competition_passed"])

    def test_precision_recall_denominators_are_explicit(self):
        self.complete(); s = summarize(self.report, self.review)
        self.assertEqual((s["independent_enrichment_tp"], s["independent_enrichment_fp"], s["independent_enrichment_fn"]), (1, 1, 1))
        self.assertEqual(s["independent_enrichment_precision"], .5)
        self.assertEqual(s["independent_enrichment_recall"], .5)
        self.assertEqual(s["independent_qa_accuracy"], 1)

    def test_developer_review_or_prior_exposure_is_not_independent(self):
        self.complete()
        for change in ({"review_kind": "developer_source_review"}, {"participated_in_development": True}, {"had_seen_questions_before_run": True}, {"gold_labels_validated": False}):
            review = copy.deepcopy(self.review)
            for r in review["rows"]: r.update(change)
            s = summarize(self.report, review)
            self.assertIsNone(s["independent_qa_accuracy"])
            self.assertIsNone(s["independent_enrichment_precision"])

    def test_source_changes_close_quality_statistics(self):
        self.report["source_stable"] = False
        self.review = review_template(self.report, self.dataset); self.complete()
        s = summarize(self.report, self.review)
        self.assertIsNone(s["independent_qa_accuracy"])
        self.assertIsNone(s["independent_enrichment_recall"])

    def test_review_cannot_change_gold_denominator_or_double_count(self):
        self.complete(); bad = copy.deepcopy(self.review)
        bad["rows"][0]["gold_fact_ids"] = ["F1"]
        with self.assertRaises(ValueError): summarize(self.report, bad)
        self.review["rows"][0]["prediction_judgments"][1].update(supported=True, gold_fact_id="F1")
        with self.assertRaises(ValueError): summarize(self.report, self.review)

    def test_mismatched_run_or_missing_case_rejected(self):
        for change in ({"run_id": "another"}, {"rows": self.review["rows"][:1]}):
            with self.assertRaises(ValueError): summarize(self.report, dict(self.review, **change))

    def test_failed_qa_stays_in_quality_denominator_and_out_of_fast_successes(self):
        self.report["rows"][1]["status"] = "error"
        self.review = review_template(self.report, self.dataset); self.complete()
        s = summarize(self.report, self.review)
        self.assertEqual(s["independent_qa_accuracy"], 0)
        self.assertEqual(s["qa_executed_denominator"], 1)
        self.assertEqual(s["timing_by_kind"]["qa"]["http_at_most_5s"], 0)

    def test_public_summary_does_not_export_response_or_credentials(self):
        text = json.dumps(summarize(self.report, self.review))
        for token in ("private output", "private credential", "api_key", "answer"): self.assertNotIn(token, text)

    def test_changed_answers_cannot_reuse_existing_reviews(self):
        self.report["rows"][1]["response"]["answer"] = "edited after capture"
        with self.assertRaises(ValueError): summarize(self.report, self.review)

    def test_archive_copies_only_selected_snapshot_and_checks_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); db = root / "fixture.sqlite3"; body = b'{"fixture": true}'
            source = {"id": "v1", "kind": "nvd", "cve_id": "CVE-2024-12345", "url": "https://nvd.nist.gov/example", "response_sha256": sha(body)}
            dataset = {"sources": [source], "cases": [{"id": "E1", "kind": "assessment", "cve_id": source["cve_id"], "sources": ["v1"], "expected_points": ["fixture"]}]}
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute("CREATE TABLE source_snapshots(cve_id,source_id,digest,body)")
                conn.execute("INSERT INTO source_snapshots VALUES(?,?,?,?)", (source["cve_id"], sha(source["url"].encode())[:16], sha(body), body))
                conn.execute("INSERT INTO source_snapshots VALUES(?,?,?,?)", ("other", "other", "private", b"private unrelated record"))
            manifest = archive_sources(dataset, root / "out", evidence_db=db)
            self.assertEqual(len(manifest["sources"]), 1)
            self.assertEqual((root / "out/sources/v1.snapshot").read_bytes(), body)
            self.assertNotIn(b"private unrelated record", b"".join(p.read_bytes() for p in (root / "out").rglob("*") if p.is_file()))
            with self.assertRaises(ValueError): archive_sources(dataset, root / "out", evidence_db=db)
            with closing(sqlite3.connect(db)) as conn, conn: conn.execute("UPDATE source_snapshots SET body=? WHERE cve_id=?", (b"corrupt", source["cve_id"]))
            with self.assertRaises(ValueError): archive_sources(dataset, root / "bad", evidence_db=db)
            self.assertFalse((root / "bad").exists())
            dataset["sources"][0]["id"] = "../escape"
            with self.assertRaises(ValueError): archive_sources(dataset, root / "unsafe", evidence_db=db)

    def test_library_archive_requires_frozen_evidence_signature(self):
        from questions.acceptance_round import source_signature
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); db = root / "library.sqlite3"; body = b"fixture article"
            metadata = {"integrity_status": "ok", "url": "https://example.org/article", "version": None,
                        "content_scope": "article_body", "evidence": [], "source_response_sha256": sha(body)}
            source = {"id": "article", "kind": "library", "document_id": "DOC-" + "a" * 16, "url": metadata["url"], "evidence_signature": source_signature(metadata)}
            dataset = {"sources": [source], "cases": [{"id": "L1", "kind": "excerpt", "sources": ["article"], "expected_points": ["fixture"]}]}
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute("CREATE TABLE library_snapshots(document_id,digest,body)")
                conn.execute("INSERT INTO library_snapshots VALUES(?,?,?)", (source["document_id"], sha(body), body))
            archive_sources(dataset, root / "out", library_db=db, library_reader=lambda *a: metadata)
            metadata["content_scope"] = "abstract"
            with self.assertRaises(ValueError): archive_sources(dataset, root / "bad", library_db=db, library_reader=lambda *a: metadata)

    def test_baseline_detects_edits_and_new_production_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "agents").mkdir(); p = root / "agents" / "test.py"; p.write_bytes(b"fixture\n")
            d = {"baseline": {"commit": "a" * 40, "production_sha256": {"agents/test.py": sha(p.read_bytes())}}}
            verify_baseline(d, root)
            p.write_bytes(b"changed\n")
            with self.assertRaises(ValueError): verify_baseline(d, root)
            p.write_bytes(b"fixture\n"); (root / "agents" / "extra.py").write_text("fixture")
            with self.assertRaises(ValueError): verify_baseline(d, root)

    def test_source_precondition_change_blocks_capture(self):
        d = {"sources": [{"id": "v1", "kind": "nvd", "cve_id": "CVE-2024-12345", "url": "https://nvd.nist.gov/example", "response_sha256": "expected"}]}
        with self.assertRaises(ValueError): source_manifest("http://localhost:8023", d, lambda *a: {"status": "ok", "source": {"sha256": "changed"}})

    def test_rules_mode_skips_cve_http_without_touching_configuration(self):
        d = {"baseline": {"commit": "a" * 40}, "sources": [], "cases": [{"id": "Q1", "kind": "qa", "category": "fixture", "stratum": "new_questions", "sources": [],
             "question": "Which CVE?", "expected_points": ["Need ID"], "expected_cves": []}]}
        calls = []
        def requester(base, route, body=None): calls.append((route, body)); return {"model": "fixture"}
        report = run("http://localhost:8023", d, requester=requester, baseline_verifier=lambda d: None)
        self.assertEqual(report["rows"][0]["status"], "skipped")
        self.assertEqual(calls, [("/api/settings", None)])

    def test_history_reuses_only_its_case_session_and_labels_are_not_sent(self):
        cases = [{"id": cid, "kind": "qa", "category": "fixture", "stratum": "new_questions", "sources": [], "question": "next?",
                  "expected_points": ["Private gold point"], "expected_cves": [], "history": ["first?"] if cid == "Q1" else []} for cid in ("Q1", "Q2")]
        seen = []
        def requester(base, route, body=None):
            if route == "/api/settings": return {"model": "fixture"}
            seen.append(body); return {"session_id": "fixture-session", "answer": "Need ID", "evidence": []}
        report = run("http://localhost:8023", {"baseline": {"commit": "a" * 40}, "sources": [], "cases": cases}, "model", requester=requester, baseline_verifier=lambda d: None)
        self.assertEqual([b["session_id"] for b in seen], ["", "fixture-session", ""])
        self.assertNotIn("Private gold point", json.dumps(seen))
        self.assertTrue(report["source_stable"])


if __name__ == "__main__": unittest.main()
