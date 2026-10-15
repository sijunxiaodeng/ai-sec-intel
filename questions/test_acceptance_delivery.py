"""Artifact provenance, path confinement and real HTTP write boundaries."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from acceptance import evidence, quality
from scripts.register_acceptance_materials import register


class AcceptanceArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"ACCEPTANCE_EVIDENCE_DIR": str(self.root / "catalog")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_registered_artifact_is_immutable_and_download_checks_content(self):
        source = self.root / "source.json"
        source.write_text('{"result":"unreviewed"}', encoding="utf-8")
        entry = {"id": "qa-proof", "path": str(source), "title": "冻结回答"}
        self.assertEqual(register([entry])["total"], 1)
        self.assertEqual(register([entry])["total"], 1)
        target, metadata = evidence.resolve("qa-proof")
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(metadata["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        source.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "不可覆盖"):
            register([entry])
        target.write_text("corrupt", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "摘要不一致"):
            evidence.resolve("qa-proof")

    def test_runtime_databases_and_traversing_manifest_are_not_downloadable(self):
        source = self.root / "secrets.db"
        source.write_bytes(b"never publish a runtime database")
        with self.assertRaises(ValueError):
            register([{"id": "bad", "path": str(source)}])
        root = evidence.directory()
        for filename in ("../secrets.txt", "..\\secrets.txt", str(self.root / "outside.txt"), "config.env"):
            (root / "manifest.json").write_text(json.dumps([{"id": "bad", "filename": filename,
                                                            "sha256": "a" * 64}]), encoding="utf-8")
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                evidence.catalog()
        with self.assertRaises(KeyError):
            (root / "manifest.json").write_text("[]", encoding="utf-8")
            evidence.resolve("../../outside")

    def test_duplicate_manifest_ids_are_rejected(self):
        root = evidence.directory()
        root.mkdir()
        item = {"id": "one", "filename": "one.json", "sha256": "b" * 64}
        (root / "manifest.json").write_text(json.dumps([item, item]), encoding="utf-8")
        with self.assertRaises(ValueError):
            evidence.catalog()


class AcceptanceHttpTests(unittest.TestCase):
    def setUp(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from api.acceptance import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def test_cross_site_write_is_denied_before_import(self):
        with patch("acceptance.quality.import_report") as importer:
            response = self.client.post("/api/acceptance/quality/import", json={},
                                        headers={"Origin": "https://untrusted.example"})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.client.post("/api/acceptance/quality/import", json={},
                                              headers={"Origin": "http://[malformed"}).status_code, 403)
            importer.assert_not_called()

    def test_json_ambiguity_and_oversized_payload_are_rejected(self):
        with patch("acceptance.quality.import_report") as importer:
            for payload in ('{"x":NaN}', '{"x":1,"x":2}', '[]', '{'):
                response = self.client.post("/api/acceptance/quality/import", content=payload,
                                            headers={"Content-Type": "application/json"})
                self.assertEqual(response.status_code, 422, payload)
            with patch("api.acceptance.MAX_BODY_BYTES", 16):
                response = self.client.post("/api/acceptance/quality/import", json={"padding": "x" * 100})
                self.assertEqual(response.status_code, 413)
            importer.assert_not_called()

    def test_download_missing_artifact_and_templates_never_resolve_user_paths(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ACCEPTANCE_EVIDENCE_DIR": directory}):
            self.assertEqual(self.client.get("/api/acceptance/evidence/not-registered/download").status_code, 404)
            for kind in ("quality", "inventory"):
                response = self.client.get("/api/acceptance/templates/" + kind)
                self.assertEqual(response.status_code, 200)
                self.assertIn("attachment", response.headers["content-disposition"])
            self.assertEqual(self.client.get("/api/acceptance/templates/../../config/local.json").status_code, 404)

    def test_revision_conflict_and_storage_failure_have_actionable_status(self):
        with patch("acceptance.quality.review_case", side_effect=quality.RevisionConflict("revision conflict")):
            response = self.client.post("/api/acceptance/quality/run/reviews/Q01", json={"expected_revision": 0})
            self.assertEqual(response.status_code, 409)
        with patch("acceptance.quality.review_case", side_effect=ValueError("expected_revision must be an integer")):
            response = self.client.post("/api/acceptance/quality/one/reviews/two", json={})
            self.assertEqual(response.status_code, 422)
        with patch("acceptance.quality.import_report", side_effect=OSError("private/path")):
            response = self.client.post("/api/acceptance/quality/import", json={})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("private/path", response.text)
