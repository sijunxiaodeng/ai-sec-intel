import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from enrichment.sample import load_sample
from rag.evidence import _connection, save
from rag.hybrid import MODEL_NAME, _save_config, config_path
from rag.semantic import MODEL_FILES, prepare_databases, status


class SemanticReadinessTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.db = self.root / "evidence.sqlite3"
        self.model_dir = self.root / "model"
        self.model_dir.mkdir()
        for name in MODEL_FILES:
            (self.model_dir / name).write_text("fixture", encoding="utf-8")
        self.record, self.documents = load_sample()
        self.addCleanup(patch.stopall)
        patch("rag.semantic.dependencies", return_value={"fastembed": "fixture", "onnxruntime": "fixture", "tokenizers": "fixture"}).start()
        owner = self

        class Model:
            passages = 0
            queries = 0

            def passage_embed(model, texts, *, batch_size):
                owner.assertEqual(batch_size, 32)
                model.passages += len(texts)
                return [[1.0] + [0.0] * 511 for _ in texts]

            def query_embed(model, text):
                model.queries += 1
                return iter([[1.0] + [0.0] * 511])

        self.model = Model()
        self.loader = patch("rag.hybrid._model", return_value=self.model).start()
        self.probe_loader = patch("rag.semantic._model", return_value=self.model).start()

    def seed(self):
        save(self.record, self.documents, self.db)

    def build(self):
        self.seed()
        return prepare_databases([self.db], self.model_dir)

    def test_status_missing_database_never_creates_parent_or_file(self):
        path = self.root / "absent" / "empty.sqlite3"
        self.assertEqual(status(path)["state"], "database_missing")
        self.assertFalse(path.parent.exists())
        self.loader.assert_not_called()

    def test_status_unprepared_explains_missing_index_without_mutation(self):
        self.seed()
        result = status(self.db)
        self.assertEqual(result["state"], "not_configured")
        self.assertEqual(result["missing_embeddings"], result["evidence_chunks"])
        self.assertGreater(result["evidence_chunks"], 0)
        self.assertFalse(config_path(self.db).exists())
        with _connection(self.db) as conn:
            self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='embeddings'").fetchone())
        self.loader.assert_not_called()

    def test_build_probe_and_second_run_reuse_all_vectors(self):
        first = self.build()
        self.assertTrue(first["ready"])
        count = self.model.passages
        self.assertGreater(count, 0)
        second = prepare_databases([self.db], self.model_dir)
        self.assertTrue(second["ready"])
        self.assertEqual(second["results"][0]["operation"], "incremental")
        self.assertEqual(second["results"][0]["index"]["updated"], 0)
        self.assertEqual(second["results"][0]["index"]["reused"], count)
        self.assertEqual(self.model.passages, count)
        self.probe_loader.assert_called_with(str(self.root / "models"), True, str(self.model_dir))

    def test_plain_status_does_not_claim_runtime_probe_or_call_model(self):
        self.build()
        self.probe_loader.reset_mock()
        result = status(self.db)
        self.assertEqual(result["state"], "indexed")
        self.assertTrue(result["index_ready"])
        self.assertIsNone(result["query_ready"])
        self.probe_loader.assert_not_called()

    def test_build_progress_exposes_counts_without_evidence_text(self):
        self.seed()
        events = []
        result = prepare_databases([self.db], self.model_dir, progress=events.append)
        self.assertTrue(result["ready"])
        self.assertEqual(events[0]["completed"], 0)
        self.assertEqual(events[-1]["stage"], "publishing")
        self.assertEqual(events[-1]["completed"], events[-1]["total"])
        self.assertTrue(all(set(event) == {"stage", "completed", "total", "database"} for event in events))

    def test_update_only_embeds_changed_evidence(self):
        self.build()
        count = self.model.passages
        with _connection(self.db) as conn:
            rowid, payload = conn.execute("SELECT rowid,payload FROM evidence LIMIT 1").fetchone()
            row = json.loads(payload)
            row["text"] += " Updated source boundary."
            conn.execute("UPDATE evidence SET payload=? WHERE rowid=?", (json.dumps(row), rowid))
        self.assertEqual(status(self.db)["stale_embeddings"], 1)
        result = prepare_databases([self.db], self.model_dir)
        self.assertTrue(result["ready"])
        self.assertEqual(result["results"][0]["index"]["updated"], 1)
        self.assertEqual(self.model.passages, count + 1)

    def test_current_digest_corrupt_vector_requires_full_rebuild(self):
        self.build()
        with _connection(self.db) as conn:
            conn.execute("UPDATE embeddings SET vector='[1,0]' WHERE rowid=(SELECT min(rowid) FROM embeddings)")
        self.assertEqual(status(self.db)["invalid_embeddings"], 1)
        result = prepare_databases([self.db], self.model_dir)
        self.assertEqual(result["results"][0]["operation"], "build")
        self.assertTrue(result["ready"])

    def test_missing_model_file_does_not_claim_ready(self):
        self.build()
        (self.model_dir / "tokenizer.json").unlink()
        result = status(self.db, probe=True)
        self.assertEqual(result["state"], "model_files_missing")
        self.assertIsNot(result["query_ready"], True)

    def test_explicit_prepare_repairs_malformed_configuration(self):
        self.build()
        config_path(self.db).write_text('{"enabled":', encoding="utf-8")
        self.assertEqual(status(self.db)["state"], "error")
        result = prepare_databases([self.db], self.model_dir)
        self.assertTrue(result["ready"])
        self.assertTrue(result["results"][0]["previous_configuration_invalid"])

    def test_probe_error_is_safe_and_never_downloads(self):
        self.build()
        self.probe_loader.side_effect = RuntimeError("private machine path or download details")
        result = status(self.db, probe=True)
        self.assertEqual(result["error_type"], "RuntimeError")
        self.assertFalse(result["query_ready"])
        self.assertNotIn("private", json.dumps(result))
        self.probe_loader.assert_called_with(str(self.root / "models"), True, str(self.model_dir))

    def test_all_database_paths_validated_before_building_any(self):
        self.seed()
        with self.assertRaisesRegex(ValueError, "database missing"):
            prepare_databases([self.db, self.root / "missing.sqlite3"], self.model_dir)
        self.assertFalse(config_path(self.db).exists())
        self.loader.assert_not_called()

    def test_failed_atomic_config_publish_keeps_previous_configuration(self):
        path = config_path(self.db)
        previous = {"model": MODEL_NAME, "enabled": False}
        path.write_text(json.dumps(previous), encoding="utf-8")
        with patch("rag.hybrid.os.replace", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                _save_config(path, {"enabled": True})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), previous)
        self.assertEqual(list(self.root.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
