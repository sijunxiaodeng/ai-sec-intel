import importlib.util
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT = Path(__file__).resolve().parents[1] / "ops_metrics.py"
SPEC = importlib.util.spec_from_file_location("ops_metrics_under_test", SCRIPT)
OPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OPS)


class OperationalMetricsTests(unittest.TestCase):
    def test_unavailable_evidence_is_not_zero_latency_or_queue(self):
        text = OPS.render_metrics({}, None)
        self.assertIn('ai_sec_probe_success{endpoint="coverage"} 0', text)
        self.assertIn("ai_sec_queue_observation_available 0", text)
        self.assertNotIn("ai_sec_processing_jobs", text)
        self.assertNotIn("ai_sec_cve_live_latency_p95_seconds", text)
        self.assertNotIn("ai_sec_source_seconds_since_success", text)

    def test_live_ai_subset_and_all_records_remain_distinct(self):
        coverage = {"observed_ai_category_count": 3,
                    "per_source_live_latency": {"NVD": {"live": {"samples": 10, "p95_hours": 12}}},
                    "per_source_ai_live_latency": {"NVD": {"live": {"samples": 2, "p95_hours": 1.5}}}}
        text = OPS.render_metrics({"coverage": coverage}, {"pending": 0})
        self.assertIn('population="all_records",source="NVD"} 43200', text)
        self.assertIn('population="current_ai_positive",source="NVD"} 5400', text)
        self.assertIn('ai_sec_processing_jobs{status="pending"} 0', text)

    def test_nonfinite_and_invalid_values_are_absent_and_labels_escaped(self):
        coverage = {"observed_ai_category_count": float("nan"), "per_source_live_latency": ["bad"],
                    "freshness_by_source": {'source"\n': {"seconds_since_success": None, "latest_run_status": "failed"}}}
        text = OPS.render_metrics({"coverage": coverage}, None)
        self.assertNotIn("nan", text)
        self.assertNotIn("ai_sec_observed_ai_source_categories", text)
        self.assertIn('source="source\\\"\\n"', text)

    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "absent.sqlite3"
            with self.assertRaises(FileNotFoundError):
                OPS.read_queue(path)
            self.assertFalse(path.exists())

    def test_queue_is_read_without_creating_missing_tables(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "main.sqlite3"
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("CREATE TABLE untouched (id INTEGER)")
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                OPS.read_queue(path)
            self.assertEqual(before, path.read_bytes())
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("CREATE TABLE processing_jobs (status TEXT)")
                connection.executemany("INSERT INTO processing_jobs VALUES (?)", [("pending",), ("pending",), ("failed",)])
            self.assertEqual(OPS.read_queue(path)["pending"], 2)
            self.assertEqual(OPS.read_queue(path)["failed"], 1)
            self.assertEqual(OPS.read_queue(path)["done"], 0)

    def test_actual_loopback_api_and_partial_failure(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith("coverage"):
                    self.send_response(503)
                    self.end_headers()
                    return
                body = json.dumps({"database_available": True} if self.path.endswith("health") else {"continuous_monitoring": {"samples": 2, "p95_hours": .5}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                text = OPS.collect_metrics("http://127.0.0.1:" + str(server.server_port), Path(temp) / "missing.db")
            self.assertIn('ai_sec_probe_success{endpoint="coverage"} 0', text)
            self.assertIn("ai_sec_intelligence_database_available 1", text)
            self.assertIn("ai_sec_cve_live_latency_p95_seconds 1800", text)
            self.assertNotIn("ai_sec_observed_ai_source_categories", text)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_credential_urls_are_rejected_before_network(self):
        with self.assertRaises(ValueError):
            OPS.read_json("https://user:secret@example.test", "/api/intelligence/health")


if __name__ == "__main__":
    unittest.main()
