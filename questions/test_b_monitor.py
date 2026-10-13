"""The optional collector cannot mutate Actions mirrors or outlive its deadline."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from api import b_monitor


class BMonitorTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.enterContext(patch.dict(os.environ, {"B_MONITOR_ENABLED": "1"}))
        self.enterContext(patch("api.b_embed.db_path", return_value=self.root / "intelligence.db"))

    def test_disabled_collector_does_not_start_process(self):
        with patch.dict(os.environ, {"B_MONITOR_ENABLED": "0"}), patch("api.b_monitor.subprocess.Popen") as spawn:
            self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "disabled")
        spawn.assert_not_called()

    def test_actions_mirror_is_read_only_even_with_collector_enabled(self):
        (self.root / ".writer-mode").write_text("actions-mirror")
        with patch("api.b_monitor.subprocess.Popen") as spawn:
            self.assertEqual(b_monitor.run_b_monitor_cycle()["status"], "failed")
        spawn.assert_not_called()
        self.assertEqual((self.root / ".writer-mode").read_text(), "actions-mirror")

    @unittest.skipIf(os.name == "nt", "POSIX process group deadline")
    def test_timeout_kills_group_and_reaps_child(self):
        child = Mock(pid=98765)
        child.wait.side_effect = [subprocess.TimeoutExpired("fixture", 1), -9]
        with patch("api.b_monitor.subprocess.Popen", return_value=child) as spawn, \
             patch("api.b_monitor.os.killpg") as kill:
            result = b_monitor.run_b_monitor_cycle(overall_timeout=1)
        self.assertEqual(result["status"], "timeout")
        kill.assert_called_once_with(98765, signal.SIGKILL)
        self.assertEqual(child.wait.call_count, 2)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])

    def test_child_returns_result_and_has_no_model_key(self):
        def launch(command, **kwargs):
            self.assertNotIn("DEEPSEEK_API_KEY", kwargs["env"])
            self.assertEqual(kwargs["env"]["CLASSIFY_V5_MAX_LLM_CALLS"], "0")
            path = Path(command[command.index("--result") + 1])
            path.write_text(json.dumps({"status": "success", "sources": {"NVD": {}}}))
            return Mock(returncode=0)
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-only-placeholder"}), \
             patch("api.b_monitor.subprocess.Popen", side_effect=launch):
            result = b_monitor.run_b_monitor_cycle()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["source_names"], ["NVD"])
