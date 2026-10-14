"""Check tool boundaries and context-dependent planning, without external calls."""
import unittest
from unittest.mock import Mock

from agents.planning import enrichment_plan, PUBLIC_FEEDS, PAPERS
from agents.tool_registry import (ToolRegistry, ToolValidationError, validate_records,
                                  validate_mapping, validate_papers, validate_paper_result)


class AgentToolsTest(unittest.TestCase):
    def test_unknown_and_invalid_calls_cannot_reach_handlers(self):
        handler = Mock(return_value={})
        registry = ToolRegistry()
        registry.register(PUBLIC_FEEDS, role="impact", handler=handler,
                          validate=validate_records, validate_result=validate_mapping)
        trace = {}
        for name, args in [("execute_shell", {}), ([], {}), ({}, {}), (PUBLIC_FEEDS, {"records": []}),
                           (PUBLIC_FEEDS, {"records": [{"item": {"cve_id": "CVE-2026-12345"}}], "url": "bad"})]:
            self.assertFalse(registry.execute(name, args, trace).ok)
        handler.assert_not_called()
        self.assertEqual(len(trace["calls"]), 5)
        with self.assertRaises(ToolValidationError):
            registry.register(PUBLIC_FEEDS, role="impact", handler=handler,
                              validate=validate_records, validate_result=validate_mapping)

    def test_failures_record_type_without_logging_secrets_or_inputs(self):
        def fail(cve_ids):
            raise ConnectionError("https://example.invalid?token=PRIVATE")
        registry = ToolRegistry()
        registry.register(PAPERS, role="research", handler=fail,
                          validate=validate_papers, validate_result=validate_paper_result)
        trace = {}
        result = registry.execute(PAPERS, {"cve_ids": ["CVE-2026-12345"]}, trace)
        self.assertEqual(result.error_type, "ConnectionError")
        self.assertNotIn("PRIVATE", str(trace))
        self.assertNotIn("CVE-2026-12345", str(trace))

    def test_wrong_result_shape_is_not_a_successful_call(self):
        registry = ToolRegistry()
        registry.register(PAPERS, role="research", handler=lambda cve_ids: ([], None),
                          validate=validate_papers, validate_result=validate_paper_result)
        result = registry.execute(PAPERS, {"cve_ids": ["CVE-2026-12345"]}, {})
        self.assertEqual(result.error_type, "ToolValidationError")

    def test_mechanisms_and_retry_feedback_change_actual_plan(self):
        infra = [{"item": {"title": "vLLM inference RCE", "description": ""}}]
        injection = [{"item": {"title": "间接提示词注入", "description": ""}}]
        self.assertEqual(enrichment_plan(infra)["decision"]["tools"], [PUBLIC_FEEDS, PAPERS])
        self.assertEqual(enrichment_plan(injection)["decision"]["tools"], [PAPERS, PUBLIC_FEEDS])
        retry = enrichment_plan(infra, ["papers_error"])
        self.assertEqual(retry["decision"]["policy"], "retry_feedback")
        self.assertEqual(retry["decision"]["tools"][0], PAPERS)
        self.assertEqual(set(retry["decision"]["tools"]), {PAPERS, PUBLIC_FEEDS})


if __name__ == "__main__":
    unittest.main()
