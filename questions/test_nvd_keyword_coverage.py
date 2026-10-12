"""NVD keyword selection: broad llm must not permanently query only 'llm'."""
import os
import unittest
from unittest.mock import patch

from agents.monitor_agent import (
    NVD_PRODUCT_KEYWORDS,
    _nvd_keyword_limit,
    _nvd_keywords,
)


class TestNvdKeywordCoverage(unittest.TestCase):
    def test_broad_llm_expands_product_stack(self):
        keys = _nvd_keywords(["llm"])
        self.assertNotEqual(keys, ["llm"])
        self.assertNotIn("llm", [k.lower() for k in keys])
        self.assertTrue(set(keys).issubset(set(NVD_PRODUCT_KEYWORDS)))
        self.assertIn("open webui", NVD_PRODUCT_KEYWORDS)
        # Rotation may omit some products this hour; open webui is first so often present,
        # but the invariant is: never permanently only-llm, always a product subset.
        self.assertGreaterEqual(len(keys), 1)
        self.assertLessEqual(len(keys), _nvd_keyword_limit())

    def test_empty_uses_product_stack(self):
        keys = _nvd_keywords([])
        self.assertTrue(set(keys).issubset(set(NVD_PRODUCT_KEYWORDS)))
        self.assertIn("open webui", NVD_PRODUCT_KEYWORDS)

    def test_comma_list_prefers_concrete_tokens(self):
        keys = _nvd_keywords(["llm", "vllm", "open webui", "ollama", "adversarial"])
        self.assertNotIn("llm", [k.lower() for k in keys])
        self.assertNotIn("adversarial", [k.lower() for k in keys])
        self.assertTrue(any(k.lower() == "open webui" for k in keys) or "vllm" in keys)

    def test_single_concrete_stays_narrow(self):
        self.assertEqual(_nvd_keywords(["open webui"]), ["open webui"])

    def test_limit_env_caps_rotation(self):
        with patch.dict(os.environ, {"NVD_KEYWORD_LIMIT": "2"}):
            keys = _nvd_keywords(["llm"])
        self.assertEqual(len(keys), 2)


if __name__ == "__main__":
    unittest.main()
