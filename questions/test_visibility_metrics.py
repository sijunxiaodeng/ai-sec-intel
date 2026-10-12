import unittest

from api.visibility_metrics import category_observation, latency_observation


class VisibilityEvidenceTests(unittest.TestCase):
    def test_source_names_are_not_input_to_category_count(self):
        self.assertEqual(category_observation({}, {'source_categories': []})[0], 0)

    def test_library_aliases_do_not_duplicate_the_same_category(self):
        count, basis = category_observation({}, {'source_categories': ['vendor', 'vendor_advisory', 'academic']})
        self.assertEqual(count, 2)
        self.assertIn('不证明实时', basis)

    def test_current_observed_categories_take_priority_over_historical_library(self):
        count, basis = category_observation({'observed_ai_categories': ['vendor_advisory', 'vendor_advisory']},
                                           {'source_categories': ['vendor', 'policy', 'research', 'standard']})
        self.assertEqual(count, 1)
        self.assertIn('当前有效', basis)

    def test_zero_b_samples_cannot_be_overridden_by_root_count(self):
        count, basis = latency_observation({'live_precise_samples': 0}, 5)
        self.assertEqual(count, 0)
        self.assertIn('按来源', basis)

    def test_zero_current_b_categories_cannot_be_replaced_by_old_library_content(self):
        count, basis = category_observation({'observed_ai_categories': [], 'observed_ai_category_count': 0},
                                           {'source_categories': ['vendor', 'policy', 'academic', 'research', 'standard']})
        self.assertEqual(count, 0)
        self.assertIn('当前有效', basis)

    def test_missing_b_evidence_is_explicit_compatibility_fallback(self):
        count, basis = latency_observation({}, 2)
        self.assertEqual(count, 2)
        self.assertIn('兼容', basis)


if __name__ == '__main__':
    unittest.main()
