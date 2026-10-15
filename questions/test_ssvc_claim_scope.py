"""SSVC observations must not become unsupported exploitability conclusions."""
import copy
import hashlib
import json
import unittest

from agents.citation_guard import claim_issues, ssvc_claims
from agents.qa_agent import _render_model_json


class SsvcClaimScopeTest(unittest.TestCase):
    def setUp(self):
        self.value = {"ssvcData": {"timestamp": "2025-02-03T04:05:06Z", "options": [
            {"exploitation": "none"}, {"automatable": "no"}, {"technicalImpact": "partial"}]}}
        text = json.dumps(self.value)
        self.chunk = {"citation_id": "CVE-2099-1234/SSVC", "locator": "metrics/ssvcV203/0",
                      "text": text, "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                      "structured_value": copy.deepcopy(self.value)}

    def test_values_preserve_the_record_time_and_are_separate_facts(self):
        claims = ssvc_claims(self.chunk)
        self.assertEqual(len(claims), 3)
        for text in claims:
            self.assertIn("2025-02-03T04:05:06Z", text)
            self.assertFalse(claim_issues(text, [self.chunk]))

    def test_valid_ssvc_citation_does_not_authorize_attack_path_or_feature_claims(self):
        for text in ("该漏洞在技术层面未被识别出可被利用的攻击路径，其自动化利用能力为无。",
                     "SSVC 为 none，因此无法利用。", "其影响是部分功能受损。",
                     "SSVC 利用状态为 active。", "SSVC 数据记录利用状态为 none。"):
            with self.subTest(text=text):
                self.assertTrue(claim_issues(text, [self.chunk]))
                payload = json.dumps({"claims": [{"text": text, "citations": [self.chunk["citation_id"]]}]})
                with self.assertRaisesRegex(ValueError, "SSVC"):
                    _render_model_json(payload, [{"evidence_chunks": [self.chunk]}])

    def test_projection_or_hash_cannot_override_source_bytes(self):
        for changed in (dict(self.chunk, text_sha256="0" * 64),
                        dict(self.chunk, structured_value={"ssvcData": {"options": [{"exploitation": "active"}]}}),
                        dict(self.chunk, text=self.chunk["text"][:-2])):
            self.assertEqual(ssvc_claims(changed), [])
            self.assertTrue(claim_issues(ssvc_claims(self.chunk)[0], [changed]))

    def test_duplicate_or_unknown_values_do_not_produce_a_verified_fact(self):
        for option in ({"exploitation": "active"}, {"automatable": "impossible"}):
            value = copy.deepcopy(self.value)
            value["ssvcData"]["options"].append(option)
            changed = dict(self.chunk, text=json.dumps(value), text_sha256=None, structured_value=value)
            self.assertEqual(ssvc_claims(changed), [])

    def test_mixing_other_fields_cannot_launder_an_ssvc_fact(self):
        description = dict(self.chunk, locator="descriptions/0", text="Unrelated description.")
        self.assertTrue(claim_issues(ssvc_claims(self.chunk)[0], [self.chunk, description]))


if __name__ == "__main__":
    unittest.main()
