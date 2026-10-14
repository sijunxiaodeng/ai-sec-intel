"""Evidence-bound taxonomy candidates from explicit NVD mechanism descriptions.

These conservative rules neither replace the AI relevance classifier nor
establish an authoritative OWASP/ATLAS mapping. General infrastructure CVEs
without an explicit covered AI attack mechanism receive no forced label.
"""
import re

from enrichment.history import field_evidence

RULE_VERSION = "nvd-mechanism-candidates-1"
OWASP_URL = "https://genai.owasp.org/llm-top-10/"
ATLAS_VERSION = "2026.09"
ATLAS_REFERENCE = "https://github.com/mitre-atlas/atlas-data/blob/3259f388d19cbcca11bacf12a0ef97f4198f711b/dist/ATLAS-latest.yaml"
NOTICE = "根据来源描述中的明确机制生成待审核标签；不是 OWASP/MITRE 对该漏洞的确认，也不证明具体攻击路径可利用。"
AI_CONTEXT = re.compile(r"\b(?:LLM|AI model|machine learning|ollama|vllm|torchserve|pytorch|tensorflow|langchain|hugging[ -]face)\b|大语言模型|语言模型|人工智能|模型推理|智能体", re.I)
NEGATIVE = re.compile(r"(?:not (?:susceptible|vulnerable|subject) to|not affected by|does not suffer from|"
                      r"no (?:evidence of|risk of)|without (?:any )?(?:risk of|evidence of))\s*(?:(?:a|an|the)\s+)?$|"
                      r"(?:不存在|不受|未发现|不具有|不涉及)(?:.{0,12})$", re.I)

# id, mechanism, literal trigger, needs explicit AI context, OWASP item, ATLAS item
RULES = (
    ("prompt_injection", "提示词注入", r"\bprompt[ -]injection\b|提示(?:词)?注入", False,
     ("LLM01:2025", "Prompt Injection"), ("AML.T0051", "LLM Prompt Injection")),
    ("system_prompt_extraction", "系统提示词提取或泄漏", r"\bsystem[ -]prompt (?:leak(?:age)?|extract(?:ion)?|disclosure)\b|"
     r"(?:leak|extract|reveal|disclose)(?:s|ed|ing)? (?:the )?system[ -]prompt|系统提示(?:词)?(?:泄漏|泄露|提取)", False,
     ("LLM07:2025", "System Prompt Leakage"), ("AML.T0056", "Extract LLM System Prompt")),
    ("training_data_poisoning", "训练数据投毒", r"\btraining[ -]data poisoning\b|\bpoison(?:ed|ing)? (?:the )?training[ -]data\b|训练数据投毒|投毒训练数据", False,
     ("LLM04:2025", "Data and Model Poisoning"), ("AML.T0020", "Training Data Poisoning")),
    ("ai_supply_chain", "AI 供应链恶意组件", r"\b(?:malicious|trojanized|poisoned) (?:model|package|dependency|weights)\b|"
     r"\bsupply[ -]chain (?:compromise|attack)\b|恶意模型|恶意(?:软件包|依赖包)|供应链(?:投毒|攻击)", True,
     ("LLM03:2025", "Supply Chain"), ("AML.T0010", "AI Supply Chain Compromise")),
    ("sensitive_model_data", "模型敏感信息泄漏", r"\b(?:model inversion|membership inference)\b|"
     r"\btraining[ -]data (?:leak(?:age)?|exfiltration|disclosure)\b|训练数据(?:泄漏|泄露)|成员推断|模型反演", False,
     ("LLM02:2025", "Sensitive Information Disclosure"), None),
    ("excessive_agent_authority", "智能体权限过大", r"\bexcessive agency\b|\bunrestricted agent permissions\b|"
     r"智能体(?:权限过大|过度权限|越权)", False,
     ("LLM06:2025", "Excessive Agency"), None),
    ("unbounded_ai_consumption", "AI 服务资源耗尽", r"\bunbounded (?:resource )?consumption\b|"
     r"\bresource exhaustion\b|\bdenial[ -]of[ -]service\b|资源耗尽|拒绝服务", True,
     ("LLM10:2025", "Unbounded Consumption"), ("AML.T0029", "Denial of AI Service")),
)


def candidates(cve, doc, sha):
    result = {"schema_version": 1, "rule_version": RULE_VERSION, "status": "empty", "items": [],
              "evidence": [], "notice": NOTICE, "independent_accuracy": None,
              "references": {"owasp_version": "2025", "owasp_url": OWASP_URL,
                             "atlas_version": ATLAS_VERSION, "atlas_data_url": ATLAS_REFERENCE}}
    found = set()
    for i, description in enumerate(cve.get("descriptions") or []):
        if not isinstance(description, dict) or not isinstance(description.get("value"), str):
            continue
        text = description["value"]
        # Scope AI context to the same sentence, not the CVE's coarse risk class.
        for sentence in re.finditer(r"[^.!?。！？\n]+(?:[.!?。！？]|$)", text):
            body = sentence.group()
            for rule_id, mechanism, pattern, needs_ai, owasp, atlas in RULES:
                if rule_id in found or (needs_ai and not AI_CONTEXT.search(body)):
                    continue
                for match in re.finditer(pattern, body, re.I):
                    if NEGATIVE.search(body[max(0, match.start() - 100):match.start()]):
                        continue
                    start, end = sentence.start() + match.start(), sentence.start() + match.end()
                    excerpt_start, excerpt_end = max(sentence.start(), start - 160), min(sentence.end(), end + 160)
                    pointer = "descriptions/%d/value；字符 [%d,%d)，相对于已存档描述" % (i, excerpt_start, excerpt_end)
                    citation = field_evidence(cve, doc, sha, pointer, text[excerpt_start:excerpt_end], "risk_taxonomy")
                    item = {"rule_id": rule_id, "mechanism": mechanism, "match_text": match.group(),
                            "match_reason": "来源描述明确出现“%s”；规则只形成待审核的机制标签。" % match.group(),
                            "source_pointer": "descriptions/%d/value" % i, "source_language": description.get("lang"),
                            "review_status": "not_reviewed", "evidence_ids": [citation["citation_id"]],
                            "owasp": [{"id": owasp[0], "name": owasp[1], "version": "2025", "url": OWASP_URL}],
                            "mitre_atlas": ([{"id": atlas[0], "name": atlas[1], "version": ATLAS_VERSION,
                                              "url": "https://atlas.mitre.org/techniques/" + atlas[0]}] if atlas else [])}
                    result["items"].append(item)
                    result["evidence"].append(citation)
                    found.add(rule_id)
                    break
    result["status"] = "candidates" if result["items"] else "empty"
    return result
