"""One source-independent AI-security admission policy, with no model calls.

Source names, query URLs and an AI vendor's reputation are discovery hints, not
classification evidence. Vulnerabilities require an AI product/path; knowledge
documents additionally require security, safety or governance context. Original
source text stays in its source table; verdicts are separately versioned.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ai_relevance import AIRelevanceClassifier


AI_CATEGORIES = frozenset({
    "ai_infrastructure", "model_and_data", "ai_application_agent", "ai_supply_chain",
})
AI_ROUTE_TERMS = (
    "artificial intelligence", "machine learning", "deep learning", "large language model",
    "language model", "llm", "llms", "generative ai", "genai", "ai", "agentic",
    "multi-agent", "ai agent", "agent tool", "chatbot", "copilot", "assistant",
    "model context protocol", "mcp server", "mcp client", "retrieval augmented generation",
    "rag", "prompt injection", "prompt leakage", "system prompt", "embedding",
    "embedder", "vector database", "inference", "model serving", "model provider",
    "multimodal", "transformer", "huggingface", "hugging face", "model registry",
    "model artifact", "model hub", "mlflow", "litellm", "mem0", "openclaw", "pipecat",
    "foundation model", "neural network", "人工智能", "大模型", "机器学习", "深度学习",
    "智能体", "生成式", "提示注入", "提示泄露", "数据投毒", "模型投毒",
)
SECURITY_TERMS = (
    "security", "secure", "cybersecurity", "vulnerability", "vulnerabilities", "advisory",
    "attack", "adversarial", "threat", "exploit", "poisoning", "injection", "privacy",
    "risk", "risks", "robustness", "safety", "safe", "jailbreak", "governance",
    "trustworthy", "responsible", "accountability", "transparency", "bias",
    "discrimination", "rights", "model evaluation", "model testing", "backdoor",
    "malicious", "data leakage", "prompt leakage", "rce", "cve", "denial of service",
    "remote code execution", "cross site scripting", "xss", "csrf", "安全", "漏洞", "攻击",
    "威胁", "风险", "隐私", "投毒", "越狱", "提示注入", "提示泄露", "治理", "合规", "可靠", "对抗",
)
# A broad acronym/entity alone remains a review candidate. These explicit
# research/governance concepts can establish the topic of a knowledge document.
DOCUMENT_AI_CONCEPTS = (
    "artificial intelligence", "machine learning", "deep learning", "large language model",
    "generative ai", "foundation model", "neural network", "人工智能", "大模型",
    "机器学习", "深度学习", "生成式人工智能",
)


@dataclass
class ScopeDecision:
    is_ai_related: bool | None
    category: str
    confidence: float
    reason: str
    evidence: list[str] = field(default_factory=list)
    decision_source: str = ""
    needs_review: bool = False
    rule_score: float = 0.0


def route_hits(text: str, classifier=None) -> list[str]:
    rules = classifier or AIRelevanceClassifier()
    terms = dict.fromkeys([
        *AI_ROUTE_TERMS,
        *(term for entities in rules.AI_ENTITIES.values() for term in entities),
        *(term for concepts in rules.AI_CONCEPTS.values() for term in concepts),
    ])
    return [term for term in terms if rules._contains_term(text, term)][:12]


def classify_scope(*, title="", description="", vendor="", product="",
                   package_names=None, record_kind="vulnerability", content_type="",
                   classifier=None) -> ScopeDecision:
    """Return true, false or unknown using identical taxonomy for every source.

    This function never instantiates a model client. Unknown records must remain
    available for review; a zero model budget must not turn unknown into false.
    """
    if record_kind not in {"vulnerability", "document"}:
        raise ValueError("Unsupported intelligence record kind")
    packages = package_names or []
    rules = classifier or AIRelevanceClassifier()
    rule = rules.classify(title=title, description=description, vendor=vendor,
                          product=product, package_names=packages)
    text = " ".join(str(value or "") for value in (
        title, description, vendor, product, " ".join(packages),
    )).lower()
    hits = route_hits(text, rules)
    security = [term for term in SECURITY_TERMS if rules._contains_term(text, term)]
    if record_kind == "document" and not security:
        return ScopeDecision(False, "non_ai", .95,
                             "No security, safety or governance context in the source text.",
                             decision_source="rule_negative", rule_score=float(rule.score))
    if rule.is_ai_related:
        return ScopeDecision(True, rule.category, max(.85, float(rule.score)),
                             "Explicit AI product/concept in the supplied source record.",
                             list(rule.evidence), "rule_positive", False, float(rule.score))
    if record_kind == "document":
        explicit = [term for term in DOCUMENT_AI_CONCEPTS if rules._contains_term(text, term)]
        # Bare AI/LLM plus direct security terminology is useful evidence in a
        # topical paper/standard/policy title, but not an affected CVE product.
        if not explicit:
            explicit = [term for term in ("ai", "llm", "llms")
                        if rules._contains_term(str(title or ""), term)]
        if explicit and security:
            return ScopeDecision(True, "model_and_data", .85,
                                 "The source text explicitly covers AI security/safety/governance.",
                                 [f"concept:{explicit[0]}", f"security:{security[0]}"],
                                 "rule_positive", False, float(rule.score))
    if hits:
        return ScopeDecision(None, "unknown", 0.0,
                             "Broad AI hints require review; no verified admission verdict.",
                             [f"route:{term}" for term in hits], "semantic_unavailable", True,
                             float(rule.score))
    return ScopeDecision(False, "non_ai", .95,
                         "No explicit AI product/concept or broad AI review signal.",
                         decision_source="rule_negative", rule_score=float(rule.score))
