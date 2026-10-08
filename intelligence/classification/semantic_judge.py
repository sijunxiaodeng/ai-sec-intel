from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

import requests
from dotenv import load_dotenv


VALID_AI_CATEGORIES = {
    "ai_infrastructure",
    "model_and_data",
    "ai_application_agent",
    "ai_supply_chain",
}


@dataclass
class SemanticJudgeResult:
    is_ai_related: bool
    category: str
    confidence: float
    reason: str
    evidence: list[str] = field(default_factory=list)
    raw_text: str = ""


class SemanticJudge:
    """
    OpenAI-compatible Chat Completions semantic judge.

    Environment variables:
        LLM_API_BASE=https://your-provider.example/v1
        LLM_API_KEY=...
        LLM_MODEL=...
        # Optional:
        LLM_CHAT_COMPLETIONS_URL=https://.../chat/completions
        LLM_TIMEOUT=60

    Notes:
    - The endpoint is provider-agnostic as long as it supports an
      OpenAI-compatible /chat/completions request/response shape.
    - For a local OpenAI-compatible server, LLM_API_KEY may be left empty.
    """

    SYSTEM_PROMPT = """You are an AI-security intelligence classifier.

Your job is to decide whether a vulnerability should be included in an
AI-security intelligence system.

A vulnerability is AI-related ONLY if the vulnerable product, feature,
processing path, or supply-chain relationship directly belongs to one of:

1. ai_infrastructure
   AI inference/serving infrastructure, model-serving gateways, inference
   frameworks, GPU/accelerator software specifically used as AI inference
   infrastructure, or LLM/model runtime infrastructure.

2. model_and_data
   Model/data lifecycle systems, model registries, vector databases used as
   AI knowledge infrastructure, embeddings, model memory, ML experiment/model
   management, model/data poisoning or model/data security.

3. ai_application_agent
   AI applications, LLM applications, copilots, chatbots, AI assistants,
   agents, agent frameworks, RAG systems, MCP systems, prompt-security issues,
   and tools whose vulnerable function directly executes or orchestrates AI.

4. ai_supply_chain
   Vulnerabilities whose security impact specifically arises from loading,
   downloading, packaging, serializing, distributing, or trusting AI models,
   model artifacts, model repositories, or AI-specific dependencies.
CATEGORY PRECEDENCE RULE:

Classify primarily by the main role of the vulnerable product or subsystem,
not merely by individual AI-related words appearing in the vulnerability.

Examples:

- An LLM proxy, gateway, inference server, or model-serving platform
  should normally be ai_infrastructure, even if one vulnerable endpoint
  implements MCP or agent-related functionality.

- An AI memory system, vector/embedding store, model registry,
  experiment/model lifecycle platform, or model/data management system
  should normally be model_and_data.

- An agent framework, chatbot application, AI assistant, orchestration
  framework, RAG application, or MCP-native agent/application system
  should normally be ai_application_agent.

- A vulnerability should be ai_supply_chain only when the security issue
  specifically arises from obtaining, loading, packaging, distributing,
  serializing, or trusting AI models or model artifacts.

When multiple categories seem possible, choose the category corresponding
to the vulnerable product's primary role.
IMPORTANT NEGATIVE RULE:
Do NOT classify ordinary infrastructure as AI-related merely because AI systems
may use it. Examples include Windows, Linux, Docker, Kubernetes, Redis,
MongoDB, PostgreSQL, Git, generic web frameworks, generic routers, OpenSSL,
generic CI/CD agents, and ordinary GPU/device drivers unless the vulnerability
itself directly concerns AI/ML functionality.

IMPORTANT TERMINOLOGY RULES:
- "agent" may mean a CI/CD or monitoring agent; this alone is NOT AI.
- "model" may mean a device/product/data model; this alone is NOT AI.
- "embedding" in OLE/Object Linking & Embedding is NOT AI embedding.
- "assistant" may be a generic UI helper; inspect context.
- An unknown/new project may still be AI-related if the description clearly
  shows LLM/model/AI-agent functionality.

Return ONLY one JSON object with exactly these fields:
{
  "is_ai_related": true,
  "category": "ai_application_agent",
  "confidence": 0.95,
  "reason": "short explanation",
  "evidence": ["short phrase from the supplied record"]
}

Rules for output:
- category must be one of:
  ai_infrastructure, model_and_data, ai_application_agent, ai_supply_chain,
  non_ai
- if is_ai_related is false, category MUST be non_ai
- confidence must be a number from 0 to 1
- evidence should quote/point to concise phrases from the supplied record
- do not invent product facts not supported by the record unless they are
  necessary to identify a well-known product; prefer the supplied text.
"""

    def __init__(
        self,
        api_base: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ):
        load_dotenv()

        self.api_base = (
            api_base
            or os.getenv("LLM_API_BASE", "")
        ).rstrip("/")

        self.api_key = (
            api_key
            if api_key is not None
            else os.getenv("LLM_API_KEY", "")
        )

        self.model = (
            model
            or os.getenv("LLM_MODEL", "")
        )

        self.timeout = int(
            timeout
            or os.getenv("LLM_TIMEOUT", "60")
        )

        explicit_url = os.getenv(
            "LLM_CHAT_COMPLETIONS_URL",
            ""
        ).strip()

        if explicit_url:
            self.url = explicit_url
        elif self.api_base:
            self.url = (
                f"{self.api_base}/chat/completions"
            )
        else:
            self.url = ""

    def is_configured(self) -> bool:
        return bool(self.url and self.model)

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        text = text or ""
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n...[truncated]"

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        text = (text or "").strip()

        if text.startswith("```"):
            text = re.sub(
                r"^```(?:json)?\s*",
                "",
                text,
                flags=re.IGNORECASE,
            )
            text = re.sub(
                r"\s*```$",
                "",
                text,
            )

        return text.strip()

    @classmethod
    def _parse_json_object(
        cls,
        text: str,
    ) -> dict:
        cleaned = cls._strip_code_fence(text)

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Fallback: extract the outermost JSON object.
        start = cleaned.find("{")
        end = cleaned.rfind("}")

        if start >= 0 and end > start:
            return json.loads(
                cleaned[start:end + 1]
            )

        raise ValueError(
            "Semantic judge did not return a valid JSON object."
        )

    @staticmethod
    def _normalize_result(
        obj: dict,
        raw_text: str,
    ) -> SemanticJudgeResult:
        is_ai = bool(
            obj.get("is_ai_related", False)
        )

        category = str(
            obj.get(
                "category",
                "non_ai" if not is_ai else ""
            )
        ).strip()

        if not is_ai:
            category = "non_ai"
        elif category not in VALID_AI_CATEGORIES:
            raise ValueError(
                f"Invalid AI category returned: {category!r}"
            )

        try:
            confidence = float(
                obj.get("confidence", 0.0)
            )
        except (TypeError, ValueError):
            confidence = 0.0

        confidence = max(
            0.0,
            min(1.0, confidence)
        )

        reason = str(
            obj.get("reason", "")
        ).strip()

        evidence_raw = obj.get(
            "evidence",
            []
        )

        if isinstance(evidence_raw, str):
            evidence = [evidence_raw]
        elif isinstance(evidence_raw, list):
            evidence = [
                str(x).strip()
                for x in evidence_raw
                if str(x).strip()
            ]
        else:
            evidence = []

        return SemanticJudgeResult(
            is_ai_related=is_ai,
            category=category,
            confidence=confidence,
            reason=reason,
            evidence=evidence,
            raw_text=raw_text,
        )

    def judge(
        self,
        *,
        cve_id: str = "",
        title: str = "",
        description: str = "",
        vendor: str = "",
        product: str = "",
        package_names: list[str] | None = None,
    ) -> SemanticJudgeResult:
        if not self.is_configured():
            raise RuntimeError(
                "SemanticJudge is not configured. "
                "Set LLM_API_BASE (or LLM_CHAT_COMPLETIONS_URL) "
                "and LLM_MODEL in .env. Set LLM_API_KEY if "
                "your endpoint requires authentication."
            )

        package_names = (
            package_names or []
        )

        record = {
            "cve_id": cve_id or "",
            "title": title or "",
            "description": self._truncate(
                description or "",
                7000,
            ),
            "vendor": vendor or "",
            "product": product or "",
            "package_names": package_names[:30],
        }

        user_content = (
            "Classify this vulnerability record:\n"
            + json.dumps(
                record,
                ensure_ascii=False,
                indent=2,
            )
        )

        headers = {
            "Content-Type": "application/json",
        }

        if self.api_key:
            headers["Authorization"] = (
                f"Bearer {self.api_key}"
            )

        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": self.SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": user_content,
                },
            ],
        }

        response = requests.post(
            self.url,
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )

        response.raise_for_status()

        data = response.json()

        try:
            raw_text = (
                data["choices"][0]
                ["message"]["content"]
            )
        except Exception as exc:
            raise ValueError(
                "Unexpected chat-completions response shape."
            ) from exc

        obj = self._parse_json_object(
            raw_text
        )

        return self._normalize_result(
            obj,
            raw_text,
        )
