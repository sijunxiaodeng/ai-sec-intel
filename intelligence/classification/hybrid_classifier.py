from __future__ import annotations

from dataclasses import dataclass, field

from classification.ai_relevance import (
    AIRelevanceClassifier,
)
from classification.semantic_judge import (
    SemanticJudge,
)
from .scope_policy import AI_ROUTE_TERMS as SCOPE_AI_ROUTE_TERMS, classify_scope, route_hits


@dataclass
class HybridClassificationResult:
    is_ai_related: bool | None
    category: str
    confidence: float
    reason: str
    evidence: list[str] = field(default_factory=list)
    decision_source: str = ""
    needs_review: bool = False
    rule_score: float = 0.0


class HybridAIClassifier:
    """
    V3 = conservative rule classifier + semantic judge.

    Routing:
    1. Rule V2 positive -> accept immediately.
    2. Rule V2 negative but broad AI signal exists -> semantic judge.
    3. No AI signal -> direct non-AI.
    4. Semantic failure -> needs_review=True (never silently force non-AI).
    """

    # Shared broad routing hints are candidates, never final labels.
    AI_ROUTE_TERMS = list(SCOPE_AI_ROUTE_TERMS)

    def __init__(
        self,
        semantic_judge: SemanticJudge | None = None,
        semantic_min_confidence: float = 0.65,
    ):
        self.rule_classifier = (
            AIRelevanceClassifier()
        )

        self.semantic_judge = (
            semantic_judge
            or SemanticJudge()
        )

        self.semantic_min_confidence = (
            semantic_min_confidence
        )

    @staticmethod
    def _normalize_text(*parts) -> str:
        return " ".join(
            str(x or "")
            for x in parts
        ).lower()

    @staticmethod
    def _contains_route_term(
        text: str,
        term: str,
    ) -> bool:
        """Broad concepts route for review, but substrings are not evidence."""
        return AIRelevanceClassifier._contains_term(text, term)

    def _should_use_semantic_judge(
        self,
        *,
        title: str,
        description: str,
        vendor: str,
        product: str,
        package_names: list[str],
    ) -> tuple[bool, list[str]]:
        text = self._normalize_text(
            title,
            description,
            vendor,
            product,
            " ".join(package_names),
        )

        hits = route_hits(text, self.rule_classifier)
        return bool(hits), hits

    def classify(
        self,
        *,
        cve_id: str = "",
        title: str = "",
        description: str = "",
        vendor: str = "",
        product: str = "",
        package_names: list[str] | None = None,
    ) -> HybridClassificationResult:
        package_names = package_names or []

        # -------------------------------------------------
        # 1. Conservative V2 rule classifier
        # -------------------------------------------------
        rule = classify_scope(
            title=title,
            description=description,
            vendor=vendor,
            product=product,
            package_names=package_names,
            classifier=self.rule_classifier,
        )

        if rule.is_ai_related:
            return HybridClassificationResult(
                is_ai_related=True,
                category=rule.category,
                confidence=max(
                    0.85,
                    float(rule.confidence),
                ),
                reason=(
                    "High-confidence AI entity/concept "
                    "matched by the deterministic rule layer."
                ),
                evidence=list(rule.evidence),
                decision_source="rule_positive",
                needs_review=False,
                rule_score=float(rule.rule_score),
            )

        # -------------------------------------------------
        # 2. Broad routing only
        # -------------------------------------------------
        should_semantic, route_hits = (
            self._should_use_semantic_judge(
                title=title,
                description=description,
                vendor=vendor,
                product=product,
                package_names=package_names,
            )
        )

        if not should_semantic:
            return HybridClassificationResult(
                is_ai_related=False,
                category="non_ai",
                confidence=0.95,
                reason=(
                    "No deterministic AI match and no broad "
                    "AI-semantic routing signal was found."
                ),
                evidence=[],
                decision_source="rule_negative",
                needs_review=False,
                rule_score=float(rule.rule_score),
            )

        # -------------------------------------------------
        # 3. Semantic judge
        # -------------------------------------------------
        if not self.semantic_judge.is_configured():
            return HybridClassificationResult(
                is_ai_related=None,
                category="unknown",
                confidence=0.0,
                reason=(
                    "Semantic review was required but the "
                    "LLM endpoint is not configured."
                ),
                evidence=[
                    f"route:{x}"
                    for x in route_hits
                ],
                decision_source="semantic_unavailable",
                needs_review=True,
                rule_score=float(rule.rule_score),
            )

        try:
            semantic = (
                self.semantic_judge.judge(
                    cve_id=cve_id,
                    title=title,
                    description=description,
                    vendor=vendor,
                    product=product,
                    package_names=package_names,
                )
            )
        except Exception as exc:
            return HybridClassificationResult(
                is_ai_related=None,
                category="unknown",
                confidence=0.0,
                reason=(
                    "Semantic judge failed: "
                    f"{type(exc).__name__}"
                ),
                evidence=[
                    f"route:{x}"
                    for x in route_hits
                ],
                decision_source="semantic_error",
                needs_review=True,
                rule_score=float(rule.rule_score),
            )

        needs_review = (
            semantic.confidence
            < self.semantic_min_confidence
        )

        return HybridClassificationResult(
            is_ai_related=semantic.is_ai_related,
            category=semantic.category,
            confidence=semantic.confidence,
            reason=semantic.reason,
            evidence=[
                *[
                    f"route:{x}"
                    for x in route_hits
                ],
                *semantic.evidence,
            ],
            decision_source="semantic_judge",
            needs_review=needs_review,
            rule_score=float(rule.rule_score),
        )

    def classify_vulnerability(
        self,
        vulnerability,
    ) -> HybridClassificationResult:
        packages = []

        for pkg in (
            getattr(
                vulnerability,
                "affected_packages",
                [],
            )
            or []
        ):
            if not isinstance(pkg, dict):
                continue

            ecosystem = str(
                pkg.get("ecosystem", "")
                or ""
            ).strip()

            name = str(
                pkg.get("name", "")
                or ""
            ).strip()

            if name:
                packages.append(
                    f"{ecosystem}:{name}"
                    if ecosystem
                    else name
                )

        return self.classify(
            cve_id=getattr(
                vulnerability,
                "cve_id",
                "",
            )
            or "",
            title=getattr(
                vulnerability,
                "title",
                "",
            )
            or "",
            description=getattr(
                vulnerability,
                "description",
                "",
            )
            or "",
            vendor=getattr(
                vulnerability,
                "vendor",
                "",
            )
            or "",
            product=getattr(
                vulnerability,
                "product",
                "",
            )
            or "",
            package_names=packages,
        )
