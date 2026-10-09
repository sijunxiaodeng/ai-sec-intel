from classification.ai_relevance import (
    AIRelevanceClassifier
)

from fusion.models import (
    UnifiedVulnerability
)


_classifier = AIRelevanceClassifier()


def classify_vulnerability(
    vulnerability: UnifiedVulnerability
) -> UnifiedVulnerability:

    # ==========================================
    # 提取 GitHub 中的软件包名称
    # ==========================================

    package_names = []

    for package in vulnerability.affected_packages:

        ecosystem = package.get(
            "ecosystem"
        )

        name = package.get(
            "name"
        )

        if name:

            if ecosystem:
                package_names.append(
                    f"{ecosystem} {name}"
                )

            else:
                package_names.append(
                    name
                )

    # ==========================================
    # 调用统一AI分类器
    # ==========================================

    result = _classifier.classify(

        title=vulnerability.title,

        description=vulnerability.description,

        vendor=vulnerability.vendor or "",

        product=vulnerability.product or "",

        package_names=package_names,
    )

    # ==========================================
    # 写回统一漏洞对象
    # ==========================================

    vulnerability.ai_related = (
        result.is_ai_related
    )

    vulnerability.ai_relevance_hint = (
        result.score
    )

    vulnerability.ai_category = (
        result.category
    )

    vulnerability.ai_evidence = (
        result.evidence
    )

    return vulnerability