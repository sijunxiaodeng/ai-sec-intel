from collections import defaultdict

from collectors.base import IntelligenceItem
from fusion.models import UnifiedVulnerability
from classification.unified_classifier import (
    classify_vulnerability
)

def merge_by_cve(
    items: list[IntelligenceItem]
) -> list[UnifiedVulnerability]:

    groups = defaultdict(list)

    # ==================================================
    # 1. 按 CVE ID 分组
    # ==================================================

    for item in items:

        if not item.cve_id:
            continue

        groups[item.cve_id].append(item)

    results = []

    # ==================================================
    # 2. 对每个 CVE 进行多源融合
    # ==================================================

    for cve_id, group in groups.items():

        merged = UnifiedVulnerability(
            cve_id=cve_id
        )

        for item in group:

            # ------------------------------------------
            # 数据来源
            # ------------------------------------------

            if item.source not in merged.sources:
                merged.sources.append(item.source)

            # ------------------------------------------
            # 保存原始数据
            # ------------------------------------------

            merged.raw_by_source[item.source] = (
                item.raw_data
            )

            # ------------------------------------------
            # 标签
            # ------------------------------------------

            for tag in item.tags:

                if tag not in merged.tags:
                    merged.tags.append(tag)

            # ------------------------------------------
            # Item 自己的 URL
            # ------------------------------------------

            if (
                item.url
                and item.url not in merged.references
            ):
                merged.references.append(item.url)

            # ------------------------------------------
            # AI相关性
            # ------------------------------------------

            merged.ai_relevance_hint = max(
                merged.ai_relevance_hint,
                item.ai_relevance_hint,
            )

            # ------------------------------------------
            # 时间
            # ------------------------------------------

            if (
                not merged.published_at
                and item.published_at
            ):
                merged.published_at = (
                    item.published_at
                )

            if (
                not merged.modified_at
                and item.modified_at
            ):
                merged.modified_at = (
                    item.modified_at
                )

            # ==================================================
            # NVD
            # ==================================================

            if item.source == "NVD":

                if item.description:
                    merged.description = (
                        item.description
                    )

                if item.severity:
                    merged.severity = (
                        item.severity
                    )

                if not merged.title:
                    merged.title = (
                        item.title
                    )

                _merge_nvd(
                    merged,
                    item.raw_data
                )

            # ==================================================
            # CISA KEV
            # ==================================================

            elif item.source == "CISA_KEV":

                merged.known_exploited = True

                raw = item.raw_data

                merged.vendor = (
                    raw.get("vendor")
                    or raw.get("vendorProject")
                )

                merged.product = raw.get(
                    "product"
                )

                merged.kev_date_added = raw.get(
                    "dateAdded"
                )

                merged.required_action = (
                    raw.get("required_action")
                    or raw.get("requiredAction")
                )

                # CISA标题通常比单纯CVE编号更有信息
                if (
                    item.title
                    and (
                        not merged.title
                        or merged.title == cve_id
                    )
                ):
                    merged.title = item.title

                if (
                    not merged.description
                    and item.description
                ):
                    merged.description = (
                        item.description
                    )

            # ==================================================
            # GitHub Security Advisory
            # ==================================================

            elif item.source == "GITHUB_ADVISORY":

                _merge_github_advisory(
                    merged,
                    item
                )

        # ==================================================
        # 最终兜底
        # ==================================================

        if not merged.title:
            merged.title = cve_id

        results.append(merged)

    return results


# ==========================================================
# NVD解析
# ==========================================================

def _merge_nvd(
    merged: UnifiedVulnerability,
    raw: dict
):

    metrics = raw.get(
        "metrics",
        {}
    )

    metric_priority = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_name in metric_priority:

        metric_list = metrics.get(
            metric_name,
            []
        )

        if not metric_list:
            continue

        cvss_data = metric_list[0].get(
            "cvssData",
            {}
        )

        score = cvss_data.get(
            "baseScore"
        )

        if score is not None:

            try:
                merged.cvss_score = float(
                    score
                )

            except (TypeError, ValueError):
                pass

        severity = cvss_data.get(
            "baseSeverity"
        )

        if (
            severity
            and not merged.severity
        ):
            merged.severity = severity

        break

    # ---------------------------
    # CWE
    # ---------------------------

    weaknesses = raw.get(
        "weaknesses",
        []
    )

    for weakness in weaknesses:

        for description in weakness.get(
            "description",
            []
        ):

            cwe = description.get(
                "value"
            )

            if (
                cwe
                and cwe not in merged.cwes
            ):
                merged.cwes.append(cwe)

    # ---------------------------
    # NVD references
    # ---------------------------

    for reference in raw.get(
        "references",
        []
    ):

        url = reference.get(
            "url"
        )

        if (
            url
            and url not in merged.references
        ):
            merged.references.append(url)


# ==========================================================
# GitHub Advisory解析
# ==========================================================

def _merge_github_advisory(
    merged: UnifiedVulnerability,
    item: IntelligenceItem
):

    raw = item.raw_data

    # ---------------------------
    # GHSA ID
    # ---------------------------

    ghsa_id = raw.get(
        "ghsa_id"
    )

    if (
        ghsa_id
        and ghsa_id not in merged.ghsa_ids
    ):
        merged.ghsa_ids.append(
            ghsa_id
        )

    # ---------------------------
    # 标题
    # ---------------------------

    summary = raw.get(
        "summary"
    )

    if summary:
        merged.title = summary

    # ---------------------------
    # 描述
    # ---------------------------

    if (
        not merged.description
        and raw.get("description")
    ):
        merged.description = raw.get(
            "description"
        )

    # ---------------------------
    # Severity
    # ---------------------------

    if (
        not merged.severity
        and raw.get("severity")
    ):
        merged.severity = (
            raw.get("severity").upper()
        )

    # ---------------------------
    # CVSS
    # ---------------------------

    cvss = raw.get(
        "cvss"
    ) or {}

    score = cvss.get(
        "score"
    )

    if (
        merged.cvss_score is None
        and score is not None
    ):

        try:
            merged.cvss_score = float(
                score
            )

        except (TypeError, ValueError):
            pass

    # ---------------------------
    # EPSS
    # ---------------------------

    epss = raw.get(
        "epss"
    ) or {}

    percentage = epss.get(
        "percentage"
    )

    if percentage is not None:

        try:
            merged.epss_score = float(
                percentage
            )

        except (TypeError, ValueError):
            pass

    # ---------------------------
    # CWE
    # ---------------------------

    for cwe in raw.get(
        "cwes",
        []
    ):

        cwe_id = cwe.get(
            "cwe_id"
        )

        if (
            cwe_id
            and cwe_id not in merged.cwes
        ):
            merged.cwes.append(
                cwe_id
            )

    # ---------------------------
    # 受影响软件包
    # ---------------------------

    for vulnerability in raw.get(
        "vulnerabilities",
        []
    ):

        package = vulnerability.get(
            "package",
            {}
        )

        patched = vulnerability.get(
            "first_patched_version"
        )

        package_info = {
            "ecosystem": package.get(
                "ecosystem"
            ),

            "name": package.get(
                "name"
            ),

            "vulnerable_version_range":
                vulnerability.get(
                    "vulnerable_version_range"
                ),

            "first_patched_version": (
                patched.get("identifier")
                if isinstance(patched, dict)
              else patched
            )
        }

        if package_info not in (
            merged.affected_packages
        ):
            merged.affected_packages.append(
                package_info
            )

    # ---------------------------
    # GitHub References
    # ---------------------------

    for reference in raw.get("references", []):

        # GitHub Global Security Advisory
        # references 通常是 URL 字符串列表
        if isinstance(reference, str):
            url = reference

        # 兼容将来可能遇到的字典格式
        elif isinstance(reference, dict):
            url = reference.get("url")

        else:
            url = None

        if (
                url
                and url not in merged.references
        ):
            merged.references.append(url)