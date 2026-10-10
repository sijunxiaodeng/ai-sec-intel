"""Deterministic, evidence-preserving fusion of collector records by CVE."""
from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import datetime, timezone

from collectors.base import IntelligenceItem
from fusion.models import UnifiedVulnerability

SOURCE_PRIORITY = {"NVD": 0, "CISA_KEV": 1, "GITHUB_ADVISORY": 2}
METRIC_PRIORITY = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _json_key(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _score(value, maximum=10.0):
    """Ignore absent, nonnumeric, infinite and out-of-range scores."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0 <= number <= maximum else None


def _time_key(value: str):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (0, parsed.timestamp(), value)
    except (TypeError, ValueError, OverflowError):
        return (1, 0, str(value))


def _published_at(item: IntelligenceItem):
    if item.source == "CISA_KEV":
        # KEV dateAdded is catalog admission, not vulnerability publication.
        return item.raw_data.get("published_at") or item.raw_data.get("published")
    return item.published_at


def merge_by_cve(items: list[IntelligenceItem]) -> list[UnifiedVulnerability]:
    groups = defaultdict(list)
    for item in items:
        cve_id = (item.cve_id or "").strip().upper()
        if cve_id:
            groups[cve_id].append(item)

    results = []
    for cve_id, group in sorted(groups.items()):
        # Stable source and record ordering avoids hash changes after input reorder.
        group = sorted(group, key=lambda item: (
            SOURCE_PRIORITY.get(item.source, 3), item.source, item.source_id,
            _json_key(item.raw_data),
        ))
        merged = UnifiedVulnerability(cve_id=cve_id)
        raw_records = defaultdict(list)
        publication = []
        modifications = []
        severity_fallbacks = []
        for item in group:
            if item.source not in merged.sources:
                merged.sources.append(item.source)
            raw_records[item.source].append(item.raw_data)
            merged.source_evidence.append({
                "source": item.source,
                "source_id": item.source_id,
                "url": item.url,
                "published_at": _published_at(item),
                "modified_at": item.modified_at,
            })
            merged.tags.extend(item.tags or [])
            if item.url:
                merged.references.append(item.url)
            hint = _score(item.ai_relevance_hint, maximum=1.0)
            if hint is not None:
                merged.ai_relevance_hint = max(merged.ai_relevance_hint, hint)
            published = _published_at(item)
            if published:
                publication.append((published, item.source))
            if item.modified_at:
                modifications.append(item.modified_at)
            if item.severity:
                severity_fallbacks.append(str(item.severity).upper())
            if not merged.title and item.title:
                merged.title = item.title
            if not merged.description and item.description:
                merged.description = item.description

            if item.source == "NVD":
                _merge_nvd(merged, item.raw_data, item.source_id)
            elif item.source == "CISA_KEV":
                raw = item.raw_data
                merged.known_exploited = True
                merged.vendor = raw.get("vendor") or raw.get("vendorProject") or merged.vendor
                merged.product = raw.get("product") or merged.product
                merged.kev_date_added = raw.get("dateAdded") or merged.kev_date_added
                merged.required_action = raw.get("required_action") or raw.get("requiredAction") or merged.required_action
                if item.title and (not merged.title or merged.title.upper() == cve_id):
                    merged.title = item.title
            elif item.source == "GITHUB_ADVISORY":
                _merge_github_advisory(merged, item)

        merged.raw_by_source = {
            source: records[0] if len(records) == 1 else records
            for source, records in raw_records.items()
        }
        if publication:
            valid_publication = [pair for pair in publication if _time_key(pair[0])[0] == 0]
            merged.published_at, merged.publication_source = min(
                valid_publication or publication,
                key=lambda pair: (_time_key(pair[0]), SOURCE_PRIORITY.get(pair[1], 3), pair[1])
            )
        if modifications:
            valid_modifications = [value for value in modifications if _time_key(value)[0] == 0]
            merged.modified_at = max(valid_modifications or modifications, key=_time_key)
        if merged.cvss_evidence:
            selected = min(merged.cvss_evidence, key=_metric_key)
            merged.cvss_score = selected["score"]
            merged.cvss_vector = selected["vector"]
            merged.cvss_version = selected["version"]
            merged.cvss_source = selected["source"]
            merged.severity = _severity(selected["score"], selected["version"])
        elif severity_fallbacks:
            merged.severity = severity_fallbacks[0]
        _set_unambiguous_cpe_product(merged)
        merged.title = merged.title or cve_id
        for name in ("tags", "references", "cwes", "ghsa_ids"):
            setattr(merged, name, sorted(set(getattr(merged, name))))
        merged.affected_packages.sort(key=_json_key)
        merged.cvss_evidence.sort(key=_metric_key)
        results.append(merged)
    return results


def _severity(score: float, version: str | None) -> str:
    if version == "2.0":
        return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH"
    return "NONE" if score == 0 else "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def _metric_key(metric):
    versions = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
    return (
        0 if metric["source"] == "NVD" else 1,
        versions.get(metric["version"], 4),
        0 if metric.get("metric_type") == "Primary" else 1,
        0 if metric.get("metric_publisher") == "nvd@nist.gov" else 1,
        metric["source_id"], _json_key(metric),
    )


def _add_metric(merged, *, source, source_id, score, vector=None, version=None,
                severity=None, metric_publisher=None, metric_type=None):
    score = _score(score)
    if score is None:
        return
    if isinstance(vector, str) and vector.startswith("CVSS:"):
        version = vector.split("/", 1)[0].split(":", 1)[1]
    evidence = {
        "source": source, "source_id": source_id, "score": score,
        "vector": vector, "version": version, "reported_severity": severity,
        "metric_publisher": metric_publisher, "metric_type": metric_type,
    }
    if evidence not in merged.cvss_evidence:
        merged.cvss_evidence.append(evidence)


def _merge_nvd(merged: UnifiedVulnerability, raw: dict, source_id: str = ""):
    metrics = raw.get("metrics") or {}
    for metric_name, version in METRIC_PRIORITY:
        for metric in metrics.get(metric_name) or []:
            data = metric.get("cvssData") or {}
            _add_metric(
                merged, source="NVD", source_id=source_id or raw.get("id", ""),
                score=data.get("baseScore"), vector=data.get("vectorString"),
                version=data.get("version") or version,
                severity=data.get("baseSeverity") or metric.get("baseSeverity"),
                metric_publisher=metric.get("source"), metric_type=metric.get("type"),
            )
    for weakness in raw.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            cwe = description.get("value")
            if cwe:
                merged.cwes.append(cwe)
    _merge_references(merged, raw.get("references") or [])
    _merge_nvd_cpes(merged, raw.get("configurations") or [], source_id or raw.get("id", ""))


def _cpe_literal(component: str) -> str | None:
    """Unbind escaped characters; ANY/NA/pattern values are not exact entities."""
    if component in {"*", "-"}:
        return None
    characters = []
    escaped = False
    for character in component:
        if escaped:
            characters.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in {"*", "?"}:
            return None
        else:
            characters.append(character)
    return "".join(characters) if not escaped else None


def _parse_cpe23(criteria) -> dict | None:
    """Split CPE 2.3 formatted strings without splitting escaped colons."""
    if not isinstance(criteria, str):
        return None
    components = []
    current = []
    escaped = False
    for character in criteria:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            components.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        return None
    components.append("".join(current))
    if (len(components) != 13 or components[:2] != ["cpe", "2.3"]
            or any(not component for component in components[2:])):
        return None
    if components[2] not in {"a", "h", "o"}:
        return None
    return {
        "part": components[2],
        "vendor": _cpe_literal(components[3]),
        "product": _cpe_literal(components[4]),
        "version": _cpe_literal(components[5]),
    }


def _vulnerable_cpe_matches(node, path="configurations"):
    if isinstance(node, list):
        for index, child in enumerate(node):
            yield from _vulnerable_cpe_matches(child, f"{path}[{index}]")
        return
    if not isinstance(node, dict) or node.get("negate") is True:
        return
    for index, match in enumerate(node.get("cpeMatch") or []):
        # False means an environmental prerequisite, not an affected product.
        if isinstance(match, dict) and match.get("vulnerable") is True:
            yield match, f"{path}.cpeMatch[{index}]"
    for key in ("nodes", "children"):
        if key in node:
            yield from _vulnerable_cpe_matches(node[key], f"{path}.{key}")


def _merge_nvd_cpes(merged, configurations, source_id):
    bounds = (
        ("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="), ("versionEndExcluding", "<"),
    )
    for match, path in _vulnerable_cpe_matches(configurations):
        criteria = match.get("criteria")
        parsed = _parse_cpe23(criteria)
        if parsed is None:
            continue
        constraints = [f"{operator} {match[key]}" for key, operator in bounds
                       if isinstance(match.get(key), str) and match[key]]
        if parsed["version"]:
            constraints.insert(0, f"== {parsed['version']}")
        info = {
            "ecosystem": "cpe", "name": parsed["product"], **parsed,
            "cpe": criteria, "source": "NVD", "source_id": source_id,
            "match_criteria_id": match.get("matchCriteriaId"),
            "configuration_path": path,
            "vulnerable_version_range": ", ".join(constraints) or None,
            # A bound describes affected versions; it does not prove a patch.
            "first_patched_version": None,
        }
        info.update({key: match[key] for key, _ in bounds if key in match})
        if info not in merged.affected_packages:
            merged.affected_packages.append(info)


def _set_unambiguous_cpe_product(merged):
    cpes = [package for package in merged.affected_packages
            if package.get("ecosystem") == "cpe" and package.get("source") == "NVD"]
    if not cpes:
        return
    for field in ("vendor", "product"):
        values = {package.get(field) for package in cpes}
        if not getattr(merged, field) and len(values) == 1 and None not in values:
            setattr(merged, field, values.pop())


def _merge_github_advisory(merged: UnifiedVulnerability, item: IntelligenceItem):
    raw = item.raw_data
    ghsa_id = raw.get("ghsa_id")
    if ghsa_id:
        merged.ghsa_ids.append(ghsa_id)
    if raw.get("summary"):
        merged.title = raw["summary"]
    if not merged.description and raw.get("description"):
        merged.description = raw["description"]
    if not item.severity and raw.get("severity") and not merged.severity:
        merged.severity = str(raw["severity"]).upper()
    candidates = [raw.get("cvss") or {}]
    # cvss_v3 names a family; without a vector/version it cannot prove 3.1.
    for version_key, version in (("cvss_v4", "4.0"), ("cvss_v3", None)):
        metric = (raw.get("cvss_severities") or {}).get(version_key) or {}
        if metric:
            candidates.append({**metric, "version": metric.get("version") or version})
    for metric in candidates:
        _add_metric(
            merged, source="GITHUB_ADVISORY", source_id=item.source_id,
            score=metric.get("score"), vector=metric.get("vector_string"),
            version=metric.get("version"), severity=raw.get("severity"),
        )
    percentage = _score((raw.get("epss") or {}).get("percentage"), maximum=1.0)
    if percentage is not None:
        merged.epss_score = max(merged.epss_score or 0.0, percentage)
    for cwe in raw.get("cwes") or []:
        if cwe.get("cwe_id"):
            merged.cwes.append(cwe["cwe_id"])
    for vulnerability in raw.get("vulnerabilities") or []:
        package = vulnerability.get("package") or {}
        patched = vulnerability.get("first_patched_version")
        info = {
            "ecosystem": package.get("ecosystem"), "name": package.get("name"),
            "vulnerable_version_range": vulnerability.get("vulnerable_version_range"),
            "first_patched_version": patched.get("identifier") if isinstance(patched, dict) else patched,
        }
        if info not in merged.affected_packages:
            merged.affected_packages.append(info)
    if not merged.product:
        names = {
            (vulnerability.get("package") or {}).get("name")
            for vulnerability in raw.get("vulnerabilities") or []
        }
        names.discard(None)
        names.discard("")
        if len(names) == 1:
            merged.product = names.pop()
    _merge_references(merged, raw.get("references") or [])


def _merge_references(merged, references):
    for reference in references:
        url = reference if isinstance(reference, str) else reference.get("url") if isinstance(reference, dict) else None
        if url:
            merged.references.append(url)
