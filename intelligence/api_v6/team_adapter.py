"""Translate B's unified records to the team's frozen IntelligenceItem schema."""
from __future__ import annotations


def _affected_text(package) -> str:
    if isinstance(package, str):
        return package
    if not isinstance(package, dict):
        return ""
    name = package.get("name") or package.get("product") or ""
    if not name:
        return ""
    ecosystem = package.get("ecosystem")
    if ecosystem and ecosystem != "cpe":
        name = f"{ecosystem}:{name}"
    version_range = package.get("vulnerable_version_range")
    version = package.get("version")
    if not version_range and version and version not in {"*", "-"}:
        version_range = version
    text = name + (" " + version_range if version_range else "（范围见原文）")
    if package.get("first_patched_version"):
        text += "（修复版本 " + package["first_patched_version"] + "）"
    return text


def to_team_item(record: dict) -> dict:
    item = record.get("item") or {}
    cve_id = record["cve_id"]
    sources = item.get("sources") or record.get("sources") or []
    raw_by_source = item.get("raw_by_source") or {}
    references = list(item.get("references") or [])
    url = references[0] if references else ""
    if "NVD" in sources:
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    elif "GITHUB_ADVISORY" in sources and item.get("ghsa_ids"):
        url = "https://github.com/advisories/" + item["ghsa_ids"][0]
    elif "CISA_KEV" in sources:
        url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    packages = list(item.get("affected_packages") or [])
    # The existing RAG and QA join these values as strings. Keep detailed
    # structured evidence in raw_data rather than breaking the frozen field.
    affected = list(dict.fromkeys(text for package in packages if (text := _affected_text(package))))
    nvd_raw = raw_by_source.get("NVD") or []
    nvd_raw = [nvd_raw] if isinstance(nvd_raw, dict) else nvd_raw
    exploits = []
    for raw in nvd_raw:
        for reference in raw.get("references") or []:
            if isinstance(reference, dict) and reference.get("url") and any(
                str(tag).casefold() == "exploit" for tag in reference.get("tags") or []
            ):
                exploits.append(reference["url"])
    return {
        "id": cve_id,
        "cve_id": cve_id,
        "title": item.get("title") or cve_id,
        "description": item.get("description") or "",
        "source": "、".join(sources),
        "sources": sources,
        "url": url,
        "published_at": item.get("published_at") or "",
        "collected_at": record.get("first_seen_at") or "",
        "product": item.get("product") or "",
        "affected": affected,
        "references": references,
        "raw_data": {
            "cvss_score": item.get("cvss_score"),
            "cvss_severity": item.get("severity"),
            "cvss_version": item.get("cvss_version"),
            "cvss_vector": item.get("cvss_vector"),
            "cvss_source": item.get("cvss_source"),
            "cvss_evidence": item.get("cvss_evidence") or [],
            "publication_source": item.get("publication_source"),
            "source_evidence": item.get("source_evidence") or [],
            "raw_by_source": raw_by_source,
            "affected_packages": packages,
            "exploit_refs": list(dict.fromkeys(exploits)),
            "classification": record.get("classification"),
            "known_exploited": item.get("known_exploited", False),
            "kev_date_added": item.get("kev_date_added"),
            "epss_score": item.get("epss_score"),
        },
    }
