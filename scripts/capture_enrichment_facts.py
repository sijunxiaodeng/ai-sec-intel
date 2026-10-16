"""Freeze actual enrichment claims and archived source excerpts for review.

This captures observations, not standard answers or an accuracy score. Reviewers
must judge the frozen predictions against the original excerpts. Nothing is
written to the service databases and no model or provider request is made.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def capture(cve_ids, commit, *, quota=10, provider_responses=()):
    from database import store
    from enrichment.assessment import assess
    from enrichment.research_associations import current
    from rag.evidence import DEFAULT_DB
    from enrichment.documents import digest

    cases, sources, coverage = [], {}, []
    buckets = {key: [] for key in ("severity", "exploitation", "affected_versions", "research", "poc", "remediation")}
    feeds = {}
    for path in provider_responses:
        frozen = json.loads(Path(path).read_text(encoding="utf-8"))
        body = frozen["body"].encode("utf-8")
        if hashlib.sha256(body).hexdigest() != frozen["response_sha256"]:
            raise ValueError("Provider response digest mismatch")
        kind = frozen["kind"]
        expected = "https://api.first.org/" if kind == "epss" else "https://www.cisa.gov/" if kind == "kev" else None
        if not expected or not frozen["url"].startswith(expected):
            raise ValueError("Expected a frozen FIRST/CISA public response")
        frozen["parsed"] = json.loads(frozen["body"])
        feeds[kind] = frozen

    def add(category, cve_id, prediction, reference, url, sha, locator, *, extra=None):
        if not sha or not url:
            return
        sources[url] = sha
        buckets[category].append({"question": cve_id + "：核对" + {
            "severity": "评分记录", "exploitation": "利用风险观测", "affected_versions": "受影响版本范围",
            "research": "研究资料关联依据", "poc": "PoC候选来源标记", "remediation": "修复候选来源标记"}[category],
            "prediction": canonical(prediction), "reference": reference,
            "context": {"cve_id": cve_id, "dimension": category, "url": url,
                        "source_response_sha256": sha, "locator": locator, **(extra or {})},
            "reasoning_kind": "enrichment", "category": category, "automatic_passed": None})

    evidence_path = Path(DEFAULT_DB)
    with sqlite3.connect(evidence_path.resolve().as_uri() + "?mode=ro", uri=True) as con:
        for cve_index, cve_id in enumerate(cve_ids):
            record = store.get_record(cve_id)
            if not record or (record["item"].get("raw_data") or {}).get("sample_mode"):
                raise ValueError("Unknown or demo CVE: " + cve_id)
            sid = digest("https://nvd.nist.gov/vuln/detail/" + cve_id)[:16]
            snapshot = con.execute("SELECT digest,body FROM source_snapshots WHERE cve_id=? AND source_id=?", (cve_id, sid)).fetchone()
            if not snapshot or hashlib.sha256(snapshot[1]).hexdigest() != snapshot[0]:
                coverage.append({"cve_id": cve_id, "status": "missing_verified_nvd"})
                continue
            raw = json.loads(snapshot[1])
            entries = [row["cve"] for row in raw.get("vulnerabilities", []) if row.get("cve", {}).get("id") == cve_id]
            if len(entries) != 1:
                coverage.append({"cve_id": cve_id, "status": "invalid_nvd_identity"})
                continue
            original = entries[0]
            report = (record["item"].get("raw_data") or {}).get("automatic_assessment") or assess(cve_id)
            url, sha = "https://nvd.nist.gov/vuln/detail/" + cve_id, snapshot[0]
            if report.get("cvss"):
                add("severity", cve_id, report["cvss"], {"original_metrics": original.get("metrics")}, url, sha, "cve.metrics")
            if report.get("affected_ranges"):
                add("affected_versions", cve_id, report["affected_ranges"], {"original_configurations": original.get("configurations")}, url, sha, "cve.configurations")
            for kind in (("epss", "kev") if cve_index % 2 == 0 else ("kev", "epss")):
                frozen, prediction = feeds.get(kind), record.get(kind)
                if not frozen or not isinstance(prediction, dict):
                    continue
                valid_statuses = {"ok", "empty"} if kind == "epss" else {"listed", "not_listed"}
                if prediction.get("status") not in valid_statuses:
                    continue  # An error status has no enrichment fact to score.
                if kind == "epss":
                    if cve_id not in frozen.get("query_cve_ids", []):
                        continue
                    rows = [r for r in frozen["parsed"].get("data", []) if r.get("cve") == cve_id]
                    reference = {"original_provider_rows": rows, "provider_total": frozen["parsed"].get("total"),
                                 "scope": "Compare score and source date; differing dates require explicit review"}
                else:
                    all_rows = frozen["parsed"].get("vulnerabilities", [])
                    if frozen["parsed"].get("count") != len(all_rows):
                        raise ValueError("CISA reference is incomplete")
                    reference = {"original_provider_rows": [r for r in all_rows if r.get("cveID") == cve_id],
                                 "catalog_count": len(all_rows), "dateReleased": frozen["parsed"].get("dateReleased"),
                                 "scope": "Full frozen catalogue checked for the exact CVE ID"}
                add("exploitation", cve_id, {"feed": kind, "observation": prediction}, reference,
                    frozen["url"], frozen["response_sha256"], "provider JSON exact CVE lookup")
            for dimension, field, tag in (("poc", "poc_candidates", "Exploit"), ("remediation", "patch_candidates", "Patch")):
                if report.get(field):
                    add(dimension, cve_id, report[field], {"original_references": original.get("references"),
                        "claim_scope": "Only the original reference tag and URL, not usability or patch effectiveness"},
                        url, sha, "cve.references (" + tag + ")")
            associations = current(record)
            for relation in associations.get("items", []):
                # Store the original chunk, not a generated expected answer.
                add("research", cve_id, {"title": relation["title"], "relation_type": relation["relation_type"],
                    "match_basis": relation["match_basis"], "review_status": relation["review_status"]},
                    {"source_excerpts": [{"text": e["text"], "locator": e.get("locator"), "citation_id": e["citation_id"]} for e in relation["evidence"]],
                     "vulnerability_description": record["item"].get("description"),
                     "scope": "Direct mention or related mechanism; does not prove shared affected versions"},
                    relation["url"], relation["source_response_sha256"], "library source excerpts",
                    extra={"document_id": relation["document_id"], "content_scope": relation["content_scope"]})
            # Keep error/missing feed observations visible as coverage; they
            # cannot become correct facts merely because their dict is nonempty.
            coverage.append({"cve_id": cve_id, "product": record["item"].get("product"),
                "epss_status": (record.get("epss") or {}).get("status"),
                "kev_status": (record.get("kev") or {}).get("status"),
                "paper_relations": associations.get("counts", {}).get("paper", 0),
                "article_relations": associations.get("counts", {}).get("blog", 0)})

    # Spread each dimension across CVEs before taking additional claims from one
    # CVE. The selection never uses a pass/fail judgment or reviewer label.
    for dimension, rows in buckets.items():
        selected, seen, remaining = [], set(), []
        for row in rows:
            cve_id = row["context"]["cve_id"]
            (remaining if cve_id in seen else selected).append(row)
            seen.add(cve_id)
        selected = (selected + remaining)[:quota]
        for row in selected:
            row["id"] = "EF-%03d" % (len(cases) + 1)
            cases.append(row)
    used = {row["context"]["url"] for row in cases}
    manifest = [{"url": url, "response_sha256": sha} for url, sha in sorted(sources.items()) if url in used]
    dataset = {"protocol": "source-bound enrichment claims v1", "cve_ids": cve_ids,
               "quota_per_dimension": quota, "cases": cases}
    return {"title": "真实富化事实小规模核验", "purpose": "development", "report": {
        "schema_version": 1, "kind": "enrichment", "evaluation_unit": "fact_unit",
        "run_at": datetime.now(timezone.utc).isoformat(), "source_commit": commit,
        "model": "source-bound rules and local research retrieval", "mode": "rules",
        "dataset_visibility": "public_development", "dataset_sha256": hashlib.sha256(canonical(dataset).encode()).hexdigest(),
        "dataset_cases": len(cases), "dataset_case_ids": [r["id"] for r in cases],
        "source_manifest": manifest, "cases": cases,
        "protocol": {"sampling": "fixed CVEs; up to quota claims/dimension; one per CVE before repeats; no filtering by correctness",
                     "reference": "original archived source excerpts, not generated gold labels", "coverage": coverage,
                     "feed_note": "EPSS/KEV require a separately frozen provider response before inclusion in accuracy"}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", action="append", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--quota", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider-response", action="append", default=[], type=Path,
                        help="Frozen FIRST/CISA response wrapper, including exact bytes digest")
    args = parser.parse_args()
    import re
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit) or not 1 <= args.quota <= 30:
        parser.error("full lowercase commit SHA and quota 1–30 required")
    ids = list(dict.fromkeys(value.upper() for value in args.cve))
    if len(ids) > 30 or any(not re.fullmatch(r"CVE-\d{4}-\d{4,7}", value) for value in ids):
        parser.error("use at most 30 valid CVE IDs")
    report = capture(ids, args.commit, quota=args.quota, provider_responses=args.provider_response)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"file": str(args.output), "facts": report["report"]["dataset_cases"]}))


if __name__ == "__main__":
    main()
