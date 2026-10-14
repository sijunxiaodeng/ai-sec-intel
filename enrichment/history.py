"""Find older CVEs with the same component in verified local NVD snapshots.

Matching components and weaknesses are investigation leads, not proof of a
variant, a shared root cause, a working exploit or a bypass of an earlier fix.
The catalogue is bounded and built once for a bulk assessment view.
"""
from datetime import datetime, timezone
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from enrichment.documents import MAX_BYTES, digest
from rag.evidence import CVE, DEFAULT_DB

CWE = re.compile(r"CWE-[1-9]\d{0,4}")
NOTICE = "同组件或相同 CWE 仅提供历史调查线索；未证明漏洞同源、补丁绕过、影响版本相同或利用成功。"
MAX_CATALOG_BYTES = 16 * 1024 * 1024


def field_evidence(cve, doc, sha, pointer, value, topic):
    """Bind a JSON field excerpt to its already verified response bytes."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    cve_id = cve["id"]
    sid = digest("https://nvd.nist.gov/vuln/detail/" + cve_id)[:16]
    eid = "FIELD-" + sid + "-" + digest(pointer + ":" + text)[:12]
    return {"cve_id": cve_id, "source_id": sid, "evidence_id": eid,
            "citation_id": cve_id + "/" + eid, "title": cve_id + " · NVD 字段",
            "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            "locator": pointer + "；来自已校验的 NVD JSON 字段",
            "retrieved_at": doc.get("retrieved_at"), "relation_type": "vulnerability_record",
            "text": text, "text_sha256": digest(text), "source_response_sha256": sha,
            "text_kind": "automatic_structured_extract", "topics": [topic]}


def weaknesses(cve):
    """Keep separate providers and languages; do not turn NVD sentinels into CWE."""
    result = []
    for i, row in enumerate(cve.get("weaknesses") or []):
        if not isinstance(row, dict):
            continue
        for j, description in enumerate(row.get("description") or []):
            if not isinstance(description, dict):
                continue
            value = description.get("value")
            if not isinstance(value, str) or not CWE.fullmatch(value):
                continue
            result.append({"cwe_id": value, "provider": row.get("source"),
                           "metric_type": row.get("type"), "language": description.get("lang"),
                           "taxonomy_url": "https://cwe.mitre.org/data/definitions/" + value[4:] + ".html",
                           "pointer": "weaknesses/%d" % i,
                           "description_pointer": "weaknesses/%d/description/%d" % (i, j),
                           "source_value": row})
    return result


def components(cve):
    result = {}

    def walk(node, pointer, complex_logic=False):
        if not isinstance(node, dict) or node.get("negate"):
            return
        complex_logic = complex_logic or node.get("operator") == "AND"
        for i, match in enumerate(node.get("cpeMatch") or []):
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            criteria = match.get("criteria")
            if not isinstance(criteria, str):
                continue
            parts = re.split(r"(?<!\\):", criteria)
            if (len(parts) != 13 or parts[:2] != ["cpe", "2.3"] or parts[2] not in {"a", "o", "h"}
                    or any(not value or value in {"*", "-"} for value in parts[3:5])):
                continue
            key = tuple(value.casefold() for value in parts[2:5])
            result.setdefault(key, []).append({"pointer": pointer + "/cpeMatch/" + str(i),
                                               "value": match, "requires_environment_review": complex_logic})
        for i, child in enumerate(node.get("nodes") or []):
            walk(child, pointer + "/nodes/" + str(i), complex_logic)

    for i, node in enumerate(cve.get("configurations") or []):
        walk(node, "configurations/" + str(i))
    return result


def _published(cve):
    value = cve.get("published")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # NVD 2.0 emits UTC timestamps both with and without the Z suffix.
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        return None


def _verified(cve_id, row):
    if not row:
        return None
    payload, sha, body = row
    try:
        doc = json.loads(payload)
        url = "https://nvd.nist.gov/vuln/detail/" + cve_id
        if (not isinstance(doc, dict) or doc.get("cve_id") != cve_id or doc.get("url") != url
                or doc.get("status") != "ok" or not isinstance(body, bytes) or len(body) > MAX_BYTES
                or hashlib.sha256(body).hexdigest() != sha or doc.get("source_response_sha256") != sha):
            return None
        data = json.loads(body)
        matches = [r["cve"] for r in data.get("vulnerabilities", [])
                   if isinstance(r, dict) and isinstance(r.get("cve"), dict) and r["cve"].get("id") == cve_id]
        if len(matches) != 1:
            return None
        return matches[0], doc, sha
    except (ValueError, TypeError, AttributeError, KeyError):
        return None


def catalogue(db_path=DEFAULT_DB, *, max_candidates=250):
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= 400:
        raise ValueError("历史目录上限必须为 1 到 400")
    result = {"sources": {}, "scope": "仅本地已存档且摘要校验通过的 NVD 记录；目录按 CVE 编号倒序取样，不是全网历史召回",
              "available_cves": 0, "examined_cves": 0, "verified_nvd_snapshots": 0,
              "invalid_snapshots": 0, "limit": max_candidates, "byte_limit": MAX_CATALOG_BYTES,
              "truncated": False}
    path = Path(db_path)
    if not path.is_file():
        return result
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        conn.execute("BEGIN")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"documents", "source_snapshots"} <= tables:
            return result
        result["available_cves"] = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM documents").fetchone()[0]
        ids = [r[0] for r in conn.execute("SELECT DISTINCT cve_id FROM documents ORDER BY cve_id DESC LIMIT ?", (max_candidates,))]
        total_bytes = 0
        for cve_id in ids:
            if not isinstance(cve_id, str) or not CVE.fullmatch(cve_id):
                continue
            sid = digest("https://nvd.nist.gov/vuln/detail/" + cve_id)[:16]
            size = conn.execute("SELECT length(body) FROM source_snapshots WHERE cve_id=? AND source_id=?", (cve_id, sid)).fetchone()
            if size and (size[0] > MAX_BYTES or total_bytes + size[0] > MAX_CATALOG_BYTES):
                result["truncated"] = True
                continue
            row = conn.execute("SELECT d.payload,s.digest,s.body FROM documents d JOIN source_snapshots s "
                               "ON d.cve_id=s.cve_id AND d.source_id=s.source_id WHERE d.cve_id=? AND d.source_id=?", (cve_id, sid)).fetchone()
            result["examined_cves"] += 1
            total_bytes += size[0] if size else 0
            verified = _verified(cve_id, row)
            if verified:
                result["sources"][cve_id] = verified
            elif row:
                result["invalid_snapshots"] += 1
    result["verified_nvd_snapshots"] = len(result["sources"])
    result["truncated"] = result["truncated"] or result["examined_cves"] < result["available_cves"]
    return result


def related(target, doc, sha, catalog, *, top_k=5):
    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 10:
        raise ValueError("历史候选上限必须为 1 到 10")
    result = {"schema_version": 1, "status": "empty", "items": [], "evidence": [],
              "notice": NOTICE, "coverage": {k: v for k, v in catalog.items() if k != "sources"},
              "independent_precision": None, "independent_recall": None}
    if catalog.get("status") == "error":
        result.update(status="error", detail="本地历史目录暂不可用；没有历史关联结果。")
        return result
    published = _published(target)
    target_components = components(target)
    if not published or not target_components:
        result.update(status="insufficient_context", detail="需要目标的有效 NVD 发布时间与具体 CPE 组件，才能判断历史关系。")
        return result
    target_cwes = {r["cwe_id"]: r for r in weaknesses(target)}
    candidates = []
    for cve_id, (candidate, candidate_doc, candidate_sha) in catalog["sources"].items():
        candidate_published = _published(candidate)
        candidate_components = components(candidate)
        shared = set(target_components) & set(candidate_components)
        if cve_id == target["id"] or not candidate_published or candidate_published >= published or not shared:
            continue
        candidate_cwes = {r["cwe_id"]: r for r in weaknesses(candidate)}
        shared_cwes = sorted(set(target_cwes) & set(candidate_cwes))
        evidence = []
        basis = []

        def bind(cve, metadata, source_sha, pointer, value):
            citation = field_evidence(cve, metadata, source_sha, pointer, value, "historical_relation")
            evidence.append(citation)
            return citation["citation_id"]

        for component in sorted(shared):
            a, b = target_components[component][0], candidate_components[component][0]
            ids = [bind(target, doc, sha, a["pointer"], a["value"]),
                   bind(candidate, candidate_doc, candidate_sha, b["pointer"], b["value"])]
            basis.append({"kind": "same_component", "part": component[0], "vendor": component[1],
                          "product": component[2], "evidence_ids": ids,
                          "requires_environment_review": a["requires_environment_review"] or b["requires_environment_review"]})
        for cwe in shared_cwes:
            a, b = target_cwes[cwe], candidate_cwes[cwe]
            basis.append({"kind": "same_weakness", "cwe_id": cwe, "evidence_ids": [
                bind(target, doc, sha, a["pointer"], a["source_value"]),
                bind(candidate, candidate_doc, candidate_sha, b["pointer"], b["source_value"])]})
        time_ids = [bind(target, doc, sha, "published", target["published"]),
                    bind(candidate, candidate_doc, candidate_sha, "published", candidate["published"])]
        basis.append({"kind": "published_before_target", "evidence_ids": time_ids})
        item = {"cve_id": cve_id, "url": candidate_doc["url"], "published_at": candidate["published"],
                "retrieved_at": candidate_doc.get("retrieved_at"), "source_response_sha256": candidate_sha,
                "association": "same_component_and_weakness" if shared_cwes else "same_component",
                "review_status": "not_reviewed", "match_basis": basis,
                "evidence_ids": list(dict.fromkeys(r["citation_id"] for r in evidence)), "notice": NOTICE}
        candidates.append((bool(shared_cwes), candidate_published, cve_id, item, evidence))
    candidates.sort(key=lambda r: r[:3], reverse=True)
    for _, _, _, item, evidence in candidates[:top_k]:
        result["items"].append(item)
        result["evidence"].extend(evidence)
    result["evidence"] = list({r["citation_id"]: r for r in result["evidence"]}.values())
    result["status"] = "candidates" if result["items"] else "empty"
    result["detail"] = "相同 CWE 优先，再按来源发布时间排序；无候选不代表不存在历史漏洞。"
    return result
