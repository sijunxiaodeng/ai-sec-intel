"""从已存档 NVD 响应形成结构化报告；读取时校验来源与证据，不联网。"""

import copy
import hashlib
import json
import math
from pathlib import Path
import re

from enrichment.documents import digest
from rag.evidence import DEFAULT_DB, CVE, _connection

FIRST = "https://www.first.org/cvss/v3.1/specification-document"
FIRST4 = "https://www.first.org/cvss/v4.0/specification-document"
FIRST30 = "https://www.first.org/cvss/v3.0/specification-document"
SEVERITY = {"NONE": "无", "LOW": "低", "MEDIUM": "中", "HIGH": "高", "CRITICAL": "严重"}
VECTOR_LABELS = {
    "AV": ("攻击途径", {"N": "网络", "A": "相邻网络", "L": "本地", "P": "物理接触"}),
    "AC": ("攻击复杂度", {"L": "低", "H": "高"}),
    "AT": ("附加攻击要求", {"N": "无", "P": "存在"}),
    "PR": ("所需权限", {"N": "无", "L": "低", "H": "高"}),
    "UI": ("用户交互", {"N": "不需要", "R": "需要", "P": "被动交互", "A": "主动交互"}),
    "S": ("影响范围变化", {"U": "未变化", "C": "变化"}),
}
for key, name in (("C", "保密性"), ("I", "完整性"), ("A", "可用性"),
                  ("VC", "易受攻击系统保密性"), ("VI", "易受攻击系统完整性"), ("VA", "易受攻击系统可用性"),
                  ("SC", "后续系统保密性"), ("SI", "后续系统完整性"), ("SA", "后续系统可用性")):
    VECTOR_LABELS[key] = (name + "影响", {"N": "无", "L": "低", "H": "高"})


def _metric(metric, key, pointer):
    data = metric.get("cvssData") or {}
    score = data.get("baseScore")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
        return None
    version = data.get("version") or {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}.get(key)
    severity = data.get("baseSeverity") or metric.get("baseSeverity")
    return {"score": score, "severity": severity, "version": version,
            "vector": data.get("vectorString"), "source": metric.get("source"),
            "metric_type": metric.get("type"), "pointer": pointer,
            "cvssData": data}


def _walk_config(node, pointer, complex_logic=False):
    complex_logic = complex_logic or node.get("operator") == "AND" or bool(node.get("negate"))
    for i, match in enumerate(node.get("cpeMatch") or []):
        if match.get("vulnerable") is not True:
            continue
        criteria = match.get("criteria") or ""
        parts = re.split(r"(?<!\\):", criteria)
        if len(parts) < 6 or parts[:2] != ["cpe", "2.3"]:
            continue
        fields = {k: match[k] for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if match.get(k)}
        terms = ["版本 = " + parts[5]] if parts[5] not in ("*", "-") else []
        for key, symbol in (("versionStartIncluding", ">="), ("versionStartExcluding", ">"), ("versionEndIncluding", "<="), ("versionEndExcluding", "<")):
            if key in fields:
                terms.append("版本 " + symbol + " " + fields[key])
        qualifiers = {}
        for index, key, label in ((6, "update", "更新/预发布标识"), (7, "edition", "版本类别"),
                                  (8, "language", "语言"), (9, "sw_edition", "软件类别"),
                                  (10, "target_sw", "运行平台"), (11, "target_hw", "硬件平台"), (12, "other", "其他限定")):
            if index < len(parts) and parts[index] != "*":
                qualifiers[key] = parts[index]
                terms.append(label + " = " + ("不适用" if parts[index] == "-" else parts[index]))
        yield dict(fields, criteria=criteria, vendor=parts[3], product=parts[4],
                   version=parts[5], qualifiers=qualifiers, display=parts[4] + "：" + ("，".join(terms) or "版本范围未单独限定，见配置原文"),
                   requires_environment_review=complex_logic,
                   pointer=pointer + "/cpeMatch/" + str(i))
    for i, child in enumerate(node.get("nodes") or []):
        yield from _walk_config(child, pointer + "/nodes/" + str(i), complex_logic)


def vector_explanations(metric):
    version = metric.get("version")
    vector = metric.get("vector") or ""
    if version not in ("3.0", "3.1", "4.0") or not vector.startswith("CVSS:" + version + "/"):
        return []
    allowed = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"} if version != "4.0" else {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
    result = []
    for component in vector.split("/")[1:]:
        key, _, value = component.partition(":")
        if key == "UI" and value not in ({"N", "P", "A"} if version == "4.0" else {"N", "R"}):
            continue
        if key in allowed and key in VECTOR_LABELS and value in VECTOR_LABELS[key][1]:
            label, mapping = VECTOR_LABELS[key]
            result.append({"metric": key, "value": value, "label": label, "text": mapping[value]})
    return result


def _empty(cve_id, detail):
    return {"schema_version": 1, "cve_id": cve_id, "status": "insufficient_evidence",
            "detail": detail, "cvss": None, "cvss_candidates": [], "affected_ranges": [],
            "attack_conditions": [], "technical_impact": [], "poc_candidates": [], "fix_records": [],
            "warnings": [], "evidence": [], "asset_impact": {"status": "unknown", "reason": "缺少资产清单、实际版本、部署权限和网络暴露信息"}}


def assess(cve_id, db_path=DEFAULT_DB):
    cve_id = cve_id.upper()
    report = _empty(cve_id, "请先抓取该编号的 NVD 关联资料")
    if not CVE.fullmatch(cve_id) or not Path(db_path).exists():
        return report
    source_url = "https://nvd.nist.gov/vuln/detail/" + cve_id
    sid = digest(source_url)[:16]
    with _connection(db_path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"documents", "source_snapshots", "evidence", "document_attempts"} <= tables:
            return report
        row = conn.execute("SELECT d.payload, s.digest, s.body FROM documents d JOIN source_snapshots s ON d.cve_id=s.cve_id AND d.source_id=s.source_id WHERE d.cve_id=? AND d.source_id=?", (cve_id, sid)).fetchone()
        if not row:
            return report
        documents = [json.loads(payload) for (payload,) in conn.execute("SELECT payload FROM documents WHERE cve_id=?", (cve_id,))]
        attempts = {source: json.loads(payload) for source, payload in conn.execute("SELECT source_id, payload FROM document_attempts WHERE cve_id=?", (cve_id,))}
        chunks = [json.loads(payload) for (payload,) in conn.execute("SELECT payload FROM evidence WHERE cve_id=?", (cve_id,))]
        snapshots = {source: (sha, body) for source, sha, body in conn.execute("SELECT source_id, digest, body FROM source_snapshots WHERE cve_id=?", (cve_id,))}
    doc, sha, body = json.loads(row[0]), row[1], row[2]
    if sha != hashlib.sha256(body).hexdigest() or sha != doc.get("source_response_sha256"):
        report["status"], report["detail"] = "invalid_evidence", "NVD 存档摘要不一致，需重新获取资料"
        return report
    try:
        matches = [v["cve"] for v in json.loads(body).get("vulnerabilities", []) if v.get("cve", {}).get("id") == cve_id]
        if len(matches) != 1:
            raise ValueError("编号不一致")
        cve = matches[0]
    except (ValueError, KeyError, TypeError):
        report["status"], report["detail"] = "invalid_evidence", "NVD 存档格式或编号不一致"
        return report
    nvd_chunks = [chunk for chunk in chunks if chunk.get("source_id") == sid and
                  chunk.get("source_response_sha256") == sha and
                  chunk.get("text_sha256") == digest(chunk.get("text", ""))]

    def cite(pointer, source_chunks=nvd_chunks):
        field = pointer.split("/cpeMatch/")[0].split("/nodes/")[0] if pointer.startswith("configurations/") else pointer
        found = [r for r in source_chunks if r.get("locator", "").startswith(field + "；")]
        for r in found:
            row = dict(r, citation_id=cve_id + "/" + r["evidence_id"])
            if not any(e["citation_id"] == row["citation_id"] for e in report["evidence"]):
                report["evidence"].append(row)
        return [cve_id + "/" + r["evidence_id"] for r in found]

    metrics = []
    for key, values in (cve.get("metrics") or {}).items():
        for i, metric in enumerate(values):
            result = _metric(metric, key, "metrics/%s/%d" % (key, i))
            if result:
                result["evidence_ids"] = cite(result["pointer"])
                result["source_url"] = source_url
                if result["evidence_ids"]:
                    metrics.append(result)
    order = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
    metrics.sort(key=lambda r: (order.get(r["version"], 4), 0 if r["metric_type"] == "Primary" else 1, r.get("source") or ""))
    report["cvss_candidates"] = metrics
    report["cvss"] = metrics[0] if metrics else None
    for i, block in enumerate(cve.get("configurations") or []):
        for match in _walk_config(block, "configurations/" + str(i)):
            match["evidence_ids"] = cite(match["pointer"])
            if match["evidence_ids"]:
                report["affected_ranges"].append(match)
    explanations = vector_explanations(metrics[0]) if metrics else []
    for explanation in explanations:
        explanation["evidence_ids"] = metrics[0]["evidence_ids"]
        destination = "attack_conditions" if explanation["metric"] in ("AV", "AC", "AT", "PR", "UI", "S") else "technical_impact"
        report[destination].append(explanation)
    report["source"] = {"url": source_url, "retrieved_at": doc["retrieved_at"], "source_last_modified": cve.get("lastModified"), "sha256": sha,
                        "latest_fetch_status": attempts.get(sid, {}).get("status", "unknown")}
    if report["source"]["latest_fetch_status"] == "error":
        report["warnings"].append("最近一次 NVD 获取失败，报告沿用标明日期的上次成功快照")
    if any(len({m["score"] for m in metrics if m["version"] == v}) > 1 for v in {m["version"] for m in metrics}):
        report["warnings"].append("同一 CVSS 版本存在不同评分，已分别保留来源；没有取平均分")
    if any(m["requires_environment_review"] for m in report["affected_ranges"]):
        report["warnings"].append("配置包含 AND 或否定条件，组件版本范围不能直接当作资产匹配结论")
    for ref_index, ref in enumerate(cve.get("references") or []):
        if "Exploit" not in ref.get("tags", []) or not ref.get("url", "").startswith("https://"):
            continue
        if any(p["url"] == ref["url"] for p in report["poc_candidates"]):
            continue
        # 此标签来自原始 NVD JSON，不要求候选网页抓取成功，更不代表已复现。
        excerpt = json.dumps(ref, ensure_ascii=False)
        evidence_id = "FIELD-" + sid + "-" + digest("references/%d:" % ref_index + excerpt)[:12]
        citation_id = cve_id + "/" + evidence_id
        report["evidence"].append({"cve_id": cve_id, "source_id": sid, "evidence_id": evidence_id,
                                   "citation_id": citation_id, "title": cve_id + " · NVD 参考标签",
                                   "url": source_url, "locator": "references/%d；来自已校验的 NVD JSON 字段" % ref_index,
                                   "retrieved_at": doc["retrieved_at"], "relation_type": "vulnerability_record",
                                   "text": excerpt, "text_sha256": digest(excerpt), "source_response_sha256": sha,
                                   "text_kind": "automatic_structured_extract", "topics": ["poc"]})
        report["poc_candidates"].append({"url": ref["url"], "status": "candidate_reference", "validation": "not_run", "source_url": source_url, "evidence_ids": [citation_id]})
    for related in documents:
        if related.get("relation_type") != "fix_record":
            continue
        snapshot = snapshots.get(related["source_id"])
        if not snapshot or snapshot[0] != related.get("source_response_sha256") or hashlib.sha256(snapshot[1]).hexdigest() != snapshot[0]:
            report["warnings"].append("一条修复来源存档校验失败，已排除该来源")
            continue
        related_chunks = [r for r in chunks if r.get("source_id") == related["source_id"] and r.get("source_response_sha256") == snapshot[0] and r.get("text_sha256") == digest(r.get("text", ""))]
        ids = []
        for r in related_chunks:
            ids += cite(r["locator"].split("；")[0], related_chunks)
        if ids:
            report["fix_records"].append({"title": related["title"], "url": related["url"], "evidence_ids": list(dict.fromkeys(ids)),
                                          "validation": "not_tested", "fixed_version": None,
                                          "latest_fetch_status": attempts.get(related["source_id"], {}).get("status", "unknown")})
            if attempts.get(related["source_id"], {}).get("status") == "error":
                report["warnings"].append("修复来源最近获取失败，引用保留上次成功获取时间")
    report["status"] = "ok" if metrics and report["affected_ranges"] else "partial"
    report["detail"] = "来源字段自动提取；影响说明依据 CVSS 向量，不是对具体部署的漏洞验证"
    standards = {"4.0": FIRST4, "3.1": FIRST, "3.0": FIRST30}
    report["interpretation_standard"] = standards.get(metrics[0]["version"]) if metrics and explanations else None
    report["warnings"].append("受影响范围的排除上界不自动等于厂商确认的修复版本")
    return report


def enrich_view(records, db_path=DEFAULT_DB):
    """扩展现有 raw_data；不写回或覆盖主监测库的历史卡片。"""
    result = copy.deepcopy(records)
    for record in result:
        report = assess(record["item"]["cve_id"], db_path)
        if report["status"] in ("ok", "partial"):
            raw = record["item"].setdefault("raw_data", {})
            raw["automatic_assessment"] = report
            if report["cvss"]:
                if record.get("cvss") and record["cvss"].get("score") != report["cvss"]["score"]:
                    report["warnings"].append("当前自动评分与监测卡片原有分数不同；报告保留源字段，原卡片未改写")
                record["cvss"] = report["cvss"]
            if report["affected_ranges"]:
                record["item"]["affected"] = [r["display"] for r in report["affected_ranges"]]
            known = {p["url"] for p in record.get("poc") or []}
            record["poc"] = list(record.get("poc") or []) + [p for p in report["poc_candidates"] if p["url"] not in known]
    return result
