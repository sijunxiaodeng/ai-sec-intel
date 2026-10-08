import re

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SCORE = re.compile(r"CVSS(?!:[234]\.[01]/)(?:\s*v?[234]\.[01])?\s*(?:基础分(?:为|是)?|评分(?:为|是)?|分数(?:为|是)?|为|是|:|：)\s*([0-9]+(?:\.[0-9]+)?)", re.I)
CITATION = re.compile(r"\[([^\[\]\n]+)\]")


def run(answer, evidence):
    known = []
    scores = []
    owner_scores = {}
    citation_owners = {}
    allowed = set()
    for index, record in enumerate(evidence or [], 1):
        allowed.add(str(index))
        item = record.get("item") or {}
        cve_id = (item.get("cve_id") or "").upper()
        if cve_id:
            known.append(cve_id)
            owner_scores[cve_id] = []
            citation_owners[str(index)] = cve_id
        cvss = record.get("cvss") or {}
        if cvss.get("score") is not None:
            scores.append(float(cvss["score"]))
            owner_scores.setdefault(cve_id, []).append(float(cvss["score"]))
        report = item.get("raw_data", {}).get("automatic_assessment") or {}
        for metric in report.get("cvss_candidates", []):
            if metric.get("score") is not None:
                scores.append(float(metric["score"]))
                owner_scores.setdefault(cve_id, []).append(float(metric["score"]))
        for chunk in record.get("evidence_chunks") or []:
            allowed.add(chunk["citation_id"])
            citation_owners[chunk["citation_id"]] = cve_id
            metric = (chunk.get("structured_value") or {}).get("cvssData") or {}
            if metric.get("baseScore") is not None:
                scores.append(float(metric["baseScore"]))
                owner_scores.setdefault(cve_id, []).append(float(metric["baseScore"]))
    missing = []
    for found in CVE.findall(answer or ""):
        if found.upper() not in known:
            missing.append(found.upper())
    bad_scores = []
    for found in SCORE.findall(answer or ""):
        value = float(found)
        if not any(abs(value - score) < 0.05 for score in scores):
            bad_scores.append(found)
    # 摘录原文可能有 Markdown 链接或 JSON 数组，它们不是回答的引用标识。
    citation_text = answer or ""
    for record in evidence or []:
        for chunk in record.get("evidence_chunks") or []:
            if chunk.get("text"):
                citation_text = citation_text.replace(chunk["text"], "")
    citations = CITATION.findall(citation_text)
    wrong_owner = []
    for clause in re.split(r"[。\n]", citation_text):
        owners = {citation_owners[c] for c in CITATION.findall(clause) if c in citation_owners}
        if len(owners) == 1:
            owner = next(iter(owners))
            for score in SCORE.findall(clause):
                if not any(abs(float(score) - valid) < .05 for valid in owner_scores.get(owner, [])):
                    wrong_owner.append(owner + "：" + score)
    invalid = [citation for citation in citations if citation not in allowed]
    lacks_citations = bool(evidence) and not citations
    verified_poc = any(row.get("validation") == "verified" for record in evidence or [] for row in record.get("poc") or [])
    claims_verified = False
    for clause in re.split(r"[。\n]", answer or ""):
        if re.search(r"(?:poc|利用代码|验证代码).{0,12}(?:已验证|已复现|验证通过)", clause, re.I):
            if not any(word in clause for word in ("未", "没有", "不能", "不代表", "无法")):
                claims_verified = True
    bad_poc = claims_verified and not verified_poc
    passed = not missing and not bad_scores and not invalid and not lacks_citations and not bad_poc and not wrong_owner
    notes = []
    if missing:
        notes.append("回答里出现了证据中没有的编号：" + "、".join(missing))
    if bad_scores:
        notes.append("回答里的分数对不上证据：" + "、".join(bad_scores))
    if invalid:
        notes.append("引用了不存在的证据标识：" + "、".join(invalid))
    if lacks_citations:
        notes.append("回答没有附上证据引用")
    if bad_poc:
        notes.append("证据没有本项目已验证可用的 PoC 状态")
    if wrong_owner:
        notes.append("显式评分不属于该句引用的漏洞：" + "、".join(wrong_owner))
    if passed:
        notes.append("已检查引用标识、编号与显式评分；尚未验证每个结论与引用原文的语义一致性。")
    return {
        "passed": passed,
        "notes": notes,
        "steps": [{
            "role": "核对",
            "action": "检查引用、编号与分数",
            "detail": "通过" if passed else "；".join(notes),
        }],
    }
