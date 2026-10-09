import re
from agents.citation_guard import answer_issues
from agents.question_scope import positive_question, topics as question_topics

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SCORE = re.compile(r"CVSS(?!:[234]\.[01]/)(?:\s*v?[234]\.[01])?\s*(?:基础分(?:为|是)?|评分(?:为|是)?|分数(?:为|是)?|为|是|:|：)\s*([0-9]+(?:\.[0-9]+)?)", re.I)
CITATION = re.compile(r"\[([^\[\]\n]+)\]")


def _condition_present(plain, row):
    # 接受字段表述、评分向量代码，以及常见中文同义表达；仍不是语义审核。
    label, text = re.escape(row["label"]), re.escape(row["text"])
    if re.search(label + r"\s*[:：为是]?\s*" + text, plain):
        return True
    if re.search(r"\b" + row["metric"].lower() + ":" + row["value"].lower() + r"\b", plain):
        return True
    aliases = {
        ("AV", "N"): r"网络(?:攻击|可达|访问)|(?:通过|经由)网络|远程攻击",
        ("AC", "L"): r"低.{0,4}复杂度|复杂度.{0,4}低",
        ("AC", "H"): r"高.{0,4}复杂度|复杂度.{0,4}高",
        ("PR", "N"): r"(?:无需|不需要|不要求).{0,4}权限",
        ("PR", "L"): r"低.{0,4}权限",
        ("PR", "H"): r"高.{0,4}权限",
        ("UI", "N"): r"(?:无需|不需要|不要求).{0,4}用户交互",
        ("UI", "R"): r"(?<!不)(?:需要|要求).{0,4}用户交互",
    }
    pattern = aliases.get((row["metric"], row["value"]))
    return bool(pattern and re.search(pattern, plain))


def required_fields(answer, evidence, question):
    """校验可直接核对的必需字段；不能代替完整语义评审。"""
    plain = CITATION.sub("", answer or "").lower()
    q = positive_question(question).lower()
    issues = []
    for record in evidence:
        from enrichment.guidance import formatted_facts
        guidance = record.get("item", {}).get("raw_data", {}).get("related_guidance") or {}
        topics = question_topics(question)
        if "conditions" in topics and not any(w in q for w in ("利用条件", "攻击条件", "暴露", "部署", "成因", "原理")):
            topics.discard("conditions")
        facts = formatted_facts(guidance, topics)
        for fact in facts:
            if fact["chunks"][0].get("structured_value") and fact["text"].lower() not in plain:
                issues.append("遗漏关联来源的版本字段或研究方升级建议")
        for topic in topics & {"conditions", "remediation"}:
            candidates = [f for f in facts if f["chunks"][0]["guidance_topic"] == topic]
            if candidates and not any(f["text"].lower() in plain for f in candidates):
                issues.append("遗漏关联来源的%s信息" % ("条件" if topic == "conditions" else "修复建议"))
        report = record.get("item", {}).get("raw_data", {}).get("automatic_assessment") or {}
        metric = report.get("cvss")
        if not metric:
            continue
        if any(w in q for w in ("cvss", "评分", "分数", "严重等级", "向量")):
            if str(metric["score"]) not in plain or metric["version"] not in plain:
                issues.append("没有完整保留来源评分和 CVSS 版本")
            provider = (metric.get("source") or "").lower()
            provider_requested = any(w in q for w in ("提供者", "评分来源", "评分记录来源"))
            if provider_requested and provider and provider not in plain:
                if not (provider == "nvd@nist.gov" and "nvd" in plain):
                    issues.append("评分提供者未与来源字段一致")
            if provider and provider != "nvd@nist.gov" and re.search(r"(?:评分提供者|评分来源|由).{0,10}nvd|nvd.{0,8}(?:自评|评分|打分)", plain):
                issues.append("将 NVD 收录的其他来源评分错误归属于 NVD")
        if any(w in q for w in ("受影响版本", "版本范围", "影响哪个版本", "影响哪些版本")):
            for row in report.get("affected_ranges", []):
                values = [row[k] for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if row.get(k)]
                if row.get("version") not in (None, "*", "-"):
                    values.append(row["version"])
                values += [v for v in row.get("qualifiers", {}).values() if v != "-"]
                if any(v.lower() not in plain for v in values):
                    issues.append("版本范围或预发布限定存在遗漏")
                    break
                boundaries = {"versionStartIncluding": (r">=|大于等于|不低于|至少", r"及以上"),
                              "versionStartExcluding": (r">(?![=])|大于|高于|晚于", r"之后"),
                              "versionEndIncluding": (r"<=|小于等于|不高于", r"及以下"),
                              "versionEndExcluding": (r"<(?![=])|小于|低于|早于", r"之前|以前")}
                for key, (before, after) in boundaries.items():
                    if row.get(key):
                        version = re.escape(row[key].lower())
                        if not re.search(r"(?:%s)\s*v?%s|%s\s*(?:%s)" % (before, version, version, after), plain):
                            issues.append("没有明确保留版本的包含/排除边界")
                if "-" in row.get("qualifiers", {}).values() and not any(w in plain for w in ("不适用", "正式", "非预发布")):
                    issues.append("没有保留 CPE 中不适用的版本限定")
        if any(w in q for w in ("poc", "复现", "验证代码", "利用代码")) and report.get("poc_candidates"):
            if not re.search(r"(?:未|没有|尚未).{0,8}(?:运行|验证|复现)|(?:不能|无法).{0,8}(?:确认|认定).{0,8}(?:验证|可用)", plain):
                issues.append("没有保留 PoC 尚未由本项目验证的边界")
        if any(w in q for w in ("修复", "缓解", "升级", "补丁")) and report.get("fix_records"):
            if not any(row["url"].lower() in plain or (re.search(r"/pull/(\d+)", row["url"]) and re.search(r"/pull/(\d+)", row["url"]).group(1) in plain) for row in report["fix_records"]):
                issues.append("遗漏了来源中的关联修复记录")
        broad_conditions = any(w in q for w in ("利用条件", "攻击条件"))
        wanted = {"AV", "AC", "AT", "PR", "UI"} if broad_conditions else set()
        if any(w in q for w in ("所需权限", "需要权限")):
            wanted.add("PR")
        if "用户交互" in q:
            wanted.add("UI")
        conditions = [row for row in report.get("attack_conditions", []) if row["metric"] in wanted]
        for row in conditions:
            if not _condition_present(plain, row):
                issues.append("没有完整保留评分向量中的%s" % row["label"])
        if conditions and not any(w in plain for w in ("cvss", "评分向量")):
            issues.append("没有说明这些条件来自评分向量解释")
    return list(dict.fromkeys(issues))


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
    field_issues = answer_issues(answer or "", evidence or [])
    passed = not missing and not bad_scores and not invalid and not lacks_citations and not bad_poc and not wrong_owner and not field_issues
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
    notes.extend(field_issues)
    if passed:
        notes.append("已检查引用标识、编号、显式评分与已识别结构化字段范围；未知字段和自由文本的完整语义仍需复核。")
    return {
        "passed": passed,
        "notes": notes,
        "steps": [{
            "role": "核对",
            "action": "检查引用字段、编号与分数",
            "detail": notes[0] if passed else "；".join(notes),
        }],
    }
