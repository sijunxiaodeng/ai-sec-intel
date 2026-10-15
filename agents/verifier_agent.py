import re
from agents.citation_guard import answer_issues, cvss_assertions, matching_cvss_metrics
from agents.question_scope import positive_question, topics as question_topics

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SCORE = re.compile(r"CVSS(?!:[234]\.[01]/)(?:\s*v?[234]\.[01])?\s*(?:基础分(?:为|是)?|评分(?:为|是)?|分数(?:为|是)?|为|是|:|：)\s*([0-9]+(?:\.[0-9]+)?)", re.I)
CITATION = re.compile(r"\[([^\[\]\n]+)\]")
POC_SUBJECT = r"(?:(?<![A-Za-z0-9_])poc(?![A-Za-z0-9_])|proof.of.concept|exploit code|利用代码|验证代码)"
POC_SUCCESS = r"(?:已(?:经)?(?:成功)?(?:验证|复现)(?:通过|成功|可用)?|验证(?:已)?通过|复现(?:已)?成功|验证成功|(?:already\s+|successfully\s+)?(?<![A-Za-z])(?:verified|validated|reproduced|runtime_verified)(?![A-Za-z]))"
POC_FORWARD = re.compile(POC_SUBJECT + r"[^。！？；;\n]{0,80}?(?P<action>" + POC_SUCCESS + ")", re.I)
POC_REVERSE = re.compile(r"(?P<action>" + POC_SUCCESS + r")[^。！？；;，,\n]{0,30}?" + POC_SUBJECT, re.I)
POC_CVE = re.compile(r"(?<![A-Za-z0-9_-])CVE-\d{4}-\d{4,7}(?![A-Za-z0-9_-])", re.I)


def _poc_successes(text):
    # URLs, citations and unrelated negative clauses are not verification claims.
    plain = CITATION.sub("", re.sub(r"https?://[^\s。；，<>]+", "", text))
    result, seen = [], set()
    for pattern in (POC_FORWARD, POC_REVERSE):
        for match in pattern.finditer(plain):
            identity = match.span("action")
            if identity in seen:
                continue
            seen.add(identity)
            before = plain[max(0, identity[0] - 40):identity[0]]
            before = re.split(r"[。！？；;，,\n]|但是|但|然而|不过|\bbut\b|\bhowever\b", before, flags=re.I)[-1]
            before = re.sub(POC_SUBJECT, "", before, flags=re.I)
            negative_tail = (r"(?:尚未|并未|未能|未|没有|不能|无法|不代表|不等于|不证明|不可|并非|没有证据)"
                             r"(?:\s|被|确认|认定|证明|断言|认为|标为|声称|据此|成功|经过|运行|状态为){0,12}$|"
                             r"\b(?:not|never|cannot|no evidence|unable to|isn't|hasn't|wasn't)\b"
                             r"(?:\s|yet|been|be|being|already|successfully){0,12}$")
            after = plain[identity[1]:identity[1] + 24]
            if re.search(negative_tail, before, re.I) or re.match(r"(?:可用|成功|通过)?的说法(?:不成立|不正确|未经证实|没有依据)", after):
                continue
            result.append(match.group())
    return result


def poc_claim_issues(answer, evidence, citation_owners):
    """A mutable candidate flag/reference is never a trusted project experiment.

    This project has no authenticated runtime-validation ledger. Consequently
    even well-scoped positive project claims must fail closed until one exists.
    Clearly attributed source quotes remain source claims, subject to their own
    exact snippet and CVE/citation binding; they do not enable project success.
    """
    records = {(r.get("item", {}).get("cve_id") or "").upper(): r for r in evidence or []}
    chunks = {c["citation_id"]: c for r in evidence or [] for c in r.get("evidence_chunks", [])}
    issues = []
    # Keep trailing citations after a full stop attached to their statement.
    next_subject = r"(?:CVE-|PoC|本项目|我们的|该项目|来源|研究方|厂商|作者|第三方)"
    clauses = re.split(r"[；;\n]|[，,](?=\s*" + next_subject + r")|(?<=[。！？!?])(?=\s*" + next_subject + r")", answer or "", flags=re.I)
    for clause in clauses:
        successes = _poc_successes(clause)
        if not successes:
            continue
        declared = {v.upper() for v in POC_CVE.findall(CITATION.sub("", clause))}
        cited = [c for c in CITATION.findall(clause) if c in chunks]
        owners = {citation_owners[c] for c in cited if c in citation_owners}
        target = next(iter(declared)) if len(declared) == 1 else ""
        if not target or owners != {target}:
            issues.append("PoC 肯定复现声明须明确单一 CVE，并与该声明的具体引用所属漏洞一致")
            continue
        source_claim = bool(re.search(r"(?:来源(?:原文|报告)?|研究方|厂商|作者|第三方)(?:声称|称|表示|报告|写道)|(?:来源|报告)原文", clause))
        own_success = bool(re.search(r"(?:本项目|本系统|我们)[^。！？；;，,\n]{0,200}" + POC_SUCCESS, clause, re.I))
        if source_claim and not own_success:
            # Only source wording actually present in the cited snippet may pass.
            if all(any(value in _poc_successes(chunk.get("text", ""))
                       for c in cited for chunk in [chunks[c]]) for value in successes):
                continue
            issues.append("来源声称 PoC 已验证的表述未绑定该 CVE 引用中的实际原文")
            continue
        candidate_urls = {r.get("url") for r in records.get(target, {}).get("poc", []) if r.get("url")}
        claimed_urls = set(re.findall(r"https?://[^\s。；，<>\[\]]+", clause))
        if not candidate_urls & claimed_urls:
            issues.append("PoC 肯定复现声明未明确绑定当前漏洞的具体候选代码")
        issues.append("证据没有可信的本项目 PoC 实验台账；verified/runtime_verified 字段或来源 Exploit 标签不能证明本项目已复现")
    return list(dict.fromkeys(issues))


def _condition_present(plain, row):
    # 接受字段表述、评分向量代码，以及常见中文同义表达；仍不是语义审核。
    label, text = re.escape(row["label"]), re.escape(row["text"])
    if re.search(label + r"\s*[:：为是]?\s*" + text, plain):
        return True
    if row.get("metric") and row.get("value") and re.search(r"\b" + row["metric"].lower() + ":" + row["value"].lower() + r"\b", plain):
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
    pattern = aliases.get((row.get("metric"), row.get("value")))
    return bool(pattern and re.search(pattern, plain))


def _limited_impact_fields(question):
    """Only an explicit list of impact components narrows completeness checks.

    'Only explain technical impact' limits the topic, not the C/I/A components.
    Do not infer a narrower scope from an arbitrary occurrence of 只 or 仅.
    """
    component = r"(?:保密性|完整性|可用性)(?:影响)?"
    selection = re.compile(r"(?:请)?(?:只|仅)(?:说明|讨论|解释|列出|介绍|比较|关注|分析|回答|看|说)?\s*"
                           r"(?P<fields>" + component + r"(?:\s*[、和与及]\s*" + component + r")*)"
                           r"(?:即可|就行)?")
    for clause in re.split(r"[，,。；;？?！!\n]", question):
        match = selection.fullmatch(clause.strip())
        if match:
            return set(re.findall(r"保密性|完整性|可用性", match["fields"]))
    return set()


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
        # A missing score cannot suppress unrelated source fields such as patch
        # references, affected versions, or project PoC-validation boundaries.
        candidates = ([metric] if metric else []) + (report.get("cvss_candidates") or [])
        scoring_rows = [{"source": row.get("source"), "type": row.get("metric_type"),
                         "cvssData": {"version": row.get("version"), "baseScore": row.get("score"),
                                      "baseSeverity": row.get("severity"), "vectorString": row.get("vector")}}
                        for row in candidates]
        explicit_profiles = []
        for line in plain.splitlines():
            facts = cvss_assertions(line)
            if facts["vectors"] or (facts["providers"] and facts["components"]):
                matches = matching_cvss_metrics(line, scoring_rows)
                if matches and all(row == matches[0] for row in matches):
                    explicit_profiles.append(matches[0])
        if metric and any(w in q for w in ("cvss", "评分", "分数", "严重等级", "向量")):
            matching = [(line, cvss_assertions(line), matches) for line in plain.splitlines()
                        if (facts := cvss_assertions(line))["scores"] and facts["versions"]
                        and (matches := matching_cvss_metrics(line, scoring_rows))]
            if not matching:
                issues.append("没有完整保留来源评分和 CVSS 版本")
            provider_requested = any(w in q for w in ("提供者", "评分来源", "评分记录来源"))
            if provider_requested and not any(facts["providers"] for _, facts, _ in matching):
                issues.append("评分提供者未与来源字段一致")
            if "严重等级" in q and not any(facts["severity"] or "severity" in facts["missing"] for _, facts, _ in matching):
                issues.append("未保留来源中的严重等级")
            if "向量" in q and not any(facts["vectors"] or "vectors" in facts["missing"] for _, facts, _ in matching):
                issues.append("未保留来源中的完整 CVSS 向量")
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
        if any(w in q for w in ("修复", "缓解", "升级", "补丁")) and report.get("patch_candidates"):
            if not any(row["url"].lower() in plain for row in report["patch_candidates"]):
                issues.append("遗漏了来源中标为 Patch 的修复候选线索")
        limited_impact = _limited_impact_fields(q)
        if any(w in q for w in ("技术影响", "危害")) or limited_impact:
            impact_rows = [row for row in report.get("technical_impact", [])
                           if not limited_impact or any(name in row["label"] for name in limited_impact)]
            for row in impact_rows:
                if not _condition_present(plain, row):
                    issues.append("没有完整保留评分向量中的%s" % row["label"])
            if impact_rows and not any(w in plain for w in ("cvss", "评分向量")):
                issues.append("没有说明技术影响来自评分向量解释")
        broad_conditions = any(w in q for w in ("利用条件", "攻击条件"))
        wanted = {"AV", "AC", "AT", "PR", "UI"} if broad_conditions else set()
        if any(w in q for w in ("所需权限", "需要权限")):
            wanted.add("PR")
        if "用户交互" in q:
            wanted.add("UI")
        condition_rows = report.get("attack_conditions", [])
        if explicit_profiles and all(row == explicit_profiles[0] for row in explicit_profiles):
            from enrichment.assessment import vector_explanations
            data = explicit_profiles[0]["cvssData"]
            condition_rows = vector_explanations({"version": data["version"], "vector": data["vectorString"]})
        conditions = [row for row in condition_rows if row.get("metric") in wanted]
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
    poc_issues = poc_claim_issues(answer or "", evidence or [], citation_owners)
    field_issues = answer_issues(answer or "", evidence or [])
    passed = not missing and not bad_scores and not invalid and not lacks_citations and not poc_issues and not wrong_owner and not field_issues
    notes = []
    if missing:
        notes.append("回答里出现了证据中没有的编号：" + "、".join(missing))
    if bad_scores:
        notes.append("回答里的分数对不上证据：" + "、".join(bad_scores))
    if invalid:
        notes.append("引用了不存在的证据标识：" + "、".join(invalid))
    if lacks_citations:
        notes.append("回答没有附上证据引用")
    notes.extend(poc_issues)
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
