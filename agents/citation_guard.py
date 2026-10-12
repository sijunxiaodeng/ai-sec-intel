"""检查结构化来源字段的引用范围；不声称完成自由文本语义推理。"""

import json
import math
import re

CITATION = re.compile(r"\[([^\[\]\n]+)\]")
LOCAL_STATE = re.compile(r"本项目|当前知识库|此技术报告未结合|登记清单|记录(?:中|里).{0,8}(?:未提供|没有|未给出|未收录)")
PATTERNS = {
    "cvss": r"cvss|基础分|评分|严重(?:等级|级别|性)",
    "vector_explanation": r"攻击途径|攻击复杂度|所需权限|用户交互|附加攻击要求|保密性|完整性|可用性|影响范围变化",
    "ssvc": r"ssvc|automatable|technicalimpact|利用状态|可自动化性",
    "versions": r"受影响(?:产品|版本|范围)|版本范围|范围.{0,6}上界|版本\s*[<>=]|版本(?:小于|大于|低于|高于)",
    "description": r"漏洞(?:成因|描述)|未校验|未检查|错误处理|空指针|路径遍历|摘要格式|digest|gguf|base64|testgetblobspath|远程代码执行|拒绝服务|\bdos\b|\brce\b",
    "reference": r"exploit|候选参考|参考链接|参考网址|标签|tags|\bpoc\b",
    "fix": r"关联修复|修复(?:记录|方向|提交)|\bpr\s*\d+|/pull/",
    "merge": r"合并(?:时间|提交|记录)|已合并|merge_commit|merged",
}
SUPPORT = {
    "cvss": {"cvss"}, "vector_explanation": {"cvss", "description"}, "ssvc": {"ssvc"},
    "versions": {"versions", "description"}, "description": {"description", "fix"},
    "reference": {"reference", "description"}, "fix": {"fix", "merge", "reference"},
    "merge": {"merge"},
}


def field_kind(chunk):
    locator = chunk.get("locator", "").split("；", 1)[0].lower()
    for prefix, kind in (("metrics/cvssmetric", "cvss"), ("metrics/ssvc", "ssvc"),
                         ("configurations", "versions"), ("descriptions", "description"),
                         ("references", "reference")):
        if locator.startswith(prefix):
            return kind
    if chunk.get("relation_type") == "fix_record" and locator == "merge_metadata":
        return "merge"
    if chunk.get("relation_type") == "fix_record" and locator in ("title", "body"):
        return "fix"
    return None  # 网页正文、人工摘要及未知格式不伪装为已完成字段语义验证。


def _metric(chunk):
    try:
        value = json.loads(chunk.get("text", ""))
    except (ValueError, TypeError):
        return None
    projection = chunk.get("structured_value")
    if isinstance(projection, dict) and projection != value:
        return None  # A derived field cannot override the cited archived JSON.
    return value if isinstance(value, dict) and isinstance(value.get("cvssData"), dict) else None


SEVERITY_VALUES = {"无": "NONE", "低": "LOW", "低危": "LOW", "中": "MEDIUM", "中危": "MEDIUM",
                   "高": "HIGH", "高危": "HIGH", "严重": "CRITICAL", "危急": "CRITICAL"}
VECTOR = re.compile(r"CVSS:[234]\.[01](?:/[A-Z]{1,4}:[A-Z0-9]+)+", re.I)
LEGACY_VECTOR = re.compile(r"(?:AV|AC|AU|C|I|A):[A-Z]+(?:/[A-Z]{1,4}:[A-Z0-9]+)+", re.I)
COMPONENT = re.compile(r"(?<![A-Z])\b(AV|AC|AT|AU|PR|UI|VC|VI|VA|SC|SI|SA|S|C|I|A):([A-Z]+)\b", re.I)


def cvss_assertions(text):
    """Read explicit structured assertions, not arbitrary prose conclusions."""
    original = CITATION.sub("", text)
    plain = re.sub(r"https?://[^\s。；，<>]+", "", original)
    values = {
        "versions": set(re.findall(r"CVSS\s*:?[ \t]*v?([234]\.[01])", plain, re.I)),
        "scores": {float(value) for pair in re.findall(
            r"(?:基础分|基础评分)(?:为|是|[:：])?\s*([0-9]+(?:\.[0-9]+)?)|"
            r"CVSS(?!:[234]\.[01]/)(?:\s*v?[234]\.[01])?\s*(?:评分|分数|为|是|[:：])(?:为|是|[:：])?\s*([0-9]+(?:\.[0-9]+)?)",
            plain, re.I) for value in pair if value},
        "vectors": {value.upper() for value in VECTOR.findall(plain)},
        "providers": {value.rstrip(".").lower() for value in re.findall(
            r"[\w.+-]+@[\w.-]+|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", plain, re.I)},
        "types": {value.lower() for value in re.findall(r"(?:类型|评分类型|metric_type|type)\s*[:：]?\s*(Primary|Secondary)\b", plain, re.I)},
        "severity": set(),
        "missing": set(),
        "components": {(key.upper(), value.upper()) for key, value in COMPONENT.findall(plain)},
    }
    for vector in LEGACY_VECTOR.findall(plain):
        if re.search(r"(?:^|/)AU:", vector, re.I):
            values["vectors"].add("CVSS:2.0/" + vector.upper())
    for name, pattern in (("severity", r"严重(?:等级|级别|性|程度)"), ("vectors", r"(?:完整\s*CVSS\s*)?向量"),
                          ("providers", r"评分(?:记录)?来源|评分提供者"), ("types", r"评分类型|类型")):
        if re.search(r"(?:" + pattern + r")\s*(?:为|是|[:：])?\s*(?:未提供|未注明|未给出|缺失|未知)", plain, re.I):
            values["missing"].add(name)
    for value in re.findall(r"(?:严重(?:等级|级别|性|程度)|风险等级|baseSeverity|severity)\s*(?:为|是|[:：])?\s*"
                            r"(CRITICAL|MEDIUM|HIGH|LOW|NONE|低危|中危|高危|危急|严重|低|中|高|无)", plain, re.I):
        values["severity"].add(SEVERITY_VALUES.get(value, value.upper()))
    for match in re.finditer(r"(?:评分(?:记录)?来源|CVSS\s*来源|评分提供者|提供者)\s*(?:为|是|[:：])?\s*([^\s，。；;,()（）]+)", original, re.I):
        provider = match.group(1).strip("'\"`").rstrip(".").lower()
        if provider not in {"未知", "未提供", "未注明", "不明确"} and not provider.startswith(("不是", "并非", "非")):
            values["providers"].add("nvd@nist.gov" if provider == "nvd" else provider)
    for match in re.finditer(r"由\s*NVD\b|NVD\s*(?:自评|评分|打分)", plain, re.I):
        prefix = plain[max(0, match.start() - 8):match.start()].strip()
        if not re.search(r"(?:(?:不是|并非)(?:由)?|不由|不能认为|不应认为)$", prefix):
            values["providers"].add("nvd@nist.gov")
    from enrichment.assessment import VECTOR_LABELS
    labels = {label: (key, mapping) for key, (label, mapping) in VECTOR_LABELS.items()}
    labels["机密性影响"] = labels["保密性影响"]
    # A single alternation prevents v4's longer VC/SC labels also matching v3 C.
    pattern = "|".join(re.escape(label) for label in sorted(labels, key=len, reverse=True))
    for match in re.finditer(pattern, plain):
        key, mapping = labels[match.group()]
        alternatives = {label: value for value, label in mapping.items()}
        if key == "PR":
            alternatives.update({"无需": "N", "不需要": "N"})
        value = re.match(r"\s*(?:为|是|[:：])?\s*(" + "|".join(re.escape(label) for label in sorted(alternatives, key=len, reverse=True)) + ")", plain[match.end():])
        if value:
            values["components"].add((key, alternatives[value.group(1)]))
    for pattern, key, value in (
        (r"无需(?:任何)?权限|不需要(?:任何)?权限|不要求(?:任何)?权限", "PR", "N"),
        (r"无需用户交互|不需要用户交互|不要求用户交互", "UI", "N"),
        (r"低(?:攻击)?复杂度", "AC", "L"), (r"高(?:攻击)?复杂度", "AC", "H"),
        (r"网络攻击|通过网络|经由网络|远程攻击", "AV", "N"),
    ):
        if re.search(pattern, plain):
            values["components"].add((key, value))
    for match in re.finditer(r"(低|高)(?:等级)?权限", plain):
        prefix = plain[max(0, match.start() - 8):match.start()]
        if not re.search(r"(?:无需|不需要|不要求|不必|无)(?:任何)?$", prefix):
            values["components"].add(("PR", "L" if match.group(1) == "低" else "H"))
    return values


def _vector_identity(value, version=None):
    if version == "2.0" and isinstance(value, str) and not value.upper().startswith("CVSS:"):
        value = "CVSS:2.0/" + value
    if not isinstance(value, str) or not VECTOR.fullmatch(value):
        return None
    head, *parts = value.upper().split("/")
    pairs = [part.split(":", 1) for part in parts]
    if len({key for key, _ in pairs}) != len(pairs):
        return None
    required = {"CVSS:2.0": {"AV", "AC", "AU", "C", "I", "A"},
                "CVSS:3.0": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
                "CVSS:3.1": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
                "CVSS:4.0": {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}}
    if not required.get(head, set()) <= {key for key, _ in pairs}:
        return None
    return head, frozenset((key, value) for key, value in pairs)


def matching_cvss_metrics(text, metrics):
    """All explicit attributes in one fact must belong to the same scoring row."""
    facts = cvss_assertions(text)
    matches = []
    from enrichment.assessment import vector_explanations
    for metric in metrics:
        if not metric:
            continue
        data = metric.get("cvssData") or {}
        score, version = data.get("baseScore"), data.get("version")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
            continue
        if version not in {"2.0", "3.0", "3.1", "4.0"}:
            continue
        if facts["versions"] - {data.get("version")} or facts["scores"] - {data.get("baseScore")}:
            continue
        source = metric.get("source") if isinstance(metric.get("source"), str) else ""
        metric_type = metric.get("type") if isinstance(metric.get("type"), str) else ""
        if facts["providers"] - {source.lower()} or facts["types"] - {metric_type.lower()}:
            continue
        severity = data.get("baseSeverity") or metric.get("baseSeverity") or ""
        severity = severity.upper() if isinstance(severity, str) else ""
        present = {"severity": severity, "vectors": data.get("vectorString"), "providers": source, "types": metric_type}
        if any(present[key] for key in facts["missing"]):
            continue
        if facts["severity"] - {severity}:
            continue
        expected = _vector_identity(data.get("vectorString"), version)
        if facts["vectors"] and (expected is None or any(_vector_identity(vector) != expected for vector in facts["vectors"])):
            continue
        components = {(row["metric"], row["value"]) for row in vector_explanations(
            {"version": data.get("version"), "vector": data.get("vectorString")})}
        if version == "2.0" and expected:
            components = expected[1]
        if facts["components"] - components:
            continue
        matches.append(metric)
    return matches


def claim_issues(text, chunks):
    plain = CITATION.sub("", text)
    if LOCAL_STATE.search(plain):
        return ["项目执行或收录状态不能用外部文献引用证明，须由系统单独说明"]
    linked = [chunk for chunk in chunks if chunk.get("relation_type") == "associated_guidance"]
    if linked:
        allowed = {CITATION.sub("", chunk.get("allowed_claim", "")).strip() for chunk in linked}
        if allowed != {plain.strip()} or "" in allowed:
            return ["关联来源事实须保留完整格式、来源归属和范围；改写未完成语义核验"]
        if len(chunks) != len(linked):
            return ["关联来源事实不能混用其他字段引用"]
        return []
    # 链接路径里的 rce/digest 等词不是本句额外作出的成因断言。
    semantic_text = re.sub(r"https?://[^\s。；，<>]+", "", plain)
    categories = {kind for kind, pattern in PATTERNS.items() if re.search(pattern, semantic_text, re.I)}
    if "/pull/" in plain:
        categories.add("fix")
    # SSVC 的 technicalImpact 不是 CVSS 影响字段。
    if "ssvc" in categories and not re.search(r"cvss|基础分|评分|向量|保密性|完整性|可用性", plain, re.I):
        categories.discard("cvss")
    kinds = [field_kind(chunk) for chunk in chunks]
    issues = []
    for category in categories:
        if all(kind is not None and kind not in SUPPORT[category] for kind in kinds):
            issues.append("引用字段不支持 %s 结论：%s" % (category, "、".join(sorted(set(kinds)))))
    # Never combine one row's score with another row's source, severity or vector.
    # Truncated/unknown metric evidence cannot authorize structured CVSS claims.
    metrics = [_metric(chunk) for chunk in chunks if field_kind(chunk) == "cvss"]
    facts = cvss_assertions(plain)
    concrete = any(facts[key] for key in ("scores", "vectors", "severity", "providers", "types", "components", "missing"))
    if concrete and ("cvss" in categories or metrics or facts["vectors"] or COMPONENT.search(plain)):
        if not matching_cvss_metrics(plain, metrics):
            issues.append("CVSS 声明的版本、分数、严重等级、向量、指标或提供者未对应同一条完整引用评分；不同评分须分别陈述")
    elif metrics and any(facts.values()) and not matching_cvss_metrics(plain, metrics):
        issues.append("CVSS 版本或评分提供者不属于本句引用的评分字段")
    return list(dict.fromkeys(issues))


def answer_issues(answer, evidence):
    chunks = {c["citation_id"]: c for r in evidence for c in r.get("evidence_chunks", [])}
    issues = []
    for line in answer.splitlines():
        cited = [chunks[c] for c in CITATION.findall(line) if c in chunks]
        # 本地状态段落无外部引用；整段原文摘录也不重新解释为模型事实。
        if cited and not any(c.get("text") and c["text"] in line for c in cited):
            issues.extend(claim_issues(line, cited))
    return list(dict.fromkeys(issues))
