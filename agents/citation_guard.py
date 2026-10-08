"""检查结构化来源字段的引用范围；不声称完成自由文本语义推理。"""

import json
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
    value = chunk.get("structured_value")
    if not isinstance(value, dict):
        try:
            value = json.loads(chunk.get("text", ""))
        except (ValueError, TypeError):
            return None
    return value if isinstance(value, dict) and isinstance(value.get("cvssData"), dict) else None


def claim_issues(text, chunks):
    if not chunks:
        return []
    plain = CITATION.sub("", text)
    if LOCAL_STATE.search(plain):
        return ["项目执行或收录状态不能用外部文献引用证明，须由系统单独说明"]
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
    # 完整的小型 CVSS 字段可继续核对版本和提供者；分片大 JSON 不强行解析。
    metrics = [_metric(chunk) for chunk in chunks if field_kind(chunk) == "cvss"]
    if "cvss" in categories and metrics and all(metric is not None for metric in metrics) and all(kind == "cvss" for kind in kinds):
        versions = re.findall(r"CVSS\s*v?([234]\.[01])", plain, re.I)
        if any(v not in {m["cvssData"].get("version") for m in metrics} for v in versions):
            issues.append("CVSS 版本不属于本句引用的评分字段")
        base_scores = re.findall(r"(?:基础分|基础评分)(?:为|是)?\s*([0-9]+(?:\.[0-9]+)?)", plain)
        if any(float(score) not in {m["cvssData"].get("baseScore") for m in metrics} for score in base_scores):
            issues.append("基础分不属于本句引用的评分字段")
        providers = re.findall(r"[\w.+-]+@[\w.-]+|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", plain, re.I)
        if any(p.lower() not in {(m.get("source") or "").lower() for m in metrics} for p in providers):
            issues.append("评分提供者不属于本句引用的评分字段")
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
