"""首日抽取式问答：直接使用核对后的片段，不调用大模型。"""

from rag.evidence import DEFAULT_DB, search_evidence

TOPIC_WORDS = {
    "ai_relevance": ("ai", "人工智能", "推理", "关联", "相关"),
    "versions": ("版本", "范围", "影响哪些", "受影响"),
    "conditions": ("条件", "利用", "攻击", "暴露", "成因", "原理", "所需权限", "需要权限", "用户交互"),
    "impact": ("有什么影响", "技术影响", "影响程度", "危害", "后果", "风险"),
    "remediation": ("修复", "缓解", "升级", "防护", "补丁", "处理"),
    "cvss": ("cvss", "评分", "分数", "严重等级", "向量"),
    "poc": ("poc", "复现", "验证代码", "利用代码"),
}


def answer(question, *, cve_id="", top_k=8, db_path=DEFAULT_DB):
    question = (question or "").strip()
    lowered = question.lower()
    topics = [topic for topic, words in TOPIC_WORDS.items() if any(word in lowered for word in words)]
    if any(word in lowered for word in ("我的", "我们", "本公司", "我公司", "哪些ip", "哪些 ip", "资产清单")):
        return {"answer": "当前样例没有你的资产清单、实际版本和网络暴露信息，无法判断你的具体资产是否受影响。", "evidence": [], "status": "insufficient_evidence", "used_model": False}
    if not topics:
        return {"answer": "当前样例只支持 AI 关联、版本、攻击条件、影响、修复、CVSS 和 PoC 状态问题；这个问题证据不足。", "evidence": [], "status": "insufficient_evidence", "used_model": False}
    # 每个意图独立检索，避免较长问题的一个意图挤掉其他意图的证据。
    evidence = []
    seen = set()
    for topic in topics:
        found = search_evidence(question, top_k=2, cve_id=cve_id, topics=[topic], db_path=db_path)
        for row in found:
            if row["evidence_id"] not in seen:
                evidence.append(row)
                seen.add(row["evidence_id"])
    evidence = evidence[:max(0, top_k)]
    if not evidence:
        return {"answer": "当前证据库没有与这个问题对应的资料，无法据此回答。", "evidence": [], "status": "insufficient_evidence", "used_model": False}
    lines = ["%s [%s]" % (row["text"], row["evidence_id"]) for row in evidence]
    missing = [topic for topic in topics if not any(topic in row["topics"] for row in evidence)]
    if missing:
        lines.append("部分问题的证据不足：" + "、".join(missing) + "。")
    return {"answer": "\n".join(lines), "evidence": evidence, "status": "partial" if missing else "answered", "used_model": False}
