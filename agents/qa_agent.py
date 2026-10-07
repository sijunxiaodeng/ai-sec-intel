from config.llm import chat, configured
from rag.retrieve import search


def _evidence_text(records):
    blocks = []
    for index, record in enumerate(records, start=1):
        item = record.get("item") or {}
        cvss = record.get("cvss") or {}
        score = cvss.get("score")
        score_text = "原文没有 CVSS" if score is None else "CVSS %s" % score
        affected = "、".join(item.get("affected") or []) or "原文没有写明版本"
        poc = record.get("poc") or []
        poc_text = "有 %d 条被 NVD 标为 Exploit 的链接" % len(poc) if poc else "当前记录没有被标为 Exploit 的链接"
        blocks.append(
            "[%d] %s | %s | %s | 产品 %s | 影响 %s | %s | 来源 %s"
            % (
                index,
                item.get("cve_id") or "",
                score_text,
                item.get("source") or "",
                item.get("product") or "",
                affected,
                poc_text,
                item.get("url") or "",
            )
        )
        blocks.append(item.get("description") or "")
    return "\n".join(blocks)


def _field_line(record):
    item = record.get("item") or {}
    cvss = record.get("cvss") or {}
    if cvss.get("score") is None:
        score = "记录里没有 CVSS 分数。"
    else:
        score = "CVSS 为 %s。" % cvss.get("score")
    affected = item.get("affected") or []
    if affected:
        version = "受影响范围写的是：%s。" % "、".join(affected[:3])
    else:
        version = "记录里没有单独写出受影响版本。"
    epss = record.get("epss") or {}
    if epss.get("status") == "ok":
        extra = "EPSS 为 %s。" % epss.get("score")
    elif epss.get("status") == "empty":
        extra = "EPSS 公开源未收录。"
    else:
        extra = ""
    kev = record.get("kev") or {}
    if kev.get("status") == "listed":
        extra += "CISA KEV 已列入。"
    elif kev.get("status") == "not_listed":
        extra += "CISA KEV 未列入。"
    poc = record.get("poc") or []
    if poc:
        extra += "有 %d 条被来源标为 Exploit 的链接，这里只保存网址。" % len(poc)
    else:
        extra += "记录里没有被标为 Exploit 的链接。"
    return score + version + extra


def _extractive(records):
    if not records:
        return "当前知识库里没有能回答这个问题的情报。"
    lines = []
    for index, record in enumerate(records, start=1):
        item = record.get("item") or {}
        lines.append("[%d] %s" % (index, item.get("cve_id") or "无编号"))
        lines.append(_field_line(record) + "见证据 [%d]。" % index)
    lines.append("以上内容来自已入库记录。未调用大模型。")
    return "\n".join(lines)


def run(question, top_k=4, cve_id=""):
    records = search(question, top_k=top_k)
    if cve_id:
        pinned = search(cve_id, top_k=1)
        pinned_ids = [(row.get("item") or {}).get("cve_id") for row in pinned]
        records = pinned + [row for row in records if (row.get("item") or {}).get("cve_id") not in pinned_ids]
    steps = [{
        "role": "问答",
        "action": "检索知识库",
        "detail": "召回 %d 条情报" % len(records),
    }]
    if not records:
        return {
            "answer": "当前知识库里没有与这个问题对应的情报。",
            "evidence": [],
            "used_model": False,
            "steps": steps,
        }
    if not configured():
        steps.append({
            "role": "问答",
            "action": "组织回答",
            "detail": "未配置大模型，改为直接摘录检索结果",
        })
        return {
            "answer": _extractive(records),
            "evidence": records,
            "used_model": False,
            "steps": steps,
        }
    messages = [
        {
            "role": "system",
            "content": (
                "你是 AI 安全情报问答。只能根据给定证据回答。"
                "不要编造漏洞编号、CVSS、版本、利用代码或链接。"
                "证据没写的内容，直接说记录里没有。"
                "回答使用中文，并在句末用 [编号] 标出证据。"
            ),
        },
        {
            "role": "user",
            "content": "问题：%s\n\n证据：\n%s" % (question, _evidence_text(records)),
        },
    ]
    try:
        answer = chat(messages)
        steps.append({
            "role": "问答",
            "action": "调用大模型",
            "detail": "只允许使用上面召回的证据",
        })
        return {
            "answer": answer,
            "evidence": records,
            "used_model": True,
            "steps": steps,
        }
    except Exception as exc:
        steps.append({
            "role": "问答",
            "action": "大模型调用失败",
            "detail": "已改用原文摘录。%s" % exc,
        })
        return {
            "answer": _extractive(records),
            "evidence": records,
            "used_model": False,
            "steps": steps,
        }
