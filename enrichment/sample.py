"""加载人工核对的首日样例，沿用 enrich()，不访问网络或改动主知识库。"""

import copy
import hashlib
import json
from pathlib import Path

from enrichment.service import enrich

SAMPLE_PATH = Path(__file__).parent / "samples" / "cve_2024_37032.json"


def load_sample(path=SAMPLE_PATH):
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    item = bundle["item"]
    cve_id = item["cve_id"]
    documents = bundle["documents"]
    source_ids, evidence_ids = set(), set()
    if not documents:
        raise ValueError("样例必须包含证据文档")
    for doc in documents:
        source_id = doc["source_id"]
        if source_id in source_ids:
            raise ValueError("重复 source_id")
        source_ids.add(source_id)
        if doc["cve_id"] != cve_id or not doc["url"].startswith("https://"):
            raise ValueError("文档编号或来源链接不合法")
        if not doc.get("retrieved_at") or not doc.get("relation_type"):
            raise ValueError("缺少来源时间或关联类型")
        if not doc.get("chunks"):
            raise ValueError("文档没有证据片段")
        for chunk in doc["chunks"]:
            evidence_id = chunk["evidence_id"]
            if evidence_id in evidence_ids:
                raise ValueError("重复 evidence_id")
            evidence_ids.add(evidence_id)
            text = chunk["text"]
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if digest != chunk["text_sha256"]:
                raise ValueError("证据片段校验失败：" + evidence_id)
            if not chunk.get("topics") or not chunk.get("locator"):
                raise ValueError("缺少证据主题或原文定位")
    record = enrich(copy.deepcopy(item))
    # raw_data 是已有公共模型允许的扩展位置；不新增顶层公共字段。
    raw = record["item"]["raw_data"]
    facts = raw["reviewed_facts"]
    for fact in facts.values():
        if not fact.get("evidence_ids") or not set(fact["evidence_ids"]) <= evidence_ids:
            raise ValueError("富化结论引用了不存在的证据")
    if record["cvss"]:
        record["cvss"].update({
            "source": raw["cvss_source"],
            "source_url": item["url"],
            "metric_type": raw["cvss_metric_type"],
        })
    for candidate in record["poc"]:
        candidate.update({
            "status": raw["poc_review"]["status"],
            "validation": raw["poc_review"]["validation"],
            "evidence_ids": facts["poc_review"]["evidence_ids"],
        })
    return record, documents
