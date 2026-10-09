"""首个已核对主题的证据关系；来源/版本/片段变化后关闭相关事实。"""

import json
from pathlib import Path
import re

from enrichment.documents import canonical
from rag.library import DOCUMENT_TYPES, LIBRARY_DB, detail, documents

REGISTRY = Path(__file__).with_name("relations.json")


def build_graph(*, document_ids=None, document_type="", db_path=LIBRARY_DB):
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    ids = list(dict.fromkeys(document_ids or []))
    if len(ids) > 4 or any(not re.fullmatch(r"DOC-[a-f0-9]{16}", value) for value in ids):
        raise ValueError("最多指定 4 个有效资料编号")
    if document_type and document_type not in DOCUMENT_TYPES:
        raise ValueError("未知资料类型")
    all_docs = documents(db_path)
    if any(value not in {d["document_id"] for d in all_docs} for value in ids):
        raise ValueError("指定资料不存在")
    selected = [d for d in all_docs if (not ids or d["document_id"] in ids)
                and (not document_type or d["document_type"] == document_type)]
    bound, health, facts, evidence, unavailable = {}, [], [], {}, []
    for name, expected in registry["sources"].items():
        matches = [d for d in selected if canonical(d["url"]) == expected["url"]]
        doc = detail(matches[0]["document_id"], db_path) if len(matches) == 1 else None
        reason = "来源未入库或不在当前选择/筛选中"
        if doc:
            reason = "资料版本、范围或完整性与已核对关系不符"
            if (doc["integrity_status"] == "ok" and doc.get("version") == expected["version"]
                    and doc["content_scope"] == expected["content_scope"]):
                bound[name] = doc
                reason = "已绑定核对版本" + ("；本次更新失败，沿用旧存档" if doc.get("retained_previous") else "")
        health.append({"source": name, "url": expected["url"], "expected_version": expected["version"],
                       "status": "ok" if name in bound else "unavailable", "reason": reason,
                       "document_id": doc["document_id"] if doc else None,
                       "retrieved_at": doc.get("retrieved_at") if doc else None,
                       "retained_previous": bool(doc and doc.get("retained_previous"))})
    for spec in registry["facts"]:
        doc = bound.get(spec["source"])
        rows = [r for r in doc["evidence"] if r["text_sha256"] == spec["evidence_text_sha256"]
                and r["locator"].split("；")[0] == spec["locator_prefix"]] if doc else []
        if len(rows) != 1:
            unavailable.append({"fact_id": spec["id"], "source": spec["source"],
                                "reason": "来源不可用或已核对片段变化；需重新核对，不能沿用中文关系说明"})
            continue
        row = rows[0]
        facts.append({k: spec[k] for k in ("id", "facet", "predicate", "label", "text", "authority", "qualifier")} |
                     {"topic": registry["topic"], "document_id": doc["document_id"], "source": spec["source"],
                      "publisher": doc["publisher"], "version": doc["version"],
                      "evidence_ids": [row["citation_id"]], "validation": "source_bound_summary"})
        evidence[row["citation_id"]] = row
    nodes = [{"id": registry["topic"], "label": registry["label"], "kind": "topic"}]
    nodes += [{"id": d["document_id"], "label": d["title"], "kind": "document"} for d in bound.values()]
    nodes += [{"id": f["id"], "label": f["label"], "kind": f["facet"]} for f in facts]
    edges = [{"source": registry["topic"], "target": f["id"], "predicate": "has_provenance" if f["facet"] == "provenance" else f["predicate"],
              "fact_id": f["id"], "evidence_ids": f["evidence_ids"]} for f in facts]
    edges += [{"source": f["document_id"], "target": f["id"], "predicate": "supports_summary",
               "fact_id": f["id"], "evidence_ids": f["evidence_ids"]} for f in facts]
    reference = next((f for f in facts if f["id"] == "N4"), None)
    if reference and "paper" in bound:
        edges.append({"source": reference["document_id"], "target": bound["paper"]["document_id"],
                      "predicate": "references", "fact_id": "N4", "evidence_ids": reference["evidence_ids"]})
    return {"schema_version": 1, "topic": registry["topic"], "label": registry["label"],
            "status": "ready" if not unavailable else "partial" if facts else "empty",
            "facts": facts, "graph": {"nodes": nodes, "edges": edges}, "evidence": list(evidence.values()),
            "source_health": health, "unavailable_facts": unavailable,
            "source_independence": "存在来源引用关系；不按文档数量认定独立验证" if reference else "未核对来源独立性",
            "registry_scope": registry["scope"], "review_kind": registry["review_kind"],
            "limitations": ["首个示范主题的已核对关系，不是所有主题的自动知识图谱",
                            "中文说明与固定版本片段绑定，程序校验不替代语义复核",
                            "不据此认定具体资产受影响，不执行攻击、PoC 或防护验证"]}
