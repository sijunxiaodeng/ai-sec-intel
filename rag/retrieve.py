"""保持整条情报返回格式，附加片段；样例库独立于监测库。"""

import copy
from enrichment.guidance import library_for, report as guidance_report
from database.store import load_kb
from rag.answer import TOPIC_WORDS
from rag.evidence import CVE, DEFAULT_DB, _tokens, load_records
from rag.hybrid import search as search_chunks


def knowledge_records(db_path=DEFAULT_DB):
    records = copy.deepcopy(load_kb())
    known = {row["item"]["cve_id"]: row for row in records}
    for row in load_records(db_path):
        key = row["item"]["cve_id"]
        if key not in known:
            records.append(row)
            known[key] = row
        else:
            current = known[key]
            current["references"] = list(dict.fromkeys((current.get("references") or []) + (row.get("references") or []) + (row["item"].get("references") or [])))
    from enrichment.assessment import enrich_view
    return enrich_view(records, db_path)


def _empty_guidance(cve_id, detail=""):
    limitations = [
        "来源声明不等于本项目验证；研究建议不能转称厂商确认。",
        "正文按规则抽取，有遗漏与语义误判可能；未完成全部自由文本语义审核。",
    ]
    if detail:
        limitations.append(detail)
    return {
        "cve_id": (cve_id or "").upper(),
        "sources": [],
        "facets": {"versions": [], "remediation": [], "conditions": []},
        "evidence": [],
        "status": "empty",
        "vendor_patched_ranges": [],
        "limitations": limitations,
    }


def _attach_guidance(record, db_path, library_db=None):
    """Attach related_guidance; never fail the whole item detail on extract deps."""
    library = library_db if library_db is not None else library_for(db_path)
    raw = record["item"].setdefault("raw_data", {})
    if library is None:
        return record
    try:
        raw["related_guidance"] = guidance_report(
            record["item"]["cve_id"], record["item"].get("product", ""), library
        )
    except Exception as exc:
        # Common on lxml 6.x without lxml_html_clean (trafilatura → justext → lxml.html.clean).
        msg = "%s: %s" % (type(exc).__name__, exc)
        if "lxml.html.clean" in msg or "lxml_html_clean" in msg:
            detail = (
                "关联建议抽取依赖不可用（缺少 lxml_html_clean）。"
                "请安装：pip install lxml_html_clean 或 lxml[html-clean]，然后重启服务。"
            )
        else:
            detail = "关联建议暂不可用（%s）。情报正文与 EPSS/KEV 仍可查看。" % msg[:160]
        raw["related_guidance"] = _empty_guidance(record["item"].get("cve_id"), detail)
    return record


def get_record(cve_id, db_path=DEFAULT_DB, *, library_db=None):
    record = next((row for row in knowledge_records(db_path) if row["item"]["cve_id"].upper() == cve_id.upper()), None)
    return _attach_guidance(record, db_path, library_db) if record else None


def _blob(record):
    item = record.get("item") or {}
    return " ".join(str(item.get(key) or "") for key in ("cve_id", "title", "description", "product", "affected", "source"))


def search(query, top_k=5, *, cve_id="", db_path=DEFAULT_DB, library_db=None):
    if top_k <= 0:
        return []
    records = knowledge_records(db_path)
    text = (query or "").strip()
    requested = {value.upper() for value in CVE.findall(text)}
    if cve_id:
        requested.add(cve_id.upper())
    available = {row["item"]["cve_id"].upper() for row in records}
    if requested and (len(requested) != 1 or not requested <= available):
        return []
    if requested:
        records = [row for row in records if row["item"]["cve_id"].upper() in requested]
    product_terms = set(_tokens(text)) & {"ollama", "vllm", "triton", "torchserve", "langchain", "ray"}
    if product_terms:
        records = [row for row in records if product_terms <= set(_tokens(str(row["item"].get("product") or "")))]
    if not records:
        return []
    if not text or text in ("全部", "所有", "列表"):
        return records[:top_k]
    topics = [topic for topic, words in TOPIC_WORDS.items() if any(word in text.lower() for word in words)]
    hits, seen, notices, modes = [], set(), set(), set()
    for topic in topics or [None]:
        result = search_chunks(text, top_k=10 if topic else 8, cve_id=cve_id,
                               topics=[topic] if topic else None, db_path=db_path, prefer_automatic=True)
        modes.add(result["mode"])
        notices.add(result["notice"])
        selected = result["evidence"]
        if topic:
            preferred = {"versions": "vulnerability_record", "cvss": "vulnerability_record", "remediation": "fix_record"}.get(topic)
            first = next((hit for hit in selected if hit.get("relation_type") == preferred), None) if preferred else None
            first = first or (selected[0] if selected else None)
            second = next((hit for hit in selected if first and hit["source_id"] != first["source_id"] and hit.get("relation_type") != first.get("relation_type")), None)
            second = second or next((hit for hit in selected if first and hit["source_id"] != first["source_id"]), None)
            selected = [hit for hit in (first, second) if hit]
        for hit in selected:
            key = (hit["cve_id"], hit["evidence_id"])
            if key not in seen:
                hit["citation_id"] = "%s/%s" % key
                hits.append(hit)
                seen.add(key)
    ranked, terms = [], set(_tokens(text))
    for original in records:
        record = copy.deepcopy(original)
        key = record["item"]["cve_id"]
        chunks = [hit for hit in hits if hit["cve_id"] == key]
        overlap = terms & set(_tokens(_blob(record)))
        score = len(overlap) + (10 if chunks else 0) + (20 if requested else 0)
        if score:
            record["evidence_chunks"] = chunks
            record["retrieval_mode"] = "hybrid" if chunks and modes == {"hybrid"} else "bm25"
            record["retrieval_notice"] = "；".join(sorted(notices))
            ranked.append((score, record))
    ranked.sort(key=lambda pair: (-pair[0], pair[1]["item"]["cve_id"]))
    return [_attach_guidance(row, db_path, library_db) for _, row in ranked[:top_k]]
