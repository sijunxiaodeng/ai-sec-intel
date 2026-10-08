"""保持整条情报返回格式，附加片段；样例库独立于监测库。"""

import copy
from database.store import load_kb
from rag.answer import TOPIC_WORDS
from rag.evidence import CVE, DEFAULT_DB, _tokens, load_records
from rag.hybrid import search as search_chunks


def knowledge_records(db_path=DEFAULT_DB):
    records = load_kb()
    known = {(row.get("item") or {}).get("cve_id") for row in records}
    return records + [row for row in load_records(db_path) if row["item"]["cve_id"] not in known]


def get_record(cve_id, db_path=DEFAULT_DB):
    return next((row for row in knowledge_records(db_path) if row["item"]["cve_id"].upper() == cve_id.upper()), None)


def _blob(record):
    item = record.get("item") or {}
    return " ".join(str(item.get(key) or "") for key in ("cve_id", "title", "description", "product", "affected", "source"))


def search(query, top_k=5, *, cve_id="", db_path=DEFAULT_DB):
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
        result = search_chunks(text, top_k=2 if topic else 8, cve_id=cve_id,
                               topics=[topic] if topic else None, db_path=db_path)
        modes.add(result["mode"])
        notices.add(result["notice"])
        for hit in result["evidence"]:
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
    return [row for _, row in ranked[:top_k]]
