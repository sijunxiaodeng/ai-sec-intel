"""Find source-bound paper/blog candidates in the existing local library.

No collection, chat model, card write, or causal inference takes place here.
Matching mechanisms/CWEs are investigation leads, never vulnerability facts.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from enrichment.documents import digest
from rag.evidence import DEFAULT_DB, _connection
from rag.library import LIBRARY_DB, _reparse, search

KINDS = {"academic_paper": "paper", "research_article": "blog"}
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CWE = re.compile(r"(?<![A-Za-z0-9_-])CWE-\d{1,5}(?![A-Za-z0-9_-])", re.I)
GENERIC_PRODUCTS = {"ai", "llm", "llms", "machine learning", "adversarial", "jailbreak", "prompt injection"}
# These are retrieval vocabulary, not a classifier proving a vulnerability.
MECHANISMS = (
    ("path_traversal", "路径遍历", r"path.traversal|directory.traversal|路径遍历|目录遍历", "path traversal directory traversal 路径遍历", {"CWE-22", "CWE-23"}),
    ("deserialization", "不安全反序列化", r"deserializ|unpickl|pickle|反序列化", "deserialization pickle 反序列化", {"CWE-502"}),
    ("prompt_injection", "提示注入", r"prompt.{0,20}inject|indirect.{0,20}inject|提示注入", "prompt injection indirect 提示注入", set()),
    ("command_injection", "命令注入", r"command.inject|shell.inject|命令注入", "command injection shell injection 命令注入", {"CWE-78"}),
    ("code_injection", "代码注入", r"code.inject|代码注入", "code injection 代码注入", {"CWE-94"}),
    ("ssrf", "服务端请求伪造", r"\bssrf\b|server.side.request.forgery|服务端请求伪造", "SSRF server side request forgery 服务端请求伪造", {"CWE-918"}),
    ("resource_exhaustion", "资源耗尽", r"resource.exhaust|uncontrolled.resource|资源耗尽|资源消耗", "resource exhaustion uncontrolled resource 资源耗尽", {"CWE-400", "CWE-770"}),
    ("authentication_bypass", "认证绕过", r"authentication.bypass|认证绕过|身份认证绕过", "authentication bypass 认证绕过", {"CWE-287"}),
)
NOTICE = "只检索已入库的论文与研究文章；关联候选尚未审核，不补写受影响版本、评分、修复或资产结论。没有候选不表示不存在相关资料，也不是独立召回率验收。"


def mentions(text, identifier):
    """ASCII identifier boundaries also reject extended/prefixed CVE numbers."""
    return bool(re.search(r"(?<![A-Za-z0-9_-])" + re.escape(identifier) + r"(?![A-Za-z0-9_-])", text, re.I))


def _nvd_weaknesses(cve_id, db_path):
    if db_path is None or not Path(db_path).is_file():
        return ""
    sid = digest("https://nvd.nist.gov/vuln/detail/" + cve_id)[:16]
    with _connection(db_path) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='source_snapshots'").fetchone():
            return ""
        row = conn.execute("SELECT digest,body FROM source_snapshots WHERE cve_id=? AND source_id=?", (cve_id, sid)).fetchone()
    if not row or hashlib.sha256(row[1]).hexdigest() != row[0]:
        return ""
    try:
        payload = json.loads(row[1])
        values = [r["cve"] for r in payload.get("vulnerabilities", []) if r.get("cve", {}).get("id") == cve_id]
        return json.dumps(values[0].get("weaknesses", []), ensure_ascii=False)[:12000] if len(values) == 1 else ""
    except (ValueError, KeyError, TypeError, AttributeError):
        return ""


def query_profile(record, evidence_db=None):
    item = record.get("item") or {}
    cve_id = str(item.get("cve_id") or "").upper()
    if not CVE.fullmatch(cve_id):
        raise ValueError("需要有效 CVE 编号")
    raw = item.get("raw_data") or {}
    context = " ".join(str(item.get(k) or "")[:12000] for k in ("title", "description"))
    weakness = " ".join(json.dumps(raw.get(k), ensure_ascii=False)[:12000] for k in ("cwe", "cwes", "weaknesses") if raw.get(k))
    weakness += " " + _nvd_weaknesses(cve_id, evidence_db)
    cwes = sorted({v.upper() for v in CWE.findall(context + " " + weakness)})[:4]
    products = []
    declared = str(item.get("product") or "").strip().lower()
    if re.fullmatch(r"[a-z0-9_.:/ -]{1,80}", declared) and declared not in GENERIC_PRODUCTS and declared and not CVE.search(declared):
        products.append(declared)
    assessment = raw.get("automatic_assessment") or {}
    for row in assessment.get("affected_ranges") or []:
        value = str(row.get("product") or "").strip().lower()
        if re.fullmatch(r"[a-z0-9_.-]{1,80}", value) and value not in GENERIC_PRODUCTS and value not in products and not CVE.search(value):
            products.append(value)
    products = products[:3]
    mechanisms = [m for m in MECHANISMS if re.search(m[2], context, re.I) or set(cwes) & m[4]][:3]
    queries = []
    for kind, values in (("product", products), ("mechanism", [m[3] for m in mechanisms]), ("cwe", cwes)):
        if values:
            queries.append({"kind": kind, "text": " ".join(values)})
    return {"cve_id": cve_id, "products": products, "cwe_ids": cwes,
            "mechanisms": [{"id": m[0], "label": m[1]} for m in mechanisms], "queries": queries}, mechanisms


def _source(doc_id, db_path):
    """Reparse the archived bytes, rather than trust mutable search tags/text."""
    with _connection(db_path) as conn:
        row = conn.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc_id,)).fetchone()
        snapshot = conn.execute("SELECT digest,body FROM library_snapshots WHERE document_id=?", (doc_id,)).fetchone()
        attempt = conn.execute("SELECT payload FROM library_attempts WHERE document_id=?", (doc_id,)).fetchone()
    if not row or not snapshot:
        return None
    doc = json.loads(row[0])
    last = json.loads(attempt[0]) if attempt else {}
    url = urlsplit(doc.get("url", ""))
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.port not in (None, 443):
        return None
    if last.get("invalidated_previous") or doc.get("document_type") not in KINDS:
        return None
    sha, body = snapshot
    if doc.get("source_response_sha256") != sha or hashlib.sha256(body).hexdigest() != sha:
        return None
    try:
        parsed, chunks = _reparse(doc["url"], doc["document_type"], doc["publisher"], doc["discovery_source_id"],
                                  body, doc["fetch_url"], doc["retrieved_at"], doc.get("content_type", "text/html"),
                                  subscription_published_at=doc.get("published_at") if doc.get("published_at_basis") == "subscription_metadata" else None,
                                  parent_document_id=doc.get("parent_document_id"), encoding=doc.get("source_encoding", "utf-8"))
        # A team summary has its own identity; both identities must reparse exactly.
        if parsed["document_id"] != doc_id or parsed["source_response_sha256"] != sha:
            return None
        return {"document": copy.deepcopy(parsed), "chunks": copy.deepcopy(chunks),
                "retained_previous": last.get("status") == "error", "latest_attempt_status": last.get("status")}
    except (ValueError, KeyError, TypeError, ImportError, OSError):
        return None


def _basis(chunk, profile, mechanisms):
    text = chunk["text"]
    rows = []
    if mentions(text, profile["cve_id"]):
        rows.append({"kind": "explicit_cve_mention", "term": profile["cve_id"], "label": "原文完整提及目标 CVE"})
    for value in profile["products"]:
        if mentions(text, value):
            rows.append({"kind": "product", "term": value, "label": "出现记录中的产品检索线索"})
    for value in profile["cwe_ids"]:
        if mentions(text, value):
            rows.append({"kind": "cwe", "term": value, "label": "原文提到相同 CWE 编号"})
    for mechanism in mechanisms:
        if re.search(mechanism[2], text, re.I):
            rows.append({"kind": "mechanism", "term": mechanism[0], "label": "原文涉及相同机制：" + mechanism[1]})
    for row in rows:
        row["citation_id"] = chunk["citation_id"]
    return rows


def report(record, *, library_db=LIBRARY_DB, evidence_db=DEFAULT_DB, top_k=4):
    """Up to 3 local queries × 2 kinds, at most 20 search hits per query/kind.

    Candidates are reconstructed on every call and never stored in CVE cards.
    BGE uses only an already prepared local model; search falls back to BM25.
    """
    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 8:
        raise ValueError("每类候选上限必须为 1 到 8")
    profile, mechanisms = query_profile(record, evidence_db)
    result = {"schema_version": 1, "cve_id": profile["cve_id"], "status": "empty", "profile": profile,
              "items": [], "retrieval": [], "warnings": [], "notice": NOTICE,
              "used_model": False, "model_attempted": False, "independent_recall": None,
              "limits": {"queries_per_kind": 3, "hits_per_query": 20, "candidates_per_kind": top_k}}
    if not profile["queries"]:
        result.update(status="insufficient_context", detail="记录缺少产品、机制或 CWE 检索线索，请先补充来源资料。")
        return result
    if not Path(library_db).is_file():
        result["detail"] = "本地资料库尚未准备；没有候选不代表不存在相关论文或文章。"
        return result
    hits = {}
    for document_type in KINDS:
        for query in profile["queries"]:
            try:
                found = search(query["text"], top_k=20, document_type=document_type, db_path=library_db)
                result["retrieval"].append({"document_type": document_type, "query_kind": query["kind"], "query": query["text"],
                                            "mode": found["mode"], "status": "ok"})
                for rank, chunk in enumerate(found["evidence"]):
                    value = hits.setdefault(chunk["document_id"], {"rank": rank, "queries": []})
                    value["rank"] = min(value["rank"], rank)
                    value["queries"].append(query["kind"])
            except (ValueError, KeyError, TypeError, ImportError, OSError, RuntimeError):
                result["retrieval"].append({"document_type": document_type, "query_kind": query["kind"], "query": query["text"], "status": "error"})
                result["warnings"].append("一项本地检索未完成，已保留其他查询的候选。")
    candidates = []
    for doc_id, hit in hits.items():
        try:
            source = _source(doc_id, library_db)
        except (ValueError, KeyError, TypeError, OSError):
            source = None
        if not source:
            continue
        doc = source["document"]
        matching = []
        for chunk in source["chunks"]:
            basis = _basis(chunk, profile, mechanisms)
            if not any(row["kind"] != "product" for row in basis):
                continue  # same product by itself is not related security research
            matching.append((basis, chunk))
        if not matching:
            continue
        matching.sort(key=lambda pair: (not any(b["kind"] == "explicit_cve_mention" for b in pair[0]), -len(pair[0]), pair[1]["citation_id"]))
        chosen = matching[:2]
        evidence = [dict(chunk, **{k: doc.get(k) for k in ("document_id", "url", "title", "publisher", "document_type", "content_scope", "retrieved_at", "source_response_sha256", "source_snapshot_kind", "snapshot_url")}) for _, chunk in chosen]
        basis = [b for rows, _ in chosen for b in rows]
        explicit = any(b["kind"] == "explicit_cve_mention" for b in basis)
        item = {"id": "AC-" + digest(profile["cve_id"] + doc_id + doc["source_response_sha256"])[:24],
                "status": "semantic_candidate", "association": "explicit_cve_mention" if explicit else "mechanism_or_cwe_candidate",
                "association_notice": "编号提及只证明原文提到此编号；机制或 CWE 相同只形成调查线索，不证明漏洞同源或影响相同。",
                "explicit_cve_mention": explicit, "category": KINDS[doc["document_type"]], "document_id": doc_id,
                "title": doc["title"], "url": doc["url"], "publisher": doc["publisher"], "content_scope": doc["content_scope"],
                "source_response_sha256": doc["source_response_sha256"], "retrieved_at": doc["retrieved_at"],
                "retained_previous": source["retained_previous"], "latest_attempt_status": source["latest_attempt_status"],
                "match_basis": basis, "retrieved_by": sorted(set(hit["queries"])), "evidence": evidence,
                "evidence_ids": [chunk["citation_id"] for chunk in evidence], "review_status": "not_reviewed"}
        priority = (not explicit, -len({b["kind"] for b in basis if b["kind"] != "product"}),
                    not any(b["kind"] == "product" for b in basis), hit["rank"], doc_id)
        candidates.append((priority, item))
    candidates.sort(key=lambda row: row[0])
    for category in KINDS.values():
        result["items"].extend([item for _, item in candidates if item["category"] == category][:top_k])
    errors = sum(row["status"] == "error" for row in result["retrieval"])
    result["status"] = "partial" if errors else "candidates" if result["items"] else "empty"
    result["warnings"] = list(dict.fromkeys(result["warnings"]))
    result["detail"] = "本地候选仅供查阅，尚未审核关联语义。" if result["items"] else "本轮未找到可展示的候选；资料覆盖与检索能力有限。"
    return result
