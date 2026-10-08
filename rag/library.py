"""通用 AI 安全资料库：公告/文章/论文独立于 CVE 卡片，原文仅保存在本机。"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import threading
import time
import urllib.parse

from collectors.library import SEEDS, SOURCES, discover, relevant
from enrichment.documents import canonical, digest, extract_document, fetch, fetch_url, make_chunks, now
from rag.evidence import CVE, DEFAULT_DB, _connection, rank_bm25
from rag.hybrid import _dense, config_path, fuse, update_index

LIBRARY_DB = DEFAULT_DB.with_name("library.sqlite3")
DOCUMENT_TYPES = {"vendor_advisory", "vendor_guidance", "research_article", "academic_paper", "standard", "policy"}
CATEGORY = {"vendor_advisory": "vendor", "vendor_guidance": "vendor", "research_article": "research", "academic_paper": "academic", "standard": "standard", "policy": "policy"}
TOPICS = {
    "prompt_injection": (r"prompt.{0,20}inject|indirect.{0,20}inject|提示注入", "提示注入 间接提示注入"),
    "jailbreak": (r"jailbreak|adversarial.{0,30}(?:attack|prompt)|越狱", "越狱 对抗攻击"),
    "model_supply_chain": (r"pickle|deserializ|supply.chain|malicious model|供应链|反序列化", "模型供应链 恶意模型 反序列化"),
    "agent_security": (r"\bagents?\b|tool.call|智能体|工具调用", "智能体安全 工具调用"),
    "ai_infrastructure": (r"vllm|ollama|torchserve|inference server|推理服务", "AI基础设施 推理服务"),
}
_SYNC_LOCK = threading.Lock()


def _schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS library_documents (document_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS library_attempts (document_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS library_snapshots (document_id TEXT PRIMARY KEY, digest TEXT NOT NULL, body BLOB NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS library_sources (source_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS library_feeds (source_id TEXT PRIMARY KEY, digest TEXT NOT NULL, body BLOB NOT NULL)")
    # 复用已有 BM25/BGE 索引格式，但只在独立 library.sqlite3 中写入。
    # 通用资料的 cve_id 为空；不为没有 CVE 的论文制造漏洞编号。
    conn.execute("CREATE TABLE IF NOT EXISTS evidence (cve_id TEXT NOT NULL, evidence_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(cve_id,evidence_id))")


def _id(url):
    return "DOC-" + digest(canonical(url))[:16]


def _paper(response, url):
    from lxml import html
    root = html.fromstring(response["body"])
    def meta(name):
        return root.xpath('//meta[@name=$name]/@content', name=name)
    abstracts = root.xpath('//blockquote[contains(concat(" ",normalize-space(@class)," ")," abstract ")]')
    title = meta("citation_title")
    if not title or not abstracts:
        raise ValueError("arXiv 页面未提供可核验的题名和摘要")
    abstract = " ".join(abstracts[0].text_content().split())
    abstract = re.sub(r"^Abstract:\s*", "", abstract)
    if len(abstract) < 100 or not relevant(title[0] + " " + abstract):
        raise ValueError("论文摘要未通过 AI 安全主题筛选")
    return {"title": title[0], "parts": [("title", title[0]), ("abstract", abstract)],
            "published_at": (meta("citation_date")[0].replace("/", "-") if meta("citation_date") else None),
            "authors": meta("citation_author"), "content_scope": "abstract",
            "full_text_url": (meta("citation_pdf_url") or [None])[0]}


def _extract(candidate, response):
    url, kind = candidate["url"], candidate["document_type"]
    if kind not in DOCUMENT_TYPES:
        raise ValueError("不支持的资料类型")
    if kind == "academic_paper":
        if urllib.parse.urlsplit(url).hostname != "arxiv.org":
            raise ValueError("本步论文解析仅支持 arXiv 摘要页")
        doc = _paper(response, url)
    elif kind == "vendor_advisory":
        data = json.loads(response["body"])
        if data.get("state") not in (None, "published") or data.get("withdrawn_at"):
            raise ValueError("公告未公开或已经撤回")
        if not data.get("ghsa_id") or not data.get("description"):
            raise ValueError("公告缺少标识或正文")
        if canonical(data.get("html_url", "")) != canonical(url):
            raise ValueError("公告返回地址与目标不一致")
        fields = ["summary", "description", "identifiers", "vulnerabilities", "cvss", "cvss_severities", "cwes", "references"]
        parts = [(key, data[key] if isinstance(data[key], str) else json.dumps(data[key], ensure_ascii=False))
                 for key in fields if data.get(key)]
        declared = [row.get("value", "").upper() for row in data.get("identifiers", []) if row.get("type") == "CVE"]
        if data.get("cve_id"):
            declared.append(data["cve_id"].upper())
        doc = {"title": data.get("summary") or data["ghsa_id"], "parts": parts,
               "published_at": data.get("published_at"), "source_last_modified": data.get("updated_at"),
               "content_scope": "advisory_fields", "declared_cve_ids": sorted({v for v in declared if CVE.fullmatch(v)}),
               "ghsa_id": data["ghsa_id"]}
    else:
        doc = extract_document(response, url)
        semantic_title = doc["title"] if doc["title"] != url else ""
        if not relevant(semantic_title + " " + "\n".join(text for _, text in doc["parts"])):
            raise ValueError("正文未通过 AI 安全主题筛选")
        doc["content_scope"] = "article_body"
        if kind == "vendor_guidance":
            # 通用文档页的启发式日期可能来自页脚/仓库历史，不充当发布时间。
            doc["published_at"] = None
    if not doc.get("published_at"):
        doc["published_at"] = candidate.get("published_at")
        doc["published_at_basis"] = "subscription_metadata" if candidate.get("published_at") else "unknown"
    else:
        doc["published_at_basis"] = "document_metadata"
    text = "\n".join(value for _, value in doc["parts"])
    mentions = sorted({v.upper() for v in CVE.findall(text)})
    declared = set(doc.get("declared_cve_ids", []))
    doc["associations"] = [{"entity_id": cve, "relation": "publisher_declared_identifier" if cve in declared else "identifier_mention",
                             "reason": "公告标识字段明确列出此编号" if cve in declared else "提取内容提到此编号；不代表整篇资料证明该漏洞的所有结论"}
                            for cve in sorted(set(mentions) | declared)]
    doc["topic_tags"] = [tag for tag, (pattern, _) in TOPICS.items() if re.search(pattern, text, re.I)]
    doc.update({"schema_version": 1, "document_id": _id(url), "source_id": digest(url)[:16],
                "url": url, "fetch_url": response["url"], "document_type": kind,
                "source_category": CATEGORY[kind], "publisher": candidate["source_name"],
                "discovery_source_id": candidate["source_id"], "discovery": candidate.get("discovery", "historical_seed"),
                "discovered_at": candidate.get("discovered_at") or now(), "retrieved_at": response.get("retrieved_at") or now(),
                "source_response_sha256": hashlib.sha256(response["body"]).hexdigest(),
                "text_sha256": digest(text), "status": "ok", "relation_type": "general_document",
                "association_reason": "独立主题资料；CVE 关联类型逐项记录，不自动作为漏洞已验证证据"})
    chunks = make_chunks(doc)
    for chunk in chunks:
        chunk["evidence_id"] = chunk["evidence_id"].replace("AUTO-", "LIB-", 1)
        # 标签只用于发现与召回，不解释为经过评估的安全事实。
        chunk["search_terms"] += " " + " ".join(labels for pattern, labels in TOPICS.values() if re.search(pattern, chunk["text"], re.I))
        chunk["citation_id"] = doc["document_id"] + "/" + chunk["evidence_id"]
    if not chunks:
        raise ValueError("文档没有可入库片段")
    return doc, chunks


def ingest_document(candidate, db_path=LIBRARY_DB, fetcher=fetch):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    candidate = dict(candidate, url=canonical(candidate["url"]))
    doc_id = _id(candidate["url"])
    try:
        response = fetcher(fetch_url(candidate["url"]))
        doc, chunks = _extract(candidate, response)
        with _connection(path) as conn:
            _schema(conn)
            old = conn.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc_id,)).fetchone()
            previous = json.loads(old[0]) if old else None
            doc["first_seen_at"] = previous["first_seen_at"] if previous else doc["discovered_at"]
            metadata = {key: value for key, value in doc.items() if key != "parts"}
            metadata["chunk_count"] = len(chunks)
            conn.execute("INSERT OR REPLACE INTO library_documents VALUES (?,?)", (doc_id, json.dumps(metadata, ensure_ascii=False)))
            conn.execute("INSERT OR REPLACE INTO library_attempts VALUES (?,?)", (doc_id, json.dumps(metadata, ensure_ascii=False)))
            conn.execute("INSERT OR REPLACE INTO library_snapshots VALUES (?,?,?)", (doc_id, doc["source_response_sha256"], response["body"]))
            previous_rows = conn.execute("SELECT evidence_id,payload FROM evidence").fetchall()
            conn.executemany("DELETE FROM evidence WHERE cve_id='' AND evidence_id=?", [(eid,) for eid, payload in previous_rows if json.loads(payload)["document_id"] == doc_id])
            for chunk in chunks:
                row = dict(metadata, **chunk, cve_id="")
                conn.execute("INSERT INTO evidence VALUES (?,?,?)", ("", row["evidence_id"], json.dumps(row, ensure_ascii=False)))
        return {"document_id": doc_id, "url": candidate["url"], "status": "ok", "chunks": len(chunks),
                "changed": not previous or previous["text_sha256"] != doc["text_sha256"]}
    except Exception as exc:
        attempt = {"document_id": doc_id, "url": candidate["url"], "document_type": candidate["document_type"],
                   "publisher": candidate["source_name"], "retrieved_at": now(), "status": "error", "error": str(exc)[:240]}
        with _connection(path) as conn:
            _schema(conn)
            old = conn.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc_id,)).fetchone()
            attempt["retained_previous"] = bool(old)
            conn.execute("INSERT OR REPLACE INTO library_attempts VALUES (?,?)", (doc_id, json.dumps(attempt, ensure_ascii=False)))
        return attempt


def _read(db_path, table):
    if not Path(db_path).exists():
        return []
    with _connection(db_path) as conn:
        _schema(conn)
        return [json.loads(row[0]) for row in conn.execute("SELECT payload FROM " + table)]


def documents(db_path=LIBRARY_DB, document_type=""):
    rows = _read(db_path, "library_documents")
    if document_type:
        rows = [r for r in rows if r["document_type"] == document_type]
    attempts = {r["document_id"]: r for r in _read(db_path, "library_attempts")}
    return sorted([dict(r, latest_attempt_status=attempts.get(r["document_id"], {}).get("status"),
                        retained_previous=attempts.get(r["document_id"], {}).get("status") == "error") for r in rows],
                  key=lambda r: (r.get("published_at") or "", r["document_id"]), reverse=True)


def _valid_evidence(db_path):
    """原始快照和片段摘要不匹配时，不把该片段作为检索/展示证据。"""
    if not Path(db_path).exists():
        return []
    with _connection(db_path) as conn:
        _schema(conn)
        good = {doc_id: sha for doc_id, sha, body in conn.execute("SELECT document_id,digest,body FROM library_snapshots")
                if hashlib.sha256(body).hexdigest() == sha}
        rows = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM evidence")]
    return [row for row in rows if good.get(row["document_id"]) == row["source_response_sha256"]
            and digest(row["text"]) == row["text_sha256"]]


def detail(document_id, db_path=LIBRARY_DB):
    doc = next((r for r in documents(db_path) if r["document_id"] == document_id), None)
    if not doc:
        return None
    rows = _valid_evidence(db_path)
    chunks = sorted([r for r in rows if r["document_id"] == document_id], key=lambda r: r["evidence_id"])
    complete = len(chunks) == doc["chunk_count"]
    return dict(doc, evidence=chunks, integrity_status="ok" if complete else "incomplete_or_invalid",
                notice="引用对应已存档的提取内容；字符定位不是网页行号。" if complete else "部分证据完整性校验未通过，异常片段不展示。")


def overview(db_path=LIBRARY_DB):
    rows = documents(db_path)
    counts = {kind: sum(r["document_type"] == kind for r in rows) for kind in sorted(DOCUMENT_TYPES)}
    return {"documents": len(rows), "chunks": sum(r["chunk_count"] for r in rows), "types": counts,
            "source_categories": sorted({r["source_category"] for r in rows}),
            "sources": sorted(_read(db_path, "library_sources"), key=lambda r: r["source_id"]),
            "failed_documents": [r for r in _read(db_path, "library_attempts") if r["status"] == "error"],
            "scope_notice": "统计为本机资料覆盖；不是赛题准确率、完整性或实时监测达标证明。论文目前收录题名/作者/摘要，不是全文。"}


def search(query, top_k=8, *, document_type="", cve_id="", db_path=LIBRARY_DB):
    if not isinstance(top_k, int) or not 1 <= top_k <= 20:
        raise ValueError("top_k 必须为 1 到 20")
    if document_type and document_type not in DOCUMENT_TYPES:
        raise ValueError("未知资料类型")
    if cve_id and not CVE.fullmatch(cve_id.upper()):
        raise ValueError("无效 CVE 编号")
    rows = _valid_evidence(db_path)
    requested = {v.upper() for v in CVE.findall(query)} | ({cve_id.upper()} if cve_id else set())
    if requested:
        rows = [r for r in rows if requested & {a["entity_id"] for a in r["associations"]}]
    if document_type:
        rows = [r for r in rows if r["document_type"] == document_type]
    if not query.strip() or not rows:
        return {"evidence": [], "mode": "bm25", "notice": "没有匹配的资料证据"}
    lexical = rank_bm25(query, rows)
    try:
        dense = _dense(query, rows, db_path)
        return {"evidence": fuse(lexical[:30], dense[:30], top_k), "mode": "hybrid", "notice": "BM25 + 本地 BGE + RRF；关联标签不代表漏洞事实已验证"}
    except Exception:
        return {"evidence": lexical[:top_k], "mode": "bm25", "notice": "使用 BM25 原文检索；本机向量索引未就绪"}


def _record_source(source, result, response, db_path):
    with _connection(db_path) as conn:
        _schema(conn)
        old = conn.execute("SELECT payload FROM library_sources WHERE source_id=?", (source["id"],)).fetchone()
        previous = json.loads(old[0]) if old else {}
        result["last_success_at"] = result["checked_at"] if result["status"] == "ok" else previous.get("last_success_at")
        if response:
            result["response_sha256"] = hashlib.sha256(response["body"]).hexdigest()
            conn.execute("INSERT OR REPLACE INTO library_feeds VALUES (?,?,?)", (source["id"], result["response_sha256"], response["body"]))
        else:
            result["last_success_response_sha256"] = previous.get("response_sha256") or previous.get("last_success_response_sha256")
        conn.execute("INSERT OR REPLACE INTO library_sources VALUES (?,?)", (source["id"], json.dumps(result, ensure_ascii=False)))


def sync(db_path=LIBRARY_DB, *, per_source=3, include_seeds=True, fetcher=fetch, sources=SOURCES, seeds=SEEDS):
    if not isinstance(per_source, int) or not 1 <= per_source <= 8:
        raise ValueError("每个来源处理数量必须为 1 到 8")
    if not _SYNC_LOCK.acquire(blocking=False):
        raise ValueError("资料同步正在运行，请等待本轮完成")
    try:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        discovered_at = now()
        candidates = [dict(seed, discovery="historical_seed", discovered_at=discovered_at) for seed in seeds] if include_seeds else []
        source_results = []
        # 每轮仅调用一次 arXiv 查询；不逐个 CVE 搜索、不在用户检索时联网。
        for source in sources:
            response = None
            result = {"source_id": source["id"], "name": source["name"], "url": source["url"], "category": source["category"], "checked_at": now()}
            try:
                found, response = discover(source, per_source, fetcher)
                candidates.extend(dict(row, discovered_at=discovered_at) for row in found)
                result.update(status="ok", discovered=len(found), coverage="有界最新窗口；不是历史全量采集")
            except Exception as exc:
                result.update(status="error", discovered=0, error=str(exc)[:240])
            _record_source(source, result, response, path)
            source_results.append(result)
        unique = {canonical(row["url"]): row for row in candidates}
        # 正文抓取最多两个并发；arXiv 摘要页单独顺序读取。
        papers = [row for row in unique.values() if row["document_type"] == "academic_paper"]
        others = [row for row in unique.values() if row["document_type"] != "academic_paper"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda row: ingest_document(row, path, fetcher), others))
        for row in papers:
            # 遵守 arXiv 的友好访问间隔；测试注入的 fetcher 不等待。
            if fetcher is fetch:
                time.sleep(3)
            results.append(ingest_document(row, path, fetcher))
        # 只复用已经准备的模型配置，不触发下载。
        if not config_path(path).exists() and config_path(DEFAULT_DB).exists():
            config_path(path).write_text(config_path(DEFAULT_DB).read_text(encoding="utf-8"), encoding="utf-8")
        index = update_index(path)
        return {"attempted": len(results), "ok": sum(r["status"] == "ok" for r in results),
                "changed": sum(bool(r.get("changed")) for r in results), "documents": results,
                "sources": source_results, "index": index, "overview": overview(path)}
    finally:
        _SYNC_LOCK.release()


def main():
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=LIBRARY_DB)
    parser.add_argument("--sync", action="store_true")
    parser.add_argument("--per-source", type=int, default=3)
    parser.add_argument("--no-seeds", action="store_true")
    parser.add_argument("--query", default="")
    args = parser.parse_args()
    result = sync(args.db, per_source=args.per_source, include_seeds=not args.no_seeds) if args.sync else search(args.query, db_path=args.db) if args.query else overview(args.db)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
