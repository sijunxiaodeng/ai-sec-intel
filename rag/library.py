"""通用 AI 安全资料库：公告/文章/论文独立于 CVE 卡片，原文仅保存在本机。"""

import argparse
from functools import lru_cache
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


def _prefer_root_collectors():
    """After embed/multi-source cycles, ROOT collectors.* must win over intelligence/."""
    try:
        from api.b_embed import prefer_root_packages

        prefer_root_packages()
    except Exception:
        pass


def _team_docs():
    """Import root collectors.team_documents reliably (never intelligence/collectors)."""
    _prefer_root_collectors()
    import collectors.team_documents as mod

    return mod


def _is_module_clash_error(text):
    value = text or ""
    return "collectors.team_documents" in value or (
        "No module named" in value and "collectors" in value
    )


def _friendly_library_error(text):
    if _is_module_clash_error(text):
        return "多源资料模块暂不可用，请稍后重试同步"
    return (text or "")[:240]


def _purge_module_clash_attempts(db_path):
    """Drop ImportError spam rows so the library page is not flooded."""
    path = Path(db_path)
    if not path.is_file():
        return 0
    removed = 0
    with _connection(path) as conn:
        _schema(conn)
        rows = list(conn.execute("SELECT document_id, payload FROM library_attempts"))
        for doc_id, payload in rows:
            try:
                data = json.loads(payload)
            except ValueError:
                continue
            if data.get("status") == "error" and _is_module_clash_error(data.get("error") or ""):
                conn.execute("DELETE FROM library_attempts WHERE document_id=?", (doc_id,))
                removed += 1
    return removed
from rag.evidence import CVE, DEFAULT_DB, _connection, rank_bm25
from rag.hybrid import _dense, config_path, fuse, update_index
from enrichment.reference_text import ARXIV_ID, catalog_document, paper_html, pdf_document, policy_document, reference_source

LIBRARY_DB = DEFAULT_DB.with_name("library.sqlite3")
DOCUMENT_TYPES = {"vendor_advisory", "vendor_guidance", "research_article", "academic_paper", "standard", "policy"}
CATEGORY = {"vendor_advisory": "vendor", "vendor_guidance": "vendor", "research_article": "research", "academic_paper": "academic", "standard": "standard", "policy": "policy"}
TOPICS = {
    "prompt_injection": (r"prompt.{0,20}inject|indirect.{0,20}inject|提示注入", "提示注入 间接提示注入"),
    "jailbreak": (r"jailbreak|adversarial.{0,30}(?:attack|prompt)|越狱", "越狱 对抗攻击"),
    "model_supply_chain": (r"pickle|deserializ|supply.chain|malicious model|供应链|反序列化", "模型供应链 恶意模型 反序列化"),
    "agent_security": (r"\bagents?\b|tool.call|智能体|工具调用", "智能体安全 工具调用"),
    "ai_infrastructure": (r"vllm|ollama|torchserve|inference server|推理服务", "AI基础设施 推理服务"),
    "ai_governance": (r"governance|risk management|risk framework|治理|管理暂行办法|服务管理|安全评估|算法备案", "AI风险管理 治理 适用范围 安全评估 算法备案"),
    "content_labeling": (r"watermark|content.*label|生成合成内容|显式标识|隐式标识|文件元数据", "生成合成内容标识 显式标识 隐式标识"),
}
QUERY_ALIASES = {"prompt_injection": "prompt injection indirect", "jailbreak": "jailbreak adversarial",
                 "model_supply_chain": "model supply chain pickle deserialization", "agent_security": "agent tool call"}
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
    team_mod = _team_docs()
    TEAM_MEDIA = team_mod.TEAM_MEDIA
    url, kind = candidate["url"], candidate["document_type"]
    if kind not in DOCUMENT_TYPES:
        raise ValueError("不支持的资料类型")
    team = response.get("content_type") == TEAM_MEDIA
    if team:
        TYPE_MAP = team_mod.TYPE_MAP
        doc, record = team_mod.extract_summary(response)
        if record["document_id"] != candidate.get("team_document_id") or canonical(record["url"]) != url or TYPE_MAP[record["source_category"]] != kind or record["source"] != candidate["source_name"]:
            raise ValueError("多源资料快照与目标资料身份不一致")
    elif kind == "academic_paper":
        if urllib.parse.urlsplit(url).hostname != "arxiv.org":
            raise ValueError("论文解析仅支持官方 arXiv 页面")
        doc = paper_html(response, url) if urllib.parse.urlsplit(url).path.startswith("/html/") else _paper(response, url)
        if candidate.get("parent_document_id"):
            doc["parent_document_id"] = candidate["parent_document_id"]
    elif kind in ("standard", "policy"):
        source = reference_source(url, kind)
        if canonical(response["url"]) != canonical(url):
            raise ValueError("官方资料返回其他地址")
        doc = policy_document(response, source) if kind == "policy" else pdf_document(response, source) if source.get("reference_format") == "pdf" else catalog_document(response, source)
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
        doc.setdefault("published_at_basis", "document_metadata")
    if candidate.get("parent_document_id"):
        doc["parent_document_id"] = candidate["parent_document_id"]
    text = "\n".join(value for _, value in doc["parts"])
    mentions = sorted({v.upper() for v in CVE.findall(text)})
    declared = set(doc.get("declared_cve_ids", []))
    doc["associations"] = [{"entity_id": cve, "relation": "publisher_declared_identifier" if cve in declared else "identifier_mention",
                             "reason": "公告标识字段明确列出此编号" if cve in declared else "提取内容提到此编号；不代表整篇资料证明该漏洞的所有结论"}
                            for cve in sorted(set(mentions) | declared)]
    doc["topic_tags"] = [tag for tag, (pattern, _) in TOPICS.items() if re.search(pattern, text, re.I)]
    identity = team_mod.team_id(record["document_id"]) if team else _id(url)
    doc.update({"schema_version": 1, "document_id": identity, "source_id": digest(identity if team else url)[:16],
                "url": url, "fetch_url": response["url"], "document_type": kind, "content_type": response.get("content_type", "text/html"),
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
    team_mod = _team_docs()
    doc_id = (
        team_mod.team_id(candidate["team_document_id"])
        if candidate.get("team_document_id")
        else _id(candidate["url"])
    )
    try:
        response = candidate.get("_prefetched_response") or fetcher(fetch_url(candidate["url"]))
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
        # Import/path clash is a process-wide issue — do not spam one row per document.
        if _is_module_clash_error(str(exc)):
            return {
                "document_id": doc_id,
                "url": candidate["url"],
                "document_type": candidate["document_type"],
                "publisher": candidate["source_name"],
                "retrieved_at": now(),
                "status": "error",
                "error": _friendly_library_error(str(exc)),
                "retained_previous": Path(db_path).is_file(),
                "skipped_persist": True,
            }
        attempt = {"document_id": doc_id, "url": candidate["url"], "document_type": candidate["document_type"],
                   "publisher": candidate["source_name"], "retrieved_at": now(), "status": "error",
                   "error": _friendly_library_error(str(exc))}
        attempt["invalidated_previous"] = str(exc) == "公告未公开或已经撤回"
        with _connection(path) as conn:
            _schema(conn)
            old = conn.execute("SELECT payload FROM library_documents WHERE document_id=?", (doc_id,)).fetchone()
            last = conn.execute("SELECT payload FROM library_attempts WHERE document_id=?", (doc_id,)).fetchone()
            if last and json.loads(last[0]).get("invalidated_previous"):
                attempt["invalidated_previous"] = True  # 超时不能恢复已经确认撤回的旧公告。
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
        invalidated = {r["document_id"] for (payload,) in conn.execute("SELECT payload FROM library_attempts")
                       if (r := json.loads(payload)).get("invalidated_previous")}
        good = {doc_id: sha for doc_id, sha, body in conn.execute("SELECT document_id,digest,body FROM library_snapshots")
                if doc_id not in invalidated and hashlib.sha256(body).hexdigest() == sha}
        rows = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM evidence")]
        docs = {json.loads(payload)["document_id"]: json.loads(payload) for (payload,) in conn.execute("SELECT payload FROM library_documents")}
        snapshots = {doc_id: body for doc_id, _, body in conn.execute("SELECT document_id,digest,body FROM library_snapshots")}
    expected = {}
    TEAM_MEDIA = _team_docs().TEAM_MEDIA
    keys = ("document_id", "url", "document_type", "content_type", "content_scope", "publisher", "source_snapshot_kind",
            "team_document_id", "team_source", "team_source_category", "team_content_updated_at", "text_sha256",
            "source_response_sha256", "snapshot_url", "published_at", "source_last_modified", "team_first_seen_at")
    for doc_id, doc in docs.items():
        if (doc.get("content_type") != TEAM_MEDIA and doc_id == _id(doc["url"])) or doc_id not in good:
            continue
        try:
            parsed, chunks = _reparse(doc["url"], doc["document_type"], doc["publisher"], doc["discovery_source_id"],
                snapshots[doc_id], doc["fetch_url"], doc["retrieved_at"], TEAM_MEDIA)
            if any(doc.get(key) != parsed.get(key) for key in keys):
                good.pop(doc_id, None)
            else:
                expected[doc_id] = {chunk["evidence_id"]: dict(parsed, **chunk) for chunk in chunks}
        except (ValueError, KeyError, TypeError):
            good.pop(doc_id, None)
    result = []
    for row in rows:
        if good.get(row["document_id"]) != row["source_response_sha256"] or digest(row["text"]) != row["text_sha256"]:
            continue
        if row["document_id"] in expected:
            original = expected[row["document_id"]].get(row["evidence_id"], {})
            if any(row.get(key) != original.get(key) for key in (*keys, "text", "locator", "citation_id")):
                continue
        result.append(row)
    return result


@lru_cache(maxsize=24)
def _reparse(url, kind, publisher, discovery_source_id, body, fetch_url_value, retrieved_at, content_type):
    TEAM_MEDIA = _team_docs().TEAM_MEDIA
    candidate = {"url": url, "document_type": kind, "source_name": publisher, "source_id": discovery_source_id}
    if content_type == TEAM_MEDIA:
        candidate["team_document_id"] = json.loads(body)["document_id"]
    response = {"body": body, "content_type": "application/json" if kind == "vendor_advisory" and content_type != TEAM_MEDIA else content_type,
                "url": fetch_url_value, "retrieved_at": retrieved_at}
    return _extract(candidate, response)


def verified_sources(db_path=LIBRARY_DB):
    """重解析校验后的快照；关联报告不把可修改的索引标签当作原始事实。"""
    if not Path(db_path).exists():
        return []
    with _connection(db_path) as conn:
        _schema(conn)
        docs = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM library_documents")]
        snapshots = {doc_id: (sha, body) for doc_id, sha, body in conn.execute("SELECT document_id,digest,body FROM library_snapshots")}
        attempts = {r["document_id"]: r for (payload,) in conn.execute("SELECT payload FROM library_attempts") if (r := json.loads(payload))}
    results = []
    TEAM_MEDIA = _team_docs().TEAM_MEDIA
    for row in docs:
        if row.get("content_type") == TEAM_MEDIA:
            continue  # 多源描述字段不作为原始公告/文章的漏洞修复事实。
        if row["document_type"] not in ("vendor_advisory", "research_article") or attempts.get(row["document_id"], {}).get("invalidated_previous"):
            continue
        snapshot = snapshots.get(row["document_id"])
        if not snapshot or row["document_id"] != _id(row["url"]):
            continue
        sha, body = snapshot
        if sha != row["source_response_sha256"] or hashlib.sha256(body).hexdigest() != sha:
            continue
        try:
            doc, chunks = _reparse(row["url"], row["document_type"], row["publisher"], row["discovery_source_id"], body, row["fetch_url"], row["retrieved_at"], row.get("content_type", "text/html"))
            import copy
            results.append({"document": copy.deepcopy(doc), "chunks": copy.deepcopy(chunks), "body": body,
                            "latest_attempt_status": attempts.get(row["document_id"], {}).get("status"),
                            "retained_previous": attempts.get(row["document_id"], {}).get("status") == "error"})
        except (ValueError, TypeError, KeyError, ImportError, OSError):
            # ImportError: lxml.html.clean missing on lxml 6.x — skip this source, do not 500.
            continue
    return results


def detail(document_id, db_path=LIBRARY_DB):
    doc = next((r for r in documents(db_path) if r["document_id"] == document_id), None)
    if not doc:
        return None
    rows = _valid_evidence(db_path)
    chunks = sorted([r for r in rows if r["document_id"] == document_id], key=lambda r: r["evidence_id"])
    complete = len(chunks) == doc["chunk_count"]
    full_text = [r for r in documents(db_path) if r.get("parent_document_id") == document_id]
    return dict(doc, evidence=chunks, full_text_documents=full_text, integrity_status="ok" if complete else "incomplete_or_invalid",
                notice="引用对应已存档的提取内容；字符定位不是网页行号。" if complete else "部分证据完整性校验未通过，异常片段不展示。")


def overview(db_path=LIBRARY_DB):
    _purge_module_clash_attempts(db_path)
    rows = documents(db_path)
    counts = {kind: sum(r["document_type"] == kind for r in rows) for kind in sorted(DOCUMENT_TYPES)}
    failed = []
    module_notice = None
    for row in _read(db_path, "library_attempts"):
        if row.get("status") != "error":
            continue
        err = row.get("error") or ""
        if _is_module_clash_error(err):
            if module_notice is None:
                module_notice = {
                    "document_id": "module-clash",
                    "url": "",
                    "status": "error",
                    "error": _friendly_library_error(err),
                    "retained_previous": True,
                    "collapsed": True,
                }
            continue
        failed.append(dict(row, error=_friendly_library_error(err)))
    if module_notice is not None:
        failed.insert(0, module_notice)
    sources = sorted(_read(db_path, "library_sources"), key=lambda r: r["source_id"])
    for source in sources:
        if source.get("error"):
            source["error"] = _friendly_library_error(source["error"])
    return {"documents": len(rows), "chunks": sum(r["chunk_count"] for r in rows), "types": counts,
            "source_categories": sorted({r["source_category"] for r in rows}),
            "sources": sources,
            "failed_documents": failed,
            "scope_counts": {scope: sum(r["content_scope"] == scope for r in rows) for scope in sorted({r["content_scope"] for r in rows})},
            "scope_notice": "按每份资料区分摘要、HTML/PDF 文字、政策条文和仅目录；不能把目录或摘要称为全文。不是赛题准确率或时效达标证明。"}


def search(query, top_k=8, *, document_type="", cve_id="", document_ids=None, db_path=LIBRARY_DB):
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
    if document_ids is not None:
        rows = [r for r in rows if r["document_id"] in set(document_ids)]
    wanted = {tag for tag in QUERY_ALIASES if re.search(TOPICS[tag][0], query, re.I | re.S)}
    if wanted:
        # 具体安全主题不能由“AI 风险”这类泛化段落替代；标签按片段原文重新判断。
        rows = [r for r in rows if r["content_scope"] in ("catalog_only", "policy_articles") or
                any(re.search(TOPICS[tag][0], r["text"] + " " + r["locator"], re.I | re.S) for tag in wanted)]
    if not query.strip() or not rows:
        return {"evidence": [], "mode": "bm25", "notice": "没有匹配的资料证据"}
    expanded_query = query + " " + " ".join(QUERY_ALIASES[tag] for tag in sorted(wanted))
    lexical = rank_bm25(expanded_query, rows)
    try:
        dense = _dense(expanded_query, rows, db_path)
        return {"evidence": fuse(lexical[:30], dense[:30], top_k), "mode": "hybrid", "notice": "BM25 + 本地 BGE + RRF；关联标签不代表漏洞事实已验证"}
    except Exception:
        return {"evidence": lexical[:top_k], "mode": "bm25", "notice": "使用 BM25 原文检索；本机向量索引未就绪"}


def full_text(document_id, db_path=LIBRARY_DB, fetcher=fetch):
    """显式获取支持的论文/文章原文，另存文档；失败不删除摘要。"""
    doc = detail(document_id, db_path)
    if doc and doc["content_scope"] == "team_summary" and doc["document_type"] in ("research_article", "vendor_advisory"):
        if doc["integrity_status"] != "ok":
            raise ValueError("团队描述存档完整性未通过检查")
        candidate = {"url": doc["url"], "document_type": doc["document_type"],
                     "source_name": doc["publisher"], "source_id": "team_source_text",
                     "parent_document_id": document_id, "discovery": "explicit_source_text"}
        result = ingest_document(candidate, db_path, fetcher)
        return dict(result, parent_document_id=document_id, index=update_index(db_path))
    if not doc or doc["document_type"] != "academic_paper" or doc["content_scope"] not in ("abstract", "team_summary"):
        raise ValueError("请选择已经入库的 arXiv 论文摘要")
    match = re.fullmatch(r"/abs/(%s)/?" % ARXIV_ID, urllib.parse.urlsplit(doc["url"]).path)
    if urllib.parse.urlsplit(doc["url"]).hostname != "arxiv.org" or not match or doc["integrity_status"] != "ok":
        raise ValueError("摘要地址或存档证据未通过检查")
    url = "https://arxiv.org/html/" + match.group(1)
    candidate = {"url": url, "source_name": "arXiv", "source_id": "arxiv_full_text", "document_type": "academic_paper",
                 "parent_document_id": document_id, "discovery": "explicit_full_text"}
    result = ingest_document(candidate, db_path, fetcher)
    return dict(result, parent_document_id=document_id, index=update_index(db_path))


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
                candidates.extend(dict(row, discovered_at=discovered_at, **({"_prefetched_response": response} if source["parser"] == "fixed" else {})) for row in found)
                result.update(status="ok", discovered=len(found), coverage="已配置官方原文更新检查；不自动发现新法规/标准" if source["parser"] == "fixed" else "有界最新窗口；不是历史全量采集")
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
        for previous in documents(path):
            if previous["content_scope"] == "full_text_html":
                # 已由用户明确获取的全文参与后续刷新，不自动为所有新论文抓取全文。
                if fetcher is fetch:
                    time.sleep(3)
                candidate = {"url": previous["url"], "source_id": "arxiv_full_text", "source_name": "arXiv",
                             "document_type": "academic_paper", "discovery": "explicit_full_text",
                             "parent_document_id": previous.get("parent_document_id")}
                results.append(ingest_document(candidate, path, fetcher))
        # 只复用已经准备的模型配置，不触发下载。
        if not config_path(path).exists() and config_path(DEFAULT_DB).exists():
            config_path(path).write_text(config_path(DEFAULT_DB).read_text(encoding="utf-8"), encoding="utf-8")
        index = update_index(path)
        return {"attempted": len(results), "ok": sum(r["status"] == "ok" for r in results),
                "changed": sum(bool(r.get("changed")) for r in results), "documents": results,
                "sources": source_results, "index": index, "overview": overview(path)}
    finally:
        _SYNC_LOCK.release()


def sync_team(db_path=LIBRARY_DB, *, max_documents=30, base_url=None, collector=None):
    """Sync multi-source document summaries into the library.

    ``base_url`` defaults to None so embed mode uses in-process reads.
    Pass an explicit HTTP base for sidecar / offline fixtures.
    """
    _prefer_root_collectors()
    _purge_module_clash_attempts(db_path)
    if collector is None:
        try:
            collector = _team_docs().TeamDocumentCollector(base_url, max_documents=max_documents)
        except Exception as exc:
            path = Path(db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            source = {"id": "team_documents", "name": "多源情报资料", "url": "inprocess://b-embed/api/documents"}
            status = {
                "source_id": source["id"], "name": source["name"], "url": source["url"],
                "category": "team", "checked_at": now(), "discovered": 0,
                "status": "error", "error": _friendly_library_error(str(exc)),
            }
            _record_source(source, status, None, path)
            return {"status": "error", "attempted": 0, "ok": 0, "changed": 0,
                    "documents": [], "source": status, "overview": overview(path)}
    if not _SYNC_LOCK.acquire(blocking=False):
        raise ValueError("资料同步正在运行，请等待本轮完成")
    try:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        source_url = (getattr(collector, "base_url", None) or base_url or "inprocess://b-embed") + "/api/documents"
        source = {"id": "team_documents", "name": "多源情报资料", "url": source_url}
        status = {"source_id": source["id"], "name": source["name"], "url": source["url"],
                  "category": "team", "checked_at": now(), "discovered": 0}
        try:
            collected = collector.collect()
        except Exception as exc:
            status.update(status="error", error=_friendly_library_error(str(exc)))
            _record_source(source, status, None, path)
            return {"status": "error", "attempted": 0, "ok": 0, "changed": 0,
                    "documents": [], "source": status, "overview": overview(path)}
        results = [ingest_document(row, path) for row in collected["candidates"]]
        module_clash_once = False
        for error in collected["errors"]:
            err_text = error.get("error") or ""
            if _is_module_clash_error(err_text):
                if module_clash_once:
                    continue
                module_clash_once = True
                error = dict(error, error=_friendly_library_error(err_text), collapsed=True)
                results.append(error)
                continue
            error = dict(error, error=_friendly_library_error(err_text))
            with _connection(path) as conn:
                _schema(conn)
                error["retained_previous"] = bool(conn.execute(
                    "SELECT 1 FROM library_documents WHERE document_id=?", (error["document_id"],)).fetchone())
                conn.execute(
                    "INSERT OR REPLACE INTO library_attempts VALUES (?,?)",
                    (error["document_id"], json.dumps(error, ensure_ascii=False)),
                )
            results.append(error)
        # Collapse ingest-time module clash returns (not persisted).
        if any(row.get("skipped_persist") for row in results):
            status.update(
                status="error",
                error=_friendly_library_error("No module named 'collectors.team_documents'"),
                discovered=collected["selected"],
                total=collected.get("total"),
                remaining=collected.get("remaining"),
                coverage=collected.get("coverage"),
            )
            _record_source(source, status, None, path)
            clean = [row for row in results if not row.get("skipped_persist")]
            return {
                "status": "error",
                "attempted": len(results),
                "ok": sum(row["status"] == "ok" for row in results),
                "changed": sum(bool(row.get("changed")) for row in results),
                "documents": clean[:1] + [row for row in clean if row.get("status") == "ok"],
                "source": status,
                "overview": overview(path),
            }
        status.update(status="partial" if any(row["status"] == "error" for row in results) else "ok",
                      discovered=collected["selected"], total=collected["total"], remaining=collected["remaining"],
                      coverage=collected["coverage"])
        _record_source(source, status, None, path)
        return {"status": status["status"], "attempted": len(results), "ok": sum(row["status"] == "ok" for row in results),
                "changed": sum(bool(row.get("changed")) for row in results), "documents": results,
                "source": status, "index": update_index(path), "overview": overview(path)}
    finally:
        _SYNC_LOCK.release()


def main():
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=LIBRARY_DB)
    parser.add_argument("--sync", action="store_true")
    parser.add_argument("--team-sync", action="store_true")
    parser.add_argument("--max-documents", type=int, default=30)
    parser.add_argument("--per-source", type=int, default=3)
    parser.add_argument("--no-seeds", action="store_true")
    parser.add_argument("--query", default="")
    args = parser.parse_args()
    result = sync_team(args.db, max_documents=args.max_documents) if args.team_sync else sync(args.db, per_source=args.per_source, include_seeds=not args.no_seeds) if args.sync else search(args.query, db_path=args.db) if args.query else overview(args.db)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.team_sync and result["status"] != "ok":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
