"""抓取关联资料并增量入库。完整原文、失败状态、索引仅保存在 data/。"""

import argparse
import copy
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from enrichment.documents import (associate, canonical, digest, extract_document, fetch,
                                  fetch_url, finish, now, nvd_document, reference_candidates)
from rag.evidence import DEFAULT_DB, CVE, _connection


def _schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS records (cve_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS evidence (cve_id TEXT NOT NULL, evidence_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(cve_id, evidence_id))")
    conn.execute("CREATE TABLE IF NOT EXISTS documents (cve_id TEXT NOT NULL, source_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(cve_id, source_id))")
    conn.execute("CREATE TABLE IF NOT EXISTS document_attempts (cve_id TEXT NOT NULL, source_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(cve_id, source_id))")
    conn.execute("CREATE TABLE IF NOT EXISTS source_snapshots (cve_id TEXT NOT NULL, source_id TEXT NOT NULL, digest TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(cve_id, source_id))")


def document_status(cve_id, db_path=DEFAULT_DB):
    if not Path(db_path).exists():
        return []
    with _connection(db_path) as conn:
        _schema(conn)
        attempts = conn.execute("SELECT payload FROM document_attempts WHERE cve_id = ? ORDER BY source_id", (cve_id,)).fetchall()
        good = {sid: json.loads(payload) for sid, payload in conn.execute("SELECT source_id, payload FROM documents WHERE cve_id = ?", (cve_id,))}
    result = []
    for (payload,) in attempts:
        attempt = json.loads(payload)
        old = good.get(attempt["source_id"])
        result.append(dict(attempt, last_success_at=old.get("retrieved_at") if old else None,
                           retained_previous=bool(old and attempt["status"] == "error")))
    return result


def store_document(record, doc, db_path):
    """失败只写尝试状态；成功才替换这个来源的证据，保留其他来源。"""
    cve_id = record["item"]["cve_id"]
    record = copy.deepcopy(record)
    record["item"].get("raw_data", {}).pop("automatic_assessment", None)
    status = {key: value for key, value in doc.items() if key not in ("parts", "text", "chunks", "references", "_response_body")}
    status["chunks"] = len(doc.get("chunks", []))
    with _connection(db_path) as conn:
        _schema(conn)
        conn.execute("INSERT OR REPLACE INTO records VALUES (?, ?)", (cve_id, json.dumps(record, ensure_ascii=False)))
        conn.execute("INSERT OR REPLACE INTO document_attempts VALUES (?, ?, ?)", (cve_id, doc["source_id"], json.dumps(status, ensure_ascii=False)))
        if doc["status"] != "ok":
            return
        old = conn.execute("SELECT payload FROM documents WHERE cve_id=? AND source_id=?", (cve_id, doc["source_id"])).fetchone()
        if old:
            conn.executemany("DELETE FROM evidence WHERE cve_id=? AND evidence_id=?", [(cve_id, chunk["evidence_id"]) for chunk in json.loads(old[0])["chunks"]])
        conn.execute("INSERT OR REPLACE INTO source_snapshots VALUES (?, ?, ?, ?)", (cve_id, doc["source_id"], doc["source_response_sha256"], doc["_response_body"]))
        archived = {k: v for k, v in doc.items() if k != "_response_body"}
        conn.execute("INSERT OR REPLACE INTO documents VALUES (?, ?, ?)", (cve_id, doc["source_id"], json.dumps(archived, ensure_ascii=False)))
        metadata = {k: v for k, v in doc.items() if k not in ("chunks", "parts", "text", "references", "_response_body")}
        for chunk in doc["chunks"]:
            row = dict(metadata, **chunk)
            conn.execute("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?)", (cve_id, chunk["evidence_id"], json.dumps(row, ensure_ascii=False)))


def ingest(record, db_path=DEFAULT_DB, max_sources=5, fetcher=fetch):
    if not 1 <= max_sources <= 10:
        raise ValueError("max_sources 必须为 1 到 10")
    cve_id = record["item"]["cve_id"].upper()
    if not CVE.fullmatch(cve_id) or record["item"]["cve_id"] != cve_id:
        raise ValueError("需要规范的 CVE 编号")
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    refs = reference_candidates(record)
    url = "https://nvd.nist.gov/vuln/detail/" + cve_id
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id
    docs = []
    try:
        response = fetcher(api_url)
        doc = finish(nvd_document(cve_id, response), cve_id, url, response, now())
        docs.append(doc)
        # 合并种子与新 NVD 参考，已有 URL 的标签也更新，避免 PR 被误分为背景。
        lookup = {row["url"]: row for row in refs}
        for ref in doc["references"]:
            if ref["url"] in lookup:
                lookup[ref["url"]].update(ref)
            else:
                lookup[ref["url"]] = ref
        refs = list(lookup.values())
    except Exception as exc:
        docs.append({"cve_id": cve_id, "source_id": digest(url)[:16], "url": url,
                     "retrieved_at": now(), "status": "error", "error": str(exc)[:240]})
        # NVD 暂时不可用时沿用有时间标注的上次成功关联依据。
        with _connection(path) as conn:
            _schema(conn)
            cached = conn.execute("SELECT payload FROM documents WHERE cve_id=? AND source_id=?", (cve_id, digest(url)[:16])).fetchone()
        if cached:
            previous = json.loads(cached[0])
            lookup = {row["url"]: row for row in refs}
            for ref in previous.get("references", []):
                row = dict(ref, origin="nvd_reference_cached", nvd_retrieved_at=previous["retrieved_at"])
                lookup[row["url"]] = row
            refs = list(lookup.values())

    def process(candidate):
        source_url = candidate["url"]
        try:
            response = fetcher(fetch_url(source_url))
            doc = extract_document(response, source_url)
            doc["relation_type"], doc["association_reason"] = associate(cve_id, candidate, doc)
            return finish(doc, cve_id, source_url, response, now())
        except Exception as exc:
            return {"cve_id": cve_id, "source_id": digest(source_url)[:16], "url": source_url,
                    "retrieved_at": now(), "status": "error", "error": str(exc)[:240]}

    def priority(row):
        url = row["url"]
        if "/pull/" in url or "Patch" in row["tags"]:
            return 0
        if cve_id.lower() in url.lower() and "/CVEProject/" not in url and "osv.dev/" not in url:
            return 1
        return 2
    refs.sort(key=lambda row: (priority(row), row["url"]))
    with ThreadPoolExecutor(max_workers=3) as pool:
        docs.extend(pool.map(process, refs[:max_sources - 1]))
    for doc in docs:
        store_document(record, doc, path)
    from rag.hybrid import update_index
    index = update_index(path)
    statuses = document_status(cve_id, path)
    return {"cve_id": cve_id, "documents": statuses, "attempted": len(docs),
            "ok": sum(doc["status"] == "ok" for doc in docs),
            "chunks": sum(len(doc.get("chunks", [])) for doc in docs),
            "deferred_sources": max(0, len(refs) - (max_sources - 1)), "index": index}


def main():
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", required=True)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--max-sources", type=int, default=5)
    args = parser.parse_args()
    from rag.retrieve import get_record
    record = get_record(args.cve.upper(), db_path=args.db)
    if not record:
        parser.error("请先监测收录此编号或载入历史样例")
    print(json.dumps(ingest(record, args.db, args.max_sources), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
