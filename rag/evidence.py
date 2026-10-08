"""独立的证据片段库与 BM25 基线；生成的 SQLite 文件留在 data/。"""

from collections import Counter
from contextlib import contextmanager
import json
import math
from pathlib import Path
import re
import sqlite3

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "task_c.sqlite3"
CVE = re.compile(r"CVE-\d{4}-\d{4,7}\b", re.I)
ENGLISH = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", re.I)
CHINESE = re.compile(r"[\u4e00-\u9fff]+")


@contextmanager
def _connection(path):
    conn = sqlite3.connect(str(path))
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def save(record, documents, db_path=DEFAULT_DB):
    """同一 CVE 原子替换样例及片段，重复运行不会累积旧证据。"""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    cve_id = record["item"]["cve_id"]
    rows = []
    ids = set()
    for doc in documents:
        if doc["cve_id"] != cve_id:
            raise ValueError("文档与情报编号不一致")
        for chunk in doc["chunks"]:
            if chunk["evidence_id"] in ids:
                raise ValueError("重复 evidence_id")
            ids.add(chunk["evidence_id"])
            row = {key: value for key, value in doc.items() if key != "chunks"}
            row.update(chunk)
            rows.append((cve_id, chunk["evidence_id"], json.dumps(row, ensure_ascii=False)))
    with _connection(path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS records (cve_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS evidence (cve_id TEXT NOT NULL, evidence_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(cve_id, evidence_id))")
        conn.execute("INSERT OR REPLACE INTO records VALUES (?, ?)", (cve_id, json.dumps(record, ensure_ascii=False)))
        conn.execute("DELETE FROM evidence WHERE cve_id = ?", (cve_id,))
        conn.executemany("INSERT INTO evidence VALUES (?, ?, ?)", rows)
    return len(rows)


def load_record(cve_id, db_path=DEFAULT_DB):
    if not Path(db_path).exists():
        return None
    with _connection(db_path) as conn:
        row = conn.execute("SELECT payload FROM records WHERE cve_id = ?", (cve_id.upper(),)).fetchone()
    return json.loads(row[0]) if row else None


def load_records(db_path=DEFAULT_DB):
    if not Path(db_path).exists():
        return []
    with _connection(db_path) as conn:
        rows = conn.execute("SELECT payload FROM records ORDER BY cve_id").fetchall()
    return [json.loads(row[0]) for row in rows]


def _all_evidence(db_path):
    if not Path(db_path).exists():
        return []
    with _connection(db_path) as conn:
        rows = conn.execute("SELECT payload FROM evidence ORDER BY cve_id, evidence_id").fetchall()
    return [json.loads(row[0]) for row in rows]


def _tokens(text):
    text = (text or "").lower()
    tokens = ENGLISH.findall(text)
    for phrase in CHINESE.findall(text):
        tokens.extend(phrase[i:i + 2] for i in range(len(phrase) - 1))
        if len(phrase) == 1:
            tokens.append(phrase)
    return tokens


def candidates(query, *, cve_id="", topics=None, db_path=DEFAULT_DB):
    rows = _all_evidence(db_path)
    requested = {value.upper() for value in CVE.findall(query or "")}
    if cve_id:
        requested.add(cve_id.upper())
    available = {row["cve_id"] for row in rows}
    if requested and (len(requested) != 1 or not requested <= available):
        return []
    if requested:
        rows = [row for row in rows if row["cve_id"] in requested]
    if topics is not None:
        rows = [row for row in rows if set(row["topics"]) & set(topics)]
    return rows


def rank_bm25(query, rows):
    if not rows or not (query or "").strip():
        return []
    terms = set(_tokens(query))
    counters = [Counter(_tokens(" ".join((row["cve_id"], row["title"], row["text"], " ".join(row["topics"]))))) for row in rows]
    lengths = [sum(counter.values()) for counter in counters]
    average = sum(lengths) / len(lengths)
    frequencies = Counter(term for counter in counters for term in counter)
    ranked = []
    for row, counter, length in zip(rows, counters, lengths):
        score = 0.0
        for term in terms:
            tf = counter[term]
            if not tf:
                continue
            df = frequencies[term]
            idf = math.log(1 + (len(rows) - df + 0.5) / (df + 0.5))
            score += idf * tf * 2.5 / (tf + 1.5 * (0.25 + 0.75 * length / average))
        if score > 0:
            ranked.append(dict(row, score=round(score, 6)))
    ranked.sort(key=lambda row: (-row["score"], row["evidence_id"]))
    return ranked


def search_evidence(query, top_k=5, *, cve_id="", topics=None, db_path=DEFAULT_DB):
    """BM25：中文二元字片段与英文词；编号过滤独立于词法得分。"""
    if not isinstance(top_k, int) or top_k <= 0:
        return []
    rows = candidates(query, cve_id=cve_id, topics=topics, db_path=db_path)
    return rank_bm25(query, rows)[:top_k]
