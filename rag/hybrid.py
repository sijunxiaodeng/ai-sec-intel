"""BM25 + 本地 BGE 中文嵌入 + RRF；查询时只读取本机模型。"""

from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path

from rag.evidence import DEFAULT_DB, _connection, candidates, rank_bm25

MODEL_NAME = "BAAI/bge-small-zh-v1.5"


def config_path(db_path):
    return Path(db_path).with_suffix(".retrieval.json")


@lru_cache(maxsize=2)
def _model(cache_dir, local_only=True, model_dir=None):
    from fastembed import TextEmbedding
    return TextEmbedding(model_name=MODEL_NAME, cache_dir=cache_dir, threads=2,
                         providers=["CPUExecutionProvider"], local_files_only=local_only,
                         specific_model_path=model_dir)


def _digest(row):
    return hashlib.sha256(row["text"].encode("utf-8")).hexdigest()


def _normal(vector):
    vector = [float(value) for value in vector]
    length = math.sqrt(sum(value * value for value in vector))
    if not vector or not math.isfinite(length) or length == 0:
        raise ValueError("嵌入向量为空或不合法")
    return [value / length for value in vector]


def build_index(db_path=DEFAULT_DB, model_dir=None):
    rows = candidates("", db_path=db_path)
    if not rows:
        raise ValueError("证据库为空，请先载入样例")
    cache_dir = str(Path(db_path).parent / "models")
    model = _model(cache_dir, bool(model_dir), str(model_dir) if model_dir else None)
    vectors = [_normal(vector) for vector in model.passage_embed([row["text"] for row in rows])]
    if len(vectors) != len(rows):
        raise ValueError("嵌入数量与证据数量不一致")
    with _connection(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS embeddings (cve_id TEXT, evidence_id TEXT, model TEXT, digest TEXT, vector TEXT, PRIMARY KEY(cve_id, evidence_id, model))")
        conn.execute("DELETE FROM embeddings WHERE model = ?", (MODEL_NAME,))
        conn.executemany("INSERT INTO embeddings VALUES (?, ?, ?, ?, ?)", [
            (row["cve_id"], row["evidence_id"], MODEL_NAME, _digest(row), json.dumps(vector))
            for row, vector in zip(rows, vectors)
        ])
    config_path(db_path).write_text(json.dumps({"model": MODEL_NAME, "cache_dir": cache_dir, "model_dir": str(Path(model_dir).resolve()) if model_dir else None, "enabled": True}, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"model": MODEL_NAME, "chunks": len(rows), "dimension": len(vectors[0])}


def _dense(query, rows, db_path):
    path = config_path(db_path)
    if not path.exists():
        raise RuntimeError("尚未建立向量索引")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not config.get("enabled") or config.get("model") != MODEL_NAME:
        raise RuntimeError("向量索引未启用或模型不匹配")
    with _connection(db_path) as conn:
        stored = conn.execute("SELECT cve_id, evidence_id, digest, vector FROM embeddings WHERE model = ?", (MODEL_NAME,)).fetchall()
    lookup = {(cve, eid): (digest, vector) for cve, eid, digest, vector in stored}
    selected = []
    for row in rows:
        old = lookup.get((row["cve_id"], row["evidence_id"]))
        if not old or old[0] != _digest(row):
            raise RuntimeError("证据已更新，请重新建立向量索引")
        selected.append((row, json.loads(old[1])))
    model = _model(config["cache_dir"], True, config.get("model_dir"))
    query_vector = _normal(next(iter(model.query_embed(query))))
    ranked = []
    for row, vector in selected:
        if len(query_vector) != len(vector):
            raise RuntimeError("向量维度不匹配")
        similarity = sum(a * b for a, b in zip(query_vector, vector))
        if similarity >= 0.45:
            ranked.append(dict(row, cosine_score=round(similarity, 6)))
    ranked.sort(key=lambda row: (-row["cosine_score"], row["cve_id"], row["evidence_id"]))
    return ranked


def fuse(lexical, dense, top_k):
    """按名次融合，避免把 BM25 分数当成余弦相似度。"""
    combined = {}
    for label, rows in (("bm25", lexical), ("dense", dense)):
        for rank, row in enumerate(rows, 1):
            key = (row["cve_id"], row["evidence_id"])
            result = combined.setdefault(key, dict(row, rrf_score=0.0, channels=[]))
            result["rrf_score"] += 1.0 / (60 + rank)
            result["channels"].append(label)
            if "cosine_score" in row:
                result["cosine_score"] = row["cosine_score"]
    return sorted(combined.values(), key=lambda row: (-row["rrf_score"], row["cve_id"], row["evidence_id"]))[:top_k]


def search(query, top_k=5, *, cve_id="", topics=None, db_path=DEFAULT_DB):
    rows = candidates(query, cve_id=cve_id, topics=topics, db_path=db_path)
    if not rows or not (query or "").strip() or top_k <= 0:
        return {"evidence": [], "mode": "bm25", "notice": "没有匹配的证据"}
    lexical = rank_bm25(query, rows)
    try:
        dense = _dense(query, rows, db_path)
    except Exception:
        # 不向网页泄露本机路径和下载异常；不会在用户提问时安装或下载。
        return {"evidence": lexical[:top_k], "mode": "bm25", "notice": "向量索引未就绪，使用 BM25；可运行 python -m rag.prepare --semantic 准备索引"}
    return {"evidence": fuse(lexical[:20], dense[:20], top_k), "mode": "hybrid", "notice": "BM25 + 本地中文嵌入 + RRF"}
