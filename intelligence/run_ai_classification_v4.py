"""Run Hybrid V3.1 classification safely against EXISTING SQLite CVE database."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from ai_pipeline.store import ClassificationStore, utc_now
from ai_pipeline.worker import run_batch

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def classifier_version() -> str:
    """Code hash changes automatically when Rule/Hybrid/Prompt source changes."""
    files = (
        ROOT / "classification" / "ai_relevance.py",
        ROOT / "classification" / "hybrid_classifier.py",
        ROOT / "classification" / "semantic_judge.py",
    )
    digest = hashlib.sha256()
    for p in files:
        if not p.is_file():
            raise FileNotFoundError(f"Missing classifier file: {p}")
        digest.update(p.name.encode("utf-8"))
        digest.update(p.read_bytes())
    return "hybrid-v3.1-" + digest.hexdigest()[:12]


def atomic_status(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ai_v4_", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="赛题九 B 模块 V4：分类结果自动入库（限额）")
    p.add_argument("--db", default=str(ROOT / "data" / "intelligence.db"))
    p.add_argument("--max-items", type=int,
                   default=int(os.getenv("CLASSIFY_V4_MAX_ITEMS", "40")))
    p.add_argument("--max-llm-calls", type=int,
                   default=int(os.getenv("CLASSIFY_V4_MAX_LLM_CALLS", "3")))
    p.add_argument("--stats", action="store_true", help="只查看统计，不分类，不调用 API")
    p.add_argument("--export", action="store_true", help="导出当前已完成分类的 JSONL")
    p.add_argument("--only-ai", action="store_true", help="导出仅 AI 相关的情报")
    p.add_argument("--output", default=str(ROOT / "exports" / "ai_classified_v4.jsonl"))
    args = p.parse_args(argv)

    version = classifier_version()
    store = ClassificationStore(args.db)
    status_path = ROOT / "data" / "classification_status.json"

    if args.stats:
        print(json.dumps(
            {"classifier_version": version, **store.stats(version)},
            indent=2, ensure_ascii=False
        ))
        return 0
    if args.export:
        n = store.export_jsonl(args.output, version, only_ai=args.only_ai)
        print(f"已导出 {n} 条已完成分类情报：{args.output}")
        return 0

    # Reuse Windows-verified cross-process lock from the V3.1 monitor.
    from monitoring.lock import AlreadyRunning, ProcessFileLock

    try:
        with ProcessFileLock(ROOT / "data" / ".ai_classification.lock"):
            start = utc_now()
            try:
                stats = run_batch(
                    db_path=args.db,
                    version=version,
                    max_items=args.max_items,
                    max_llm_calls=args.max_llm_calls,
                )
                atomic_status(status_path, {
                    "status": "success", "started_at": start,
                    "finished_at": utc_now(), "classifier_version": version,
                    "stats": stats, "error": None,
                })
                print(">>> V4 分类汇总", json.dumps(stats, ensure_ascii=False))
                return 0
            except Exception as exc:
                atomic_status(status_path, {
                    "status": "failed", "started_at": start,
                    "finished_at": utc_now(), "classifier_version": version,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                raise
    except AlreadyRunning:
        print(">>> 已有分类任务运行中，当前任务安全跳过。")
        return 0


if __name__ == "__main__":
    sys.exit(main())
