"""B-module V5: prioritized AI classification and rule-only fast backfill."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from ai_pipeline.store import ClassificationStore
from ai_pipeline.priority_v5 import plan_batch
from ai_pipeline.worker_v5 import run_priority_batch
from run_ai_classification_v4 import classifier_version, atomic_status

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def main(argv=None):
    parser = argparse.ArgumentParser(description="B 模块 V5：AI 优先 + 历史快速回填")
    parser.add_argument("--db", default=str(ROOT / "data" / "intelligence.db"))
    parser.add_argument("--max-items", type=int,
                        default=int(os.getenv("CLASSIFY_V5_MAX_ITEMS", "300")))
    parser.add_argument("--max-llm-calls", type=int,
                        default=int(os.getenv("CLASSIFY_V5_MAX_LLM_CALLS", "2")))
    parser.add_argument("--preview", type=int, nargs="?", const=15,
                        help="查看优先队列前 N 项（可初始化分类表，不写分类结果，无需 API）")
    parser.add_argument("--stats", action="store_true", help="只看分类表统计")
    args = parser.parse_args(argv)
    state_dir = Path(args.db).resolve().parent
    version = classifier_version()  # NEVER alter V4's classifier version.
    store = ClassificationStore(args.db)
    if args.stats:
        print(json.dumps({"classifier_version": version, **store.stats(version)},
                         ensure_ascii=False, indent=2))
        return 0
    if args.preview is not None:
        from classification.hybrid_classifier import HybridAIClassifier
        selected, meta = plan_batch(store, version, HybridAIClassifier(),
                                    max(args.max_items, args.preview), args.max_llm_calls, preview=True)
        print(json.dumps({"queue": meta, "examples": [c.brief() for c in selected[:args.preview]]},
                         ensure_ascii=False, indent=2))
        return 0
    from monitoring.lock import AlreadyRunning, ProcessFileLock
    from ai_pipeline.store import utc_now
    try:
        with ProcessFileLock(state_dir / ".ai_classification.lock"):
            start = utc_now()
            try:
                report = run_priority_batch(args.db, version, args.max_items,
                                            args.max_llm_calls)
                atomic_status(state_dir / "classification_status.json", {
                    "status": "success", "started_at": start,
                    "finished_at": utc_now(), "classifier_version": version,
                    "worker": "V5_priority", "stats": report, "error": None,
                })
                print(">>> V5 优先分类汇总", json.dumps(report, ensure_ascii=False))
                return 0
            except Exception as exc:
                atomic_status(state_dir / "classification_status.json", {
                    "status": "failed", "started_at": start,
                    "finished_at": utc_now(), "classifier_version": version,
                    "worker": "V5_priority", "error": f"{type(exc).__name__}: {exc}",
                })
                raise
    except AlreadyRunning:
        print(">>> 已有分类任务运行中，本轮安全跳过")
        return 0


if __name__ == "__main__":
    sys.exit(main())
