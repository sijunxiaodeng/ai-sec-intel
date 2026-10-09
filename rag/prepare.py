"""显式载入历史样例；--semantic 下载本地模型并建立向量索引。"""

import argparse
import json
from pathlib import Path
import sys

from enrichment.sample import load_sample
from rag.evidence import DEFAULT_DB, save


def prepare(db_path=DEFAULT_DB, semantic=False, model_dir=None):
    record, documents = load_sample()
    count = save(record, documents, db_path)
    result = {"cve_id": record["item"]["cve_id"], "mode": "historical_manual_sample", "chunks": count}
    if semantic:
        from rag.hybrid import build_index
        result["index"] = build_index(db_path, model_dir)
    return result


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semantic", action="store_true")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--model-dir", type=Path, help="已下载的官方 ONNX 模型目录")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.db, args.semantic, args.model_dir), ensure_ascii=False, indent=2))
    except Exception as exc:
        parser.exit(1, "准备未完成：%s。样例仍可使用 BM25 检索。\n" % exc)


if __name__ == "__main__":
    main()
