"""python -m rag.demo：加载样例、入库、检索和带引用的抽取式问答。"""

import argparse
import json
from pathlib import Path
import sys

from enrichment.sample import load_sample
from rag.answer import answer
from rag.evidence import DEFAULT_DB, save

QUESTIONS = Path(__file__).resolve().parent.parent / "questions" / "cve_2024_37032.json"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--question", help="只运行一个问题")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="本地证据库位置")
    parser.add_argument("--json", action="store_true", help="输出结构化结果")
    args = parser.parse_args()
    record, documents = load_sample()
    count = save(record, documents, args.db)
    questions = [args.question] if args.question else [row["question"] for row in json.loads(QUESTIONS.read_text(encoding="utf-8"))["cases"] if row["demo"]]
    results = [{"question": question, **answer(question, cve_id=record["item"]["cve_id"], db_path=args.db)} for question in questions]
    if args.json:
        print(json.dumps({"mode": "historical_manual_sample", "documents": len(documents), "chunks": count, "record": record, "results": results}, ensure_ascii=False, indent=2))
    else:
        print("任务 C 首日样例：%s；人工核对；%d 个来源，%d 个证据片段。" % (record["item"]["cve_id"], len(documents), count))
        print("本地库：%s；使用 BM25 与抽取式回答，未调用大模型。" % args.db)
        for result in results:
            print("\n问题：" + result["question"])
            print(result["answer"])
            for row in result["evidence"]:
                print("[%s] %s | %s | %s" % (row["evidence_id"], row["title"], row["locator"], row["url"]))


if __name__ == "__main__":
    main()
