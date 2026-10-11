"""Private process entry point for A's explicitly enabled local B collector."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitoring.multisource import run_cycle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--workers", type=int, required=True)
    args = parser.parse_args()
    result = run_cycle(ROOT, db_path=args.db, workers=args.workers,
                       timeout_seconds=args.timeout, poll_interval_minutes=15)
    Path(args.result).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
