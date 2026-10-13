"""Private process entry point for A's explicitly enabled local B collector."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
# Only this private process prefers B collectors; A's module cache is untouched.
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--workers", type=int, required=True)
    parser.add_argument("--poll-minutes", type=int, default=15)
    args = parser.parse_args(argv)
    status = 0
    try:
        from monitoring.multisource import run_cycle
        result = run_cycle(ROOT, db_path=Path(args.db).resolve(), workers=args.workers,
                           timeout_seconds=args.timeout, poll_interval_minutes=args.poll_minutes)
    except Exception as exc:
        result = {"status": "failed", "sources": {}, "error": type(exc).__name__ + ": B collector could not complete"}
        status = 1
    target = Path(args.result)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, target)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
