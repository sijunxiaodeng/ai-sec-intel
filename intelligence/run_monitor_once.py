"""Scheduled-task entrypoint. Calls existing run_incremental_v2.py for all sources."""
from pathlib import Path
from monitoring.service import run_once


if __name__ == '__main__':
    result = run_once(Path(__file__).resolve().parent)
    print(f"\n监测状态：{result['status']}", flush=True)
    raise SystemExit(0 if result['status'] in ('success', 'skipped') else 1)
