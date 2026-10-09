"""One-shot or periodic monitor. Interval scheduling keeps failed windows retryable."""
import argparse
import time
from pathlib import Path
from monitoring.service import run_once


def main(argv=None, *, runner=run_once, wait=time.sleep):
    parser = argparse.ArgumentParser(description='B 模块三源监测：默认一次，可选持续运行')
    parser.add_argument('--interval-minutes', type=float, default=0,
                        help='0 表示一次；例如 60 表示按小时持续运行')
    parser.add_argument('--max-runs', type=int, default=None,
                        help='限制持续运行轮数，默认不限')
    args = parser.parse_args(argv)
    if not 0 <= args.interval_minutes < float('inf') or (args.max_runs is not None and args.max_runs <= 0):
        parser.error('间隔必须是有限的非负数，轮数必须大于 0')
    runs = 0
    try:
        while True:
            started = time.monotonic()
            result = runner(Path(__file__).resolve().parent)
            runs += 1
            print(f"\n监测状态：{result['status']}", flush=True)
            if args.interval_minutes == 0 or (args.max_runs is not None and runs >= args.max_runs):
                return 0 if result['status'] in ('success', 'partial', 'skipped') else 1
            # No catch-up storm when a source was slow; continue on next interval.
            wait(max(0, args.interval_minutes * 60 - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print('\n监测已停止。已入库的数据和增量检查点保留。', flush=True)
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
