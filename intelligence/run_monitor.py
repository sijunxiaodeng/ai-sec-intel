"""Eight-category monitoring daemon with independent deadlines and fast retries."""
import argparse
import math
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from monitoring.multisource import run_cycle
from monitoring.source_registry import get_sources


def main(argv=None, *, runner=run_cycle, wait=time.sleep):
    root = Path(__file__).resolve().parent
    load_dotenv(root / '.env')
    parser = argparse.ArgumentParser(description='至少七类来源，默认每15分钟一轮')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval-minutes', type=float, default=float(os.getenv('MONITOR_INTERVAL_MINUTES', '15')))
    parser.add_argument('--source-timeout', type=int, default=int(os.getenv('SOURCE_TIMEOUT_SECONDS', '120')))
    parser.add_argument('--workers', type=int, default=int(os.getenv('MONITOR_WORKERS', '4')))
    parser.add_argument('--max-runs', type=int)
    parser.add_argument('--db', default=str(root / 'data' / 'intelligence.db'))
    parser.add_argument('--config')
    args = parser.parse_args(argv)
    if (not math.isfinite(args.interval_minutes) or not 0 < args.interval_minutes < 360
            or not 0 < args.source_timeout < 21600 or not 0 < args.workers <= 16
            or (args.max_runs is not None and args.max_runs <= 0)):
        parser.error('轮询周期和来源超时必须小于6小时，worker为1..16，轮数大于0')
    sources = get_sources(args.config)
    settle_minutes = int(os.getenv('INCREMENTAL_SETTLE_MINUTES', '5'))
    cycle_budget = math.ceil(len(sources) / args.workers) * args.source_timeout + 90
    if (settle_minutes < 0 or not sources or
            args.interval_minutes * 60 + settle_minutes * 60 + cycle_budget >= 21600):
        parser.error('轮询间隔、稳定等待与整轮最坏耗时之和必须严格小于6小时')
    rounds = 0
    try:
        while True:
            started = time.monotonic()
            result = runner(root, db_path=args.db, config_path=args.config,
                            workers=args.workers, timeout_seconds=args.source_timeout,
                            poll_interval_minutes=args.interval_minutes)
            rounds += 1
            print(f"监测状态: {result['status']}", flush=True)
            if args.once or (args.max_runs is not None and rounds >= args.max_runs):
                return 1 if result['status'] == 'failed' else 0
            # Cap recovery frequency; an overrun does not launch a catch-up storm.
            wait(max(1, args.interval_minutes * 60 - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print('监测停止；来源记录、游标和缓存保留。', flush=True)
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
