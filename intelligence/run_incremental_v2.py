"""Incremental NVD / GitHub + CISA snapshot, using the user's V1 SQLite database.

Safe to run repeatedly. Does not replace run_ingestion.py or existing collectors.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')

from collectors.cisa_kev import CISAKEVCollector
from storage.sqlite_store import SQLiteIntelligenceStore, utc_now
from incremental.api_collectors import NVDModifiedCollector, GithubModifiedCollector
from incremental.cursors import CursorStore
from incremental.engine import ingest_incremental_source


def config_int(name, default, minimum=0):
    val = int(os.getenv(name, str(default)))
    if val < minimum:
        raise ValueError(f'{name} must be >= {minimum}')
    return val


def main():
    parser = argparse.ArgumentParser(description='赛题九 B 模块增量监测 V2')
    parser.add_argument('--source', choices=['all', 'NVD', 'GITHUB_ADVISORY', 'CISA_KEV'], default='all',
                        help='首轮建议先用 --source NVD 测试')
    args = parser.parse_args()
    db_path = ROOT / 'data' / 'intelligence.db'
    store = SQLiteIntelligenceStore(db_path)
    cursors = CursorStore(db_path)

    config = dict(
        overlap_minutes=config_int('INCREMENTAL_OVERLAP_MINUTES', 30),
        settle_minutes=config_int('INCREMENTAL_SETTLE_MINUTES', 10),
        window_days=config_int('INCREMENTAL_WINDOW_DAYS', 7, 1),
        max_windows=config_int('INCREMENTAL_MAX_WINDOWS', 8, 1),
    )
    now = datetime.now(timezone.utc)
    sources = [
        ('NVD', NVDModifiedCollector(max_pages=config_int('NVD_MAX_PAGES', 30, 1)),
         config_int('NVD_BOOTSTRAP_DAYS', 7, 1)),
        ('GITHUB_ADVISORY', GithubModifiedCollector(max_pages=config_int('GITHUB_MAX_PAGES', 30, 1)),
         config_int('GITHUB_BOOTSTRAP_DAYS', 7, 1)),
    ]
    ok, failed = 0, 0
    for name, collector, bootstrap_days in sources:
        if args.source not in ('all', name):
            continue
        print(f'\n>>> 开始增量采集 {name}')
        try:
            result = ingest_incremental_source(
                name=name, collector=collector, store=store, cursors=cursors,
                now=now, bootstrap_days=bootstrap_days, **config,
            )
            print('增量采集结果:', result)
            ok += 1
        except Exception as exc:
            failed += 1
            store.record_failure(name, f'{type(exc).__name__}: {exc}', started_at=utc_now())
            print(f'ERROR {name}: {type(exc).__name__}: {exc}')
            print('失败窗口的进度没有推进；修复网络/限流后重跑即可。')

    if args.source in ('all', 'CISA_KEV'):
        print('\n>>> 同步 CISA KEV 全量目录快照（保留数据库内容哈希去重）')
        started = utc_now()
        try:
            result = store.ingest_batch('CISA_KEV', CISAKEVCollector().collect(), started_at=started)
            print('CISA 快照去重结果:', result)
            ok += 1
        except Exception as exc:
            failed += 1
            store.record_failure('CISA_KEV', f'{type(exc).__name__}: {exc}', started_at=started)
            print(f'ERROR CISA_KEV: {type(exc).__name__}: {exc}')

    print('\n>>> 数据库', db_path)
    print('>>> 汇总', store.stats())
    print(f'>>> 成功来源 {ok}，失败来源 {failed}')
    if failed or not ok:
        sys.exit(1)


if __name__ == '__main__':
    main()
