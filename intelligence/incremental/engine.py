"""Window-by-window incremental ingestion with safe checkpoint advancement."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Callable

from storage.sqlite_store import utc_now


def ingest_incremental_source(
    *, name: str, collector, store, cursors,
    now: datetime,
    bootstrap_days: int = 7, overlap_minutes: int = 30,
    settle_minutes: int = 10, window_days: int = 7,
    max_windows: int = 8, log: Callable = print, window_hours: float | None = None,
):
    if any(x < 0 for x in [bootstrap_days, overlap_minutes, settle_minutes]):
        raise ValueError('Bootstrap/overlap/settle values cannot be negative')
    if bootstrap_days <= 0 or window_days <= 0 or max_windows <= 0:
        raise ValueError('bootstrap_days, window_days, max_windows must be positive')
    if window_days > 119:
        raise ValueError('Window cannot exceed 119 days')
    if window_hours is not None and (isinstance(window_hours, bool)
            or not math.isfinite(window_hours) or not 0 < window_hours <= 119 * 24):
        raise ValueError('window_hours must be positive and no more than 119 days')
    window = timedelta(hours=window_hours) if window_hours is not None else timedelta(days=window_days)
    if overlap_minutes >= 119 * 24 * 60:
        raise ValueError('Overlap must be less than 119 days')
    if now.tzinfo is None:
        raise ValueError('now must be timezone aware')
    now = now.astimezone(timezone.utc)
    safe_end = (now - timedelta(minutes=settle_minutes)).replace(microsecond=0)
    cursor = cursors.get(name)
    if cursor is not None:
        if cursor.tzinfo is None:
            raise ValueError('Checkpoint must be timezone aware')
        cursor = cursor.astimezone(timezone.utc)
    start = ((cursor - timedelta(minutes=overlap_minutes)) if cursor else
             (safe_end - timedelta(days=bootstrap_days)))
    if start >= safe_end:
        log(f'{name}: 数据源缓冲窗口内暂无可同步时间段')
        return {'windows': 0, 'fetched': 0, 'inserted': 0, 'updated': 0, 'unchanged': 0, 'pending': False}

    outcome = {'windows': 0, 'fetched': 0, 'inserted': 0, 'updated': 0, 'unchanged': 0, 'pending': False}
    # Anchor forward progress on the checkpoint, not on its replay overlap.
    # Otherwise a large overlap + small max_windows can replay forever.
    position = min(cursor, safe_end) if cursor else start
    first_window = True
    while position < safe_end and outcome['windows'] < max_windows:
        query_start = start if first_window else position
        end = min(position + window, safe_end,
                  query_start + timedelta(days=119))
        if end <= position:
            raise ValueError('Overlap leaves no room for forward window progress')
        log(f'{name}: 同步窗口 [{query_start.isoformat()} ~ {end.isoformat()}]')
        started_at = utc_now()
        # NEVER advance cursor if network, pagination, conversion or DB ingestion fails.
        items = collector.collect_window(query_start, end)
        result = store.ingest_batch(name, items, started_at=started_at)
        # Validate the result before checkpoint advancement as well as checking
        # that ingestion returned successfully.
        counts = {key: int(result[key]) for key in ('fetched', 'inserted', 'updated', 'unchanged')}
        cursors.advance(name, end)
        for key in ('fetched', 'inserted', 'updated', 'unchanged'):
            outcome[key] += counts[key]
        outcome['windows'] += 1
        log(f'{name}: 已入库并推进增量进度 {end.isoformat()} | {result}')
        position = end
        first_window = False
    outcome['pending'] = position < safe_end
    if outcome['pending']:
        log(f'{name}: 还有积压窗口，后续再次运行会继续处理')
    return outcome
