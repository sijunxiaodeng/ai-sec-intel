"""Window-by-window incremental ingestion with safe checkpoint advancement."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Callable

from collectors.http import CollectionBudgetExceeded
from incremental.cursors import iso_utc
from incremental.limits import WindowPageLimitExceeded
from storage.sqlite_store import utc_now


def ingest_incremental_source(
    *, name: str, collector, store, cursors,
    now: datetime,
    bootstrap_days: int = 7, overlap_minutes: int = 30,
    settle_minutes: int = 10, window_days: int = 7,
    max_windows: int = 8, log: Callable = print, window_hours: float | None = None,
    adaptive_min_window_minutes: int = 15, max_attempts: int = 64,
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
    if adaptive_min_window_minutes <= 0 or max_attempts <= 0:
        raise ValueError('Adaptive minimum window and max_attempts must be positive')
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
    if cursor is not None:
        replay_end = cursors.get_replay_end(name, cursor)
        if isinstance(replay_end, datetime):
            start = max(start, replay_end)
    outcome = {'windows': 0, 'fetched': 0, 'inserted': 0, 'updated': 0,
               'unchanged': 0, 'pending': False, 'attempts': 0, 'split_windows': 0, 'replayed_windows': 0,
               'cursor_start_at': iso_utc(cursor) if cursor else None,
               'target_end_at': iso_utc(safe_end), 'pending_reason': None}
    checkpoint = cursor

    def finish():
        outcome['cursor_end_at'] = iso_utc(checkpoint) if checkpoint else None
        outcome['lag_seconds'] = max(0, (safe_end - (checkpoint or start)).total_seconds())
        outcome['pending'] = outcome['lag_seconds'] > 0
        return outcome

    if start >= safe_end:
        log(f'{name}: 数据源缓冲窗口内暂无可同步时间段')
        return finish()

    # Anchor forward progress on the checkpoint, not on its replay overlap.
    # Otherwise a large overlap + small max_windows can replay forever.
    position = min(cursor, safe_end) if cursor else start
    first_window = True
    current_window = window
    saved_window = cursors.get_window_seconds(name)
    if isinstance(saved_window, (int, float)) and math.isfinite(saved_window) and saved_window > 0:
        current_window = min(window, timedelta(seconds=saved_window))
        if current_window < window:
            # An already split range resumes from its query/replay position;
            # anchoring each retry on the forward cursor would enlarge the
            # dense overlap again and spend every new budget on the same split.
            position = start
    while position < safe_end and outcome['windows'] < max_windows:
        query_start = start if first_window else position
        end = min(position + current_window, safe_end,
                  query_start + timedelta(days=119))
        if end <= position:
            raise ValueError('Overlap leaves no room for forward window progress')
        # Dense modification periods must be split, including the replay
        # overlap itself. Successful replay slices never move a cursor backward.
        while True:
            if outcome['attempts'] >= max_attempts:
                outcome['pending_reason'] = 'attempt_budget'
                return finish()
            log(f'{name}: 同步窗口 [{query_start.isoformat()} ~ {end.isoformat()}]')
            started_at = utc_now()
            outcome['attempts'] += 1
            try:
                items = collector.collect_window(query_start, end)
                break
            except CollectionBudgetExceeded:
                outcome['pending_reason'] = 'request_or_time_budget'
                return finish()
            except WindowPageLimitExceeded:
                span = end - query_start
                if span <= timedelta(minutes=adaptive_min_window_minutes):
                    raise
                current_window = max(span / 2, timedelta(minutes=adaptive_min_window_minutes))
                end = query_start + current_window
                cursors.save_window_seconds(name, current_window.total_seconds())
                outcome['split_windows'] += 1
                log(f'{name}: 修改量超过分页预算，缩小窗口后重试；游标未推进')
        # NEVER advance cursor if pagination, conversion or DB ingestion fails.
        result = store.ingest_batch(name, items, started_at=started_at)
        # Validate the result before checkpoint advancement as well as checking
        # that ingestion returned successfully.
        counts = {key: int(result[key]) for key in ('fetched', 'inserted', 'updated', 'unchanged')}
        if checkpoint is None or end > checkpoint:
            cursors.advance(name, end)
            checkpoint = end
            outcome['windows'] += 1
        else:
            cursors.save_replay_end(name, checkpoint, end)
            outcome['replayed_windows'] += 1
        for key in ('fetched', 'inserted', 'updated', 'unchanged'):
            outcome[key] += counts[key]
        log(f'{name}: 已入库并推进增量进度 {end.isoformat()} | {result}')
        position = end
        first_window = False
        page_size = getattr(collector, 'page_size', 100)
        pages = getattr(collector, 'max_pages', None)
        if (isinstance(page_size, int) and isinstance(pages, int)
                and counts['fetched'] <= page_size * pages // 4):
            current_window = min(current_window * 2, window)
        cursors.save_window_seconds(name, current_window.total_seconds())
    if position < safe_end:
        outcome['pending_reason'] = 'window_budget'
        log(f'{name}: 还有积压窗口，后续再次运行会继续处理')
    return finish()
