"""Independent API watermark table; does not alter V1 source_items schema."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Checkpoint timezone is missing')
    return parsed.astimezone(timezone.utc)


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError('Naive datetime is not supported')
    precision = 'microseconds' if dt.microsecond else 'seconds'
    return dt.astimezone(timezone.utc).isoformat(timespec=precision)


class CursorStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS incremental_cursors(
                source TEXT PRIMARY KEY,
                window_end_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS incremental_window_hints(
                source TEXT PRIMARY KEY,
                window_seconds REAL NOT NULL CHECK(window_seconds > 0)
            )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS incremental_replay_cursors(
                source TEXT PRIMARY KEY,
                checkpoint_at TEXT NOT NULL,
                replay_end_at TEXT NOT NULL
            )''')

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA busy_timeout=30000')
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get(self, source: str) -> datetime | None:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT window_end_at FROM incremental_cursors WHERE source=?',
                (source,),
            ).fetchone()
        return as_utc(row['window_end_at']) if row else None

    def advance(self, source: str, end: datetime) -> None:
        """Call ONLY after a complete source window is stored successfully."""
        if not source.strip():
            raise ValueError('source must not be empty')
        stamp = iso_utc(end)
        now = iso_utc(datetime.now(timezone.utc))
        with self._connect() as conn:
            # Comparing ISO strings is unsafe for legacy offset/Z timestamps
            # and for mixed fractional precision. Lock the read/update pair.
            conn.execute('BEGIN IMMEDIATE')
            previous = conn.execute(
                'SELECT window_end_at FROM incremental_cursors WHERE source=?',
                (source,),
            ).fetchone()
            if previous and as_utc(previous['window_end_at']) >= end.astimezone(timezone.utc):
                return
            conn.execute('''INSERT INTO incremental_cursors(source, window_end_at, recorded_at)
                VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET
                  window_end_at=excluded.window_end_at,
                  recorded_at=excluded.recorded_at''',
                (source, stamp, now))

    def get_window_seconds(self, source: str) -> float | None:
        """Resume density adaptation across bounded collection cycles."""
        with self._connect() as conn:
            row = conn.execute('SELECT window_seconds FROM incremental_window_hints WHERE source=?',
                               (source,)).fetchone()
        return float(row['window_seconds']) if row else None

    def save_window_seconds(self, source: str, seconds: float) -> None:
        if not source.strip() or not 0 < seconds <= 119 * 86400:
            raise ValueError('Invalid window hint')
        with self._connect() as conn:
            conn.execute('''INSERT INTO incremental_window_hints VALUES (?,?)
                ON CONFLICT(source) DO UPDATE SET window_seconds=excluded.window_seconds''',
                         (source, seconds))

    def get_replay_end(self, source: str, checkpoint: datetime) -> datetime | None:
        with self._connect() as conn:
            row = conn.execute('SELECT checkpoint_at,replay_end_at FROM incremental_replay_cursors WHERE source=?',
                               (source,)).fetchone()
        if row and as_utc(row['checkpoint_at']) == checkpoint:
            end = as_utc(row['replay_end_at'])
            if end <= checkpoint:
                return end
        return None

    def save_replay_end(self, source: str, checkpoint: datetime, end: datetime) -> None:
        """Only replayed, fully committed slices may bypass the next replay."""
        if not source.strip() or end > checkpoint:
            raise ValueError('Replay progress cannot exceed the forward checkpoint')
        with self._connect() as conn:
            conn.execute('''INSERT INTO incremental_replay_cursors VALUES (?,?,?)
                ON CONFLICT(source) DO UPDATE SET checkpoint_at=excluded.checkpoint_at,
                replay_end_at=excluded.replay_end_at''',
                         (source, iso_utc(checkpoint), iso_utc(end)))
