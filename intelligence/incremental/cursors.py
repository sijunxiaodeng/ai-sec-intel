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
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')


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
        stamp = iso_utc(end)
        now = iso_utc(datetime.now(timezone.utc))
        with self._connect() as conn:
            conn.execute('''INSERT INTO incremental_cursors(source, window_end_at, recorded_at)
                VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET
                  window_end_at=excluded.window_end_at,
                  recorded_at=excluded.recorded_at
                WHERE excluded.window_end_at > incremental_cursors.window_end_at''',
                (source, stamp, now))
