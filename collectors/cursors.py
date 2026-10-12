# Cross-run watermarks for root-level NVD/OSV collectors (JSON, not the
# intelligence/ SQLite incremental_cursors table). Advance only after a
# successful collect+upsert for that source.

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CURSOR_PATH = ROOT / "data" / "collect_cursors.json"


def _read():
    if not CURSOR_PATH.exists():
        return {}
    try:
        data = json.loads(CURSOR_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _write(data):
    CURSOR_PATH.parent.mkdir(exist_ok=True)
    CURSOR_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def get_cursor(source):
    """Return ISO watermark string for source, or empty string."""
    row = _read().get(source) or {}
    if isinstance(row, dict):
        return str(row.get("window_end_at") or "")
    return str(row or "")


def set_cursor(source, window_end_at, *, meta=None):
    """Persist watermark after a successful source window."""
    if not source or not window_end_at:
        return
    data = _read()
    prev = data.get(source) if isinstance(data.get(source), dict) else {}
    stamp = str(window_end_at)
    old = str((prev or {}).get("window_end_at") or "")
    if old and old >= stamp:
        # Monotonic: never move watermark backwards.
        return
    entry = {"window_end_at": stamp}
    if meta and isinstance(meta, dict):
        entry["meta"] = meta
    data[source] = entry
    _write(data)


def clear_cursor(source=None):
    data = _read()
    if source is None:
        _write({})
        return
    data.pop(source, None)
    _write(data)
