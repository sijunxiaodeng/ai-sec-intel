# Cross-run watermarks for root-level NVD/OSV collectors (JSON, not the
# intelligence/ SQLite incremental_cursors table). Advance only after a
# successful collect+upsert for that source.

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading

ROOT = Path(__file__).resolve().parent.parent
CURSOR_PATH = ROOT / "data" / "collect_cursors.json"
_LOCK = threading.RLock()


def scoped_key(source, *identity):
    """Versioned query identity; old source-wide positions are not safe to reuse."""
    value = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return source + ":v2:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_utc(value):
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _read():
    if not CURSOR_PATH.exists():
        return {}
    try:
        data = json.loads(CURSOR_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _write(data):
    CURSOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".collect_cursors_", dir=CURSOR_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, CURSOR_PATH)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def get_state(source):
    with _LOCK:
        row = _read().get(source) or {}
        return copy.deepcopy(row) if isinstance(row, dict) else {"window_end_at": str(row)}


def get_cursor(source):
    """Return ISO watermark string for source, or empty string."""
    return str(get_state(source).get("window_end_at") or "")


def commit_states(updates):
    """Commit only completed windows / emitted OSV revisions after upsert.

    OSV merges individual acknowledgements, never treating a package's latest
    timestamp as proof that its capped or failed records were stored.
    """
    with _LOCK:
        data = _read()
        for source, update in updates.items():
            stamp = update.get("window_end_at")
            current = parse_utc(stamp)
            if not source or current is None:
                raise ValueError("Cursor requires a source and timezone-aware timestamp")
            old = data.get(source)
            entry = copy.deepcopy(old) if isinstance(old, dict) else ({"window_end_at": old} if isinstance(old, str) else {})
            previous = parse_utc(entry.get("window_end_at"))
            if previous is None or current > previous:
                entry["window_end_at"] = stamp
            revisions = update.get("record_revisions")
            if revisions is not None:
                saved = entry.get("record_revisions")
                saved = dict(saved) if isinstance(saved, dict) else {}
                saved.update(revisions)
                entry["record_revisions"] = saved
            if isinstance(update.get("meta"), dict):
                entry["meta"] = copy.deepcopy(update["meta"])
            data[source] = entry
        if updates:
            _write(data)


def set_cursor(source, window_end_at, *, meta=None):
    """Persist watermark after a successful source window."""
    if not source or not window_end_at:
        return
    commit_states({source: {"window_end_at": str(window_end_at), "meta": meta or {}}})


def clear_cursor(source=None):
    with _LOCK:
        data = _read()
        if source is None:
            _write({})
            return
        data.pop(source, None)
        _write(data)
