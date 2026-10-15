"""Local durable acceptance records, separate from production intelligence."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3


def path(db_path=None):
    if db_path is not None:
        return Path(db_path).expanduser().resolve()
    from config.paths import DATA_ROOT
    return Path(os.environ.get("ACCEPTANCE_DB_PATH") or DATA_ROOT / "acceptance.sqlite3").expanduser().resolve()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical_hash(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@contextmanager
def connect(db_path=None):
    target = path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(target, timeout=20)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=20000")
        connection.execute("PRAGMA journal_mode=WAL")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
