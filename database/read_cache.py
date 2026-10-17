"""Bounded read views invalidated by committed SQLite changes, including WAL.

File timestamps and an upsert-only callback miss other writers, withdrawals and
evidence updates. A retained read-only connection's data_version observes all
other connections; no read transaction is held between checks. Each caller gets
its own copy so transient display fields never mutate a cached view.
"""
from collections import OrderedDict
import copy
from pathlib import Path
import sqlite3
import threading

_MISSING = object()
_KNOWLEDGE_TABLES = ('knowledge_records', 'scope_tombstones')
_KNOWLEDGE_TRIGGERS = tuple('knowledge_read_' + table + '_' + operation
                           for table in _KNOWLEDGE_TABLES for operation in ('insert', 'update', 'delete'))


def install_knowledge_version(connection):
    """Track content commits, excluding durable task/heartbeat writes.

    SQLite triggers also cover other processes and direct SQL. The counter is
    in the same transaction, so rolled-back writes do not invalidate readers.
    """
    connection.execute('CREATE TABLE IF NOT EXISTS knowledge_read_version '
                       '(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)')
    if not connection.execute('SELECT 1 FROM knowledge_read_version WHERE id=1').fetchone():
        connection.execute('INSERT OR IGNORE INTO knowledge_read_version VALUES(1,0)')
    for table in _KNOWLEDGE_TABLES:
        for operation in ('insert', 'update', 'delete'):
            connection.execute(f'CREATE TRIGGER IF NOT EXISTS knowledge_read_{table}_{operation} '
                               f'AFTER {operation.upper()} ON {table} BEGIN '
                               'UPDATE knowledge_read_version SET version=version+1 WHERE id=1; END')


class _DatabaseVersion:
    def __init__(self, path):
        self.path = Path(path)
        self.connection = None
        self.identity = None
        self.schema = None
        self.knowledge_version = False

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self.identity = None
        self.schema = None
        self.knowledge_version = False

    def token(self):
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            self.close()
            return ("missing",)
        identity = (stat.st_dev, stat.st_ino)
        if self.connection is None or identity != self.identity:
            self.close()
            self.connection = sqlite3.connect(
                self.path.as_uri() + "?mode=ro", uri=True, timeout=1,
                check_same_thread=False, isolation_level=None,
            )
            self.identity = identity
        schema = self.connection.execute('PRAGMA schema_version').fetchone()[0]
        if schema != self.schema:
            names = self.connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
            self.knowledge_version = (set(_KNOWLEDGE_TRIGGERS) <= {row[0] for row in names}
                                      and bool(self.connection.execute("SELECT 1 FROM sqlite_master "
                                                                       "WHERE name='knowledge_read_version' AND type='table'").fetchone()))
            self.schema = schema
        if self.knowledge_version:
            row = self.connection.execute('SELECT version FROM knowledge_read_version WHERE id=1').fetchone()
            if row is not None:
                return identity + ('knowledge', schema, row[0])
        version = self.connection.execute('PRAGMA data_version').fetchone()[0]
        return identity + ('database', schema, version)


class _Entry:
    def __init__(self, paths):
        self.databases = [_DatabaseVersion(path) for path in paths]
        self.value, self.version = _MISSING, None

    def token(self):
        try:
            return tuple(db.token() for db in self.databases)
        except (sqlite3.Error, OSError):
            # Cache failure must never turn into serving the previous snapshot.
            self.close()
            return None

    def close(self):
        for db in self.databases:
            db.close()
        self.value, self.version = _MISSING, None


class ReadViewCache:
    def __init__(self, max_entries=2):
        self.max_entries = max_entries
        self.entries = OrderedDict()
        self.lock = threading.RLock()

    def clear(self):
        with self.lock:
            for entry in self.entries.values():
                entry.close()
            self.entries.clear()

    def get(self, paths, build):
        key = tuple(dict.fromkeys(Path(path).resolve() for path in paths))
        # Serialize misses to avoid several requests rebuilding the same view.
        with self.lock:
            entry = self.entries.pop(key, None) or _Entry(key)
            self.entries[key] = entry
            while len(self.entries) > self.max_entries:
                _, old = self.entries.popitem(last=False)
                old.close()
            before = entry.token()
            if before is not None and entry.value is not _MISSING and before == entry.version:
                return copy.deepcopy(entry.value)
            entry.value, entry.version = _MISSING, None
            value = build()
            after = entry.token()
            # A writer committing during construction invalidates the build;
            # it must not become the cache for that newer database version.
            if before is not None and before == after:
                entry.value, entry.version = value, after
                return copy.deepcopy(value)
            return value
