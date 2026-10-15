"""Portable exclusive file locks for deployment writers.

Linux/macOS use fcntl.flock; Windows uses msvcrt.locking. The lock is held only
while the file handle stays open; the OS releases it if the process exits.

``timeout`` matches monitoring.ProcessFileLock: 0 means non-blocking, otherwise
wait up to that many seconds before raising ``OSError``.
"""
from __future__ import annotations

import math
import os
import time
from contextlib import contextmanager
from pathlib import Path


def _is_windows() -> bool:
    return os.name == "nt"


def _ensure_lock_byte(handle) -> None:
    # Windows msvcrt.locking needs a byte at offset 0; fstat avoids reading a
    # range another process may already hold (PermissionError on Windows).
    if os.fstat(handle.fileno()).st_size == 0:
        handle.write(b"\0")
        handle.flush()
    handle.seek(0)


def lock_exclusive(handle, *, blocking: bool = True, timeout: float | None = None) -> None:
    """Acquire an exclusive lock on an open binary file handle."""
    _ensure_lock_byte(handle)
    if timeout is not None:
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 <= timeout <= 300):
            raise ValueError("Lock timeout must be between 0 and 300 seconds")
        blocking = False
        deadline = time.monotonic() + float(timeout)
        while True:
            try:
                _lock_once(handle, blocking=False)
                return
            except OSError as exc:
                if not _is_windows() and not isinstance(exc, BlockingIOError):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
    _lock_once(handle, blocking=blocking)


def _lock_once(handle, *, blocking: bool) -> None:
    if _is_windows():
        import msvcrt

        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        msvcrt.locking(handle.fileno(), mode, 1)
        return
    import fcntl

    flags = fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(handle.fileno(), flags)


def unlock_exclusive(handle) -> None:
    handle.seek(0)
    if _is_windows():
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def exclusive_file_lock(path, *, blocking: bool = True, timeout: float | None = None):
    """Open ``path`` and hold an exclusive OS lock for the ``with`` body."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        lock_exclusive(handle, blocking=blocking, timeout=timeout)
    except BaseException:
        handle.close()
        raise
    try:
        yield handle
    finally:
        try:
            unlock_exclusive(handle)
        finally:
            handle.close()
