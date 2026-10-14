"""Portable process lock. OS releases the lock if the Python process exits."""
from __future__ import annotations

import os
import math
from pathlib import Path
import time


class AlreadyRunning(RuntimeError):
    """Another scheduled monitoring run currently holds the lock."""


class ProcessFileLock:
    def __init__(self, path: Path, *, timeout: float = 0):
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 <= timeout <= 300):
            raise ValueError("Lock timeout must be between 0 and 300 seconds")
        self.path = Path(path)
        self.timeout = timeout
        self._file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = self.path.open('a+b')
        try:
            # On Windows, reading a byte another process has locked can raise
            # PermissionError *before* the lock attempt.  fstat checks the size
            # without touching the locked range.  Keep the 1-byte sentinel so
            # msvcrt.locking always has a byte to lock at offset zero.
            if os.fstat(f.fileno()).st_size == 0:
                f.write(b'0')
                f.flush()
            f.seek(0)
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    # Preserve immediate failure for existing monitoring callers;
                    # publication/role callers opt into bounded serialization.
                    if os.name != 'nt' and not isinstance(exc, BlockingIOError):
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AlreadyRunning('另一轮任务尚未释放状态锁') from exc
                    time.sleep(min(0.05, remaining))
                else:
                    break
            self._file = f
            return self
        except BaseException:
            f.close()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        f = self._file
        if f is not None:
            try:
                f.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            finally:
                f.close()
                self._file = None
