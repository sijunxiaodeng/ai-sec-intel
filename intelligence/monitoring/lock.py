"""Portable process lock. OS releases the lock if the Python process exits."""
from __future__ import annotations

import os
from pathlib import Path


class AlreadyRunning(RuntimeError):
    """Another scheduled monitoring run currently holds the lock."""


class ProcessFileLock:
    def __init__(self, path: Path):
        self.path = Path(path)
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
            if os.name == 'nt':
                import msvcrt
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise AlreadyRunning('另一轮监测尚未结束，跳过本次任务') from exc
            else:
                import fcntl
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise AlreadyRunning('另一轮监测尚未结束，跳过本次任务') from exc
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
