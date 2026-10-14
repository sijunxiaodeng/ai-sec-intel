#!/usr/bin/env python3
"""Verified main/C state backup and restore to a new directory, never in place."""
from __future__ import annotations

import argparse
import ctypes
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
import errno
from pathlib import Path
import shutil
import sqlite3
import tempfile
import sys

DATABASES = frozenset({"knowledge.sqlite3", "task_c.sqlite3", "library.sqlite3", "assets.sqlite3",
                       "asset-observations.sqlite3", "poc-sources.sqlite3", "paper_queries.sqlite3"})
PUBLIC_FILES = frozenset({"cards.json", "cards.js", "monitor.json", "knowledge.json", "runs.json"})
SETTINGS = "model-settings.json"
MANIFEST = "backup-manifest.json"


class BackupError(ValueError):
    pass


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def check_database(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise BackupError("SQLite integrity check failed")
        return sorted(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'"))


def destination_allowed(destination):
    if destination.is_symlink() or destination.exists():
        raise BackupError("Destination must not exist; restore never replaces existing data")
    destination.parent.mkdir(parents=True, exist_ok=True)


def destination_path(value):
    path = Path(value).absolute()
    if path.is_symlink():
        raise BackupError("Destination cannot be a symbolic link")
    return path.parent.resolve() / path.name


def publish_directory(staged, destination):
    """Atomically install a complete directory, refusing a concurrent target."""
    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        rename = getattr(library, "renameat2", None)
        if rename is None:
            raise BackupError("Atomic no-replace publication requires Linux renameat2")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staged), -100, os.fsencode(destination), 1):
            number = ctypes.get_errno()
            if number in {errno.EEXIST, errno.ENOTEMPTY}:
                raise BackupError("Destination appeared during publication; existing data preserved")
            raise OSError(number, os.strerror(number))
    elif os.name == "nt":
        # Windows rename refuses an existing target, including an empty directory.
        os.rename(staged, destination)
    else:
        raise BackupError("Atomic no-replace publication is supported on Linux and Windows")


def backup(source, destination, *, quiesced=False, include_settings=False):
    """SQLite backup folds WAL into each copy. Stop writers for a cross-DB cut."""
    source, destination = Path(source).resolve(), destination_path(destination)
    if not quiesced:
        raise BackupError("Stop main/C writers before a cross-database backup and pass --quiesced")
    if not source.is_dir() or not (source / "knowledge.sqlite3").is_file():
        raise BackupError("Source must contain an existing main knowledge.sqlite3")
    if source in destination.parents:
        raise BackupError("Destination cannot be inside the source data directory")
    destination_allowed(destination)
    staged = Path(tempfile.mkdtemp(prefix=".backup-", dir=destination.parent))
    try:
        names = DATABASES | PUBLIC_FILES | ({SETTINGS} if include_settings else set())
        files = {}
        for name in sorted(names):
            live, copied = source / name, staged / name
            if live.is_symlink():
                raise BackupError("Backup source contains a non-regular state file")
            if not live.exists():
                continue
            if not live.is_file():
                raise BackupError("Backup source contains a non-regular state file")
            if name in DATABASES:
                with closing(sqlite3.connect(live.as_uri() + "?mode=ro", uri=True, timeout=30)) as connection:
                    with closing(sqlite3.connect(copied, timeout=30)) as target:
                        connection.backup(target)
                        target.execute("PRAGMA journal_mode=DELETE")
                tables = check_database(copied)
            else:
                shutil.copyfile(live, copied)
                tables = None
            os.chmod(copied, 0o600)
            files[name] = {"sha256": digest(copied), "size": copied.stat().st_size}
            if tables is not None:
                files[name]["tables"] = tables
        manifest = {"format_version": 1, "kind": "main-and-c", "created_at": datetime.now(timezone.utc).isoformat(),
                    "writers_quiesced": True, "secrets_included": SETTINGS in files, "files": files,
                    "excluded": [".env.production", "config/local.json", "logs", "WAL/SHM/locks", "B collector/Actions generation"]}
        manifest_path = staged / MANIFEST
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        verify(staged)
        publish_directory(staged, destination)
        return manifest
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def verify(source):
    source = Path(source).resolve()
    if (source / MANIFEST).is_symlink():
        raise BackupError("Manifest cannot be a symbolic link")
    try:
        manifest = json.loads((source / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError("Backup manifest unavailable or invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("format_version") != 1 or manifest.get("kind") != "main-and-c":
        raise BackupError("Unsupported backup manifest")
    files = manifest.get("files")
    allowed = DATABASES | PUBLIC_FILES | {SETTINGS}
    if not isinstance(files, dict) or "knowledge.sqlite3" not in files or not set(files) <= allowed:
        raise BackupError("Backup file inventory is invalid")
    if set(path.name for path in source.iterdir()) != set(files) | {MANIFEST}:
        raise BackupError("Backup contents do not match the manifest")
    for name, info in files.items():
        path = source / name
        if not isinstance(info, dict) or path.is_symlink() or not path.is_file():
            raise BackupError("Backup contains a non-regular state file")
        if path.stat().st_size != info.get("size") or digest(path) != info.get("sha256"):
            raise BackupError("Backup checksum or size mismatch")
        if name in DATABASES and check_database(path) != info.get("tables"):
            raise BackupError("Backup SQLite schema inventory mismatch")
    return manifest


def restore(source, destination):
    source, destination = Path(source).resolve(), destination_path(destination)
    manifest = verify(source)
    destination_allowed(destination)
    staged = Path(tempfile.mkdtemp(prefix=".restore-", dir=destination.parent))
    try:
        for name in manifest["files"]:
            copied = staged / name
            shutil.copyfile(source / name, copied)
            os.chmod(copied, 0o600)
            if digest(copied) != manifest["files"][name]["sha256"]:
                raise BackupError("Backup changed while restoring")
        publish_directory(staged, destination)
        return {"restored_files": sorted(manifest["files"]), "secrets_included": manifest.get("secrets_included", False)}
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("backup", "verify", "restore"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination")
    parser.add_argument("--quiesced", action="store_true", help="Main/C writers have been stopped")
    parser.add_argument("--include-settings", action="store_true", help="Include model-settings.json, which can contain API credentials")
    args = parser.parse_args()
    if args.command != "verify" and not args.destination:
        parser.error("--destination is required")
    try:
        result = verify(args.source) if args.command == "verify" else (
            backup(args.source, args.destination, quiesced=args.quiesced, include_settings=args.include_settings)
            if args.command == "backup" else restore(args.source, args.destination))
        # Manifest includes file metadata only, never model settings or record bodies.
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (BackupError, OSError, sqlite3.Error) as exc:
        parser.exit(1, "State operation failed: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
