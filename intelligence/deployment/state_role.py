"""Prevent a local collector and an Actions mirror from sharing writable state."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from .file_lock import exclusive_file_lock
except ImportError:  # Direct script: python deployment/state_role.py …
    if not __package__:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from deployment.file_lock import exclusive_file_lock
    except ImportError:
        from file_lock import exclusive_file_lock


def claim_role(directory, role):
    if role not in {"collector", "actions-mirror"}:
        raise ValueError("Unknown state role")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with exclusive_file_lock(directory / ".runtime-role.lock", timeout=30):
        marker = directory / ".writer-mode"
        if marker.exists() and marker.read_text().strip() != role:
            raise RuntimeError("This volume belongs to a different writer mode; use a separate volume")
        if role == "actions-mirror" and (directory / "intelligence.db").exists():
            raise RuntimeError("A collector database exists in the mirror volume; it cannot be overwritten")
        if role == "collector" and ((directory / "current").exists() or (directory / "snapshots").exists()):
            raise RuntimeError("Mirror snapshots exist in the collector volume; use a separate volume")
        marker.write_text(role + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--role", choices=("collector", "actions-mirror"), required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("An executable command is required after --")
    claim_role(args.directory, args.role)
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
