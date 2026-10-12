"""Migrate legacy UID 10002 state to shared UID 10001 inside the main container.

Only the two fixed application data mounts are traversed. No files are deleted,
content is never opened, symbolic links are refused, and unfamiliar owners abort
before any ownership changes. Run while application/collector writers are stopped.
"""
import argparse
import os
from pathlib import Path
import stat


ROOTS = (Path('/app/data'), Path('/app/intelligence/data'))


def candidates():
    result = []
    for root in ROOTS:
        if not root.exists():
            continue
        if root.is_symlink() or root.resolve() != root:
            raise RuntimeError('data root must be the exact application mount: ' + str(root))
        for path in (root, *root.rglob('*')):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise RuntimeError('refusing special or symbolic state path: ' + str(path))
            if info.st_uid not in {10001, 10002}:
                raise RuntimeError('unexpected state owner; inspect before migration: ' + str(path))
            if info.st_uid == 10002:
                result.append(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Change only legacy-owned paths; default is read-only inspection')
    args = parser.parse_args()
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise RuntimeError('run this helper as container root, not from the Windows host')
    paths = candidates()
    if args.apply:
        for path in paths:
            os.chown(path, 10001, 10001, follow_symlinks=False)
    print(('Migrated' if args.apply else 'Legacy-owned paths found:') + ' ' + str(len(paths)))


if __name__ == '__main__':
    main()
