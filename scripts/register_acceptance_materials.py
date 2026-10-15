"""Register an explicit local artifact allowlist for the acceptance dashboard.

The web API never accepts a filesystem path. Run this operator-side command
with a JSON list of {id, path, title, kind, source_commit, captured_at, note}.
Existing files are immutable: register a new id for a revised artifact.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from acceptance import evidence


def register(entries):
    if not isinstance(entries, list) or not entries:
        raise ValueError("登记清单须为非空数组")
    root = evidence.directory()
    root.mkdir(parents=True, exist_ok=True)
    original = evidence.catalog()
    records = {row["id"]: {key: value for key, value in row.items()
                           if key not in {"available", "bytes", "download_url"}} for row in original}
    planned = []
    for item in entries:
        identity = item["id"]
        if not isinstance(identity, str) or not evidence.IDENTITY.fullmatch(identity):
            raise ValueError("材料编号格式无效")
        source = Path(item["path"]).resolve(strict=True)
        if not source.is_file() or source.suffix.lower() not in evidence.ALLOWED:
            raise ValueError("不允许的材料文件类型")
        sha = hashlib.sha256(source.read_bytes()).hexdigest()
        filename = identity + "-" + sha[:12] + source.suffix.lower()
        row = {"id": identity, "filename": filename, "sha256": sha,
               "title": str(item.get("title") or source.name), "kind": str(item.get("kind") or "evidence"),
               "source_commit": str(item.get("source_commit") or ""),
               "captured_at": str(item.get("captured_at") or ""), "note": str(item.get("note") or "")}
        if identity in records and records[identity] != row:
            raise ValueError("已登记编号不可覆盖；请为新版本使用新编号：" + identity)
        records[identity] = row
        planned.append((source, root / filename, sha))
    for source, target, sha in planned:
        if target.exists():
            if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != sha:
                raise ValueError("材料目标已存在且内容不一致")
            continue
        with target.open("xb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(list(records.values()), handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, root / "manifest.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"registered": len(entries), "total": len(records)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(register(json.loads(args.manifest.read_text(encoding="utf-8"))), ensure_ascii=False))
