"""Serve only registered, hash-checked acceptance artifacts, never runtime files."""
import hashlib
import json
import os
from pathlib import Path
import re

ALLOWED = {".pdf", ".docx", ".pptx", ".mp4", ".png", ".jpg", ".json", ".txt", ".log"}
IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


def directory():
    from config.paths import DATA_ROOT
    return Path(os.environ.get("ACCEPTANCE_EVIDENCE_DIR") or DATA_ROOT / "acceptance-evidence").resolve()


def catalog():
    root = directory()
    manifest = root / "manifest.json"
    if not manifest.is_file():
        return []
    if manifest.stat().st_size > 1024 * 1024:
        raise ValueError("验收材料清单过大")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, list) or len(data) > 300:
        raise ValueError("验收材料清单格式错误")
    seen, result = set(), []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("验收材料条目格式错误")
        identity, name, sha = entry.get("id", ""), entry.get("filename", ""), entry.get("sha256", "")
        if not isinstance(identity, str) or not IDENTITY.fullmatch(identity) or identity in seen:
            raise ValueError("验收材料编号须唯一")
        if not isinstance(name, str) or not name or name != Path(name).name or "/" in name or "\\" in name:
            raise ValueError("验收材料只能使用登记目录中的单个文件")
        target = root / name
        if target.suffix.lower() not in ALLOWED or target.is_symlink() or not target.resolve().is_relative_to(root):
            raise ValueError("不允许的验收材料文件")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
            raise ValueError("验收材料缺少 SHA-256")
        seen.add(identity)
        result.append({"id": identity, "filename": name, "title": str(entry.get("title") or name)[:200],
                       "kind": str(entry.get("kind") or "evidence")[:60], "sha256": sha,
                       "source_commit": str(entry.get("source_commit") or "")[:64],
                       "captured_at": str(entry.get("captured_at") or "")[:50],
                       "note": str(entry.get("note") or "")[:1000], "available": target.is_file(),
                       "bytes": target.stat().st_size if target.is_file() else None,
                       "download_url": "/api/acceptance/evidence/" + identity + "/download"})
    return result


def resolve(identity):
    entry = next((row for row in catalog() if row["id"] == identity), None)
    if entry is None or not entry["available"]:
        raise KeyError("材料不存在或尚未登记")
    target = directory() / entry["filename"]
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != entry["sha256"]:
        raise ValueError("材料摘要不一致，已停止下载；请重新核对登记文件")
    return target, entry
