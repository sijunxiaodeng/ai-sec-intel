"""Content versioning for the standalone web client, with no build-tool dependency."""
import hashlib
import re
from pathlib import Path


def web_version(directory):
    root = Path(directory)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".html", ".js", ".css"}:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def versioned_html(directory, version):
    text = (Path(directory) / "index.html").read_text(encoding="utf-8")
    text = text.replace("__WEB_VERSION__", version)
    return re.sub(r'(/assets/[^"?]+)(?:\?v=[^"\s]+)?(?=")',
                  lambda match: match.group(1) + "?v=" + version, text)
