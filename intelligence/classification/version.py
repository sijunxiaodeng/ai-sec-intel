"""One dependency-free classification contract for workers, APIs and snapshots."""
from __future__ import annotations

import hashlib
from pathlib import Path

CLASSIFIER_FILES = (
    "classification/ai_relevance.py",
    "classification/hybrid_classifier.py",
    "classification/semantic_judge.py",
    "classification/scope_policy.py",
)


def classifier_version(root: Path | None = None) -> str:
    """Hash all decision inputs without loading settings or provider credentials."""
    root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for name in CLASSIFIER_FILES:
        path = root / name
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return "hybrid-v3.1-" + digest.hexdigest()[:12]
