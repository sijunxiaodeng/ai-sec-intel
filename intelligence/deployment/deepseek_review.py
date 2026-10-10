"""Bounded optional DeepSeek phase after public intelligence has been committed.

Only the child receives a model credential. It runs in its own process group,
which is killed at an absolute deadline. Persisted classifications survive that
deadline; collection timestamps, source cursors and first-seen values are read
only here. Progress and public status contain an explicit safe field allowlist.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_URL = "https://api.deepseek.com/v1/chat/completions"
DEFAULT_MODEL = "deepseek-chat"
MAX_CALLS = 2
REQUEST_TIMEOUT_SECONDS = 20
WALL_TIMEOUT_SECONDS = 60
REASONS = {
    "completed", "no_candidates", "disabled", "missing_api_key", "classification_locked",
    "wall_timeout", "authentication_failed", "rate_limited", "request_timeout",
    "provider_unavailable", "invalid_response", "request_error", "processing_error",
    "invalid_configuration", "progress_unavailable", "progress_invalid",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".deepseek_", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _valid_model(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", value) is not None


def _classification_snapshot(path):
    """Read only classification metadata, never source data or credential files."""
    if not Path(path).is_file():
        return {}
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        db.execute("PRAGMA query_only=ON")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='ai_classifications' AND type='table'").fetchone():
            return {}
        rows = db.execute("""SELECT cve_id,attempts,content_sha256,classifier_version,
            state,decision_source,updated_at FROM ai_classifications""").fetchall()
    return {row[0]: tuple(row[1:]) for row in rows}


def _committed(before, after):
    changed = [value for cve, value in after.items() if before.get(cve) != value]
    return (
        sum(value[3] in {"classified", "review"} and value[4] == "semantic_judge" for value in changed),
        sum(value[3] == "retry" for value in changed),
    )


def _read_progress(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            # This is a tiny internal counter file, never a raw provider response.
            value = json.loads(stream.read(4097))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    for key in ("semantic_calls", "semantic_success", "retry"):
        number = value.get(key)
        if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= MAX_CALLS:
            return None
    if value["semantic_success"] + value["retry"] > value["semantic_calls"]:
        return None
    if value.get("reason_category") not in REASONS:
        return None
    if value.get("status") not in {"running", "success", "partial", "failed", "skipped"}:
        return None
    return {key: value[key] for key in ("semantic_calls", "semantic_success", "retry", "reason_category", "status")}


def _child_environment(api_key, model):
    # Do not give source/GitHub credentials to the model subprocess.
    allowed = {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR",
               "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"}
    env = {name: value for name, value in os.environ.items() if name in allowed}
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "DEEPSEEK_API_KEY": api_key,
                "DEEPSEEK_MODEL": model, "LLM_CHAT_COMPLETIONS_URL": "", "LLM_API_BASE": "",
                "LLM_API_KEY": "", "LLM_MODEL": "", "LLM_TIMEOUT": str(REQUEST_TIMEOUT_SECONDS)})
    return env


def _worker_command(db_path, progress_path, max_calls, model):
    return [sys.executable, str(Path(__file__).resolve()), "--worker", "--db", str(db_path),
            "--progress", str(progress_path), "--max-llm-calls", str(max_calls), "--model", model]


def run_review(db_path, *, enabled=True, api_key=None, model=DEFAULT_MODEL,
               max_llm_calls=MAX_CALLS, timeout_seconds=WALL_TIMEOUT_SECONDS, run_id=None):
    """Return public status even on model failure; never block collection backup."""
    db_path = Path(db_path).resolve()
    status_path = db_path.parent / "deepseek_status.json"
    if api_key is None:
        api_key = os.getenv("DEEPSEEK_API_KEY", "")
    run_id = run_id if run_id is not None else os.getenv("GITHUB_RUN_ID", "local")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
        run_id = "unknown"
    status = {
        "status": "running", "model": model if _valid_model(model) else DEFAULT_MODEL,
        "provider": "deepseek", "started_at": utc_now(), "finished_at": None,
        "run_id": run_id, "semantic_calls": 0, "semantic_success": 0, "retry": 0,
        "max_llm_calls": max_llm_calls if isinstance(max_llm_calls, int) and not isinstance(max_llm_calls, bool)
                         and 0 <= max_llm_calls <= MAX_CALLS else MAX_CALLS,
        "reason_category": "completed", "committed_classifications": 0, "committed_retries": 0,
    }
    progress_path, child = None, None
    try:
        if not enabled:
            status.update(status="skipped", reason_category="disabled")
        elif not isinstance(api_key, str) or not api_key.strip():
            status.update(status="skipped", reason_category="missing_api_key")
        elif (not _valid_model(model) or isinstance(max_llm_calls, bool) or not isinstance(max_llm_calls, int)
              or not 1 <= max_llm_calls <= MAX_CALLS or not 0 < timeout_seconds <= WALL_TIMEOUT_SECONDS
              or os.name != "posix"):
            status.update(status="failed", reason_category="invalid_configuration")
        else:
            before = _classification_snapshot(db_path)
            fd, temporary = tempfile.mkstemp(prefix=".deepseek_progress_", suffix=".json", dir=db_path.parent)
            os.close(fd)
            progress_path = Path(temporary)
            child = subprocess.Popen(
                _worker_command(db_path, progress_path, max_llm_calls, model), cwd=ROOT,
                env=_child_environment(api_key, model), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
            )
            timed_out = False
            try:
                child.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                # No graceful interval extends the absolute deadline; descendants
                # cannot continue issuing paid requests after this group is killed.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=2)
            progress = _read_progress(progress_path)
            if progress is not None:
                status.update(progress)
            if timed_out:
                status.update(status="timeout", reason_category="wall_timeout")
            elif child.returncode != 0:
                status.update(status="failed", reason_category="processing_error")
            elif progress is None:
                status.update(status="failed", reason_category="progress_unavailable")
            elif progress["status"] == "running":
                status.update(status="failed", reason_category="processing_error")
            saved, retries = _committed(before, _classification_snapshot(db_path))
            status.update(committed_classifications=saved, committed_retries=retries)
    except Exception:
        # Never serialize exception text: URLs, headers or server text may contain a credential.
        status.update(status="failed", reason_category="processing_error")
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
    finally:
        if progress_path is not None:
            progress_path.unlink(missing_ok=True)
        status["finished_at"] = utc_now()
        _atomic_json(status_path, status)
    return status


def _reason(exc):
    import requests
    code = getattr(getattr(exc, "response", None), "status_code", None)
    if code in {401, 403}:
        return "authentication_failed"
    if code == 429:
        return "rate_limited"
    if isinstance(code, int) and code >= 500:
        return "provider_unavailable"
    if isinstance(exc, requests.Timeout):
        return "request_timeout"
    if isinstance(exc, ValueError):
        return "invalid_response"
    return "request_error"


def _worker(db_path, progress_path, model, max_calls):
    """Child only: reuse the validated semantic/rule classifier and additive store."""
    sys.path.insert(0, str(ROOT))
    from classification.semantic_judge import SemanticJudge
    from classification.hybrid_classifier import HybridAIClassifier
    from ai_pipeline.worker_v5 import run_priority_batch
    from monitoring.lock import AlreadyRunning, ProcessFileLock

    progress = {"status": "running", "semantic_calls": 0, "semantic_success": 0,
                "retry": 0, "reason_category": "completed"}

    def save():
        _atomic_json(progress_path, progress)

    class BoundedJudge(SemanticJudge):
        def __init__(self):
            # No .env reads or configurable endpoint: this phase is DeepSeek only.
            self.url, self.model, self.timeout = OFFICIAL_URL, model, REQUEST_TIMEOUT_SECONDS
            self.api_key = os.getenv("DEEPSEEK_API_KEY", "")

        def is_configured(self):
            return bool(self.api_key.strip()) and _valid_model(self.model)

        def judge(self, **record):
            if progress["semantic_calls"] >= max_calls:
                raise RuntimeError("Model invocation budget exhausted")
            progress["semantic_calls"] += 1
            save()
            try:
                result = super().judge(**record)
            except Exception as exc:
                progress["retry"] += 1
                progress["reason_category"] = _reason(exc)
                save()
                raise
            progress["semantic_success"] += 1
            save()
            return result

    save()
    try:
        if not _valid_model(model) or not 1 <= max_calls <= MAX_CALLS or not os.getenv("DEEPSEEK_API_KEY", "").strip():
            progress.update(status="failed", reason_category="invalid_configuration")
            return 1
        with ProcessFileLock(Path(db_path).parent / ".ai_classification.lock"):
            # Same code digest as the existing worker/API, without importing the
            # CLI modules that automatically read a local .env file.
            import hashlib
            digest = hashlib.sha256()
            for name in ("ai_relevance.py", "hybrid_classifier.py", "semantic_judge.py"):
                source = ROOT / "classification" / name
                digest.update(source.name.encode())
                digest.update(source.read_bytes())
            version = "hybrid-v3.1-" + digest.hexdigest()[:12]
            run_priority_batch(db_path, version, 300, max_calls,
                               HybridAIClassifier(BoundedJudge()), verbose=False)
        if progress["retry"]:
            progress["status"] = "partial" if progress["semantic_success"] else "failed"
        else:
            progress.update(status="success", reason_category="completed" if progress["semantic_calls"] else "no_candidates")
        return 0
    except AlreadyRunning:
        progress.update(status="skipped", reason_category="classification_locked")
        return 0
    except Exception:
        progress.update(status="failed", reason_category="processing_error")
        return 1
    finally:
        save()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Optional bounded DeepSeek semantic review")
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "intelligence.db")
    parser.add_argument("--model", default=os.getenv("DEEPSEEK_MODEL", DEFAULT_MODEL))
    parser.add_argument("--max-llm-calls", type=int, default=MAX_CALLS)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--progress", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        if args.progress is None:
            return 1
        return _worker(args.db, args.progress, args.model, args.max_llm_calls)
    enabled = os.getenv("DEEPSEEK_REVIEW_ENABLED", "true").strip().lower() in {"true", "1", "yes"}
    try:
        status = run_review(args.db, enabled=enabled, model=args.model, max_llm_calls=args.max_llm_calls)
    except Exception:
        print("::notice::DeepSeek status could not be saved; public collection state remains available.", flush=True)
        return 0
    print(json.dumps(status, ensure_ascii=False, sort_keys=True), flush=True)
    if status["status"] in {"failed", "partial", "timeout"}:
        print("::notice::DeepSeek review was incomplete; committed results and public collection will still be backed up.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
