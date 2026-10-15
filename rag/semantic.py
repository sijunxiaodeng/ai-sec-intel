"""Read-only local semantic readiness; explicit offline preparation for both databases.

No implicit downloads, demo import, cloud model calls, or global model-setting writes.
Use rag/download_model.ps1 to fetch the pinned official ONNX bundle first.
"""
import argparse
from contextlib import closing
import importlib.metadata
import importlib.util
import json
import math
from pathlib import Path
import sqlite3
import sys
import time

from config.paths import DATA_ROOT
from rag.hybrid import MODEL_NAME, _digest, _model, _normal, build_index, config_path, update_index

MODEL_FILES = ("config.json", "model_optimized.onnx", "special_tokens_map.json",
               "tokenizer.json", "tokenizer_config.json", "vocab.txt")


def dependencies():
    result = {}
    for module, distribution in (("fastembed", "fastembed"), ("onnxruntime", "onnxruntime"),
                                 ("tokenizers", "tokenizers")):
        try:
            result[module] = importlib.metadata.version(distribution) if importlib.util.find_spec(module) else None
        except (ImportError, ValueError, importlib.metadata.PackageNotFoundError):
            result[module] = None
    return result


def _configuration(db_path):
    path = config_path(db_path)
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or value.get("model") != MODEL_NAME
            or value.get("enabled") is not True or not isinstance(value.get("cache_dir"), str)):
        raise ValueError("Invalid retrieval configuration")
    if value.get("model_dir") is not None and not isinstance(value["model_dir"], str):
        raise ValueError("Invalid local model directory")
    return value


def status(db_path, *, probe=False):
    """Inspect a single SQLite snapshot without creating a DB/table/config.

    index_ready covers current evidence digests/vectors. Only an explicit local
    probe confirms the runtime can actually produce the expected query vector.
    Paths and evidence text are deliberately absent from the returned status.
    """
    path = Path(db_path).resolve()
    result = {"database": path.name, "model": MODEL_NAME, "state": "database_missing",
              "index_ready": False, "query_ready": None, "evidence_chunks": 0,
              "current_embeddings": 0, "missing_embeddings": 0, "stale_embeddings": 0,
              "invalid_embeddings": 0, "orphan_embeddings": 0, "dependencies": dependencies()}
    if not path.is_file():
        return result
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "evidence" not in tables:
                result["state"] = "evidence_missing"
                return result
            rows = [json.loads(row[0]) for row in conn.execute("SELECT payload FROM evidence")]
            stored = {(cve, eid): (digest, vector) for cve, eid, digest, vector in conn.execute(
                "SELECT cve_id,evidence_id,digest,vector FROM embeddings WHERE model=?", (MODEL_NAME,))} if "embeddings" in tables else {}
        keys = set()
        for row in rows:
            key = row["cve_id"], row["evidence_id"]
            keys.add(key)
            old = stored.get(key)
            if old is None:
                result["missing_embeddings"] += 1
            elif old[0] != _digest(row):
                result["stale_embeddings"] += 1
            else:
                try:
                    vector = json.loads(old[1])
                    if (not isinstance(vector, list) or len(vector) != 512
                            or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in vector)
                            or not 0.99 <= sum(v * v for v in vector) <= 1.01):
                        raise ValueError("Invalid vector")
                    result["current_embeddings"] += 1
                except (ValueError, TypeError):
                    result["invalid_embeddings"] += 1
        result["evidence_chunks"] = len(rows)
        result["orphan_embeddings"] = len(set(stored) - keys)
        result["index_ready"] = bool(rows) and result["current_embeddings"] == len(rows)
        config = _configuration(path)
        if not rows:
            result["state"] = "evidence_empty"
        elif config is None:
            result["state"] = "not_configured"
        elif not all(result["dependencies"].values()):
            result["state"] = "dependencies_missing"
        elif config.get("model_dir") and not all((Path(config["model_dir"]) / name).is_file() for name in MODEL_FILES):
            result["state"] = "model_files_missing"
        elif not result["index_ready"]:
            result["state"] = "index_pending"
        else:
            result["state"] = "indexed"
            if probe:
                started = time.monotonic()
                vector = _normal(next(iter(_model(config["cache_dir"], True, config.get("model_dir")).query_embed("AI 安全漏洞修复"))))
                if len(vector) != 512:
                    raise ValueError("Unexpected query embedding dimension")
                result.update(state="ready", query_ready=True, probe_ms=round((time.monotonic() - started) * 1000))
    except Exception as exc:
        result.update(state="error", error_type=type(exc).__name__, query_ready=False if probe else None)
    return result


def prepare_databases(databases, model_dir, *, probe=True, progress=None):
    """Build once, then reuse unchanged embeddings on repeated preparation.

    Existing hybrid writers fence concurrent evidence changes at commit. Such a
    conflict is reported, never bypassed or solved by replacing the evidence DB.
    """
    paths = [Path(path).resolve() for path in databases]
    if not paths or len(set(paths)) != len(paths):
        raise ValueError("Specify distinct existing evidence databases")
    if not all(path.is_file() for path in paths):
        raise ValueError("Evidence database missing; collect/import evidence first")
    directory = Path(model_dir).resolve()
    if not all((directory / name).is_file() for name in MODEL_FILES):
        raise ValueError("Complete local ONNX model required; use rag/download_model.ps1 first")
    if not all(dependencies().values()):
        raise ValueError("Install requirements-rag.txt in the service Python environment first")
    results = []
    for path in paths:
        started = time.monotonic()
        result = {"database": path.name}
        try:
            try:
                config = _configuration(path)
            except (ValueError, TypeError):
                config = None
                result["previous_configuration_invalid"] = True
            same_model = config is not None and config.get("model_dir") and Path(config["model_dir"]).resolve() == directory
            before = status(path)
            # A corrupted vector with the current digest needs rebuilding as well.
            if same_model and not before["invalid_embeddings"]:
                result.update(operation="incremental", index=update_index(path))
            else:
                callback = (lambda event: progress(dict(event, database=path.name))) if progress else None
                result.update(operation="build", index=build_index(path, directory, progress=callback))
            result["status"] = status(path, probe=probe)
        except Exception as exc:
            result.update(error_type=type(exc).__name__, status=status(path))
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        results.append(result)
    return {"model": MODEL_NAME, "downloaded": False, "results": results,
            "ready": all(row.get("status", {}).get("query_ready") is True for row in results)}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", action="append", type=Path, help="Repeat for each existing evidence database")
    parser.add_argument("--prepare", action="store_true", help="Explicitly build/update using local model files only")
    parser.add_argument("--model-dir", type=Path)
    parser.add_argument("--probe", action="store_true", help="Also verify local CPU query inference; never downloads")
    args = parser.parse_args()
    databases = args.db or [DATA_ROOT / "task_c.sqlite3", DATA_ROOT / "library.sqlite3"]
    if args.prepare and not args.model_dir:
        parser.error("--prepare requires --model-dir; implicit model downloads are disabled")
    try:
        if args.prepare:
            report = prepare_databases(databases, args.model_dir, progress=lambda event:
                                       print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True))
        else:
            rows = [status(path, probe=args.probe) for path in databases]
            report = {"results": rows, "ready": all(row["query_ready"] is True for row in rows)}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ready"] or (not args.prepare and not args.probe) else 1
    except Exception as exc:
        print(json.dumps({"ready": False, "error_type": type(exc).__name__, "detail": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
