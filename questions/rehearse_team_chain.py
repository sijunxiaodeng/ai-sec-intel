"""Three isolated offline HTTP rehearsals; synthetic data is never real CVE evidence.

Run in the root environment, passing B's separate Python with --team-python.
Only committed source is exported; each run has fresh data and localhost ports.
External monitoring and document fetches are fixture substitutions in this tool,
not changes to the production app. No chat model or embedding model is downloaded.
"""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import socket
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2026-10001"


def fixture():
    return {
        "id": CVE,
        "descriptions": [{"lang": "en", "value":
            "SYNTHETIC OFFLINE FIXTURE: Ollama regression input, not a real vulnerability claim."}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "0.1.34",
        }]}]}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "synthetic-fixture",
            "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
        "references": [{"url": "https://example.org/offline-unavailable/" + CVE}],
    }


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def command(args, cwd):
    result = subprocess.run(args, cwd=cwd, encoding="utf-8", errors="replace",
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError("child command failed (%d): %s" % (result.returncode, result.stderr[-2000:]))
    return result.stdout


def inspect_state():
    from rag.ingest import document_status
    from rag.retrieve import search
    from rag.evidence import DEFAULT_DB, _all_evidence, _connection
    with _connection(DEFAULT_DB) as connection:
        snapshots = connection.execute("SELECT digest, body FROM source_snapshots").fetchall()
    from rag.library import LIBRARY_DB
    library_hashes_ok = False
    if LIBRARY_DB.exists():
        with _connection(LIBRARY_DB) as connection:
            library_snapshots = connection.execute("SELECT digest,body FROM library_snapshots").fetchall()
        library_hashes_ok = bool(library_snapshots) and all(
            digest == hashlib.sha256(body).hexdigest() for digest, body in library_snapshots)
    return {"documents": document_status(CVE), "mode": search(CVE + " CVSS")[0]["retrieval_mode"],
            "ids": [row["evidence_id"] for row in _all_evidence(DEFAULT_DB)],
            "library_hashes_ok": library_hashes_ok,
            "snapshots_match_hashes": bool(snapshots) and all(
                digest == hashlib.sha256(body).hexdigest() for digest, body in snapshots)}


def seed_team(db):
    # Separate process: B and the root project have overlapping package names.
    sys.path.insert(0, str(ROOT / "intelligence"))
    from collectors.base import IntelligenceItem
    from storage.sqlite_store import SQLiteIntelligenceStore
    SQLiteIntelligenceStore(db).ingest_batch("NVD", [IntelligenceItem(
        source="NVD", source_id=CVE, cve_id=CVE,
        title="SYNTHETIC OFFLINE FIXTURE", description=fixture()["descriptions"][0]["value"],
        url=None, published_at="2026-10-08T01:00:00Z", modified_at="2026-10-08T02:00:00Z",
        severity=None, raw_data=fixture(),
    )])
    from collectors.documents import KnowledgeDocument, make_document_id
    from storage.document_store import SQLiteDocumentStore
    store = SQLiteDocumentStore(db)
    for category in ("security_blog", "academic_paper", "technical_standard", "policy_regulation"):
        source = "SYNTHETIC_" + category.upper()
        store.ingest(source, category, [KnowledgeDocument(
            document_id=make_document_id(source, "offline-fixture"), source=source,
            source_category=category, content_type=category,
            title="SYNTHETIC OFFLINE LLM security " + category,
            description="Synthetic prompt injection summary: LLM applications may read untrusted instructions in retrieved documents.",
            url="https://example.org/offline-fixture/" + category,
            published_at="2026-10-08", modified_at=None, raw_data={"synthetic_fixture": True},
        )])


def serve_fixture_app(team_url, port):
    from unittest.mock import patch
    import uvicorn
    from agents import monitor_agent, orchestrator
    from collectors.intelligence import IntelligenceCollector
    from rag.ingest import ingest
    from rag.library import sync_team
    from api.app import app

    original_open = urllib.request.urlopen

    def localhost_only(request, *args, **kwargs):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if urllib.parse.urlsplit(url).hostname != "127.0.0.1":
            raise OSError("offline rehearsal blocks external HTTP")
        return original_open(request, *args, **kwargs)

    def fetch_fixture(url):
        if urllib.parse.urlsplit(url).hostname == "services.nvd.nist.gov":
            payload = {"vulnerabilities": [{"cve": fixture()}]}
            return {"body": json.dumps(payload).encode("utf-8"),
                    "content_type": "application/json", "url": url}
        raise TimeoutError("synthetic offline reference failure")

    with ExitStack() as stack:
        stack.enter_context(patch.object(monitor_agent.NVDCollector, "collect",
                                         side_effect=TimeoutError("synthetic NVD monitor failure")))
        stack.enter_context(patch.object(monitor_agent.OSVCollector, "collect",
                                         side_effect=TimeoutError("synthetic OSV monitor failure")))
        stack.enter_context(patch.object(monitor_agent, "IntelligenceCollector",
            side_effect=lambda keyword: IntelligenceCollector(keyword, base_url=team_url, timeout=2)))
        stack.enter_context(patch.object(orchestrator, "ingest",
            side_effect=lambda record, **kwargs: ingest(record, fetcher=fetch_fixture, **kwargs)))
        stack.enter_context(patch("rag.library.sync_team", side_effect=lambda **kwargs: sync_team(base_url=team_url, **kwargs)))
        stack.enter_context(patch.object(urllib.request, "urlopen", side_effect=localhost_only))
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def export_source(destination):
    destination.mkdir()
    archive = destination.parent / "source.tar"
    with archive.open("wb") as output:
        subprocess.run(["git", "archive", "HEAD"], cwd=ROOT, stdout=output, check=True, timeout=30)
    # Reject symlinks/traversal, and write regular files only (also works on Python 3.10).
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe source archive member")
            target = destination.joinpath(*relative.parts).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise ValueError("source archive escapes rehearsal directory")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as file:
                    target.write_bytes(file.read())
    if (destination / "data").exists() or (destination / "config/local.json").exists():
        raise ValueError("archive unexpectedly contains local state")
    # Disable committed historical demo cards in this disposable fixture copy only.
    (destination / "cards.json").write_text("[]", encoding="utf-8")
    (destination / "cards.js").write_text("window.CARDS = [];\n", encoding="utf-8")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(base, path, payload=None):
    start = time.perf_counter()
    request = urllib.request.Request(base + path,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        value = json.load(response)
    return value, round((time.perf_counter() - start) * 1000, 2)


def wait_ready(process, base, path):
    deadline = time.monotonic() + 20
    while process.poll() is None and time.monotonic() < deadline:
        try:
            return http(base, path)[0]
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("local service did not become ready; see service log")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def rehearse(directory, team_python):
    directory.mkdir()
    source = directory / "source"
    export_source(source)
    result = {"passed": False, "checks": [], "http": [], "model_calls": 0}
    raw_responses = []

    def require(name, passed):
        result["checks"].append({"name": name, "passed": bool(passed)})
        if not passed:
            raise AssertionError(name)

    def request(path, payload=None):
        value, elapsed = http(root_base, path, payload)
        result["http"].append({"path": path, "elapsed_ms": elapsed})
        raw_responses.append({"path": path, "request": payload, "response": value})
        return value

    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    db = directory / "intelligence.db"
    env["INTELLIGENCE_DB_PATH"] = str(db)
    processes = []
    try:
        command([team_python, "-m", "questions.rehearse_team_chain", "--seed-team", str(db)], source)
        command([team_python, str(source / "intelligence/run_rebuild_unified.py"), "--db", str(db)], source)
        command([team_python, str(source / "intelligence/run_ai_classification_v5.py"), "--db", str(db),
                 "--max-items", "10", "--max-llm-calls", "0"], source)
        status = json.loads((directory / "classification_status.json").read_text(encoding="utf-8"))
        require("rule_classification_without_model", status["stats"]["positive"] == 1
                and status["stats"]["semantic_calls"] == 0)
        with ExitStack() as files:
            team_port = free_port()
            team_base = "http://127.0.0.1:%d" % team_port
            team_log = files.enter_context((directory / "team.log").open("w", encoding="utf-8"))
            team = subprocess.Popen([team_python, str(source / "intelligence/run_intelligence_api_v6.py"),
                "--port", str(team_port)], cwd=source, env=env, stdout=team_log, stderr=team_log)
            processes.append(team)
            health = wait_ready(team, team_base, "/api/intelligence/health")
            require("team_database_available", health["database_available"])
            root_port = free_port()
            root_base = "http://127.0.0.1:%d" % root_port
            root_log = files.enter_context((directory / "root.log").open("w", encoding="utf-8"))
            root = subprocess.Popen([sys.executable, "-m", "questions.rehearse_team_chain", "--serve",
                "--team-url", team_base, "--port", str(root_port)], cwd=source, env=env,
                stdout=root_log, stderr=root_log)
            processes.append(root)
            settings = wait_ready(root, root_base, "/api/settings")
            require("no_chat_key", not settings["has_key"])
            collected = request("/api/collect", {"keyword": "ollama"})
            require("team_collect_enrich_store", collected["count"] == 1
                    and collected["items"][0]["cve_id"] == CVE and collected["items"][0]["cvss"] == 9.8)
            failed_steps = [row for row in collected["steps"] if "失败" in row["action"]]
            require("nvd_osv_failures_preserved", len(failed_steps) == 2)
            score = request("/api/ask", {"question": CVE + " 的 CVSS 评分、向量和来源是什么？"})
            require("score_and_source", "9.8" in score["answer"] and "CVSS:3.1/" in score["answer"]
                    and "synthetic-fixture" in score["answer"])
            versions = request("/api/ask", {"question": "那受影响的版本范围是什么？不要比较评分。",
                                             "session_id": score["session_id"]})
            require("followup_keeps_entity_and_changes_fields", versions["turn"] == 2
                    and versions["context"]["cve_ids"] == [CVE] and "0.1.34" in versions["answer"]
                    and "9.8" not in versions["answer"])
            for answer in (score, versions):
                citations = set(re.findall(r"\[(CVE-\d{4}-\d{4,7}/[^\]\s]+)\]", answer["answer"]))
                known = {row["citation_id"] for row in answer["evidence_chunks"]}
                require("citations_and_verifier", bool(citations) and citations <= known and answer["verdict"]["passed"])
                require("model_not_attempted", not answer["model_attempted"] and not answer["used_model"])
            ambiguous = request("/api/ask", {"question": "那版本范围呢？"})
            require("new_session_has_no_old_context", not ambiguous["evidence"]
                    and "无法确定" in ambiguous["answer"])
            unknown = request("/api/ask", {"question": "CVE-2099-99999 的评分？",
                                            "session_id": score["session_id"]})
            require("unknown_cve_has_no_old_evidence", not unknown["evidence"] and "9.8" not in unknown["answer"])
            before = json.loads(command([sys.executable, "-m", "questions.rehearse_team_chain", "--inspect"], source))
            repeated = request("/api/collect", {"keyword": "ollama"})
            require("repeat_collection_is_idempotent", repeated["count"] == 1)
            inspection = json.loads(command([sys.executable, "-m", "questions.rehearse_team_chain", "--inspect"], source))
            require("document_failure_preserved", any(row["status"] == "error" for row in inspection["documents"]))
            require("bm25_without_vector_model", inspection["mode"] == "bm25")
            require("repeat_evidence_is_stable", bool(inspection["ids"]) and before["ids"] == inspection["ids"])
            require("source_snapshots_match_hashes", inspection["snapshots_match_hashes"])
            imported = request("/api/library/team-sync", {"max_documents": 10})
            require("four_non_cve_types_imported", imported["status"] == "ok" and imported["ok"] == 4)
            listing = request("/api/library")
            docs = listing["items"]
            require("team_summaries_have_distinct_scope", len(docs) == 4 and all(
                doc["content_scope"] == "team_summary" and doc["source_snapshot_kind"] == "team_api_record" for doc in docs))
            library_answer = request("/api/library/ask", {"question": "prompt injection", "use_model": False,
                                                          "document_ids": [doc["document_id"] for doc in docs]})
            cited = set(re.findall(r"\[(DOC-[a-f0-9]{16}/[^\]\s]+)\]", library_answer["answer"]))
            require("team_summary_qa_has_bound_citations", bool(cited) and cited <= {
                row["citation_id"] for row in library_answer["evidence"]} and library_answer["verdict"]["passed"])
            require("team_summary_qa_retains_scope_without_model", not library_answer["model_attempted"]
                    and "接口字段摘录" in library_answer["answer"] and "非原始全文" in library_answer["answer"])
            repeat_import = request("/api/library/team-sync", {"max_documents": 10})
            require("repeat_team_document_import_is_stable", repeat_import["ok"] == 4 and repeat_import["changed"] == 0)
            library_state = json.loads(command([sys.executable, "-m", "questions.rehearse_team_chain", "--inspect"], source))
            require("team_api_snapshots_match_hashes", library_state["library_hashes_ok"])
            stop(team)
            outage = request("/api/library/team-sync", {"max_documents": 10})
            require("team_service_outage_retains_documents", outage["status"] == "error"
                    and outage["overview"]["documents"] == 4)
            after_outage = request("/api/library/ask", {"question": "prompt injection", "use_model": False,
                                                        "document_ids": [doc["document_id"] for doc in docs]})
            require("stored_summaries_remain_answerable", after_outage["answer"] == library_answer["answer"])
            result["team_documents"] = {"types": sorted({doc["document_type"] for doc in docs}),
                                        "count": 4, "scope": "team_summary", "outage_retained": True}
            # Stop only the processes created by this rehearsal, including on failure.
            for process in reversed(processes):
                stop(process)
        result["retrieval_mode"] = inspection["mode"]
        result["document_statuses"] = [row["status"] for row in inspection["documents"]]
        result["passed"] = True
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        for process in reversed(processes):
            stop(process)
        write_json(directory / "responses.json", raw_responses)
        write_json(directory / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--team-python", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seed-team", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--inspect", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--team-url", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.seed_team:
        seed_team(args.seed_team)
        return
    if args.serve:
        serve_fixture_app(args.team_url, args.port)
        return
    if args.inspect:
        print(json.dumps(inspect_state(), ensure_ascii=False))
        return
    if not args.team_python or not args.team_python.is_file() or not args.output:
        parser.error("--team-python and --output are required")
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "data").resolve()) or output.exists():
        parser.error("output must be a new directory under this checkout's data/")
    if command(["git", "status", "--porcelain"], ROOT).strip():
        parser.error("commit changes first; rehearsal exports committed source only")
    output.mkdir(parents=True)
    team_python = str(args.team_python.absolute())
    result = {
        "source_commit": command(["git", "rev-parse", "HEAD"], ROOT).strip(),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"os": platform.platform(), "python": platform.python_version(),
            "root_dependencies": json.loads(command([sys.executable, "-m", "pip", "list", "--format=json"], ROOT)),
            "team_dependencies": json.loads(command([team_python, "-m", "pip", "list", "--format=json"], ROOT))},
        "scope": "same-machine isolated offline CVE and team summary HTTP rehearsal with synthetic input; not original document retrieval, independent quality or six-hour latency",
        "fixture_cve": CVE,
        "fixture_sha256": hashlib.sha256(json.dumps(fixture(), sort_keys=True).encode()).hexdigest(),
        "fresh_runs": [rehearse(output / ("run%d" % i), team_python) for i in range(1, 4)],
        "independent_accuracy": None, "competition_passed": None,
    }
    result["passed"] = all(run["passed"] for run in result["fresh_runs"])
    write_json(output / "summary.json", result)
    print(json.dumps({"passed": result["passed"], "source_commit": result["source_commit"],
                      "runs": result["fresh_runs"]}, ensure_ascii=False, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
