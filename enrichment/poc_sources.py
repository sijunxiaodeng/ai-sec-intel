"""Pinned PoC text collection and development static review; never execution.

Only explicitly catalogued GitHub files are fetched. Stored bytes are reparsed
on every report, and the current catalog is the independent hash anchor. This
module neither imports downloaded Python nor contacts a vulnerability target.
"""
import ast
from contextlib import closing
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request


ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = Path(__file__).with_name("poc_catalog.json")
DEFAULT_DB = ROOT / "data" / "poc-sources.sqlite3"
MAX_FILES = 5
MAX_CANDIDATES = 3
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
FETCH_BUDGET = 30.0
CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
NOTICE = "仅采集固定提交的公开文本并进行开发者静态审阅；没有运行 PoC、安装其依赖或请求漏洞目标。静态审阅不证明代码可用、RCE 成立或修复有效。"


def _now():
    return datetime.now(timezone.utc)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(body):
    return hashlib.sha256(body).hexdigest()


def _git_sha(body):
    return hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()


def _cve(value):
    if not isinstance(value, str) or not CVE.fullmatch(value.upper()):
        raise ValueError("需要有效 CVE 编号")
    return value.upper()


def _file_url(candidate, path, *, raw=False):
    prefix = "https://raw.githubusercontent.com/" if raw else "https://github.com/"
    middle = "/" if raw else "/blob/"
    return prefix + candidate["repository"] + middle + candidate["commit_sha"] + "/" + quote(path, safe="/")


def _validate_candidate(value):
    if not isinstance(value, dict):
        raise ValueError("PoC 目录条目必须为对象")
    candidate = copy.deepcopy(value)
    candidate["cve_id"] = _cve(candidate.get("cve_id"))
    for key, pattern in (("candidate_id", r"[A-Za-z0-9_.-]{1,120}"),
                         ("repository", REPOSITORY.pattern), ("commit_sha", r"[0-9a-f]{40}")):
        if not isinstance(candidate.get(key), str) or not re.fullmatch(pattern, candidate[key]):
            raise ValueError("PoC 目录身份或提交格式不正确")
    if any(part in (".", "..") for part in candidate["repository"].split("/")):
        raise ValueError("PoC 仓库路径无效")
    files = candidate.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("PoC 文件清单超出限定数量")
    paths = set()
    for row in files:
        if not isinstance(row, dict):
            raise ValueError("PoC 文件元数据格式不正确")
        path = row.get("path")
        if (not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,160}", path)
                or any(part in ("", ".", "..") for part in path.split("/"))
                or PurePosixPath(path).is_absolute() or path in paths
                or (PurePosixPath(path).suffix not in (".py", ".md", ".txt") and path != "LICENSE")):
            raise ValueError("PoC 文件路径不在安全文本清单内")
        paths.add(path)
        if (not isinstance(row.get("size"), int) or isinstance(row["size"], bool)
                or not 0 <= row["size"] <= MAX_FILE_BYTES
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))
                or not re.fullmatch(r"[0-9a-f]{40}", str(row.get("git_blob_sha", "")))):
            raise ValueError("PoC 文件大小或固定摘要无效")
        if set(row) != {"path", "size", "sha256", "git_blob_sha"}:
            raise ValueError("PoC 文件元数据含有未知字段")
    if sum(row["size"] for row in files) > MAX_TOTAL_BYTES:
        raise ValueError("PoC 文本总大小超出限制")
    review = candidate.get("review", {})
    if not isinstance(review, dict) or len(_json(review)) > 16000:
        raise ValueError("PoC 静态审阅元数据无效")
    if review.get("runtime_validation", "not_run") != "not_run":
        raise ValueError("PoC 文本目录不能声明已进行运行验证")
    dependencies = review.get("dependencies_file")
    if dependencies is not None and dependencies not in paths:
        raise ValueError("PoC 依赖文件不在固定清单内")
    return candidate


def _catalog(cve_id):
    if not CATALOG_PATH.is_file():
        return []
    if CATALOG_PATH.stat().st_size > 128000:
        raise ValueError("PoC 目录大小超出限制")
    raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    rows = raw.get("candidates", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("PoC 目录格式无效")
    # A malformed configured row must be visible as a configuration error,
    # rather than quietly turn a requested CVE into "unconfigured".
    validated = [_validate_candidate(row) for row in rows]
    selected = [row for row in validated if row["cve_id"] == cve_id]
    if len(selected) > MAX_CANDIDATES or len({row["candidate_id"] for row in selected}) != len(selected):
        raise ValueError("PoC 候选数量或身份重复")
    return selected


def _fingerprint(candidate):
    return _sha(_json(candidate).encode("utf-8"))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "PoC source redirects are refused", headers, fp)


def _fetch(url, deadline):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com" or parsed.query or parsed.fragment:
        raise ValueError("PoC 只能读取固定 GitHub 原始文件地址")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("PoC 文本采集时间预算已用尽")
    # Honor the user's normal HTTPS proxy configuration. The requested host,
    # TLS verification, redirect rejection and pinned byte hashes still apply.
    opener = build_opener(ProxyHandler(), _NoRedirect())
    request = Request(url, headers={"User-Agent": "ai-sec-intel-poc-text/1", "Accept": "text/plain"})
    with opener.open(request, timeout=remaining) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("PoC 来源未返回固定提交文件")
        declared = response.headers.get("Content-Length")
        if declared and (not declared.isdigit() or int(declared) > MAX_FILE_BYTES):
            raise ValueError("PoC 来源文件大小超出限制")
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("PoC 文本采集时间预算已用尽")
            # urllib's initial timeout alone would reset per read. Keep this
            # owned socket's reads within the remaining shared fetch budget.
            sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
            if sock is not None:
                sock.settimeout(remaining)
            reader = getattr(response, "read1", None)
            # HTTPResponse.read(n) may perform many internal socket reads while
            # a server drips bytes. read1 returns after at most one raw read;
            # a compatibility fallback asks for one byte before checking time.
            part = reader(min(65536, MAX_FILE_BYTES + 1 - size)) if callable(reader) else response.read(1)
            if not part:
                return b"".join(chunks)
            size += len(part)
            if size > MAX_FILE_BYTES:
                raise ValueError("PoC 来源文件大小超出限制")
            chunks.append(part)


def _verify_file(row, body):
    if not isinstance(body, bytes) or len(body) > MAX_FILE_BYTES:
        raise ValueError("PoC 来源必须为限定大小的原始字节")
    if len(body) != row["size"] or _sha(body) != row["sha256"] or _git_sha(body) != row["git_blob_sha"]:
        raise ValueError("PoC 来源字节与固定提交清单不一致")
    text = body.decode("utf-8", errors="strict")
    if "\x00" in text:
        raise ValueError("PoC 来源不是可审阅的 UTF-8 文本")
    return text


def _initialize(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS poc_snapshots (
            cve_id TEXT NOT NULL, candidate_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
            catalog TEXT NOT NULL, retrieved_at TEXT NOT NULL,
            PRIMARY KEY(cve_id,candidate_id));
        CREATE TABLE IF NOT EXISTS poc_files (
            cve_id TEXT NOT NULL, candidate_id TEXT NOT NULL, path TEXT NOT NULL,
            sha256 TEXT NOT NULL, git_blob_sha TEXT NOT NULL, size INTEGER NOT NULL,
            body BLOB NOT NULL, PRIMARY KEY(cve_id,candidate_id,path));
        CREATE TABLE IF NOT EXISTS poc_attempts (
            cve_id TEXT NOT NULL, candidate_id TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY(cve_id,candidate_id));
    """)


def _save(candidate, bodies, attempt, path):
    def previous_time(value):
        try:
            stamp = datetime.fromisoformat(value)
            return stamp if stamp.tzinfo is not None and stamp <= _now() else None
        except (TypeError, ValueError):
            return None

    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(path), timeout=5)) as conn:
        _initialize(conn)
        with conn:
            # Serialize the short publication transaction, not the network
            # request. Order by collection start: an older, slow failure must
            # not overwrite the latest status of a newer successful request.
            conn.execute("BEGIN IMMEDIATE")
            cve, cid = candidate["cve_id"], candidate["candidate_id"]
            started_at = datetime.fromisoformat(attempt["queried_at"])
            previous_attempt = conn.execute("SELECT payload FROM poc_attempts WHERE cve_id=? AND candidate_id=?", (cve, cid)).fetchone()
            try:
                last_attempt_at = previous_time(json.loads(previous_attempt[0]).get("queried_at")) if previous_attempt else None
            except (ValueError, TypeError, AttributeError):
                last_attempt_at = None
            newer_attempt = last_attempt_at is not None and last_attempt_at > started_at
            previous_snapshot = conn.execute("SELECT retrieved_at FROM poc_snapshots WHERE cve_id=? AND candidate_id=?", (cve, cid)).fetchone()
            last_snapshot_at = previous_time(previous_snapshot[0]) if previous_snapshot else None
            newer_snapshot = last_snapshot_at is not None and last_snapshot_at > started_at
            if bodies is not None and not newer_snapshot:
                conn.execute("INSERT OR REPLACE INTO poc_snapshots VALUES(?,?,?,?,?)",
                             (cve, cid, _fingerprint(candidate), _json(candidate), attempt["queried_at"]))
                conn.execute("DELETE FROM poc_files WHERE cve_id=? AND candidate_id=?", (cve, cid))
                conn.executemany("INSERT INTO poc_files VALUES(?,?,?,?,?,?,?)", [
                    (cve, cid, row["path"], row["sha256"], row["git_blob_sha"], row["size"], bodies[row["path"]])
                    for row in candidate["files"]])
            if not newer_attempt:
                conn.execute("INSERT OR REPLACE INTO poc_attempts VALUES(?,?,?)", (cve, cid, _json(attempt)))


def _load(candidate, conn):
    cve, cid = candidate["cve_id"], candidate["candidate_id"]
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"poc_snapshots", "poc_files", "poc_attempts"} <= tables:
        return None, None, None
    attempt_row = conn.execute("SELECT payload FROM poc_attempts WHERE cve_id=? AND candidate_id=?", (cve, cid)).fetchone()
    attempt = json.loads(attempt_row[0]) if attempt_row else None
    if attempt is not None and (not isinstance(attempt, dict) or attempt.get("cve_id") != cve or attempt.get("candidate_id") != cid
                                or attempt.get("status") not in ("ok", "error")):
        raise ValueError("PoC 最近采集状态绑定无效")
    if attempt is not None:
        attempt_at = datetime.fromisoformat(attempt.get("queried_at", ""))
        if attempt_at.tzinfo is None or attempt_at > _now():
            raise ValueError("PoC 最近采集时间无效")
    snapshot = conn.execute("SELECT fingerprint,catalog,retrieved_at FROM poc_snapshots WHERE cve_id=? AND candidate_id=?", (cve, cid)).fetchone()
    rows = conn.execute("SELECT path,sha256,git_blob_sha,size,body FROM poc_files WHERE cve_id=? AND candidate_id=?", (cve, cid)).fetchall()
    if not snapshot:
        if rows:
            raise ValueError("PoC 文件缺少完整快照元数据")
        return None, None, attempt
    if snapshot[0] != _fingerprint(candidate) or snapshot[1] != _json(candidate):
        raise ValueError("PoC 快照与当前固定目录不一致；需要重新采集")
    at = datetime.fromisoformat(snapshot[2])
    if at.tzinfo is None or at > _now():
        raise ValueError("PoC 快照采集时间无效")
    expected = {row["path"]: row for row in candidate["files"]}
    if {row[0] for row in rows} != set(expected) or len(rows) != len(expected):
        raise ValueError("PoC 快照文件清单不完整或含有额外文件")
    bodies = {}
    for path, sha, git_sha, size, body in rows:
        manifest = expected[path]
        if (sha, git_sha, size) != (manifest["sha256"], manifest["git_blob_sha"], manifest["size"]):
            raise ValueError("PoC 文件存储元数据被修改")
        _verify_file(manifest, body)
        bodies[path] = body
    return bodies, snapshot[2], attempt


def _python_analysis(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return {"syntax_status": "invalid", "error_line": getattr(exc, "lineno", None), "imports": [], "functions": []}
    imports, functions = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(node.name)
    return {"syntax_status": "valid", "imports": sorted(imports)[:32], "functions": sorted(functions)[:64]}


def _dependency_lines(text):
    items = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Read declarations, never resolve includes/URLs or install anything.
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)(==|>=|<=|~=|>|<|!=)?([A-Za-z0-9.*+!_-]*)", stripped)
        items.append({"line": number, "declaration": stripped[:240], "status": "plain_declaration" if match else "unresolved",
                      "name": match.group(1) if match else None,
                      "specifier": (match.group(2) or "") + match.group(3) if match else None})
        if len(items) >= 64:
            break
    return items


def _review(candidate, texts, files):
    configured = copy.deepcopy(candidate.get("review") or {})
    valid = (configured.get("reviewed_by") == "development_agent"
             and configured.get("review_method") == "manual_source_read_and_ast"
             and bool(configured.get("summary"))
             and all(row.get("syntax_status") != "invalid" for row in files))
    findings = configured.get("findings", [])
    if not isinstance(findings, list) or len(findings) > 24:
        valid = False
        findings = []
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("text"), str) or len(finding["text"]) > 800:
            valid = False
            continue
        lines = finding.get("lines")
        if (finding.get("file") not in texts or not isinstance(lines, list) or len(lines) != 2
                or any(not isinstance(v, int) or isinstance(v, bool) for v in lines)
                or not 1 <= lines[0] <= lines[1] <= len(texts[finding["file"]].splitlines())):
            valid = False
    target = configured.get("target_version_claim")
    if target:
        lines = target.get("lines") if isinstance(target, dict) else None
        if (not isinstance(lines, list) or len(lines) != 2 or target.get("file") not in texts
                or any(not isinstance(v, int) or isinstance(v, bool) for v in lines)
                or not 1 <= lines[0] <= lines[1] <= len(texts[target["file"]].splitlines())
                or not isinstance(target.get("version"), str)
                or target["version"] not in "\n".join(texts[target["file"]].splitlines()[lines[0] - 1:lines[1]])):
            valid = False
    if not valid:
        return {"status": "attention_required", "reviewed_by": "development_agent",
                "review_method": "manual_source_read_and_ast", "runtime_validation": "not_run",
                "summary": "固定来源已保存；静态审阅信息或 Python 语法需要进一步核对。", "findings": [], "notes": [NOTICE]}
    configured.update(status="development_static_review", runtime_validation="not_run", independent_validation=False)
    return configured


def _evidence(candidate, text, *, kind, locator, retrieved_at, source_url, source_sha):
    fingerprint = _fingerprint(candidate)
    evidence_id = "POC-" + _sha((fingerprint + kind + locator + text).encode("utf-8"))[:24]
    return {"cve_id": candidate["cve_id"], "evidence_id": evidence_id,
            "citation_id": candidate["cve_id"] + "/" + evidence_id,
            "candidate_id": candidate["candidate_id"], "source_id": candidate["candidate_id"],
            "source_type": "poc_source_code", "title": "PoC 固定来源与静态审阅",
            "source_title": "PoC 固定来源与静态审阅", "source_url": source_url, "url": source_url,
            "retrieved_at": retrieved_at, "text": text, "locator": locator,
            "text_sha256": _sha(text.encode("utf-8")), "source_response_sha256": source_sha,
            "text_kind": kind, "topics": ["poc"], "review_fingerprint": fingerprint,
            "validation": "not_run"}


def _item(candidate, bodies=None, retrieved_at=None, attempt=None, error=None):
    result = {"candidate_id": candidate["candidate_id"], "repository": candidate["repository"],
              "commit_sha": candidate["commit_sha"], "repository_url": "https://github.com/" + candidate["repository"],
              "parent_repository": candidate.get("parent_repository"), "license": candidate.get("license"),
              "copyright": candidate.get("copyright"),
              "status": "error" if error else "not_collected", "validation": "not_run", "availability": "pending",
              "files": [], "dependencies": [], "review": {"status": "not_reviewed", "runtime_validation": "not_run"},
              "evidence_ids": [], "evidence": [], "facts": [], "latest_attempt": attempt}
    if error:
        result["detail"] = error
    if bodies is None:
        if not error and attempt and attempt.get("status") == "error":
            result.update(status="error", collection_failed=True,
                          detail="最近来源采集失败，尚未保存完整快照；本次没有发布部分文件。")
        return result
    texts = {path: body.decode("utf-8") for path, body in bodies.items()}
    files = []
    for row in candidate["files"]:
        value = dict(row, url=_file_url(candidate, row["path"]), retrieved_at=retrieved_at)
        if row["path"].endswith(".py"):
            value.update(_python_analysis(texts[row["path"]]))
        files.append(value)
    review = _review(candidate, texts, files)
    result.update(status="static_reviewed" if review["status"] == "development_static_review" else "collected",
                  files=files, review=review, retrieved_at=retrieved_at,
                  retained_previous=bool(attempt and attempt.get("status") == "error"))
    evidence = []

    def add(text, kind, locator, source_url, source_sha):
        row = _evidence(candidate, text, kind=kind, locator=locator, retrieved_at=retrieved_at,
                        source_url=source_url, source_sha=source_sha)
        evidence.append(row)
        result["facts"].append({"text": text, "evidence_ids": [row["citation_id"]]})
        return row["citation_id"]

    commit_url = "https://github.com/" + candidate["repository"] + "/tree/" + candidate["commit_sha"]
    add("PoC 来源仓库：" + candidate["repository"] + "；固定提交：" + candidate["commit_sha"] + "。",
        "poc_source_metadata", "catalog/repository,commit_sha", commit_url, _fingerprint(candidate))
    for row in files:
        add("已保存来源文件 " + row["path"] + "，大小 " + str(row["size"]) + " 字节，SHA-256：" + row["sha256"] + "。",
            "poc_source_metadata", row["path"] + ":bytes", row["url"], row["sha256"])
    dependencies_file = candidate.get("review", {}).get("dependencies_file")
    if dependencies_file:
        result["dependencies"] = _dependency_lines(texts[dependencies_file])
        meta = next(row for row in files if row["path"] == dependencies_file)
        for dependency in result["dependencies"]:
            dependency["evidence_ids"] = [add("依赖文件原文声明：" + dependency["declaration"] + "；本项目未安装或验证该依赖。",
                "poc_source_declaration", dependencies_file + ":L" + str(dependency["line"]), meta["url"], meta["sha256"])]
    if review["status"] == "development_static_review":
        local_url = "/api/poc-code/" + candidate["cve_id"]
        review["evidence_ids"] = [add("开发者静态审阅：" + review["summary"], "development_static_review",
                                     "development-review/summary", local_url, _fingerprint(candidate))]
        for finding in review.get("findings", []):
            locator = finding["file"] + ":L" + str(finding["lines"][0]) + "-L" + str(finding["lines"][1])
            finding["evidence_ids"] = [add("开发者静态审阅：" + finding["text"], "development_static_review",
                                         locator, local_url, _fingerprint(candidate))]
        claim = review.get("target_version_claim")
        if claim:
            meta = next(row for row in files if row["path"] == claim["file"])
            claim["evidence_ids"] = [add("来源 README 的示例环境声明使用版本 " + claim["version"] + "；这不是受影响版本范围或运行验证结论。",
                "poc_source_declaration", claim["file"] + ":L" + str(claim["lines"][0]) + "-L" + str(claim["lines"][1]), meta["url"], meta["sha256"])]
    result["evidence"] = evidence
    result["evidence_ids"] = [row["citation_id"] for row in evidence]
    return result


def report(cve_id, *, db_path=None):
    """Read only; no network, model, downloaded import, or schema creation."""
    cve_id = _cve(cve_id)
    candidates = _catalog(cve_id)
    result = {"schema_version": 1, "cve_id": cve_id, "status": "unconfigured" if not candidates else "not_collected",
              "detail": "没有配置该 CVE 的固定 PoC 来源。" if not candidates else "请先显式采集固定来源文本；本项目尚未运行验证。",
              "items": [], "evidence": [], "facts": [], "notice": NOTICE,
              "validation": "not_run", "independent_validation": False, "latest_attempt": None}
    result["fetch_policy"] = {"timeout_seconds": FETCH_BUDGET, "budget_kind": "soft",
                              "detail": "网络请求和分块读取使用共享软预算；操作系统 DNS、TLS 或底层阻塞可能超出预算。"}
    path = Path(db_path) if db_path is not None else DEFAULT_DB
    if not candidates:
        return result
    if not path.is_file():
        result["items"] = [_item(candidate) for candidate in candidates]
        return result
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as conn:
            conn.execute("BEGIN")
            for candidate in candidates:
                try:
                    bodies, at, attempt = _load(candidate, conn)
                    result["items"].append(_item(candidate, bodies, at, attempt))
                except (ValueError, TypeError, KeyError, UnicodeError, sqlite3.DatabaseError) as exc:
                    result["items"].append(_item(candidate, error="来源快照完整性检查未通过；请重新采集固定来源。"))
    except sqlite3.DatabaseError:
        result["items"] = [_item(candidate, error="PoC 来源数据库无法读取；保留原文件并检查存储。") for candidate in candidates]
    for item in result["items"]:
        result["evidence"].extend(item["evidence"])
        result["facts"].extend(item["facts"])
    states = {item["status"] for item in result["items"]}
    result["status"] = next(iter(states)) if len(states) == 1 else "partial"
    attempts = [item["latest_attempt"] for item in result["items"] if item["latest_attempt"]]
    if attempts:
        result["latest_attempt"] = max(attempts, key=lambda value: value.get("queried_at", ""))
    if any(item.get("retained_previous") for item in result["items"]):
        result["detail"] = "最近采集失败，仍显示上次通过完整性检查的固定来源；运行验证未进行。"
    elif any(item.get("collection_failed") for item in result["items"]):
        result["detail"] = "最近来源采集失败，未获得对应候选的完整快照；请查看采集状态后重试。"
    elif result["status"] == "static_reviewed":
        result["detail"] = "固定来源已保存并完成开发者静态审阅；PoC 可用性仍待隔离运行验证。"
    elif "error" in states:
        result["detail"] = "部分来源完整性检查失败，已停止展示相关证据；请重新采集。"
    elif result["status"] == "collected":
        result["detail"] = "固定来源已保存，静态审阅需要进一步核对；运行验证未进行。"
    return result


def collect(cve_id, *, db_path=None, fetcher=None):
    """Explicit bounded collection; injected fetcher accepts a URL -> bytes.

    File publication is all-or-nothing per candidate. A failed refresh records
    a separate attempt while preserving the last complete, still-pinned source.
    Fetches and chunk reads share a 30-second soft timeout budget. OS DNS, TLS,
    response headers or other system-level blocking may exceed this budget;
    it is not a hard end-to-end deadline or a subprocess termination boundary.
    """
    cve_id = _cve(cve_id)
    candidates = _catalog(cve_id)
    path = Path(db_path) if db_path is not None else DEFAULT_DB
    deadline = time.monotonic() + FETCH_BUDGET
    for candidate in candidates:
        attempt = {"cve_id": cve_id, "candidate_id": candidate["candidate_id"],
                   "queried_at": _now().isoformat(), "status": "ok", "files_fetched": 0}
        bodies = {}
        try:
            for row in candidate["files"]:
                if time.monotonic() >= deadline:
                    raise TimeoutError("PoC 文本采集时间预算已用尽")
                url = _file_url(candidate, row["path"], raw=True)
                body = fetcher(url) if fetcher is not None else _fetch(url, deadline)
                _verify_file(row, body)
                bodies[row["path"]] = body
                attempt["files_fetched"] += 1
            if time.monotonic() >= deadline:
                raise TimeoutError("PoC 文本采集时间预算已用尽")
        except Exception as exc:
            attempt.update(status="error", error_type=type(exc).__name__,
                           detail="固定来源采集未完成或摘要不匹配；本次不发布部分文件。")
            bodies = None
        _save(candidate, bodies, attempt, path)
    return report(cve_id, db_path=path)


def refresh_record(record, *, db_path=None, fetcher=None):
    """Optional caller adapter; does not mutate the record or persist the KB."""
    if not isinstance(record, dict):
        raise ValueError("需要 CVE 情报记录")
    return collect((record.get("item") or {}).get("cve_id"), db_path=db_path, fetcher=fetcher)
