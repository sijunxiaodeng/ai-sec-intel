"""Legacy arXiv CVE lookup; bounded rotating batches, never semantic proof."""
from bisect import bisect_left
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import sqlite3
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ATOM = "{http://www.w3.org/2005/Atom}"
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
ARXIV_PATH = re.compile(r"/abs/(?:\d{4}\.\d{4,5}|[a-zA-Z.-]+/\d{7})(?:v\d+)?/?")
CURSOR_PATH = Path(__file__).resolve().parent.parent / "data" / "paper_queries.sqlite3"
MAX_BYTES = 2 * 1024 * 1024


class _PaperRows(dict):
    """Keep the old mapping/error pair; optional metadata describes coverage."""
    def __init__(self, ids):
        super().__init__((cve_id, []) for cve_id in ids)
        self.metadata = {"requested_cve_ids": ids, "queried_cve_ids": [], "deferred_cve_ids": ids, "batches": [],
                         "checked_at": datetime.now(timezone.utc).isoformat(),
                         "scope": "每批仅取前 8 项；编号提及不等于论文验证该漏洞，不是全量论文搜索"}


def _text(node, name):
    child = node.find(ATOM + name)
    return " ".join(child.text.split()) if child is not None and child.text else ""


def _reserve(ids, budget, path):
    """Reserve only query turns, not successful publication/ingestion watermarks.

    A persisted next-ID anchor avoids always querying the first 12 CVEs. SQLite
    serializes concurrent reservations. Failed batches retry after the rotation.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=2)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS paper_rotation (id INTEGER PRIMARY KEY CHECK(id=1),next_cve_id TEXT NOT NULL)")
        row = conn.execute("SELECT next_cve_id FROM paper_rotation WHERE id=1").fetchone()
        start = bisect_left(ids, row[0]) % len(ids) if row else 0
        count = min(budget, len(ids))
        chosen = [ids[(start + offset) % len(ids)] for offset in range(count)]
        next_id = ids[(start + count) % len(ids)]
        conn.execute("INSERT OR REPLACE INTO paper_rotation VALUES (1,?)", (next_id,))
        conn.commit()
    return chosen


def _fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student"})
    with urllib.request.urlopen(request, timeout=10) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("arXiv 响应超过 2 MiB 上限")
    return raw


def _paper_url(entry):
    options = [row.attrib.get("href", "") for row in entry.findall(ATOM + "link")
               if row.attrib.get("rel") in (None, "alternate")]
    options.append(_text(entry, "id"))
    for url in options:
        if url.startswith("http://arxiv.org/abs/"):
            url = "https://" + url[7:]
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme == "https" and parsed.netloc == "arxiv.org" and ARXIV_PATH.fullmatch(parsed.path)
                and not parsed.query and not parsed.fragment):
            return url
    return ""


def _parse(raw, ids):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("arXiv 响应不是有界字节流")
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.I):
        raise ValueError("arXiv 响应含不支持的 DTD/实体")
    root = ET.fromstring(raw)
    if root.tag != ATOM + "feed":
        raise ValueError("arXiv 未返回有效 Atom feed")
    entries = root.findall(ATOM + "entry")
    if any("/api/errors" in _text(row, "id") for row in entries):
        raise ValueError("arXiv API 返回查询错误")
    sha = hashlib.sha256(raw).hexdigest()
    found = {cve_id: [] for cve_id in ids}
    for entry in entries[:8]:
        title, summary = _text(entry, "title"), _text(entry, "summary")
        link = _paper_url(entry)
        if not link:
            continue
        blob = title + " " + summary
        for cve_id in ids:
            pattern = r"(?<![A-Za-z0-9_-])" + re.escape(cve_id) + r"(?![A-Za-z0-9_-])"
            if re.search(pattern, blob, re.I) and not any(row["url"] == link for row in found[cve_id]):
                found[cve_id].append({"title": title, "summary": summary[:400], "url": link,
                                      "association": "explicit_cve_mention", "content_scope": "title_and_abstract",
                                      "feed_response_sha256": sha})
    return found


def fetch_papers(cve_ids, *, max_batches=4, batch_size=12, cursor_path=None, fetcher=None):
    """Return (mapping, error), retaining good batches when another batch fails.

    Default budget: ≤4 HTTPS requests, ≤12 CVE IDs/request, ≤8 results/request.
    Larger ID sets rotate across calls; metadata/error explicitly report deferred
    IDs. No network retries or unbounded pagination are performed.
    """
    if isinstance(max_batches, bool) or not isinstance(max_batches, int) or not 1 <= max_batches <= 8:
        raise ValueError("max_batches 必须为 1 到 8")
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 12:
        raise ValueError("batch_size 必须为 1 到 12")
    ids = sorted({value.upper() for value in cve_ids if isinstance(value, str) and CVE.fullmatch(value)})
    found = _PaperRows(ids)
    if not ids:
        return found, None
    try:
        chosen = _reserve(ids, max_batches * batch_size, cursor_path or CURSOR_PATH)
    except (OSError, sqlite3.Error, ValueError):
        return found, "论文查询轮转状态不可用；本轮未请求，已有论文保留。"
    found.metadata.update(queried_cve_ids=chosen, deferred_cve_ids=[v for v in ids if v not in set(chosen)],
                          max_batches=max_batches, batch_size=batch_size)
    errors = []
    for start in range(0, len(chosen), batch_size):
        batch = chosen[start:start + batch_size]
        query = " OR ".join("all:%s" % cve_id for cve_id in batch)
        url = "https://export.arxiv.org/api/query?" + urllib.parse.urlencode({"search_query": query, "start": 0, "max_results": 8})
        status = {"cve_ids": batch, "status": "ok"}
        try:
            if fetcher is None and start:
                time.sleep(3)  # same courtesy interval as the existing library sync
            results = _parse((fetcher or _fetch)(url), batch)
            for cve_id, papers in results.items():
                found[cve_id].extend(papers)
            status["matched_papers"] = sum(len(rows) for rows in results.values())
        except Exception as exc:
            status.update(status="error", message=str(exc)[:200])
            errors.append("批次 %d 查询失败" % (len(found.metadata["batches"]) + 1))
        found.metadata["batches"].append(status)
    if found.metadata["deferred_cve_ids"]:
        errors.append("本轮预算已用完，%d 个编号延后轮转查询" % len(found.metadata["deferred_cve_ids"]))
    return found, "；".join(errors) if errors else None
