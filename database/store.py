# 知识库。同一 cve_id 只保留一条 EnrichedIntelligence。

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import tempfile
import threading
import time

from models import enriched_record, normalize
from enrichment.service import merge_feed

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
KB_PATH = DATA / "knowledge.json"
CARDS_PATH = ROOT / "cards.json"
CARDS_JS_PATH = ROOT / "cards.js"
RUNS_PATH = DATA / "runs.json"
LOCK_TIMEOUT = 5.0
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()
_HELD = threading.local()


class StoreBusy(TimeoutError):
    """Another writer/cycle holds the persistent lock; retry the operation."""


class StoreCorruptError(ValueError):
    """Existing state is invalid. Preserve it rather than importing stale cards."""


class StoreWriteError(OSError):
    """Publishing or restoring state failed; the caller must not acknowledge."""


def _try_file_lock(handle):
    handle.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_file(handle):
    handle.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _persistent_lock(path, *, timeout=LOCK_TIMEOUT):
    """Reentrant per-thread + OS file lock, with one finite total wait budget.

    Never unlink a lock file: replacing its inode could admit a second writer.
    The OS releases a crashed process's lock. All cooperating processes must
    use the same state directory; locks on unrelated directories are separate.
    """
    path = Path(path).resolve()
    key = os.path.normcase(str(path))
    timeout = max(0.0, float(timeout))
    deadline = time.monotonic() + timeout
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(key, threading.RLock())
    if not lock.acquire(timeout=timeout):
        raise StoreBusy("知识库写入或采集正在进行，请稍后重试")
    handle = None
    held = getattr(_HELD, "paths", None)
    if held is None:
        held = _HELD.paths = set()
    try:
        if key in held:
            yield
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+b")
        if path.stat().st_size == 0:
            handle.write(b"\0")
            handle.flush()
        while True:
            try:
                _try_file_lock(handle)
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StoreBusy("知识库写入或采集正在进行，请稍后重试") from None
                time.sleep(min(0.05, remaining))
        held.add(key)
        try:
            yield
        finally:
            held.remove(key)
            _unlock_file(handle)
    finally:
        if handle is not None:
            handle.close()
        lock.release()


def _write_lock(*, timeout=LOCK_TIMEOUT):
    return _persistent_lock(KB_PATH.parent / ".knowledge.lock", timeout=timeout)


def collection_lock(*, timeout=0):
    """Shared manual/scheduled/direct collection gate, including cursor ack.

    The outer API/scheduler holds it through pipeline finalization. Nested
    run_collect in the same thread is allowed; another thread/process is busy.
    """
    return _persistent_lock(KB_PATH.parent / ".collection.lock", timeout=timeout)


def _stage_bytes(path, content, *, suffix="pending"):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".%s.%s-" % (path.name, suffix), dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


def _sync_directory(path):
    # Windows has no portable directory fsync; files are fsynced before replace.
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _replace(src, dst):
    # Windows readers may briefly deny deletion/replacement of an open file.
    # Retry that sharing conflict within a small finite budget; other IO errors
    # fail immediately and a persistent permission error still fails the save.
    deadline = time.monotonic() + 0.5
    while True:
        try:
            return os.replace(src, dst)
        except PermissionError:
            if os.name != "nt" or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _publish(payloads):
    """Stage complete snapshots, replace atomically, restore on ordinary errors.

    knowledge.json is published last by its caller. Derived cards may briefly
    lead it if the process dies between replacements; no cursor is acknowledged
    until every replacement completes. This is not a multi-file crash transaction.
    Restoration failure retains the old backup files for explicit recovery.
    """
    staged, backups, replaced = {}, {}, []
    keep_backups = set()
    try:
        for path, content in payloads:
            path = Path(path)
            staged[path] = _stage_bytes(path, content.encode("utf-8"))
            backups[path] = _stage_bytes(path, path.read_bytes(), suffix="backup") if path.exists() else None
        try:
            for path, _ in payloads:
                path = Path(path)
                _replace(staged[path], path)
                replaced.append(path)
                _sync_directory(path.parent)
        except BaseException as exc:
            failed = []
            for path in reversed(replaced):
                try:
                    backup = backups[path]
                    if backup is None:
                        path.unlink(missing_ok=True)
                    else:
                        _replace(backup, path)
                    _sync_directory(path.parent)
                except OSError:
                    failed.append(path.name)
                    if backups[path] is not None:
                        keep_backups.add(backups[path])
            if failed:
                raise StoreWriteError("写入失败且部分文件未能恢复，旧备份已保留：" + ", ".join(failed)) from exc
            raise
    finally:
        for path in list(staged.values()) + [p for p in backups.values() if p is not None]:
            if path not in keep_backups:
                path.unlink(missing_ok=True)


def _ensure():
    DATA.mkdir(parents=True, exist_ok=True)


def _read_list(path):
    if not path.exists():
        return None
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise StoreCorruptError("%s 已损坏；已保留原文件，请恢复后重试" % path.name) from exc
    if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
        return rows
    raise StoreCorruptError("%s 格式无效；已保留原文件，请恢复后重试" % path.name)


def import_cards():
    with _write_lock():
        rows = _read_list(CARDS_PATH) or []
        records = []
        for row in rows:
            card = normalize(row)
            if card.get("cve_id"):
                records.append(enriched_record(card))
        return save_kb(records)


def load_kb():
    with _write_lock():
        _ensure()
        rows = _read_list(KB_PATH)
        if rows is not None:
            return [enriched_record(row) for row in rows]
        return import_cards()


def _union(old_values, new_values):
    found = []
    for value in list(old_values or []) + list(new_values or []):
        if value and value not in found:
            found.append(value)
    return found


def merge_records(old, new):
    """同一编号合并。已有的分数和富化结果不被空值盖掉，采集时间保留第一次。"""
    old = enriched_record(old)
    new = enriched_record(new)
    old_item = old.get("item") or {}
    new_item = new.get("item") or {}
    sources = _union(old_item.get("sources"), new_item.get("sources"))
    old_title = old_item.get("title") or ""
    new_title = new_item.get("title") or ""
    # Prefer explicit demo/Chinese labels over stale English seed placeholders.
    if new_title.startswith("【演示】") or (new_title and old_title.startswith("Demo")):
        title = new_title
    else:
        title = old_title or new_title
    description = old_item.get("description") or ""
    new_description = new_item.get("description") or ""
    if new_description.startswith("演示用") or new_description.startswith("【演示】"):
        description = new_description
    elif len(new_description) > len(description):
        description = new_description
    collected_times = [value for value in (old_item.get("collected_at"), new_item.get("collected_at")) if value]
    papers = []
    seen_papers = set()
    for paper in (old.get("papers") or []) + (new.get("papers") or []):
        url = paper.get("url") if isinstance(paper, dict) else ""
        if url and url not in seen_papers:
            seen_papers.add(url)
            papers.append(paper)
    poc = []
    seen_poc = set()
    for row in (old.get("poc") or []) + (new.get("poc") or []):
        url = row.get("url") if isinstance(row, dict) else ""
        if url and url not in seen_poc:
            seen_poc.add(url)
            poc.append(row)
    old_cvss = old.get("cvss") if (old.get("cvss") or {}).get("score") is not None else None
    item = dict(new_item)
    item.update({
        "title": title,
        "description": description,
        "source": "、".join(sources),
        "sources": sources,
        "url": old_item.get("url") or new_item.get("url"),
        "published_at": old_item.get("published_at") or new_item.get("published_at"),
        "collected_at": min(collected_times) if collected_times else "",
        "product": old_item.get("product") or new_item.get("product"),
        "affected": _union(old_item.get("affected"), new_item.get("affected"))[:8],
        "references": _union(old.get("references"), new.get("references")),
        "raw_data": dict(old_item.get("raw_data") or {}),
    })
    item["raw_data"].update(new_item.get("raw_data") or {})
    return enriched_record({
        "item": item,
        "cvss": old_cvss or new.get("cvss"),
        "epss": merge_feed(old.get("epss"), new.get("epss")),
        "kev": merge_feed(old.get("kev"), new.get("kev")),
        "poc": poc,
        "papers": papers,
        "references": item["references"],
    })


def save_kb(records):
    """Explicit snapshot replacement; use upsert for read/modify/write callers."""
    with _write_lock():
        return _save_kb(records)


def _save_kb(records):
    _ensure()
    merged = {}
    order = []
    for record in records:
        record = enriched_record(record)
        key = (record.get("item") or {}).get("cve_id") or ""
        if not key:
            continue
        if key not in merged:
            order.append(key)
            merged[key] = record
        else:
            merged[key] = merge_records(merged[key], record)
    rows = [merged[key] for key in order]
    rows.sort(key=lambda row: (row.get("item") or {}).get("published_at") or "", reverse=True)
    cards_text = _cards_text(rows)
    _publish([
        (CARDS_PATH, cards_text),
        (CARDS_JS_PATH, "window.CARDS = %s;\n" % cards_text),
        (KB_PATH, json.dumps(rows, ensure_ascii=False, indent=2)),
    ])
    return rows


def export_cards(records):
    with _write_lock():
        text = _cards_text(records)
        _publish([(CARDS_PATH, text), (CARDS_JS_PATH, "window.CARDS = %s;\n" % text)])


def _cards_text(records):
    cards = []
    for record in records:
        item = record.get("item") or {}
        cvss = record.get("cvss") or {}
        cards.append(normalize({
            "id": item.get("cve_id"),
            "cve_id": item.get("cve_id"),
            "title": item.get("title"),
            "description": item.get("description"),
            "source": item.get("source"),
            "url": item.get("url"),
            "published_at": item.get("published_at"),
            "collected_at": item.get("collected_at"),
            "product": item.get("product"),
            "affected": item.get("affected") or [],
            "cvss": cvss.get("score"),
            "references": record.get("references") or [],
        }))
    return json.dumps(cards, ensure_ascii=False, indent=2)


def upsert(records):
    with _write_lock():
        current = load_kb()
        return save_kb(current + list(records))


def upsert_stats(records):
    """Merge incoming records; return saved rows plus per-round counts.

    - inserted: CVE id not previously in the knowledge base
    - merged: CVE id already present (fields unioned)
    - fetched: incoming rows with a CVE id
    - total: knowledge base size after save

    Use this for monitor UI「本轮命中 / 新增 / 合并」— do not treat total as
    「本轮新写入」.
    """
    with _write_lock():
        return _upsert_stats(records)


def _upsert_stats(records):
    current = load_kb()
    existing = set()
    for row in current:
        cve = (row.get("item") or {}).get("cve_id")
        if cve:
            existing.add(cve)
    incoming = list(records or [])
    fetched = 0
    inserted = 0
    merged = 0
    for record in incoming:
        record = enriched_record(record)
        cve = (record.get("item") or {}).get("cve_id") or ""
        if not cve:
            continue
        fetched += 1
        if cve in existing:
            merged += 1
        else:
            inserted += 1
            existing.add(cve)
    saved = save_kb(current + incoming)
    return {
        "records": saved,
        "fetched": fetched,
        "inserted": inserted,
        "merged": merged,
        "skipped_dup": merged,
        "total": len(saved),
    }


def get_record(cve_id):
    for record in load_kb():
        if (record.get("item") or {}).get("cve_id") == cve_id:
            return record
    return None


def append_run(steps, kind):
    with _write_lock():
        _ensure()
        runs = _read_list(RUNS_PATH) or []
        runs.insert(0, {"kind": kind, "steps": steps})
        _publish([(RUNS_PATH, json.dumps(runs[:20], ensure_ascii=False, indent=2))])


def latest_run():
    with _write_lock():
        runs = _read_list(RUNS_PATH) or []
        if not runs:
            return None
        return runs[0]
