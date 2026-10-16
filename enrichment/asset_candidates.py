"""Read exact component routing hints from verified local NVD bytes.

This is only candidate discovery. Impact still requires the assessment module's
complete source/field checks. Cache entries are keyed by source byte digest.
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from enrichment.documents import digest
from enrichment.history import components
from rag.evidence import DEFAULT_DB

_CACHE = {}
_LOCK = threading.Lock()


def archived_identities(cve_ids, *, evidence_db=None):
    path = Path(evidence_db or DEFAULT_DB)
    if not path.is_file():
        return {}
    requested, result = set(cve_ids), {}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='source_snapshots'").fetchone():
            return {}
        rows = conn.execute("SELECT cve_id,source_id,digest FROM source_snapshots").fetchall()
        with _LOCK:
            for cve_id, source_id, sha in rows:
                if cve_id not in requested or source_id != digest("https://nvd.nist.gov/vuln/detail/" + cve_id)[:16]:
                    continue
                key = (str(path.resolve()), cve_id, sha)
                if key not in _CACHE:
                    body = conn.execute("SELECT body FROM source_snapshots WHERE cve_id=? AND source_id=?", (cve_id, source_id)).fetchone()[0]
                    identities = set()
                    try:
                        if isinstance(body, bytes) and hashlib.sha256(body).hexdigest() == sha:
                            payload = json.loads(body)
                            found = [row["cve"] for row in payload.get("vulnerabilities", []) if row.get("cve", {}).get("id") == cve_id]
                            if len(found) == 1:
                                identities = set(components(found[0]))
                    except (ValueError, KeyError, TypeError):
                        pass
                    if len(_CACHE) >= 4096:
                        _CACHE.clear()
                    _CACHE[key] = identities
                if _CACHE[key]:
                    result[cve_id] = _CACHE[key]
    return result
