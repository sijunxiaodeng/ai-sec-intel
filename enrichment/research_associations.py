"""Persist source-bound research leads without promoting them to CVE facts."""
import copy
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database import store
from enrichment.article_candidates import report as candidates, _source, _basis, query_profile, KINDS
from rag.evidence import DEFAULT_DB
from rag.library import LIBRARY_DB

KEY = "research_associations"


def refresh(record, *, library_db=None, evidence_db=None, top_k=3):
    """Local search only. The caller commits through the normal revision fence."""
    result = candidates(record, library_db=library_db or LIBRARY_DB,
                        evidence_db=evidence_db or DEFAULT_DB, top_k=top_k)
    result = copy.deepcopy(result)
    result.update(source_revision=store.source_revision(record),
                  checked_at=datetime.now(timezone.utc).isoformat(),
                  storage="knowledge_record", review_required=True)
    # Keep direct CVE mentions and mechanism/background relations explicit.
    for row in result["items"]:
        row["relation_type"] = "direct_mention" if row["explicit_cve_mention"] else "related_research"
        row["review_status"] = "not_reviewed"
    record["item"].setdefault("raw_data", {})[KEY] = result
    return result


def current(record, *, library_db=None, evidence_db=None):
    """Exclude changed/withdrawn sources and stale CVE revisions at read time."""
    saved = copy.deepcopy(((record.get("item") or {}).get("raw_data") or {}).get(KEY))
    if not isinstance(saved, dict):
        return {"status": "not_run", "items": [], "counts": {"paper": 0, "blog": 0},
                "detail": "尚未保存研究关联；可更新本地关联，或等待后台富化。"}
    if saved.get("source_revision") != store.source_revision(record):
        saved.update(status="stale", items=[], detail="情报已修订，旧研究关联等待重新检索。")
    kept, invalid = [], 0
    path = Path(library_db or LIBRARY_DB)
    profile, mechanisms = query_profile(record, evidence_db or DEFAULT_DB)
    for row in saved.get("items", []):
        try:
            source = _source(row["document_id"], path) if path.is_file() else None
            valid = (source and source["document"].get("source_response_sha256") == row.get("source_response_sha256"))
            available = {e["citation_id"] for e in source["chunks"]} if source else set()
            valid = valid and bool(row.get("evidence_ids")) and set(row["evidence_ids"]).issubset(available)
            chunks = [e for e in source["chunks"] if e["citation_id"] in row["evidence_ids"]] if valid else []
            basis = [b for e in chunks for b in _basis(e, profile, mechanisms)]
            valid = valid and bool(basis) and all(_basis(e, profile, mechanisms) for e in chunks)
            valid = valid and sorted(basis, key=str) == sorted(row.get("match_basis", []), key=str)
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
            valid = False
        if valid:
            doc = source["document"]
            row.update(title=doc["title"], url=doc["url"], category=KINDS[doc["document_type"]],
                       explicit_cve_mention=any(b["kind"] == "explicit_cve_mention" for b in basis))
            row["relation_type"] = "direct_mention" if row["explicit_cve_mention"] else "related_research"
            row.update(match_basis=basis, review_status="not_reviewed", retrieved_at=doc["retrieved_at"],
                       retained_previous=source["retained_previous"], latest_attempt_status=source["latest_attempt_status"])
            row["evidence"] = [dict(chunk, **{key: doc.get(key) for key in (
                "document_id", "url", "title", "publisher", "document_type", "content_scope", "retrieved_at",
                "source_response_sha256", "source_snapshot_kind", "snapshot_url")}) for chunk in chunks]
            kept.append(row)
        else:
            invalid += 1
    saved.update(items=kept, invalidated_items=invalid,
                 counts={kind: sum(row.get("category") == kind for row in kept) for kind in ("paper", "blog")})
    if invalid:
        saved.update(status="partial", detail="部分资料已变化或不可读取，旧关联已隐藏，请更新本地关联。")
    return saved


def refresh_and_save(record, **kwargs):
    expected = store.source_revision(record)
    working = copy.deepcopy(record)
    refresh(working, **kwargs)
    accepted = store.apply_enrichment([working], expected_revisions={record["item"]["cve_id"]: expected})
    if record["item"]["cve_id"] not in accepted:
        raise ValueError("情报在检索期间已变化，本次旧结果未保存，请重试")
    return current(working, library_db=kwargs.get("library_db"), evidence_db=kwargs.get("evidence_db"))
