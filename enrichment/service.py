# 富化只抄公开来源。失败时留下状态，不编分数，也不中断主流程。

import copy
from datetime import datetime, timezone
import json
import urllib.request

from models import enriched_record

EPSS_URL = "https://api.first.org/data/v1/epss?cve=%s"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _now():
    return datetime.now(timezone.utc).isoformat()


class _FeedRows(dict):
    """Keep query metadata even when a successful feed contains no matching CVE."""
    def __init__(self):
        super().__init__()
        self.queried_at = _now()
        self.source_date = None


def _attempt(row):
    if isinstance(row.get("latest_attempt"), dict):
        return copy.deepcopy(row["latest_attempt"])
    return {key: row[key] for key in ("status", "queried_at", "source_url", "message") if key in row}


def _attempt_time(row):
    value = _attempt(row).get("queried_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


def merge_feed(previous, incoming):
    """A fresh successful observation replaces old data; a failed attempt does not.

    queried_at/last_success_at describe our query, not the source's publication.
    source_date and KEV date_added retain their separate source meanings.
    """
    if incoming is None:
        return copy.deepcopy(previous)
    if not isinstance(incoming, dict):
        return copy.deepcopy(previous if previous is not None else incoming)
    if isinstance(previous, dict):
        old_time, new_time = _attempt_time(previous), _attempt_time(incoming)
        if old_time and new_time and new_time < old_time:
            return copy.deepcopy(previous)
        if incoming.get("status") == "error" and previous.get("status") in {"ok", "empty", "listed", "not_listed"}:
            retained = copy.deepcopy(previous)
            retained.update(latest_attempt=_attempt(incoming), retained_previous=True)
            return retained
    return copy.deepcopy(incoming)


def _observation(values, rows, source_url, *, error=None):
    queried_at = getattr(rows, "queried_at", None) or _now()
    result = dict(values)
    result.update(queried_at=queried_at, source_url=source_url)
    result["latest_attempt"] = {"status": "error" if error else "ok", "result_status": result["status"],
                                "queried_at": queried_at, "source_url": source_url}
    if error:
        result["latest_attempt"]["message"] = result["message"]
    else:
        result.update(last_success_at=queried_at, retained_previous=False)
        result.setdefault("source_date", getattr(rows, "source_date", None))
    return result


def enrich(item):
    """C 的富化接口。当前写入 NVD 已有的 CVSS 和被标记的参考链接。"""
    return enriched_record(item)


def _get_json(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_epss(cve_ids):
    found = _FeedRows()
    ids = [cve_id for cve_id in cve_ids if cve_id]
    if not ids:
        return found, None
    try:
        payload = _get_json(EPSS_URL % ",".join(ids), 20)
    except Exception as exc:
        found.queried_at = _now()
        return found, str(exc)
    found.queried_at = _now()
    for row in payload.get("data") or []:
        cve_id = row.get("cve")
        if not cve_id:
            continue
        found[cve_id] = {
            "status": "ok",
            "score": row.get("epss"),
            "percentile": row.get("percentile"),
            "source_date": row.get("date"),
        }
    return found, None


def fetch_kev():
    found = _FeedRows()
    try:
        payload = _get_json(KEV_URL, 25)
    except Exception as exc:
        found.queried_at = _now()
        return found, str(exc)
    found.queried_at = _now()
    found.source_date = payload.get("dateReleased")
    for row in payload.get("vulnerabilities") or []:
        cve_id = row.get("cveID")
        if cve_id:
            found[cve_id] = {
                "status": "listed",
                "date_added": row.get("dateAdded") or "",
                "name": row.get("vulnerabilityName") or "",
                "source_date": found.source_date,
            }
    return found, None


def apply_public_feeds(records):
    """为已入库记录补 EPSS 和 KEV。单项失败不影响其他字段。"""
    cve_ids = []
    for record in records:
        cve_id = (record.get("item") or {}).get("cve_id")
        if cve_id:
            cve_ids.append(cve_id)
    epss_map, epss_error = fetch_epss(cve_ids)
    kev_map, kev_error = fetch_kev()
    for record in records:
        cve_id = (record.get("item") or {}).get("cve_id")
        if epss_error:
            epss = {"status": "error", "message": "EPSS 查询失败"}
        elif cve_id in epss_map:
            epss = epss_map[cve_id]
        else:
            epss = {"status": "empty"}
        record["epss"] = merge_feed(record.get("epss"), _observation(epss, epss_map, EPSS_URL % cve_id, error=epss_error))
        if kev_error:
            kev = {"status": "error", "message": "KEV 查询失败"}
        elif kev_map and cve_id in kev_map:
            kev = kev_map[cve_id]
        else:
            kev = {"status": "not_listed"}
        record["kev"] = merge_feed(record.get("kev"), _observation(kev, kev_map, KEV_URL, error=kev_error))
    return {
        "epss_error": epss_error,
        "kev_error": kev_error,
    }
