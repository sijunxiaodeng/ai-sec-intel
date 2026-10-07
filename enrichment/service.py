# 富化只抄公开来源。失败时留下状态，不编分数，也不中断主流程。

import json
import urllib.request

from models import enriched_record

EPSS_URL = "https://api.first.org/data/v1/epss?cve=%s"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def enrich(item):
    """C 的富化接口。当前写入 NVD 已有的 CVSS 和被标记的参考链接。"""
    return enriched_record(item)


def _get_json(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_epss(cve_ids):
    found = {}
    ids = [cve_id for cve_id in cve_ids if cve_id]
    if not ids:
        return found, None
    try:
        payload = _get_json(EPSS_URL % ",".join(ids), 20)
    except Exception as exc:
        return found, str(exc)
    for row in payload.get("data") or []:
        cve_id = row.get("cve")
        if not cve_id:
            continue
        found[cve_id] = {
            "status": "ok",
            "score": row.get("epss"),
            "percentile": row.get("percentile"),
        }
    return found, None


def fetch_kev():
    try:
        payload = _get_json(KEV_URL, 25)
    except Exception as exc:
        return None, str(exc)
    found = {}
    for row in payload.get("vulnerabilities") or []:
        cve_id = row.get("cveID")
        if cve_id:
            found[cve_id] = {
                "status": "listed",
                "date_added": row.get("dateAdded") or "",
                "name": row.get("vulnerabilityName") or "",
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
            record["epss"] = {"status": "error", "message": "EPSS 查询失败"}
        elif cve_id in epss_map:
            record["epss"] = epss_map[cve_id]
        else:
            record["epss"] = {"status": "empty"}
        if kev_error:
            record["kev"] = {"status": "error", "message": "KEV 查询失败"}
        elif kev_map and cve_id in kev_map:
            record["kev"] = kev_map[cve_id]
        else:
            record["kev"] = {"status": "not_listed"}
    return {
        "epss_error": epss_error,
        "kev_error": kev_error,
    }
