"""Offline provider-export observations; no DNS, scans, requests or exploit execution.

An imported file is a user's copy of provider data, not an authenticated provider
response. Hashes bind local excerpts to that file; they do not prove its origin.
"""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3

from enrichment.assets import impact_report
from rag.evidence import _connection

DEFAULT_OBSERVATION_DB = Path(__file__).resolve().parent.parent / "data" / "asset-observations.sqlite3"
MAX_EXPORT_BYTES = 1024 * 1024
MAX_ROWS = 500
MAX_OBSERVATIONS = 5000
MAX_EXPORTS = 200
MAX_STORAGE_BYTES = 32 * 1024 * 1024
STALE_DAYS = 30  # Local review policy, not a contest requirement or provider guarantee.
FOFA_FIELDS = {"ip", "port", "protocol", "host", "domain", "product", "product.version", "lastupdatetime",
               "title", "server", "country", "country_name", "region", "city", "as_number", "as_organization"}
SECRET_KEYS = {"apikey", "key", "password", "passwd", "authorization", "token", "accesstoken", "secret", "clientsecret"}
DOCUMENTATION_NETS = tuple(ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
QUALIFIERS = ("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other")
PROVENANCE_WARNING = "导出文件由用户提供；未验证提供商签名、账户或真实性，摘要仅用于本地完整性核对"
LIMITATIONS = [PROVENANCE_WARNING,
               "提供商观测可能过期、识别不完整；版本命中仅表示需要核查，不证明目标当前在线或漏洞可利用",
               "不连接、扫描或执行目标代码；没有进行漏洞复现",
               "超过 30 天标为过期是本项目本地核查策略，不是赛题阈值",
               "演示数据与真实数据分开标记；内网、保留或文档地址不计入真实互联网资产"]


def _now():
    return datetime.now(timezone.utc)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def _write_connection(path):
    try:
        with _connection(path) as conn:
            yield conn
    except sqlite3.Error as exc:
        raise ValueError("观测库不可写、已损坏或繁忙；本批次未完成导入") from exc


def _strict_json(value):
    def pairs(entries):
        result = {}
        for key, item in entries:
            if key in result:
                raise ValueError("JSON 对象存在重复字段")
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON 不能含 NaN 或 Infinity")))
    except (TypeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("导出内容不是有效 JSON/JSONL") from exc


def _reject_secrets(value, depth=0):
    if depth > 30:
        raise ValueError("导出嵌套层数过多")
    if isinstance(value, dict):
        for key, item in value.items():
            if re.sub(r"[^a-z]", "", key.lower()) in SECRET_KEYS:
                raise ValueError("导出包含凭据字段；请先移除 API Key、令牌或密码")
            _reject_secrets(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _reject_secrets(item, depth + 1)


def _fields(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 32 or any(not isinstance(k, str) or k not in FOFA_FIELDS for k in value):
        raise ValueError("FOFA fields 必须为支持的官方字段名列表")
    if len(set(value)) != len(value):
        raise ValueError("FOFA fields 不能重复")
    return value


def _rows(provider, content, fields):
    if provider not in ("shodan", "fofa"):
        raise ValueError("仅支持 shodan 或 fofa 离线导出")
    if not isinstance(content, str) or not content.strip() or len(content.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise ValueError("导出应为非空文本，UTF-8 大小不超过 1 MiB")
    if provider == "shodan" and fields:
        raise ValueError("Shodan 不使用 FOFA fields 列定义")
    try:
        value = _strict_json(content)
    except ValueError:
        if provider != "shodan":
            raise
        value = [_strict_json(line) for line in content.splitlines() if line.strip()]
        locators = ["line:%d" % (index + 1) for index, line in enumerate(content.splitlines()) if line.strip()]
    else:
        locators = None
    _reject_secrets(value)
    if isinstance(value, dict):
        key = "matches" if provider == "shodan" else "results"
        if provider == "fofa" and value.get("error") is True:
            raise ValueError("FOFA 导出包含错误响应")
        value = value.get(key)
        if not isinstance(value, list):
            raise ValueError("导出缺少 %s 数组" % key)
        locators = ["/%s/%d" % (key, index) for index in range(len(value))]
    elif isinstance(value, list):
        locators = locators or ["/%d" % index for index in range(len(value))]
    else:
        raise ValueError("导出必须为提供商结果对象、数组或 Shodan JSONL")
    if len(value) > MAX_ROWS:
        raise ValueError("每批最多 500 条观测，超过时请明确拆分文件")
    rows = []
    for row, locator in zip(value, locators):
        original = row
        if provider == "fofa" and isinstance(row, list):
            if not fields or len(row) != len(fields):
                raise ValueError("FOFA 数组行必须提供顺序明确且长度一致的 fields")
            row = dict(zip(fields, row))
        if not isinstance(row, dict):
            raise ValueError("每条观测必须为对象或有 fields 的 FOFA 数组行")
        if provider == "fofa" and set(row) - FOFA_FIELDS:
            raise ValueError("FOFA 对象行含不支持的字段；请按官方字段导出")
        rows.append((copy.deepcopy(row), locator, copy.deepcopy(original)))
    return rows


def _text(value, field, maximum=200):
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError("%s 必须为长度有限的普通文本" % field)
    return value.strip()


def _timestamp(value, provider, imported_at):
    if value in (None, ""):
        return "", "unknown", "缺少提供商观测时间"
    if not isinstance(value, str) or len(value) > 80 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?", value):
        return "", "invalid", "观测时间格式不完整或不受支持"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "", "invalid", "观测时间无效"
    if parsed.tzinfo is None:
        if provider != "shodan":
            return "", "unknown", "FOFA 时间没有时区；无法可靠换算 UTC"
        parsed = parsed.replace(tzinfo=timezone.utc)  # Shodan banner timestamp is UTC.
    parsed = parsed.astimezone(timezone.utc)
    if parsed > imported_at:
        return parsed.isoformat(), "invalid", "观测时间晚于导入时间；不能作为当前有效观测"
    if _now() - parsed > timedelta(days=STALE_DAYS):
        return parsed.isoformat(), "stale", "观测超过本项目 30 天核查策略，需更新数据"
    return parsed.isoformat(), "current", ""


def _cpe(value):
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"] or parts[2] not in ("a", "o", "h"):
        return None
    if any(not re.fullmatch(r"(?:[a-zA-Z0-9_.-]+|\*)", p) for p in parts[3:]) or parts[3] in ("*", "-") or parts[4] in ("*", "-"):
        return None  # Escaped or pattern CPEs are left for manual review.
    return {"part": parts[2], "vendor": parts[3].lower(), "product": parts[4].lower(),
            "version": "" if parts[5] in ("*", "-") else parts[5],
            "qualifiers": {key: part.lower() for key, part in zip(QUALIFIERS, parts[6:]) if part != "*"}}


def _identity(row, provider):
    product = _text(row.get("product"), "product", 100)
    version_key = "version" if provider == "shodan" else "product.version"
    version = _text(row.get(version_key), version_key, 100)
    cpes = row.get("cpe23") if provider == "shodan" else None
    if cpes is None:
        cpes = []
    elif isinstance(cpes, str):
        cpes = [cpes]
    if not isinstance(cpes, list) or len(cpes) > 32:
        raise ValueError("cpe23 必须为最多 32 条字符串的数组")
    parsed = [_cpe(value) for value in cpes]
    warnings = []
    candidate = {"part": "a", "vendor": "", "product": "", "version": version, "qualifiers": {}}
    if parsed:
        if any(value is None for value in parsed):
            return candidate, "unknown", ["CPE 格式、转义或通配身份不受当前筛选器支持"]
        unique = {_json(value) for value in parsed}
        if len(unique) != 1:
            return candidate, "conflict", ["同一服务含多个不同 CPE 身份、版本或限定，不能自动选择"]
        candidate = parsed[0]
        if product and product.lower() != candidate["product"]:
            return candidate, "conflict", ["提供商 product 与 CPE 产品标识不一致，需人工核查"]
        if version and candidate["version"] and version != candidate["version"]:
            return candidate, "conflict", ["提供商 version 与 CPE 版本不一致，需人工核查"]
        candidate = dict(candidate, version=version or candidate["version"])
        state = "exact_cpe"
    elif product.lower() == "ollama":
        candidate.update(vendor="ollama", product="ollama")
        state = "exact_alias"
        warnings.append("仅使用明确 Ollama 产品字段的固定映射 ollama/ollama；不是从端口或 banner 猜测")
    else:
        state = "unknown"
        warnings.append("缺少可支持的确切 CPE 或固定产品映射；不能根据端口、标题、banner 或近似名称识别")
    # Legacy Shodan cpe values cannot establish an identity, but a contradictory
    # explicit identity must not be hidden behind the supported cpe23/product.
    legacy = row.get("cpe") if provider == "shodan" else None
    if legacy:
        legacy = [legacy] if isinstance(legacy, str) else legacy
        if not isinstance(legacy, list) or len(legacy) > 32:
            raise ValueError("cpe 必须为最多 32 条字符串的数组")
        for value in legacy:
            parts = value.split(":") if isinstance(value, str) else []
            if len(parts) not in (4, 5, 6, 7) or parts[:2] != ["cpe", "/" + candidate["part"]] or parts[2:4] != [candidate["vendor"], candidate["product"]] or (len(parts) > 4 and parts[4] not in ("", "*", "-") and parts[4] != candidate["version"]):
                state = "conflict"
                warnings.append("旧式 cpe 字段与确切身份/版本不一致或格式不支持，需人工核查")
                break
            if any(part not in ("", "*") and part.lower() != candidate["qualifiers"].get(key) for key, part in zip(("update", "edition"), parts[5:])):
                state = "conflict"
                warnings.append("旧式 CPE 更新/版本类别与 CPE 2.3 限定不一致或缺少对应限定，需人工核查")
                break
    if not candidate["version"]:
        warnings.append("缺少明确版本字段/CPE 版本，版本影响待确认")
    return candidate, state, warnings


def _normalize(provider, row, locator, original, export_sha, is_demo, imported_at):
    value = row.get("ip_str") if provider == "shodan" else row.get("ip")
    if not isinstance(value, str):
        raise ValueError("观测缺少明确的 IP 地址字段；不解析域名或 FOFA host 猜测 IP")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("观测 IP 地址无效；不进行 DNS 解析") from exc
    documentation = any(address.version == net.version and address in net for net in DOCUMENTATION_NETS)
    if not is_demo and (documentation or address.is_reserved or address.is_unspecified or address.is_multicast):
        raise ValueError("文档、保留、未指定或多播地址只允许以 is_demo=true 导入")
    port = row.get("port")
    if provider == "fofa" and isinstance(port, str) and re.fullmatch(r"[0-9]{1,5}", port):
        port = int(port)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("观测 port 必须为 1–65535 的整数")
    protocol = _text(row.get("transport" if provider == "shodan" else "protocol"), "protocol", 40).lower()
    identity, identity_status, warnings = _identity(row, provider)
    observed_at, time_status, warning = _timestamp(row.get("timestamp" if provider == "shodan" else "lastupdatetime"), provider, imported_at)
    if warning:
        warnings.append(warning)
    internet = bool(address.is_global and not getattr(address, "is_site_local", False))
    if isinstance(address, ipaddress.IPv6Address):
        embedded = [ip for ip in (address.ipv4_mapped, address.sixtofour) if ip is not None]
        embedded += list(address.teredo or ())
        if any(not ip.is_global for ip in embedded):
            internet = False
    if not internet:
        warnings.append("IP 不是全局可路由地址，不计为真实互联网观测")
    if is_demo:
        warnings.append("此条为演示观测，不计入真实互联网资产或效果指标")
    raw_sha = _sha(_json(original))
    # FOFA arrays have no field names. Bind their explicit column interpretation
    # too, otherwise changing fields could silently reuse a different row's ID.
    oid = "OBS-" + _sha(_json([provider, is_demo, original, row]))[:24]
    endpoint = "PASSIVE-" + _sha(_json([provider, is_demo, str(address), port, protocol]))[:24]
    return dict(identity, observation_id=oid, asset_id=endpoint, name="%s %s:%s" % (provider, address, port),
                provider=provider, address=str(address), port=port, protocol=protocol,
                identity_status=identity_status, time_status=time_status, observed_at=observed_at,
                source_observed_at=row.get("timestamp" if provider == "shodan" else "lastupdatetime"),
                imported_at=imported_at.isoformat(), is_demo=is_demo, is_internet=internet,
                exposure="internet" if internet else "unknown", authentication="unknown", criticality="unknown",
                source_label="用户提供的 %s 导出" % provider, inventory_source="provider_export",
                source_response_sha256=export_sha, raw_row_sha256=raw_sha, locator=locator,
                warnings=warnings, raw_row=original, provenance="user_supplied_provider_export", validation="not_tested")


def preview_export(provider, content, fields=None, *, is_demo=False):
    if type(is_demo) is not bool:
        raise ValueError("is_demo 必须为布尔值")
    fields = _fields(fields)
    rows = _rows(provider, content, fields)
    now = _now()
    sha = _sha(content)
    items = [_normalize(provider, row, locator, original, sha, is_demo, now) for row, locator, original in rows]
    return {"schema_version": 1, "provider": provider, "count": len(items), "items": items,
            "is_demo": is_demo, "fields": fields, "source_response_sha256": sha,
            "warnings": [PROVENANCE_WARNING], "limitations": list(LIMITATIONS), "preview": True}


def _export_id(provider, sha, fields, is_demo):
    return _sha(_json([provider, sha, fields, is_demo]))


def import_export(provider, content, fields=None, *, is_demo=False, db_path=None):
    report = preview_export(provider, content, fields, is_demo=is_demo)
    path = Path(db_path or DEFAULT_OBSERVATION_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    export_id = _export_id(provider, report["source_response_sha256"], report["fields"], is_demo)
    recorded_at = _now().isoformat()
    with _write_connection(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("CREATE TABLE IF NOT EXISTS observation_exports (export_id TEXT PRIMARY KEY, provider TEXT NOT NULL, body TEXT NOT NULL, digest TEXT NOT NULL, fields TEXT NOT NULL, is_demo INTEGER NOT NULL, imported_at TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS observation_rows (observation_id TEXT PRIMARY KEY, export_id TEXT NOT NULL REFERENCES observation_exports(export_id), locator TEXT NOT NULL, raw_row TEXT NOT NULL, raw_digest TEXT NOT NULL)")
        conn.execute("BEGIN IMMEDIATE")
        existing = {r[0] for r in conn.execute("SELECT observation_id FROM observation_rows")}
        export_exists = conn.execute("SELECT 1 FROM observation_exports WHERE export_id=?", (export_id,)).fetchone() is not None
        count, storage = conn.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(body AS BLOB))),0) FROM observation_exports").fetchone()
        if not export_exists and (count >= MAX_EXPORTS or storage + len(content.encode("utf-8")) > MAX_STORAGE_BYTES):
            raise ValueError("本地原始导出存储上限为 200 批 / 32 MiB；未删除旧证据，请明确归档后再导入")
        ids = {item["observation_id"] for item in report["items"]}
        if len(existing | ids) > MAX_OBSERVATIONS:
            raise ValueError("本地观测历史上限为 5000 条；未覆盖旧观测")
        conn.execute("INSERT OR IGNORE INTO observation_exports VALUES (?,?,?,?,?,?,?)", (export_id, provider, content, report["source_response_sha256"], _json(report["fields"]), int(is_demo), recorded_at))
        conn.executemany("INSERT OR IGNORE INTO observation_rows VALUES (?,?,?,?,?)", [
            (item["observation_id"], export_id, item["locator"], _json(item["raw_row"]), item["raw_row_sha256"]) for item in report["items"]])
    report.update(preview=False, imported=len(ids - existing), unchanged=len(ids & existing),
                  created=len(ids - existing), updated=0, total=len(existing | ids),
                  historical_total=len(existing | ids), export_id=export_id, recorded_at=recorded_at)
    return report


def _latest(items):
    endpoints = {}
    for item in items:
        endpoints.setdefault(item["asset_id"], []).append(item)
    current = []
    for key, history in sorted(endpoints.items()):
        timed = [item for item in history if item["observed_at"] and item["time_status"] != "invalid"]
        selected = max(timed, key=lambda r: r["observed_at"]) if timed else max(history, key=lambda r: (r["imported_at"], r["observation_id"]))
        selected = copy.deepcopy(selected)
        peers = [r for r in history if r["observed_at"] == selected["observed_at"]] if selected["observed_at"] else history
        signatures = {_json([r["part"], r["vendor"], r["product"], r["version"], r["qualifiers"], r["identity_status"]]) for r in peers}
        history_ids = sorted({oid for r in history for oid in r.get("history_observation_ids", [r["observation_id"]])})
        selected["history_count"] = len(history_ids)
        selected["history_observation_ids"] = history_ids
        if len(signatures) > 1:
            selected["identity_status"] = "conflict"
            selected["warnings"].append("同一服务在相同观测时间存在不同身份、版本或限定；保留历史并等待人工核查")
        # Undated/future/invalid records cannot invalidate chronology by pretending to be the latest.
        # They do, however, make the endpoint uncertain until their provenance is reviewed.
        untimed = [r for r in history if not r["observed_at"] or r["time_status"] == "invalid"]
        if timed and any(_json([r["vendor"], r["product"], r["version"], r["qualifiers"]]) != _json([selected["vendor"], selected["product"], selected["version"], selected["qualifiers"]]) for r in untimed):
            selected["identity_status"] = "conflict"
            selected["warnings"].append("另有无可靠时间的冲突观测，不能自动覆盖或排除")
        current.append(selected)
    return current


def load_observations(db_path=None):
    path = Path(db_path or DEFAULT_OBSERVATION_DB)
    if not path.exists():
        return []
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            conn.execute("BEGIN")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"observation_exports", "observation_rows"} <= tables:
                raise ValueError("观测库缺少所需表；保留原文件并等待修复")
            exports = conn.execute("SELECT export_id,provider,body,digest,fields,is_demo,imported_at FROM observation_exports").fetchall()
            saved = conn.execute("SELECT observation_id,export_id,locator,raw_row,raw_digest FROM observation_rows").fetchall()
        finally:
            conn.close()
        if any(any(not isinstance(row[index], str) for index in (0, 1, 2, 3, 4, 6)) or type(row[5]) is not int for row in exports):
            raise ValueError("导出快照字段类型无效")
        if len(exports) > MAX_EXPORTS or len(saved) > MAX_OBSERVATIONS or sum(len(r[2].encode("utf-8")) for r in exports) > MAX_STORAGE_BYTES:
            raise ValueError("观测库超过限定大小")
        derived = {}
        for eid, provider, body, digest, fields_json, demo, imported in exports:
            fields = _fields(_strict_json(fields_json))
            if demo not in (0, 1) or digest != _sha(body) or eid != _export_id(provider, digest, fields, bool(demo)):
                raise ValueError("导出快照元数据或摘要不一致")
            at = datetime.fromisoformat(imported)
            if at.tzinfo is None or at > _now():
                raise ValueError("导入记录时间无效")
            for row, locator, original in _rows(provider, body, fields):
                item = _normalize(provider, row, locator, original, digest, bool(demo), at)
                derived[(eid, locator)] = item
        items = []
        for oid, eid, locator, raw, digest in saved:
            item = derived.get((eid, locator))
            if not item or oid != item["observation_id"] or digest != item["raw_row_sha256"] or raw != _json(item["raw_row"]):
                raise ValueError("观测行与原始导出不一致；停止使用该库证据")
            items.append(item)
        if {row[0] for row in saved} != {item["observation_id"] for item in derived.values()}:
            raise ValueError("观测行缺失或多余；不能用不完整历史排除冲突")
        return _latest(items)
    except (sqlite3.Error, TypeError, KeyError, OverflowError) as exc:
        raise ValueError("观测库无效或不可读取；未使用未经验证的数据") from exc


def _observation_evidence(row):
    excerpt = {key: row[key] for key in ("provider", "address", "port", "protocol", "part", "vendor", "product", "version", "qualifiers", "observed_at", "source_observed_at", "identity_status", "time_status", "is_demo")}
    text = _json(excerpt)
    return {"evidence_id": row["observation_id"], "citation_id": "OBSERVATION/" + row["observation_id"],
            "title": row["source_label"], "url": "/api/asset-observations", "locator": row["locator"],
            "retrieved_at": row["imported_at"], "text_kind": "user_supplied_provider_export",
            "text": text, "text_sha256": _sha(text), "source_response_sha256": row["source_response_sha256"],
            "raw_row_sha256": row["raw_row_sha256"], "source_id": row["provider"], "provenance": row["provenance"]}


def evaluate_observations(assessment, observations):
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ValueError("观测评估必须为限定大小的列表")
    rows = _latest(copy.deepcopy(observations))
    assets = []
    for row in rows:
        assets.append({key: row[key] for key in ("asset_id", "name", "part", "vendor", "product", "version", "qualifiers", "address", "exposure", "authentication", "criticality", "is_demo")})
    report = impact_report(copy.deepcopy(assessment), assets, preview=True)
    by_id = {row["asset_id"]: row for row in rows}
    for result in report["results"]:
        row = by_id[result["asset"]["asset_id"]]
        result["asset"].update({k: row[k] for k in ("provider", "port", "protocol", "observed_at", "identity_status", "time_status", "inventory_source", "is_internet")})
        # Re-evaluate freshness at use time. Missing version remains unknown in the existing CPE matcher.
        at, time_status, warning = _timestamp(row.get("source_observed_at"), row["provider"], datetime.fromisoformat(row["imported_at"]))
        row["time_status"] = time_status
        result["asset"]["time_status"] = time_status
        reasons = list(row["warnings"])
        if warning and warning not in reasons:
            reasons.append(warning)
        if row["identity_status"] not in ("exact_cpe", "exact_alias") or time_status != "current":
            result.update(status="unknown", label="待确认", priority="补充信息", reason="；".join(reasons) or "观测身份或时间待确认")
            result["checks"] = [dict(check, status="unknown", reason="提供商观测缺少有效身份或当前时间；版本检查仅作候选") for check in result["checks"]]
        result["provider_observation"] = {k: v for k, v in row.items() if k != "raw_row"}
        result["validation"] = "not_tested"
        evidence = _observation_evidence(row)
        result["observation_evidence_ids"] = [evidence["citation_id"]]
        result["evidence_ids"] = list(dict.fromkeys(result["evidence_ids"] + result["observation_evidence_ids"]))
        report["evidence"].append(evidence)
    report["counts"] = {state: sum(r["status"] == state for r in report["results"]) for state in ("matched_version", "not_matched", "unknown")}
    report.update(schema_version=1, inventory_source="provider_export", observation_count=len(rows),
                  real_internet_count=sum(not r["is_demo"] and r["is_internet"] for r in rows),
                  real_internet_candidate_count=sum(r["status"] == "matched_version" and not r["asset"]["is_demo"] and r["asset"]["is_internet"] for r in report["results"]),
                  limitations=list(LIMITATIONS), freshness_policy={"stale_after_days": STALE_DAYS, "basis": "local_review_policy"})
    report["warnings"] = list(dict.fromkeys(report["warnings"] + [PROVENANCE_WARNING]))
    return report
