"""本机自报资产清单与保守版本筛选；不连接或扫描资产。"""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Dict, List, Literal

from pydantic import BaseModel, Field, StrictBool, constr, validator
from rag.evidence import _connection

DEFAULT_ASSET_DB = Path(__file__).resolve().parent.parent / "data" / "assets.sqlite3"
QUALIFIERS = {"update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"}
STATUS_LABELS = {"matched_version": "版本命中，可能受影响", "not_matched": "未命中当前来源范围", "unknown": "待确认"}


class Asset(BaseModel):
    asset_id: constr(strict=True, strip_whitespace=True, regex=r"^[A-Za-z0-9_.-]{1,64}$")
    name: constr(strict=True, strip_whitespace=True, min_length=1, max_length=120)
    vendor: constr(strict=True, strip_whitespace=True, min_length=1, max_length=100)
    product: constr(strict=True, strip_whitespace=True, min_length=1, max_length=100)
    version: constr(strict=True, strip_whitespace=True, max_length=100) = ""
    part: Literal["a", "o", "h"] = "a"
    address: constr(strict=True, strip_whitespace=True, max_length=200) = ""
    exposure: Literal["internet", "internal", "isolated", "unknown"] = "unknown"
    authentication: Literal["required", "none", "unknown"] = "unknown"
    criticality: Literal["high", "medium", "low", "unknown"] = "unknown"
    qualifiers: Dict[str, str] = Field(default_factory=dict)
    is_demo: StrictBool = False

    class Config:
        extra = "forbid"

    @validator("vendor", "product")
    def identity(cls, value):
        value = value.lower()
        if not re.fullmatch(r"[a-z0-9_.-]+", value):
            raise ValueError("请填写 CPE 的确切厂商/产品标识，不使用名称猜测")
        return value

    @validator("qualifiers", pre=True)
    def qualifiers_valid(cls, value):
        if not isinstance(value, dict) or set(value) - QUALIFIERS:
            raise ValueError("qualifiers 仅接受 CPE 限定字段")
        if any(not isinstance(v, str) or not v.strip() or len(v) > 100 or "*" in v or "?" in v or "\\" in v for v in value.values()):
            raise ValueError("限定值需为 1–100 字符的确切值；不适用填 -")
        return {k: v.strip().lower() for k, v in value.items()}


class AssetImport(BaseModel):
    assets: List[Asset] = Field(..., min_items=1, max_items=500)

    class Config:
        extra = "forbid"

    @validator("assets")
    def unique_ids(cls, value):
        if len({r.asset_id for r in value}) != len(value):
            raise ValueError("同一批次 asset_id 不能重复")
        return value


class AssetPreview(AssetImport):
    cve_id: constr(strict=True, strip_whitespace=True, regex=r"^(?i:CVE)-\d{4}-\d{4,7}$")


def load_assets(db_path=None):
    path = Path(db_path or DEFAULT_ASSET_DB)
    if not path.exists():
        return []
    with _connection(path) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='assets'").fetchone():
            return []
        return [json.loads(row[0]) for row in conn.execute("SELECT payload FROM assets ORDER BY asset_id")]


def import_assets(payload, db_path=None):
    # 先验证整个批次，再事务写入；同 ID 更新，其余资产保留。
    batch = AssetImport.parse_obj(payload)
    path = Path(db_path or DEFAULT_ASSET_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    rows = [dict(row.dict(), recorded_at=timestamp, inventory_source="user_declared") for row in batch.assets]
    with _connection(path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS assets (asset_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        existing = {row[0] for row in conn.execute("SELECT asset_id FROM assets")}
        if len(existing | {row["asset_id"] for row in rows}) > 2000:
            raise ValueError("本机清单上限为 2000 条")
        conn.executemany("INSERT OR REPLACE INTO assets VALUES (?,?)", [(r["asset_id"], json.dumps(r, ensure_ascii=False)) for r in rows])
    updated = sum(row["asset_id"] in existing for row in rows)
    return {"imported": len(rows), "created": len(rows) - updated, "updated": updated,
            "total": len(existing | {r["asset_id"] for r in rows}), "recorded_at": timestamp}


def _numeric(value):
    # 只比较数字点分版本，不对 rc/nightly/厂商自定义后缀猜测顺序。
    match = re.fullmatch(r"v?(\d+(?:\.\d+){0,7})", value or "", re.I)
    if not match:
        return None
    parts = [int(v) for v in match[1].split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _compare(left, right):
    a, b = _numeric(left), _numeric(right)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _check(asset, row):
    parts = re.split(r"(?<!\\):", row.get("criteria") or "")
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return "unknown", "CPE 格式不受当前筛选器支持"
    if any("\\" in p or "?" in p or ("*" in p and p != "*") for p in parts[2:]):
        return "unknown", "CPE 含转义或模式匹配，需人工核对"
    for index, key in ((2, "part"), (3, "vendor"), (4, "product")):
        if parts[index] == "*":
            return "unknown", "CPE 身份为通配符，需人工核对"
        if parts[index].lower() != asset[key].lower():
            return "not_matched", "组件类别、厂商或产品与此范围不一致"
    if row.get("requires_environment_review"):
        return "unknown", "配置含 AND/否定条件，当前筛选器不判定完整环境逻辑"
    if not asset["version"]:
        return "unknown", "资产实际版本未填写"
    checks, uncertain = [], []
    version = parts[5]
    if version == "-":
        return "unknown", "来源版本标为不适用，需核对"
    if version != "*":
        compared = _compare(asset["version"], version)
        if compared is None:
            if asset["version"] == version:
                checks.append(True)
            else:
                uncertain.append("非数字版本无法可靠比较")
        else:
            checks.append(compared == 0)
    bounds = (("versionStartIncluding", lambda c: c >= 0), ("versionStartExcluding", lambda c: c > 0),
              ("versionEndIncluding", lambda c: c <= 0), ("versionEndExcluding", lambda c: c < 0))
    bounded = False
    for key, predicate in bounds:
        if not row.get(key):
            continue
        bounded = True
        compared = _compare(asset["version"], row[key])
        if compared is None:
            uncertain.append("带后缀或非数字版本的范围比较待确认")
        else:
            checks.append(predicate(compared))
    for index, key in enumerate(("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"), 6):
        expected = parts[index].lower()
        if expected == "*":
            continue
        actual = asset.get("qualifiers", {}).get(key)
        if actual is None:
            uncertain.append("缺少 CPE 限定：" + key)
        else:
            checks.append(actual == expected)
    if False in checks:
        return "not_matched", "版本边界或 CPE 限定未命中此范围"
    if uncertain:
        return "unknown", "；".join(dict.fromkeys(uncertain))
    if version == "*" and not bounded:
        return "unknown", "来源没有独立版本范围，不据此确认资产命中"
    return "matched_version", "登记的组件版本与来源范围一致；尚未验证可利用性"


def impact_report(assessment, assets, *, preview=False):
    results = []
    for source_asset in assets:
        asset = copy.deepcopy(source_asset)
        checks = []
        for row in assessment.get("affected_ranges") or []:
            if not row.get("evidence_ids") or assessment.get("status") not in ("ok", "partial"):
                continue
            status, reason = _check(asset, row)
            checks.append({"status": status, "reason": reason, "range": row["display"],
                           "criteria": row["criteria"], "pointer": row["pointer"], "evidence_ids": row["evidence_ids"]})
        state = "matched_version" if any(r["status"] == "matched_version" for r in checks) else "unknown" if not checks or any(r["status"] == "unknown" for r in checks) else "not_matched"
        priority = "优先核查" if state == "matched_version" and (asset["exposure"] == "internet" or asset["criticality"] == "high") else "核查" if state == "matched_version" else "补充信息" if state == "unknown" else "暂无范围命中"
        evidence_ids = list(dict.fromkeys(eid for row in checks for eid in row["evidence_ids"]))
        results.append({"asset": asset, "status": state, "label": STATUS_LABELS[state], "priority": priority,
                        "reason": "；".join(dict.fromkeys(r["reason"] for r in checks if r["status"] == state)) if checks else "缺少可引用的 NVD 版本配置，请先抓取关联资料",
                        "checks": checks, "evidence_ids": evidence_ids, "validation": "not_tested"})
    counts = {state: sum(r["status"] == state for r in results) for state in STATUS_LABELS}
    return {"schema_version": 1, "cve_id": assessment["cve_id"], "preview": preview,
            "status": "empty_inventory" if not assets else "evaluated", "counts": counts,
            "asset_count": len(assets), "demo_count": sum(bool(r.get("is_demo")) for r in assets),
            "cvss": assessment.get("cvss"), "source": assessment.get("source"),
            "results": sorted(results, key=lambda r: ({"matched_version": 0, "unknown": 1, "not_matched": 2}[r["status"]], 0 if r["priority"] == "优先核查" else 1, r["asset"]["asset_id"])),
            "evidence": assessment.get("evidence") or [], "warnings": assessment.get("warnings") or [],
            "limitations": ["结果依据登记信息和来源版本配置，不是主动扫描或漏洞复现", "未命中当前范围不表示资产不存在其他漏洞", "优先级为核查顺序规则，不修改 CVSS，不计算业务损失"]}


def inventory_evidence(asset):
    text = json.dumps(asset, ensure_ascii=False, sort_keys=True)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    eid = asset["asset_id"] + "-" + sha[:12]
    return {"evidence_id": eid, "citation_id": "ASSET/" + eid, "title": "登记资产：" + asset["name"],
            "url": "/api/assets", "locator": "资产编号 " + asset["asset_id"] + "；登记信息快照",
            "retrieved_at": asset.get("recorded_at", ""), "text_kind": "user_declared_inventory", "text": text,
            "text_sha256": sha, "source_response_sha256": sha, "source_id": "inventory"}


def answer_assets(question, cve_id=""):
    from rag.evidence import CVE
    from rag.retrieve import get_record
    from enrichment.assessment import assess
    assets = load_assets()
    if not assets:
        return {"answer": "当前没有你的资产清单、实际版本和网络暴露信息，无法判断具体资产是否受影响。", "evidence": [], "used_model": False, "steps": []}
    requested = {value.upper() for value in CVE.findall(question)} | ({cve_id.upper()} if cve_id else set())
    if len(requested) != 1:
        return {"answer": "请指定一条已收录的 CVE 编号，以便匹配登记资产。", "evidence": [], "used_model": False, "steps": []}
    selected = requested.pop()
    record = get_record(selected)
    if not record:
        return {"answer": "知识库没有这条情报，请先收录并抓取关联资料。", "evidence": [], "used_model": False, "steps": []}
    assessment = (record["item"].get("raw_data") or {}).get("automatic_assessment") or assess(selected)
    report = impact_report(assessment, assets)
    record = copy.deepcopy(record)
    record["evidence_chunks"] = list(report["evidence"])
    lines = ["[1] 登记资产与 %s 的版本范围匹配：" % selected]
    for result in report["results"][:50]:
        asset = result["asset"]
        chunk = inventory_evidence(asset)
        record["evidence_chunks"].append(chunk)
        lines.append("%s（%s，%s %s%s）：%s；%s；核查顺序：%s。 [%s] %s" % (
            asset["name"], asset["asset_id"], asset["product"], asset["version"] or "版本未知", "，演示资产" if asset["is_demo"] else "",
            result["label"], result["reason"], result["priority"], chunk["citation_id"],
            " ".join("[%s]" % eid for eid in result["evidence_ids"])))
    if len(report["results"]) > 50:
        lines.append("回答展示前 50 条，请在资产影响页面查看完整结果。")
    lines.extend(report["limitations"] + report["warnings"])
    return {"answer": "\n".join(lines), "evidence": [record], "used_model": False,
            "steps": [{"role": "资产评估", "action": "本地匹配登记资产", "detail": "共 %d 条，版本命中 %d 条、待确认 %d 条；没有调用大模型或扫描资产。" % (len(assets), report["counts"]["matched_version"], report["counts"]["unknown"])}]}
