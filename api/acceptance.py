"""Acceptance dashboard endpoints; never execute imported reports or arbitrary paths."""
import json
import sqlite3
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from acceptance import dashboard, evidence, quality, observation

router = APIRouter(prefix="/api/acceptance", tags=["acceptance"])
MAX_BODY_BYTES = 8 * 1024 * 1024


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except KeyError:
        raise HTTPException(status_code=404, detail="验收记录不存在") from None
    except quality.RevisionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)[:500]) from None
    except ValueError as exc:
        text = str(exc)[:500]
        conflict = any(word in text.lower() for word in ("already frozen", "已冻结", "已经冻结"))
        raise HTTPException(status_code=409 if conflict else 422, detail=text) from None
    except OSError:
        raise HTTPException(status_code=503, detail="验收存储暂不可用") from None
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="验收存储繁忙或暂不可用，请稍后重试") from None


async def _body(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="请使用 application/json")
    origin = request.headers.get("origin")
    try:
        origin_url = urlsplit(origin) if origin else None
    except ValueError:
        raise HTTPException(status_code=403, detail="请求来源无效") from None
    if request.headers.get("sec-fetch-site") == "cross-site" or (origin and
            (origin_url.scheme, origin_url.netloc) != (request.url.scheme, request.url.netloc)):
        raise HTTPException(status_code=403, detail="验收写入只接受同源网页请求")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="JSON 文件不能超过 8 MiB")
        chunks.append(chunk)
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        body = json.loads(b"".join(chunks), object_pairs_hook=unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(status_code=422, detail="JSON 内容无效，不允许 NaN 或 Infinity") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="JSON 顶层须为对象")
    return body


def _export(data, name):
    return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{name}.json"',
                                       "X-Content-Type-Options": "nosniff"})


@router.get("/summary")
def summary():
    return _call(dashboard.summary)


@router.get("/quality")
def quality_runs():
    return _call(quality.list_runs)


@router.post("/quality/import")
async def import_quality(request: Request):
    return await run_in_threadpool(_call, quality.import_report, await _body(request))


@router.get("/quality/{run_id}")
def quality_run(run_id: str):
    return _call(quality.get_run, run_id)


@router.post("/quality/{run_id}/reviews/{case_id}")
async def review_quality(run_id: str, case_id: str, request: Request):
    return await run_in_threadpool(_call, quality.review_case, run_id, case_id, await _body(request))


@router.get("/quality/{run_id}/export")
def export_quality(run_id: str):
    return _export(_call(quality.export_run, run_id), "quality-report")


@router.get("/observations")
def observation_windows():
    return _call(observation.list_windows)


@router.post("/observations")
async def create_observation(request: Request):
    return await run_in_threadpool(_call, observation.create_window, await _body(request))


@router.get("/observations/{window_id}")
def observation_window(window_id: str):
    return _call(observation.get_window, window_id)


@router.post("/observations/{window_id}/inventory")
async def import_inventory(window_id: str, request: Request):
    return await run_in_threadpool(_call, observation.import_inventory, window_id, await _body(request))


@router.post("/observations/{window_id}/freeze")
async def freeze_observation(window_id: str, request: Request):
    await _body(request)
    return await run_in_threadpool(_call, observation.freeze_window, window_id)


@router.get("/observations/{window_id}/export")
def export_observation(window_id: str):
    result = _call(observation.get_window, window_id)
    # An active export is explicitly a progress snapshot; only a frozen report
    # can be used as the immutable final observation artifact.
    return _export({"schema_version": 1, "export_kind": "frozen" if result.get("status") == "frozen" else "progress",
                    "window": result}, "observation-report")


@router.get("/evidence/{identity}/download")
def download_evidence(identity: str):
    path, entry = _call(evidence.resolve, identity)
    return FileResponse(path, filename=entry["filename"], media_type="application/octet-stream",
                        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


@router.get("/templates/{kind}")
def template(kind: str):
    if kind == "quality":
        body = {"title": "填写本次富化事实评测名称", "purpose": "acceptance", "report": {
            "schema_version": 1, "kind": "enrichment", "run_at": "填写真实带时区运行时间",
            "model": "填写实际模型/规则版本", "mode": "model", "dataset_visibility": "unspecified",
            "dataset_sha256": "填写冻结题单的64位SHA256", "dataset_cases": 1, "dataset_case_ids": ["E001"],
            "evaluation_unit": "fact_unit", "source_manifest": [{"url": "https://example.org/replace-with-source",
            "response_sha256": "填写实际来源响应的64位SHA256"}], "cases": [{"id": "E001",
            "question": "填写待核对的单个富化事实", "prediction": "填写实际输出，不能只保留正确输出",
            "reference": "填写独立核对的参考事实和字段定位", "context": "填写关联漏洞、范围及来源证据",
            "reasoning_kind": "enrichment",
            "automatic_passed": None}]}}
    elif kind == "inventory":
        body = {"schema_version": 1, "source": "填写窗口已登记的来源名称", "scope": "填写明确的查询与AI范围",
                "captured_at": "填写清单实际获取时间，含时区", "coverage_start": "填写覆盖起点，含时区",
                "coverage_end": "填写覆盖终点，含时区", "reference_url": "https://example.org/replace-with-upstream-list",
                "response_sha256": "填写上游列表响应的64位SHA256", "response_body": "填写实际原始响应全文并核对UTF-8摘要",
                "completeness_declaration": False,
                "items": [{"id": "填写来源记录ID", "published_at": "填写原始发布时间，含时区",
                           "url": "https://example.org/replace-with-record", "in_scope": None}]}
    else:
        raise HTTPException(status_code=404, detail="模板不存在")
    return _export(body, "acceptance-" + kind + "-template")
