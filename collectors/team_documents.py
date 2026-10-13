"""Read B's document API as stored summary fields, never as original full text."""
import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request

from enrichment.documents import canonical, digest, now
from collectors.intelligence import team_intel_disabled
from team_change_protocol import validate_page

# Local demo / compose hosts only (never arbitrary remote).
_ALLOWED_TEAM_HOSTS = frozenset({"127.0.0.1", "localhost", "b-api"})

TEAM_MEDIA = "application/vnd.ai-sec-intel.team-document+json"
TYPE_MAP = {"security_blog": "research_article", "security_community": "research_article",
            "academic_paper": "academic_paper", "technical_standard": "standard",
            "policy_regulation": "policy", "vendor_advisory": "vendor_advisory",
            "government_alert": "vendor_advisory", "vulnerability_database": "vendor_advisory"}


def team_id(document_id):
    return "DOC-" + digest("team-document:" + document_id)[:16]


def parse_record(body):
    row = json.loads(body)
    if not isinstance(row, dict):
        raise ValueError("资料摘要详情不是对象")
    for key in ("document_id", "source", "source_category", "title", "url"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError("资料摘要缺少字段：" + key)
    if not re.fullmatch(r"doc-[0-9a-f]{64}", row["document_id"]):
        raise ValueError("资料摘要标识不符合约定")
    if row["source_category"] not in TYPE_MAP:
        raise ValueError("尚不支持该资料摘要类别")
    if not isinstance(row.get("description"), str) or not row["description"].strip():
        raise ValueError("资料摘要没有可引用的描述字段")
    url = urllib.parse.urlsplit(row["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.port not in (None, 443):
        raise ValueError("资料摘要来源需要公开 HTTPS 地址")
    if url.hostname == "localhost":
        raise ValueError("资料摘要来源不是公开地址")
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("资料摘要来源不是公开地址")
    for key in ("published_at", "modified_at", "first_seen_at", "content_updated_at"):
        if row.get(key) is not None and not isinstance(row[key], str):
            raise ValueError("资料摘要时间字段无效")
    return row


def extract_summary(response):
    row = parse_record(response["body"])
    return {"title": row["title"], "parts": [("team_api.title", row["title"]),
            ("team_api.description", row["description"])], "content_scope": "team_summary",
            "published_at": row.get("published_at"), "published_at_basis": "team_record_metadata",
            "source_last_modified": row.get("modified_at"),
            "team_document_id": row["document_id"], "team_source": row["source"],
            "team_source_category": row["source_category"], "team_first_seen_at": row.get("first_seen_at"),
            "team_content_updated_at": row.get("content_updated_at"),
            "team_classification": row.get("classification"),
            "source_snapshot_kind": "team_api_record", "snapshot_url": response["url"],
            "extraction_notice": "当前引用来自队友接口存档的题名/描述字段，未核对原始网页、论文或法规全文；"
                "不能把描述当成完整条款、标准要求或本项目验证结果。"}, row


def _embed_mode():
    mode = os.environ.get("TEAM_INTEL_MODE", "embed").strip().lower()
    return mode in {"embed", "inprocess", "1", "true", "yes", ""}


class TeamDocumentCollector:
    def __init__(self, base_url=None, timeout=10, max_documents=30, use_changefeed=False):
        if type(max_documents) is not int or not 1 <= max_documents <= 200:
            raise ValueError("每轮多源资料数量必须为 1 到 200")
        self.timeout, self.max_documents = timeout, max_documents
        self.use_changefeed = use_changefeed
        self.disabled = base_url is None and team_intel_disabled()
        if self.disabled:
            self.embed = False
            self.base_url = "disabled://team"
            return
        # Omit base_url in embed mode (in-process). An explicit base_url always
        # selects the HTTP adapter so sidecar/tests keep host/port validation.
        if base_url is None and _embed_mode():
            self.embed = True
            self.base_url = "inprocess://b-embed"
            return
        self.embed = False
        base_url = (base_url or os.environ.get("TEAM_INTEL_UPSTREAM") or os.environ.get("TEAM_INTEL_BASE_URL") or "http://127.0.0.1:8765").rstrip("/")
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in _ALLOWED_TEAM_HOSTS
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("多源资料 API 仅允许本机或 compose 服务名 b-api 的 HTTP 地址")
        if parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port not in (8765, 8023):
            raise ValueError("多源资料 API 本机端口必须为 8765 或 8023")
        self.base_url, self.timeout, self.max_documents = base_url, timeout, max_documents
        self.use_changefeed = use_changefeed

    def collect_changes(self, cursor=None):
        if getattr(self, "disabled", False):
            return {"candidates": [], "errors": [], "retracted_ids": [],
                    "selected": 0, "total": None, "remaining": None,
                    "has_more": False, "reset": False,
                    "cursor": {"epoch": None, "seq": 0, "base_url": self.base_url},
                    "coverage": "按配置跳过资料摘要同步；未查询当前总量"}
        saved = cursor or {}
        if saved.get("base_url", self.base_url) != self.base_url:
            saved = {}
        params = {"kind": "document", "cursor": saved.get("seq", 0), "limit": min(100, self.max_documents)}
        if saved.get("epoch"):
            params["epoch"] = saved["epoch"]
        if saved.get("through") is not None:
            params["through"] = saved["through"]
        response = self.get("/api/team/changes?" + urllib.parse.urlencode(params))
        page = validate_page(json.loads(response["body"]), params["cursor"])
        if not page["reset"]:
            validate_page(page, params["cursor"], saved.get("epoch"), saved.get("through"))
        candidates, errors, retracted = [], [], []
        # Defensive coalescing also supports producers that emit every event.
        # A retract followed by a successful reclassification must finish as an
        # upsert, irrespective of their occurrence in the same page.
        latest = {event["entity_id"]: event for event in page["changes"]}
        for event in latest.values():
            if event["operation"] == "retract":
                if not re.fullmatch(r"doc-[0-9a-f]{64}", event["entity_id"]):
                    raise ValueError("资料摘要撤回事件标识无效")
                retracted.append(team_id(event["entity_id"]))
                continue
            row = event["item"]
            try:
                current = parse_record(json.dumps(row, ensure_ascii=False).encode())
                if current["document_id"] != event["entity_id"]:
                    raise ValueError("资料摘要变更与资料身份不一致")
                # Snapshot the event payload itself, so source updates between
                # list and detail cannot change a page's imported evidence.
                snapshot = {"body": json.dumps(current, ensure_ascii=False).encode(),
                            "url": self.base_url + "/api/documents/" + current["document_id"],
                            "retrieved_at": response["retrieved_at"], "content_type": TEAM_MEDIA}
                candidates.append({"url": current["url"], "document_type": TYPE_MAP[current["source_category"]],
                    "source_name": current["source"], "source_id": "team_documents", "discovery": "team_api",
                    "team_document_id": current["document_id"], "discovered_at": now(), "_prefetched_response": snapshot})
            except Exception as exc:
                errors.append({"document_id": team_id(event["entity_id"]), "url": row.get("url", ""),
                    "document_type": TYPE_MAP.get(row.get("source_category"), "unknown"), "publisher": row.get("source", "unknown"),
                    "status": "error", "retrieved_at": now(), "error": str(exc)[:240]})
        next_state = {"epoch": page["epoch"], "seq": page["next_cursor"], "base_url": self.base_url}
        if page["has_more"]:
            next_state["through"] = page["through"]
        return {"candidates": candidates, "errors": errors, "retracted_ids": retracted,
                "selected": len(page["changes"]), "total": None, "remaining": None,
                "has_more": page["has_more"], "reset": page["reset"],
                "cursor": next_state,
                "coverage": "持久变更游标；首次从零导入全部有效 AI 资料，后续消费新增、更新及撤回"}

    def get(self, path):
        if getattr(self, "disabled", False):
            raise ValueError("资料摘要同步已按配置禁用")
        if self.embed:
            from api.b_embed import list_changes_page
            parsed = urllib.parse.urlsplit(path)
            if parsed.path != "/api/team/changes":
                raise ValueError("嵌入资料变更读取仅支持 changefeed")
            params = urllib.parse.parse_qs(parsed.query)
            page = list_changes_page(
                kind="document", cursor=int(params.get("cursor", [0])[0]),
                through=int(params["through"][0]) if "through" in params else None,
                epoch=params.get("epoch", [None])[0], limit=int(params.get("limit", [100])[0]),
            )
            return {"body": json.dumps(page, ensure_ascii=False).encode(), "url": self.base_url + path,
                    "retrieved_at": now(), "content_type": TEAM_MEDIA}
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError("多源资料 API 不接受重定向")
        url = self.base_url + path
        request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-team-documents"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=self.timeout) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise ValueError("多源资料 API 响应超过大小限制")
        return {"body": body, "url": url, "retrieved_at": now(), "content_type": TEAM_MEDIA}

    def _collect_embed(self):
        from api.b_embed import db_path, ensure_intelligence_path, INTEL_ROOT
        ensure_intelligence_path()
        from api_v6.document_repository import DocumentRepository

        docs = DocumentRepository(db_path(), INTEL_ROOT)
        records, total = [], None
        while total is None or len(records) < min(total, self.max_documents):
            page = docs.list_items(
                limit=min(100, self.max_documents - len(records)),
                offset=len(records),
                include_raw=True,
            )
            if type(page.get("total")) is not int or page["total"] < 0 or not isinstance(page.get("items"), list):
                raise ValueError("资料摘要分页无效")
            if total is not None and page["total"] != total:
                raise ValueError("资料摘要总数在分页期间改变，请重试")
            total = page["total"]
            rows = page["items"]
            if not rows and len(records) < min(total, self.max_documents):
                break
            records.extend(rows)
        if any(not isinstance(row, dict) or not re.fullmatch(r"doc-[0-9a-f]{64}", str(row.get("document_id", ""))) for row in records):
            raise ValueError("资料摘要列表标识无效")
        candidates, errors = [], []
        for current in records:
            try:
                if current["source_category"] not in TYPE_MAP:
                    raise ValueError("尚不支持该资料摘要类别")
                body = json.dumps(current, ensure_ascii=False).encode("utf-8")
                response = {
                    "body": body,
                    "url": "inprocess://b-embed/api/documents/" + current["document_id"],
                    "retrieved_at": now(),
                    "content_type": TEAM_MEDIA,
                }
                # Re-validate through parse_record for the same contract as HTTP path.
                parsed = parse_record(response["body"])
                candidates.append({
                    "url": parsed["url"],
                    "document_type": TYPE_MAP[parsed["source_category"]],
                    "source_name": parsed["source"],
                    "source_id": "team_documents",
                    "discovery": "team_api",
                    "team_document_id": parsed["document_id"],
                    "discovered_at": now(),
                    "_prefetched_response": response,
                })
            except Exception as exc:
                errors.append({
                    "document_id": team_id(str(current.get("document_id", ""))),
                    "url": current.get("url", ""),
                    "document_type": TYPE_MAP.get(current.get("source_category"), "unknown"),
                    "publisher": current.get("source", "unknown"),
                    "status": "error", "retrieved_at": now(), "error": str(exc)[:240],
                })
        return {
            "candidates": candidates, "errors": errors, "total": total or 0,
            "selected": len(records), "remaining": max(0, (total or 0) - len(records)),
            "coverage": "同进程嵌入读取 B 资料库窗口；非全量镜像",
        }

    def collect(self):
        if getattr(self, "disabled", False):
            return {"status": "skipped", "enabled": False, "candidates": [], "errors": [],
                    "total": None, "selected": 0, "remaining": None,
                    "coverage": "按配置跳过资料摘要同步；未查询当前总量"}
        if self.embed:
            return self._collect_embed()
        records, total = [], None
        while total is None or len(records) < min(total, self.max_documents):
            query = urllib.parse.urlencode({"limit": min(100, self.max_documents - len(records)),
                                           "offset": len(records)})
            page = json.loads(self.get("/api/documents?" + query)["body"])
            if not isinstance(page, dict) or type(page.get("total")) is not int or page["total"] < 0 or not isinstance(page.get("items"), list):
                raise ValueError("资料摘要分页无效")
            if total is not None and page["total"] != total:
                raise ValueError("资料摘要总数在分页期间改变，请重试")
            total = page["total"]
            rows = page["items"]
            if not rows and len(records) < min(total, self.max_documents):
                raise ValueError("资料摘要分页提前结束")
            if len(rows) > min(100, self.max_documents - len(records)) or len(records) + len(rows) > total:
                raise ValueError("资料摘要分页数量矛盾")
            records.extend(rows)
        if any(not isinstance(row, dict) or not re.fullmatch(r"doc-[0-9a-f]{64}", str(row.get("document_id", ""))) for row in records):
            raise ValueError("资料摘要列表标识无效")
        identifiers = [row["document_id"] for row in records]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("资料摘要分页出现重复标识，请重试")
        candidates, errors = [], []
        for row in records:
            try:
                response = self.get("/api/documents/" + urllib.parse.quote(row["document_id"], safe=""))
                current = parse_record(response["body"])
                if current["document_id"] != row["document_id"] or current["source"] != row["source"] or canonical(current["url"]) != canonical(row["url"]):
                    raise ValueError("资料摘要详情与列表身份不一致")
                candidates.append({"url": current["url"], "document_type": TYPE_MAP[current["source_category"]],
                    "source_name": current["source"], "source_id": "team_documents", "discovery": "team_api",
                    "team_document_id": current["document_id"], "discovered_at": now(),
                    "_prefetched_response": response})
            except Exception as exc:
                errors.append({"document_id": team_id(row["document_id"]), "url": row.get("url", ""),
                    "document_type": TYPE_MAP.get(row.get("source_category"), "unknown"), "publisher": row.get("source", "unknown"),
                    "status": "error", "retrieved_at": now(), "error": str(exc)[:240]})
        return {"candidates": candidates, "errors": errors, "total": total,
                "selected": len(records), "remaining": max(0, total - len(records)),
                "coverage": "按更新时间导入本轮最新窗口；非全量镜像，不以记录缺席认定来源撤回"}
