"""Read B's document API as stored summary fields, never as original full text."""
import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request

from enrichment.documents import canonical, digest, now

# Local demo / compose hosts only (never arbitrary remote).
_ALLOWED_TEAM_HOSTS = frozenset({"127.0.0.1", "localhost", "b-api"})

TEAM_MEDIA = "application/vnd.ai-sec-intel.team-document+json"
TYPE_MAP = {"security_blog": "research_article", "security_community": "research_article",
            "academic_paper": "academic_paper", "technical_standard": "standard",
            "policy_regulation": "policy", "vendor_advisory": "vendor_advisory"}


def team_id(document_id):
    return "DOC-" + digest("team-document:" + document_id)[:16]


def parse_record(body):
    row = json.loads(body)
    if not isinstance(row, dict):
        raise ValueError("团队资料详情不是对象")
    for key in ("document_id", "source", "source_category", "title", "url"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError("团队资料缺少字段：" + key)
    if not re.fullmatch(r"doc-[0-9a-f]{64}", row["document_id"]):
        raise ValueError("团队资料标识不符合约定")
    if row["source_category"] not in TYPE_MAP:
        raise ValueError("尚不支持该团队资料类别")
    if not isinstance(row.get("description"), str) or not row["description"].strip():
        raise ValueError("团队资料没有可引用的描述字段")
    url = urllib.parse.urlsplit(row["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.port not in (None, 443):
        raise ValueError("团队资料来源需要公开 HTTPS 地址")
    if url.hostname == "localhost":
        raise ValueError("团队资料来源不是公开地址")
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("团队资料来源不是公开地址")
    for key in ("published_at", "modified_at", "first_seen_at", "content_updated_at"):
        if row.get(key) is not None and not isinstance(row[key], str):
            raise ValueError("团队资料时间字段无效")
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
            "source_snapshot_kind": "team_api_record", "snapshot_url": response["url"],
            "extraction_notice": "当前引用来自队友接口存档的题名/描述字段，未核对原始网页、论文或法规全文；"
                "不能把描述当成完整条款、标准要求或本项目验证结果。"}, row


def _embed_mode():
    mode = os.environ.get("TEAM_INTEL_MODE", "embed").strip().lower()
    return mode in {"embed", "inprocess", "1", "true", "yes", ""}


class TeamDocumentCollector:
    def __init__(self, base_url=None, timeout=10, max_documents=30):
        if type(max_documents) is not int or not 1 <= max_documents <= 200:
            raise ValueError("每轮多源资料数量必须为 1 到 200")
        self.timeout, self.max_documents = timeout, max_documents
        # Omit base_url in embed mode (in-process). An explicit base_url always
        # selects the HTTP adapter so sidecar/tests keep host/port validation.
        if base_url is None and _embed_mode():
            self.embed = True
            self.base_url = "inprocess://b-embed"
            return
        self.embed = False
        base_url = (base_url or os.environ.get("TEAM_INTEL_BASE_URL") or "http://127.0.0.1:8765").rstrip("/")
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
        self.base_url = base_url

    def get(self, path):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError("团队 API 不接受重定向")
        url = self.base_url + path
        request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-team-documents"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=self.timeout) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise ValueError("团队 API 响应超过大小限制")
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
                raise ValueError("团队资料分页无效")
            if total is not None and page["total"] != total:
                raise ValueError("团队资料总数在分页期间改变，请重试")
            total = page["total"]
            rows = page["items"]
            if not rows and len(records) < min(total, self.max_documents):
                break
            records.extend(rows)
        if any(not isinstance(row, dict) or not re.fullmatch(r"doc-[0-9a-f]{64}", str(row.get("document_id", ""))) for row in records):
            raise ValueError("团队资料列表标识无效")
        candidates, errors = [], []
        for current in records:
            try:
                if current["source_category"] not in TYPE_MAP:
                    raise ValueError("尚不支持该团队资料类别")
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
        if self.embed:
            return self._collect_embed()
        records, total = [], None
        while total is None or len(records) < min(total, self.max_documents):
            query = urllib.parse.urlencode({"limit": min(100, self.max_documents - len(records)),
                                           "offset": len(records)})
            page = json.loads(self.get("/api/documents?" + query)["body"])
            if not isinstance(page, dict) or type(page.get("total")) is not int or page["total"] < 0 or not isinstance(page.get("items"), list):
                raise ValueError("团队资料分页无效")
            if total is not None and page["total"] != total:
                raise ValueError("团队资料总数在分页期间改变，请重试")
            total = page["total"]
            rows = page["items"]
            if not rows and len(records) < min(total, self.max_documents):
                raise ValueError("团队资料分页提前结束")
            if len(rows) > min(100, self.max_documents - len(records)) or len(records) + len(rows) > total:
                raise ValueError("团队资料分页数量矛盾")
            records.extend(rows)
        if any(not isinstance(row, dict) or not re.fullmatch(r"doc-[0-9a-f]{64}", str(row.get("document_id", ""))) for row in records):
            raise ValueError("团队资料列表标识无效")
        identifiers = [row["document_id"] for row in records]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("团队资料分页出现重复标识，请重试")
        candidates, errors = [], []
        for row in records:
            try:
                response = self.get("/api/documents/" + urllib.parse.quote(row["document_id"], safe=""))
                current = parse_record(response["body"])
                if current["document_id"] != row["document_id"] or current["source"] != row["source"] or canonical(current["url"]) != canonical(row["url"]):
                    raise ValueError("团队资料详情与列表身份不一致")
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
