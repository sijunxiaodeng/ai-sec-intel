"""从情报参考链接处理关联文档；第三方内容只作为数据，不执行其中代码。"""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request

from rag.evidence import CVE

MAX_BYTES = 4 * 1024 * 1024
TOPICS = {
    "versions": r"version|before|prior to|affected|版本",
    "remediation": r"fix|patch|upgrad|mitigat|validat|修复|升级|缓解",
    "conditions": r"attack|exploit|authentication|traversal|digest|攻击|利用|条件",
    "impact": r"remote code|execution|arbitrary|denial|impact|vulnerab|风险|执行|影响",
    "ai_relevance": r"ollama|llm|model|inference|machine learning|模型|推理",
    "cvss": r"cvss|baseScore|评分",
    "poc": r"proof.of.concept|\bpoc\b|exploit|复现",
}
LABELS = {"versions": "版本 受影响", "remediation": "修复 缓解 升级",
          "conditions": "利用 条件 原理", "impact": "影响 风险 危害",
          "ai_relevance": "AI 关联 推理", "cvss": "CVSS 评分", "poc": "PoC 复现"}


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(url):
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path, p.query, ""))


def public_url(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.port not in (None, 443):
        raise ValueError("只处理公开 HTTPS 页面")
    addresses = socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError("不处理本机或内网地址")


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url):
    public_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student/0.3",
                                                  "Accept": "application/json,text/html,text/plain,application/atom+xml,application/xml,application/pdf"})
    opener = urllib.request.build_opener(PublicRedirect())
    with opener.open(request, timeout=15) as response:
        content_type = response.headers.get_content_type()
        if content_type not in ("application/json", "text/html", "text/plain", "application/xhtml+xml",
                                "application/atom+xml", "application/xml", "text/xml", "application/rss+xml", "application/pdf"):
            raise ValueError("暂不支持此文档类型：" + content_type)
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("响应超过 4 MiB 上限")
        return {"body": body, "content_type": content_type, "url": response.geturl(),
                "encoding": response.headers.get_content_charset() or "utf-8"}


def fetch_url(url):
    # PR/安全公告用官方 JSON 接口，避免把 GitHub 导航当成正文。
    p = urllib.parse.urlsplit(url)
    match = re.fullmatch(r"/([^/]+)/([^/]+)/pull/(\d+)/?", p.path)
    if p.hostname == "github.com" and match:
        owner, repo, number = match.groups()
        return "https://api.github.com/repos/%s/%s/pulls/%s" % (owner, repo, number)
    advisory = re.fullmatch(r"/([^/]+)/([^/]+)/security/advisories/(GHSA-[\w-]+)", p.path)
    if p.hostname == "github.com" and advisory:
        return "https://api.github.com/repos/%s/%s/security-advisories/%s" % advisory.groups()
    if p.hostname == "github.com" and re.fullmatch(r"/advisories/GHSA-[\w-]+", p.path):
        return "https://api.github.com" + p.path
    if p.hostname == "github.com" and p.path.startswith("/CVEProject/cvelistV5/"):
        match = re.fullmatch(r"/CVEProject/cvelistV5/(?:blob|tree)/([^/]+)/(cves/.+\.json)", p.path)
        if match:
            return "https://raw.githubusercontent.com/CVEProject/cvelistV5/%s/%s" % match.groups()
    if p.hostname == "osv.dev" and p.path.startswith("/vulnerability/"):
        return "https://api.osv.dev/v1/vulns/" + p.path.rsplit("/", 1)[-1]
    return url


def reference_candidates(record):
    item = record["item"]
    raw = item.get("raw_data") or {}
    refs = list(record.get("references") or []) + list(item.get("references") or [])
    refs += [d["url"] for d in raw.get("related_documents", []) if d.get("url")]
    result = []
    for url in refs:
        if isinstance(url, dict):
            url = url.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        url = canonical(url)
        if urllib.parse.urlsplit(url).hostname in ("nvd.nist.gov", "services.nvd.nist.gov"):
            continue
        if not any(row["url"] == url for row in result):
            result.append({"url": url, "tags": [], "origin": "record_reference"})
    return result


def nvd_document(cve_id, response):
    payload = json.loads(response["body"])
    rows = [row["cve"] for row in payload.get("vulnerabilities", []) if row.get("cve", {}).get("id") == cve_id]
    if len(rows) != 1:
        raise ValueError("NVD 没有返回对应编号")
    cve = rows[0]
    parts = [("id", cve_id)]
    parts += [("descriptions/%d" % i, row.get("value", "")) for i, row in enumerate(cve.get("descriptions", []))]
    for key, metrics in (cve.get("metrics") or {}).items():
        for i, metric in enumerate(metrics):
            parts.append(("metrics/%s/%d" % (key, i), json.dumps(metric, ensure_ascii=False)))
    for i, block in enumerate(cve.get("configurations", [])):
        parts.append(("configurations/%d" % i, json.dumps(block, ensure_ascii=False)))
    if cve.get("references"):
        parts.append(("references", json.dumps(cve["references"], ensure_ascii=False)))
    refs = []
    for ref in cve.get("references", []):
        if ref.get("url", "").startswith("https://"):
            refs.append({"url": canonical(ref["url"]), "tags": ref.get("tags", []), "origin": "nvd_reference"})
    return {"title": cve_id + " · NVD", "parts": parts, "published_at": cve.get("published"),
            "source_last_modified": cve.get("lastModified"), "relation_type": "vulnerability_record",
            "association_reason": "NVD API 的 cve.id 与当前编号完全一致", "references": refs}


def extract_document(response, url):
    if response["content_type"] == "application/json" or ("raw.githubusercontent.com/CVEProject/cvelistV5/" in response.get("url", "")):
        data = json.loads(response["body"])
        if data.get("dataType") == "CVE_RECORD":
            metadata = data.get("cveMetadata") or {}
            cna = (data.get("containers") or {}).get("cna") or {}
            parts = [("cveMetadata/cveId", metadata.get("cveId") or "")]
            parts += [("containers/cna/" + field, json.dumps(cna[field], ensure_ascii=False)) for field in
                      ("descriptions", "affected", "metrics", "problemTypes") if field in cna]
            return {"title": cna.get("title") or metadata.get("cveId") or "CVE Record",
                    "parts": parts, "published_at": metadata.get("datePublished")}
        text = data.get("description") or data.get("details") or data.get("body") or ""
        title = data.get("title") or data.get("summary") or ""
        if not title and not text:
            raise ValueError("JSON 没有可用正文")
        parts = [("title", title), ("body", text)]
        identifiers = {k: data[k] for k in ("id", "cve_id", "aliases") if data.get(k) and (k != "id" or isinstance(data[k], str))}
        if identifiers:
            parts.append(("identifiers", json.dumps(identifiers, ensure_ascii=False)))
        if "merged" in data:
            parts.append(("merge_metadata", json.dumps({key: data.get(key) for key in
                          ("merged", "merged_at", "merge_commit_sha")}, ensure_ascii=False)))
        return {"title": title or str(data.get("id") or url), "parts": parts, "published_at": data.get("published_at") or data.get("published") or data.get("created_at")}
    text = response["body"].decode(response.get("encoding", "utf-8"), errors="replace")
    if response["content_type"] == "text/plain":
        return {"title": url, "parts": [("text", text)], "published_at": None}
    from trafilatura import extract
    parsed = extract(text, url=url, output_format="json", with_metadata=True,
                     include_comments=False, include_tables=True)
    data = json.loads(parsed) if parsed else {}
    body = data.get("text") or ""
    if len(body.strip()) < 100 or re.search(r"^(just a moment|access denied|verify you are human)", body, re.I):
        raise ValueError("没有可用文章正文，可能为空页或访问验证页")
    return {"title": data.get("title") or url, "parts": [("extracted_text", body)],
            "published_at": data.get("date")}


def associate(cve_id, candidate, doc):
    text = "\n".join(value for _, value in doc["parts"])
    tags = {tag.lower() for tag in candidate["tags"]}
    # 编号必须在已提取正文或标题中出现；不能只看 URL。
    exact = cve_id in {value.upper() for value in CVE.findall(text + "\n" + doc["title"])}
    parsed_url = urllib.parse.urlsplit(candidate["url"])
    pr = parsed_url.hostname == "github.com" and bool(re.fullmatch(r"/[^/]+/[^/]+/pull/\d+/?", parsed_url.path))
    fix = "patch" in tags or (candidate["origin"].startswith("nvd_reference") and pr)
    if fix:
        reason = "NVD 对应记录引用的补丁或 PR；修复有效性未由本项目测试"
        if candidate["origin"] == "nvd_reference_cached":
            reason += "；关联依据为上次成功 NVD 快照：" + candidate["nvd_retrieved_at"]
        return "fix_record", reason
    if exact:
        if parsed_url.hostname == "osv.dev" or (parsed_url.hostname == "github.com" and (parsed_url.path.startswith("/advisories/") or parsed_url.path.startswith("/CVEProject/cvelistV5/"))):
            return "vulnerability_record", "公开漏洞库/安全公告的正文或标题包含对应编号"
        if "exploit" in tags:
            return "poc_candidate", "正文/标题含对应编号，且 NVD 标为 Exploit；代码未执行"
        return "direct_analysis", "已提取正文或标题包含对应 CVE 编号"
    return "background", "参考链接未在正文匹配对应编号，且不是 NVD 补丁/PR；不进入漏洞问答证据"


def make_chunks(doc, max_chars=1000):
    chunks = []
    for field, value in doc["parts"]:
        start = 0
        while start < len(value):
            end = min(start + max_chars, len(value))
            if end < len(value):
                boundary = value.rfind("\n", start + max_chars // 2, end)
                if boundary < 0:
                    boundary = value.rfind(" ", start + max_chars // 2, end)
                if boundary >= 0:
                    end = boundary + 1
            offset = start
            text = value[start:end]
            start = end
            if not text.strip():
                continue
            topics = [key for key, pattern in TOPICS.items() if re.search(pattern, text, re.I)]
            if doc["relation_type"] == "fix_record":
                topics = list(dict.fromkeys(topics + ["remediation"]))
            eid = "AUTO-" + doc["source_id"] + "-" + digest(field + ":" + str(offset) + ":" + text)[:12]
            chunks.append({"evidence_id": eid, "text": text, "text_sha256": digest(text),
                           "topics": topics, "search_terms": " ".join(LABELS[k] for k in topics),
                           "locator": "%s；字符 [%d,%d)，相对于存档提取正文，非原网页行号" % (field, offset, offset + len(text)),
                           "text_kind": "automatic_source_extract"})
            if field.startswith("metrics/") and offset == 0 and len(value) <= max_chars:
                chunks[-1]["structured_value"] = json.loads(value)
    return chunks


def finish(doc, cve_id, source_url, response, retrieved_at):
    text = "\n".join(value for _, value in doc["parts"])
    doc.update({"cve_id": cve_id, "url": source_url, "fetch_url": response["url"],
                "retrieved_at": retrieved_at, "source_id": digest(canonical(source_url))[:16],
                "source_response_sha256": hashlib.sha256(response["body"]).hexdigest(),
                "text_sha256": digest(text), "text": text, "status": "ok"})
    doc["_response_body"] = response["body"]
    doc["chunks"] = make_chunks(doc) if doc["relation_type"] != "background" else []
    return doc
