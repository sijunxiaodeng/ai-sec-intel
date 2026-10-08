"""独立发现公告、研究文章和论文；订阅响应是数据，不是执行指令。"""

from email.utils import parsedate_to_datetime
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET

from enrichment.documents import canonical, fetch

ATOM = "{http://www.w3.org/2005/Atom}"
AI = re.compile(r"\b(?:ai|llms?|vllm|ollama|agents?|hugging\s*face|machine learning|language models?)\b|prompt injection|模型|智能体", re.I)
SECURITY = re.compile(r"secur|vulnerab|attack|exploit|inject|jailbreak|poison|malicious|pickle|安全|漏洞|攻击", re.I)
PAPER_QUERY = '(all:"prompt injection" OR all:"LLM security" OR all:"model supply chain")'
SOURCES = (
    {"id": "vllm_advisories", "name": "vLLM 项目安全公告", "category": "vendor_advisory",
     "url": "https://api.github.com/repos/vllm-project/vllm/security-advisories?state=published&sort=published&direction=desc&per_page=30",
     "parser": "github", "prefix": "https://github.com/vllm-project/vllm/security/advisories/"},
    {"id": "transformers_advisories", "name": "Transformers 项目安全公告", "category": "vendor_advisory",
     "url": "https://api.github.com/repos/huggingface/transformers/security-advisories?state=published&sort=published&direction=desc&per_page=30",
     "parser": "github", "prefix": "https://github.com/huggingface/transformers/security/advisories/"},
    {"id": "trailofbits_research", "name": "Trail of Bits 研究博客", "category": "research_article",
     "url": "https://blog.trailofbits.com/feed/", "parser": "rss", "prefix": "https://blog.trailofbits.com/"},
    {"id": "arxiv_security", "name": "arXiv AI 安全论文", "category": "academic_paper",
     "url": "https://export.arxiv.org/api/query?" + urllib.parse.urlencode({
         "search_query": PAPER_QUERY, "start": 0, "max_results": 8,
         "sortBy": "submittedDate", "sortOrder": "descending"}),
     "parser": "atom", "prefix": "https://arxiv.org/abs/"},
)
# 明确标注历史起始资料，不能把它们计为实时发现的新情报。
SEEDS = (
    {"url": "https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032",
     "source_id": "wiz_seed", "source_name": "Wiz Research", "document_type": "research_article"},
    {"url": "https://docs.vllm.ai/en/latest/usage/security/",
     "source_id": "vllm_guidance_seed", "source_name": "vLLM 官方文档", "document_type": "vendor_guidance"},
    {"url": "https://huggingface.co/docs/hub/security-pickle",
     "source_id": "huggingface_guidance_seed", "source_name": "Hugging Face 官方文档", "document_type": "vendor_guidance"},
    {"url": "https://arxiv.org/abs/2302.12173",
     "source_id": "arxiv_seed", "source_name": "arXiv", "document_type": "academic_paper"},
    {"url": "https://arxiv.org/abs/2307.15043",
     "source_id": "arxiv_seed", "source_name": "arXiv", "document_type": "academic_paper"},
)


def relevant(text):
    return bool(AI.search(text) and SECURITY.search(text))


def _allowed_url(url, source):
    if not isinstance(url, str):
        return None
    # arXiv 的 Atom ID 常使用 http，仅对已知官方主机规范为 HTTPS。
    if source["parser"] == "atom" and url.startswith("http://arxiv.org/abs/"):
        url = "https://" + url[7:]
    url = canonical(url)
    return url if url.startswith(source["prefix"]) else None


def parse_feed(source, response, limit=3):
    """只读公开 published 数据；限定官方前缀，按发布顺序选择有界窗口。"""
    body = response["body"]
    rows = []
    if source["parser"] == "github":
        data = json.loads(body)
        if not isinstance(data, list):
            raise ValueError("公告接口未返回列表")
        for entry in data:
            if entry.get("state") not in (None, "published") or entry.get("withdrawn_at"):
                continue
            if not entry.get("ghsa_id") or not entry.get("description"):
                continue
            rows.append({"url": entry.get("html_url"), "title": entry.get("summary", ""),
                         "published_at": entry.get("published_at"), "updated_at": entry.get("updated_at")})
    else:
        # 拒绝 DTD/实体，避免解析订阅时扩展实体或读取外部资源。
        if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", body, re.I):
            raise ValueError("订阅包含不支持的 DTD/实体")
        root = ET.fromstring(body)
        if source["parser"] == "rss":
            if root.tag != "rss" or root.find("channel") is None:
                raise ValueError("订阅未返回有效 RSS channel")
            for entry in root.findall("./channel/item"):
                title, summary = entry.findtext("title", ""), entry.findtext("description", "")
                if not relevant(title + " " + summary):
                    continue
                published = entry.findtext("pubDate")
                if published:
                    try:
                        published = parsedate_to_datetime(published).isoformat()
                    except (ValueError, TypeError):
                        published = None
                rows.append({"url": entry.findtext("link"), "title": title, "published_at": published})
        elif source["parser"] == "atom":
            if root.tag != ATOM + "feed":
                raise ValueError("订阅未返回有效 Atom feed")
            for entry in root.findall(ATOM + "entry"):
                if "/api/errors" in entry.findtext(ATOM + "id", ""):
                    raise ValueError("arXiv API 返回查询错误")
                title = " ".join(entry.findtext(ATOM + "title", "").split())
                summary = " ".join(entry.findtext(ATOM + "summary", "").split())
                if relevant(title + " " + summary):
                    rows.append({"url": entry.findtext(ATOM + "id"), "title": title,
                                 "published_at": entry.findtext(ATOM + "published"),
                                 "updated_at": entry.findtext(ATOM + "updated")})
        else:
            raise ValueError("未知订阅解析器")
    selected, seen = [], set()
    rows.sort(key=lambda row: row.get("published_at") or "", reverse=True)
    for row in rows:
        url = _allowed_url(row.get("url"), source)
        if not url or url in seen:
            continue
        seen.add(url)
        selected.append(dict(row, url=url, source_id=source["id"], source_name=source["name"],
                             document_type=source["category"], discovery="subscription"))
        if len(selected) == limit:
            break
    return selected


def discover(source, limit=3, fetcher=fetch):
    response = fetcher(source["url"])
    return parse_feed(source, response, limit), response
