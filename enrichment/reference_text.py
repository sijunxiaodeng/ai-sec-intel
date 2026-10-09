"""论文 HTML、PDF 页文本、政策条文及标准目录的有界只读解析。"""

from io import BytesIO
import re
from urllib.parse import urlsplit

from collectors.reference import REFERENCE_SOURCES
from enrichment.documents import canonical, extract_document

ARXIV_ID = r"[0-9]{4}\.[0-9]{4,5}(?:v[0-9]+)?"
MAX_PAGES = 120
MAX_TEXT = 1_000_000


def reference_source(url, kind):
    source = next((s for s in REFERENCE_SOURCES if canonical(s["url"]) == canonical(url) and s["category"] == kind), None)
    if not source:
        raise ValueError("该标准/政策不在已核对的官方来源列表中")
    return source


def pdf_document(response, source):
    from pypdf import PdfReader
    if not response["body"].startswith(b"%PDF-"):
        raise ValueError("响应不是 PDF 原文")
    reader = PdfReader(BytesIO(response["body"]))
    if reader.is_encrypted:
        raise ValueError("不处理加密 PDF")
    if not 1 <= len(reader.pages) <= MAX_PAGES:
        raise ValueError("PDF 页数超出 1 到 120 页范围")
    parts, total = [], 0
    for number, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        total += len(text)
        if len(text) > 100_000 or total > MAX_TEXT:
            raise ValueError("PDF 提取文本超出上限")
        if len(text.strip()) < 30:
            raise ValueError("PDF 含空白/扫描或不可可靠提取的页面，尚未支持 OCR")
        parts.append(("PDF page %d" % number, text))
    if source["expected_title"].lower() not in " ".join(parts[0][1].split()).lower():
        raise ValueError("PDF 首页题名与已核对来源不匹配")
    return {"title": source["version"], "parts": parts, "page_count": len(parts),
            "content_scope": "full_text_pdf", "version": source["version"],
            "published_at": source.get("published_at"), "published_at_basis": "official_publication_metadata",
            "reference_kind": source["reference_kind"],
            "extraction_notice": "PDF 各页的可提取文字；页码为文件物理页码。未识别图片、公式或表格布局。"}


def paper_html(response, url):
    from lxml import html
    identifier = re.fullmatch(r"/html/(%s)/?" % ARXIV_ID, urlsplit(url).path)
    if urlsplit(url).hostname != "arxiv.org" or not identifier:
        raise ValueError("只支持官方 arXiv HTML 全文")
    resolved = re.fullmatch(r"/html/(%s)/?" % ARXIV_ID, urlsplit(response["url"]).path)
    if urlsplit(response["url"]).hostname != "arxiv.org" or not resolved or re.sub(r"v\d+$", "", resolved.group(1)) != re.sub(r"v\d+$", "", identifier.group(1)):
        raise ValueError("全文重定向到了其他论文或非官方地址")
    root = html.fromstring(response["body"])
    articles = root.xpath('//article[contains(concat(" ",normalize-space(@class)," ")," ltx_document ")]')
    titles = root.xpath('//h1[contains(concat(" ",normalize-space(@class)," ")," ltx_title_document ")]')
    if len(articles) != 1 or not titles:
        raise ValueError("页面不是可核验的 arXiv 全文；保留原摘要")
    base = re.sub(r"v\d+$", "", identifier.group(1))
    versions = {m.group(1) for href in root.xpath('//a/@href')
                if (m := re.fullmatch(r"/abs/(%sv\d+)" % re.escape(base), href))}
    if len(versions) != 1:
        raise ValueError("全文页未提供唯一可核对的论文版本")
    version = versions.pop()
    if "v" in identifier.group(1) and version != identifier.group(1):
        raise ValueError("全文返回了其他论文版本")
    article = articles[0]
    for node in article.xpath('.//script | .//style | .//nav'):
        node.drop_tree()
    # 按最外层章节保留子章节、图表标题与附录，避免嵌套 section 重复。
    sections = article.xpath('./section | ./div[contains(@class,"ltx_abstract")] | ./div[contains(@class,"ltx_bibliography")]')
    parts = []
    for index, node in enumerate(sections):
        text = re.sub(r"[ \t]+", " ", node.text_content()).strip()
        if text:
            headings = node.xpath('./h2 | ./h3 | ./h6')
            heading = " ".join(headings[0].text_content().split()) if headings else node.get("id", "abstract")
            parts.append(("HTML section %s: %s" % (node.get("id") or index, heading), text))
    if not parts or sum(len(t) for _, t in parts) < 3000 or sum(len(t) for _, t in parts) > MAX_TEXT:
        raise ValueError("全文长度不满足有界提取要求")
    return {"title": " ".join(titles[0].text_content().split()), "parts": parts, "content_scope": "full_text_html",
            "version": version, "published_at": None, "full_text_url": url,
            "extraction_notice": "arXiv HTML 的可提取正文与附录；图像、公式排版及 HTML 转换遗漏未作完整核验。"}


def policy_document(response, source):
    doc = extract_document(response, source["url"])
    body = "\n".join(text for _, text in doc["parts"])
    if source["expected_title"] not in body or "征求意见稿" in doc["title"]:
        raise ValueError("页面不是预期的正式政策正文")
    matches = list(re.finditer(r"(?m)^第([一二三四五六七八九十百]+)条\s*", body))
    article_names = ("一 二 三 四 五 六 七 八 九 十 十一 十二 十三 十四 十五 十六 十七 十八 十九 二十 二十一 二十二 二十三 二十四").split()
    if [match.group(1) for match in matches] != article_names[:source["last_article"]]:
        raise ValueError("条文编号缺失、重复或顺序不一致，不能标为完整政策正文")
    parts = [("发布说明", body[:matches[0].start()])]
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        parts.append(("第" + match.group(1) + "条", body[match.start():end].strip()))
    effect = re.search(r"本办法自(\d{4})年(\d{1,2})月(\d{1,2})日起施行", parts[-1][1])
    if not effect:
        raise ValueError("正式政策缺少明确施行日期")
    dates = re.findall(r"(\d{4})年(\d{1,2})月(\d{1,2})日", parts[0][1])
    issued = "%s-%02d-%02d" % (dates[-1][0], int(dates[-1][1]), int(dates[-1][2])) if dates else None
    return {"title": source["expected_title"], "parts": parts, "content_scope": "policy_articles",
            "published_at": doc.get("published_at"), "issued_at": issued,
            "effective_at": "%s-%02d-%02d" % (effect[1], int(effect[2]), int(effect[3])),
            "scope_excerpt": parts[2][1], "reference_kind": "published_policy_text",
            "document_status": "正式发布正文；本库未自动核对是否已修改、废止或存在配套规定",
            "version": "发布文本 " + (issued or "日期未提取"), "article_count": len(matches)}


def catalog_document(response, source):
    doc = extract_document(response, source["url"])
    lines = [line.strip() for _, text in doc["parts"] for line in text.splitlines() if line.strip()]
    if source["expected_title"] not in doc["title"]:
        raise ValueError("标准目录返回其他编号")
    fields = {"标准号": source["expected_title"]}
    for key in ("中文标准名称", "标准状态", "发布日期", "实施日期", "发布单位"):
        index = next((i for i, s in enumerate(lines) if s.rstrip("：:") == key), None)
        if index is None or index + 1 == len(lines):
            raise ValueError("标准目录缺少 " + key)
        fields[key] = lines[index + 1]
    return {"title": fields["标准号"] + " " + fields["中文标准名称"],
            "parts": [("catalog/" + key, key + "：" + value) for key, value in fields.items()],
            "content_scope": "catalog_only", "published_at": fields["发布日期"], "effective_at": fields["实施日期"],
            "version": fields["标准号"], "catalog_fields": fields, "reference_kind": source["reference_kind"],
            "extraction_notice": "仅官方目录字段；未获取标准全文，不能据此解释技术条款。状态为抓取时目录标记。"}
