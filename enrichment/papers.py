# 只保留标题或摘要里出现该漏洞编号的论文。对不上就不写入。

import urllib.request
import xml.etree.ElementTree as ET

ATOM = "{http://www.w3.org/2005/Atom}"


def _text(node, name):
    child = node.find(ATOM + name)
    if child is None or not child.text:
        return ""
    return " ".join(child.text.split())


def fetch_papers(cve_ids):
    ids = []
    for cve_id in cve_ids:
        if cve_id and cve_id not in ids:
            ids.append(cve_id)
    if not ids:
        return {}, None
    query = "+OR+".join("all:%s" % cve_id for cve_id in ids[:12])
    url = "http://export.arxiv.org/api/query?search_query=%s&start=0&max_results=8" % query
    request = urllib.request.Request(url, headers={"User-Agent": "ai-sec-intel-student"})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read()
    except Exception as exc:
        return {}, str(exc)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return {}, str(exc)
    found = {cve_id: [] for cve_id in ids}
    for entry in root.findall(ATOM + "entry"):
        title = _text(entry, "title")
        summary = _text(entry, "summary")
        link = ""
        for row in entry.findall(ATOM + "link"):
            if row.attrib.get("rel") in (None, "alternate") and row.attrib.get("href"):
                link = row.attrib["href"]
                break
        if not link:
            continue
        blob = (title + " " + summary).upper()
        for cve_id in ids:
            if cve_id.upper() in blob:
                papers = found[cve_id]
                if not any(paper.get("url") == link for paper in papers):
                    papers.append({
                        "title": title,
                        "summary": summary[:400],
                        "url": link,
                    })
    return found, None
