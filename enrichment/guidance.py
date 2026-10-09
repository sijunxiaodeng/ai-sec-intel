"""关联公告字段与研究建议；保持来源声明、研究建议和项目验证状态分离。"""

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from collectors.library import SOURCES
from enrichment.documents import canonical, digest, fetch
from rag.evidence import CVE, DEFAULT_DB, _connection
from rag.library import LIBRARY_DB, ingest_document, verified_sources

RULES = {
    "remediation": r"\b(?:upgrad\w*|patch\w*|mitigat\w*|recommend\w*|fix\w*)\b|修复|升级|缓解|防护",
    "conditions": r"\b(?:requires?|required|authentication|unauthenticated|exposed|binds?|listen\w*)\b|must.{0,40}(?:send|access|enable|configure)|利用条件|认证|暴露",
}
PRODUCTS = {"ollama", "vllm", "transformers", "torchserve", "langchain", "triton", "ray"}


def library_for(db_path=DEFAULT_DB):
    # 开发评测/离线临时库不得隐式混入生产资料；需要时显式指定 library_db。
    return LIBRARY_DB if Path(db_path).resolve() == DEFAULT_DB.resolve() else None


def _citation(doc, cve_id, pointer, text, topic, authority, value=None):
    eid = "LINK-" + digest(doc["source_response_sha256"] + pointer + text)[:20]
    return {"cve_id": cve_id, "evidence_id": eid, "citation_id": cve_id + "/" + eid,
            "document_id": doc["document_id"], "source_id": doc["source_id"], "title": doc["title"],
            "url": doc["url"], "retrieved_at": doc["retrieved_at"], "published_at": doc.get("published_at"),
            "locator": pointer, "text": text, "text_sha256": digest(text),
            "source_response_sha256": doc["source_response_sha256"], "topics": [topic],
            "text_kind": "automatic_associated_extract", "relation_type": "associated_guidance",
            "guidance_authority": authority, "guidance_topic": topic, "structured_value": value}


def _vendor(doc):
    return any(s["category"] == "vendor_advisory" and doc["url"].startswith(s["prefix"]) for s in SOURCES)


def _product_match(package, product):
    name = (package.get("name") or "").lower().split("/")[-1]
    return bool(name and (not product or name == product.lower()))


def _sentences(text):
    # 使用存档中的字符偏移，不把文字片段重新排序或当作网页行号。
    for paragraph in re.finditer(r"[^\n]+", text):
        for sentence in re.finditer(r".+?(?:[.!?](?=\s+[A-Z]|$)|$)", paragraph.group()):
            raw = sentence.group()
            stripped = raw.strip()
            if stripped:
                start = paragraph.start() + sentence.start() + len(raw) - len(raw.lstrip())
                yield stripped, start


def report(cve_id, product="", library_db=LIBRARY_DB):
    cve_id = cve_id.upper()
    if not CVE.fullmatch(cve_id):
        raise ValueError("需要有效 CVE 编号")
    result = {"cve_id": cve_id, "sources": [], "facets": {"versions": [], "remediation": [], "conditions": []},
              "evidence": [], "status": "empty", "vendor_patched_ranges": [],
              "limitations": ["来源声明不等于本项目验证；研究建议不能转称厂商确认。", "正文按规则抽取，有遗漏与语义误判可能；未完成全部自由文本语义审核。"]}
    if library_db is None:
        return result
    for source in verified_sources(library_db):
        doc = source["document"]
        relation = next((r for r in doc["associations"] if r["entity_id"] == cve_id), None)
        if not relation:
            continue
        source_view = {key: doc.get(key) for key in ("document_id", "title", "url", "publisher", "published_at", "retrieved_at", "source_response_sha256")}
        source_view.update(relation=relation["relation"], eligible=False, reason="仅编号提及或主题资料，不自动输出具体漏洞建议",
                           retained_previous=source["retained_previous"])
        result["sources"].append(source_view)

        def add(topic, text, pointer, authority, value=None):
            citation = _citation(doc, cve_id, pointer, text, topic, authority, value)
            result["evidence"].append(citation)
            result["facets"][topic].append({"text": text, "authority": authority, "publisher": doc["publisher"],
                "document_id": doc["document_id"], "evidence_ids": [citation["citation_id"]], "structured_value": value})
            source_view["eligible"] = True

        if doc["document_type"] == "vendor_advisory" and _vendor(doc) and set(doc.get("declared_cve_ids", [])) == {cve_id}:
            payload = json.loads(source["body"])
            if not any(_product_match(row.get("package") or {}, product) for row in payload.get("vulnerabilities") or []):
                source_view["reason"] = "公告包名与目标产品不匹配，不绑定版本或正文建议"
                continue
            source_view["reason"] = "受信项目公告的标识字段明确归属唯一 CVE；版本逐条匹配包名"
            for index, row in enumerate(payload.get("vulnerabilities") or []):
                package = row.get("package") or {}
                if not _product_match(package, product):
                    continue
                for field, topic in (("vulnerable_version_range", "versions"), ("patched_versions", "remediation")):
                    value = row.get(field)
                    if not isinstance(value, str) or not value.strip():
                        continue
                    bound = {"package": package, field: value}
                    add(topic, json.dumps(bound, ensure_ascii=False), "vulnerabilities/%d/%s；JSON 字段" % (index, field), "vendor_statement", bound)
                    if field == "patched_versions":
                        result["vendor_patched_ranges"].append({"package": package, "range": value, "url": doc["url"]})
            # 公告描述的文字还可能与顶层版本字段不同；不把它们强行合并。
            for text, start in _sentences(payload.get("description") or ""):
                if len(text) > 600 or text.startswith(("#", "```", "-", "+", "**")) or "http" in text:
                    continue
                if re.search(r"discovered|reported by|disclosure|acknowledg|credit|initiative", text, re.I):
                    continue
                if any(v.upper() != cve_id for v in CVE.findall(text)):
                    continue
                for topic, pattern in RULES.items():
                    if re.search(pattern, text, re.I):
                        add(topic, text, "description；字符 [%d,%d)，相对于存档公告 description" % (start, start + len(text)), "vendor_statement")
                        break
        elif doc["document_type"] == "research_article":
            identifiers = {v.upper() for _, value in doc["parts"] for v in CVE.findall(value)}
            # 题名指向唯一目标且正文没有其他编号，才允许将具体产品句子用于建议。
            if cve_id not in {v.upper() for v in CVE.findall(doc["title"])} or identifiers != {cve_id} or not product:
                continue
            source_view["reason"] = "题名指向目标 CVE、正文未出现其他 CVE；仅提取包含目标产品的完整句子，作为研究方描述/建议"
            for field, body in doc["parts"]:
                for text, start in _sentences(body):
                    if not 35 <= len(text) <= 600 or not re.search(r"\b" + re.escape(product) + r"\b", text, re.I):
                        continue
                    if (set(re.findall(r"\b(?:" + "|".join(PRODUCTS) + r")\b", text.lower())) - {product.lower()}) or "http" in text:
                        continue
                    for topic, pattern in RULES.items():
                        if re.search(pattern, text, re.I):
                            if topic == "remediation" and not re.search(r"upgrad\w*|mitigat\w*|recommend\w*|should|must|升级|建议|缓解", text, re.I):
                                continue
                            if topic == "conditions" and re.search(r"as of|as-of|scanning|our scan|survey|截至|扫描统计", text, re.I):
                                continue  # 历史暴露统计不作为当前利用条件。
                            upgrade = re.search(r"(?:recommend\w*|encouraged\s+to).{0,100}\bupgrade.{0,100}\bversion\s+([0-9]+(?:\.[0-9]+)+)\s+or\s+(?:newer|later)", text, re.I) if topic == "remediation" else None
                            if upgrade and re.search(r"\b(?:not|never|avoid)\b", upgrade.group(), re.I):
                                upgrade = None
                            value = {"recommended_version_range": ">=" + upgrade.group(1), "product": product} if upgrade else None
                            add(topic, text, "%s；字符 [%d,%d)，相对于存档提取正文，非网页行号" % (field, start, start + len(text)), "research_recommendation", value)
                            break
    # 对每个意图限制数量；优先版本字段和明确升级建议，避免长文挤占问答预算。
    chosen = set()
    for topic, rows in result["facets"].items():
        rows.sort(key=lambda r: (not bool(r["structured_value"]), not bool(re.search(r"upgrade|upgrad|reverse.proxy|authentication|升级", r["text"], re.I)), len(r["text"])))
        result["facets"][topic] = rows[:4]
        chosen.update(eid for row in rows[:4] for eid in row["evidence_ids"])
    result["evidence"] = [row for row in result["evidence"] if row["citation_id"] in chosen]
    result["status"] = "ok" if result["evidence"] else "empty"
    return result


def formatted_facts(guidance, topics):
    """确定性格式化，模型引用关联字段时必须保留此归属及原始范围。"""
    facts = []
    lookup = {r["citation_id"]: r for r in guidance.get("evidence", [])}
    for topic in ("versions", "remediation", "conditions"):
        if topic not in topics:
            continue
        for row in guidance.get("facets", {}).get(topic, []):
            value = row.get("structured_value") or {}
            publisher = row["publisher"]
            if "vulnerable_version_range" in value:
                text = "项目公告字段（%s）：包 %s；受影响版本范围：%s。" % (publisher, value["package"]["name"], value["vulnerable_version_range"])
            elif "patched_versions" in value:
                text = "项目公告声明（%s）：包 %s；修复版本范围：%s。" % (publisher, value["package"]["name"], value["patched_versions"])
            elif "recommended_version_range" in value:
                text = "研究方升级建议（%s）：%s 版本 %s。" % (publisher, value["product"], value["recommended_version_range"])
            else:
                text = ("项目公告原文" if row["authority"] == "vendor_statement" else "研究方建议/条件原文") + "（%s）：%s" % (publisher, row["text"])
            chunks = []
            for eid in row["evidence_ids"]:
                chunk = dict(lookup[eid], allowed_claim=text)
                chunks.append(chunk)
            facts.append({"text": text, "chunks": chunks, "evidence_ids": row["evidence_ids"]})
    return facts


def refresh(record, library_db=LIBRARY_DB, max_sources=4, fetcher=fetch, db_path=DEFAULT_DB):
    """显式刷新时从已校验 NVD 参考及现有链接发现来源；用户问答不联网。"""
    cve_id = record["item"]["cve_id"]
    if not isinstance(max_sources, int) or not 1 <= max_sources <= 8:
        raise ValueError("max_sources 必须为 1 到 8")
    refs = list(record.get("references") or []) + list(record["item"].get("references") or [])
    if Path(db_path).exists():
        with _connection(db_path) as conn:
            if conn.execute("SELECT name FROM sqlite_master WHERE name='source_snapshots'").fetchone():
                snapshots = conn.execute("SELECT digest,body FROM source_snapshots WHERE cve_id=?", (cve_id,)).fetchall()
                for sha, body in snapshots:
                    if hashlib.sha256(body).hexdigest() != sha:
                        continue
                    try:
                        data = json.loads(body)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not isinstance(data, dict):
                        continue
                    for row in data.get("vulnerabilities", []):
                        cve = row.get("cve") or {}
                        if cve.get("id") == cve_id:
                            refs.extend(r.get("url", "") for r in cve.get("references", []))
    candidates = {}
    for url in refs:
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        url = canonical(url)
        vendor = next((s for s in SOURCES if s["category"] == "vendor_advisory" and url.startswith(s["prefix"])), None)
        domain = urlsplit(url).hostname
        if vendor:
            candidate = {"url": url, "source_id": vendor["id"], "source_name": vendor["name"], "document_type": "vendor_advisory"}
        elif domain in ("www.wiz.io", "blog.trailofbits.com"):
            candidate = {"url": url, "source_id": "cve_reference", "source_name": "Wiz Research" if domain == "www.wiz.io" else "Trail of Bits", "document_type": "research_article"}
        else:
            continue
        candidates[url] = dict(candidate, discovery="cve_reference")
    results = [ingest_document(candidate, library_db, fetcher) for candidate in list(candidates.values())[:max_sources]]
    from rag.hybrid import update_index
    return {"attempted": len(results), "ok": sum(r["status"] == "ok" for r in results), "documents": results,
            "index": update_index(library_db), "guidance": report(cve_id, record["item"].get("product", ""), library_db)}


def main():
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", required=True)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    from rag.retrieve import get_record
    record = get_record(args.cve.upper())
    if not record:
        parser.error("请先收录这条漏洞")
    result = refresh(record) if args.refresh else report(args.cve, record["item"].get("product", ""))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
