from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collectors.reference import REFERENCE_SOURCES
from enrichment.reference_text import catalog_document, paper_html, pdf_document, policy_document
from rag.library import detail, documents, full_text, ingest_document, overview, sync
from rag.evidence import _connection


def response(url, body, kind="text/html"):
    return {"url": url, "body": body.encode() if isinstance(body, str) else body, "content_type": kind}


def html_paper(version="2302.12173v2", words=None):
    content = words or "LLM applications face indirect prompt injection through untrusted retrieved documents. " * 45
    return ('<html><body><a href="/abs/' + version + '">arXiv</a><article class="ltx_document">'
            '<h1 class="ltx_title_document">Indirect prompt injection security</h1>'
            '<div class="ltx_abstract"><h6>Abstract</h6><p>LLM security research.</p></div>'
            '<section id="S1"><h2>1 Introduction</h2><p>' + content + '</p>'
            '<section id="S1.SS1"><h3>1.1 Subsection</h3><p>Nested explanation.</p></section></section>'
            '<section id="A1"><h2>Appendix</h2><p>Appendix material.</p></section>'
            '<script>DO_NOT_EXECUTE_JS</script></article></body></html>')


def policy_body(source):
    names = ["一", "二", "三", "四", "五", "六", "七", "八", "九", "十", "十一", "十二", "十三", "十四", "十五", "十六", "十七", "十八", "十九", "二十", "二十一", "二十二", "二十三", "二十四"]
    parts = [source["expected_title"], "2023年7月10日"]
    for number, name in enumerate(names[:source["last_article"]], 1):
        text = "生成式人工智能服务应开展安全评估并依法保护训练数据，仅供合成测试使用。"
        if number == 2:
            text = "向境内公众提供服务的，适用本办法。\n未向境内公众提供生成式人工智能服务的，不适用本办法的规定。"
        if number == source["last_article"]:
            text = "本办法自2023年8月15日起施行。"
        parts.append("第" + name + "条 " + text)
    return "\n".join(parts)


class ReferenceTextTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "library.sqlite3"

    def test_html_sections_version_appendix_and_no_duplicate_nested_text(self):
        url = "https://arxiv.org/html/2302.12173"
        doc = paper_html(response(url, html_paper()), url)
        self.assertEqual(doc["version"], "2302.12173v2")
        self.assertEqual(doc["content_scope"], "full_text_html")
        body = "\n".join(t for _, t in doc["parts"])
        self.assertEqual(body.count("Nested explanation."), 1)
        self.assertIn("Appendix material", body)
        self.assertNotIn("DO_NOT_EXECUTE_JS", body)

    def test_html_missing_version_or_body_is_not_full_text(self):
        url = "https://arxiv.org/html/2302.12173"
        for body in (html_paper().replace('/abs/2302.12173v2', '/abs/2302.12173'), '<html>Not available</html>'):
            with self.assertRaises(ValueError):
                paper_html(response(url, body), url)

    def test_html_other_version_and_redirected_paper_rejected(self):
        url = "https://arxiv.org/html/2302.12173v1"
        with self.assertRaisesRegex(ValueError, "其他论文版本"):
            paper_html(response(url, html_paper()), url)
        with self.assertRaisesRegex(ValueError, "重定向"):
            paper_html(response("https://arxiv.org/html/2307.15043", html_paper()), "https://arxiv.org/html/2302.12173")

    def test_full_text_failure_retains_abstract_and_last_good_full_text(self):
        url = "https://arxiv.org/abs/2302.12173"
        abstract = ('<html><head><meta name="citation_title" content="LLM prompt injection security">'
                    '<meta name="citation_pdf_url" content="https://arxiv.org/pdf/2302.12173"></head><body>'
                    '<blockquote class="abstract">' + 'LLM security prompt injection research. ' * 10 + '</blockquote></body></html>')
        candidate = {"url": url, "document_type": "academic_paper", "source_name": "arXiv", "source_id": "fixture"}
        first = ingest_document(candidate, self.db, lambda u: response(u, abstract))
        self.assertEqual(first["status"], "ok")
        with patch("rag.library.update_index", return_value={"status": "fixture"}):
            success = full_text(first["document_id"], self.db, lambda u: response(u, html_paper()))
            failure = full_text(first["document_id"], self.db, lambda u: response(u, "HTML not available"))
        self.assertEqual(success["status"], "ok")
        self.assertEqual(failure["status"], "error")
        self.assertTrue(failure["retained_previous"])
        self.assertEqual(len(documents(self.db)), 2)
        self.assertEqual(detail(first["document_id"], self.db)["content_scope"], "abstract")
        full = detail(success["document_id"], self.db)
        self.assertEqual(full["parent_document_id"], first["document_id"])
        self.assertEqual(full["version"], "2302.12173v2")
        self.assertTrue(full["retained_previous"])

    def test_untrusted_reference_url_is_not_classified_as_policy(self):
        candidate = {"url": "https://untrusted.example/policy", "document_type": "policy", "source_id": "fixture", "source_name": "Untrusted"}
        result = ingest_document(candidate, self.db, lambda u: response(u, '<html><title>生成式 AI 安全</title></html>'))
        self.assertEqual(result["status"], "error")
        self.assertEqual(documents(self.db), [])

    def test_policy_keeps_complete_application_exemption_and_effective_date(self):
        source = REFERENCE_SOURCES[0]
        body = policy_body(source)
        with patch("enrichment.reference_text.extract_document", return_value={"title": source["expected_title"], "parts": [("body", body)], "published_at": "2023-07-13"}):
            doc = policy_document({}, source)
        self.assertIn("不适用", doc["scope_excerpt"])
        self.assertEqual(doc["article_count"], 24)
        self.assertEqual(doc["issued_at"], "2023-07-10")
        self.assertEqual(doc["effective_at"], "2023-08-15")
        self.assertEqual(doc["published_at"], "2023-07-13")

    def test_policy_draft_or_missing_article_not_marked_as_formal_full_body(self):
        source = REFERENCE_SOURCES[0]
        for title, body in ((source["expected_title"] + "（征求意见稿）", policy_body(source)),
                            (source["expected_title"], policy_body(source).replace("第三条", "遗漏条文"))):
            with patch("enrichment.reference_text.extract_document", return_value={"title": title, "parts": [("body", body)]}):
                with self.assertRaises(ValueError):
                    policy_document({}, source)

    def test_catalog_only_does_not_claim_technical_clauses(self):
        source = REFERENCE_SOURCES[-1]
        body = "中文标准名称：\n网络安全技术 生成式人工智能服务安全基本要求\n标准状态：\n现行\n发布日期\n2025-04-25\n实施日期\n2025-11-01\n发布单位\n国家市场监督管理总局、国家标准化管理委员会"
        with patch("enrichment.reference_text.extract_document", return_value={"title": source["expected_title"], "parts": [("body", body)]}):
            doc = catalog_document({}, source)
        self.assertEqual(doc["content_scope"], "catalog_only")
        self.assertEqual(doc["effective_at"], "2025-11-01")
        self.assertNotIn("技术条款", " ".join(t for _, t in doc["parts"]))
        self.assertIn("未获取标准全文", doc["extraction_notice"])

    def test_duplicate_or_swapped_policy_articles_rejected_even_with_same_count(self):
        source = REFERENCE_SOURCES[0]
        body = policy_body(source)
        for invalid in (body.replace("第三条", "第四条"), body.replace("第三条", "占位条").replace("第四条", "第三条").replace("占位条", "第四条")):
            with patch("enrichment.reference_text.extract_document", return_value={"title": source["expected_title"], "parts": [("body", invalid)]}):
                with self.assertRaisesRegex(ValueError, "编号"):
                    policy_document({}, source)

    def test_pdf_extracts_actual_page_numbers_and_preserves_page_text(self):
        from pypdf import PdfWriter
        from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
        writer = PdfWriter()
        for text in ("Artificial Intelligence Risk Management Framework test page", "Second page discusses prompt injection and AI security risks."):
            page = writer.add_blank_page(width=300, height=300)
            font = DictionaryObject({NameObject('/Type'): NameObject('/Font'), NameObject('/Subtype'): NameObject('/Type1'), NameObject('/BaseFont'): NameObject('/Helvetica')})
            page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): font})})
            stream = DecodedStreamObject(); stream.set_data(('BT /F1 10 Tf 10 260 Td (' + text + ') Tj ET').encode())
            page[NameObject('/Contents')] = stream
        buffer = BytesIO(); writer.write(buffer)
        doc = pdf_document(response(REFERENCE_SOURCES[2]["url"], buffer.getvalue(), "application/pdf"), REFERENCE_SOURCES[2])
        self.assertEqual(doc["page_count"], 2)
        self.assertEqual([f for f, _ in doc["parts"]], ['PDF page 1', 'PDF page 2'])
        self.assertIn("prompt injection", doc["parts"][1][1])

    def test_pdf_not_pdf_scanned_encrypted_and_page_budget_rejected(self):
        source = REFERENCE_SOURCES[2]
        with self.assertRaises(ValueError):
            pdf_document(response(source["url"], b"<html>Blocked</html>"), source)
        for encrypted, pages in ((True, []), (False, [None] * 121)):
            with patch("pypdf.PdfReader") as reader:
                reader.return_value.is_encrypted = encrypted; reader.return_value.pages = pages
                with self.assertRaises(ValueError):
                    pdf_document(response(source["url"], b"%PDF-fixture"), source)

    def test_fixed_reference_monitor_reuses_response_and_source_category(self):
        source = REFERENCE_SOURCES[0]
        body = policy_body(source)
        calls = []
        def fetcher(url):
            calls.append(url)
            return response(url, "fixture response")
        with patch("enrichment.reference_text.extract_document", return_value={"title": source["expected_title"], "parts": [("body", body)]}), patch("rag.library.update_index", return_value={"status": "fixture"}):
            result = sync(self.db, sources=(source,), seeds=(), include_seeds=False, fetcher=fetcher)
        self.assertEqual(calls, [source["url"]])
        self.assertEqual(result["ok"], 1)
        self.assertEqual(overview(self.db)["source_categories"], ["policy"])
        self.assertIn("不自动发现", result["sources"][0]["coverage"])


if __name__ == "__main__":
    unittest.main()
