"""跨块摘录不能拼错来源、漏掉条件或由模型改写。"""
import json
import unittest

from agents.excerpts import fallback, options, select, SelectionError


class ExcerptTest(unittest.TestCase):
    def row(self, text, start=0, *, part="body", doc="DOC-" + "a" * 16, citation="first"):
        return {"text": text, "locator": f"{part}；字符 [{start},{start + len(text)})，相对于存档提取正文，非原网页行号",
                "document_id": doc, "citation_id": doc + "/LIB-" + citation, "content_scope": "article_body"}

    def build(self, rows, retrieved=None):
        docs = {}
        for row in rows:
            doc = docs.setdefault(row["document_id"], {"content_scope": row["content_scope"], "evidence": []})
            doc["evidence"].append(row)
        return options(rows if retrieved is None else retrieved, docs)

    def test_adjacent_chunks_render_one_whole_paragraph_with_all_citations(self):
        first = "The kernel verified proofs, but we still needed to "
        second = "manually audit the theorem statements to check the intended property.\nNext unrelated paragraph."
        rows = [self.row(first), self.row(second, len(first), citation="second")]
        choices = self.build(rows, [rows[0]])
        self.assertEqual(len(choices), 1)
        self.assertEqual(choices[0]["quote"], first + second.splitlines()[0])
        self.assertEqual(choices[0]["rows"], rows)
        self.assertNotIn("unrelated", choices[0]["quote"])

    def test_chunk_gaps_or_parts_and_documents_cannot_be_joined(self):
        first = "A partial paragraph without a natural ending "
        rows = [self.row(first), self.row("attacker supplied final words that must not be appended.", len(first) + 3, citation="gap")]
        self.assertEqual(self.build(rows), [])
        for changes in ({"part": "other section"}, {"doc": "DOC-" + "b" * 16}):
            rows = [self.row(first), self.row("This belongs to another source boundary.", len(first), citation="other", **changes)]
            for candidate in self.build(rows): self.assertEqual(len(candidate["rows"]), 1)

    def test_full_paragraph_retains_negation_and_exceptions(self):
        text = "Scanning can detect unsafe imports. However, this is not foolproof and does not prove safety."
        choices = self.build([self.row(text[:50]), self.row(text[50:], 50, citation="second")])
        self.assertEqual(choices[0]["quote"], text)
        self.assertEqual(select('{"selections":[{"excerpt_id":"EX-01"}]}', choices, set())[0]["quote"], text)

    def test_duplicate_ids_are_deduplicated_and_unknown_or_added_quote_fails(self):
        choices = self.build([self.row("Original statement with a qualification that cannot be removed.")])
        picked = select('{"selections":[{"excerpt_id":"EX-01"},{"excerpt_id":"EX-01"}]}', choices, set())
        self.assertEqual(len(picked), 1)
        for choice, code in (({"excerpt_id": "EX-99"}, "unknown_excerpt"), ({"excerpt_id": "EX-01", "quote": "rewrite"}, "invalid_schema")):
            with self.assertRaises(SelectionError) as caught: select(json.dumps({"selections": [choice]}), choices, set())
            self.assertEqual(caught.exception.code, code)

    def test_overlong_paragraph_not_silently_cut_to_fit_limit(self):
        row = self.row("A condition and exception. " * 120)
        self.assertEqual(self.build([row]), [])

    def test_paragraph_whitespace_and_character_locator_stay_exact(self):
        row = self.row("  Original   paragraph with exact whitespace and conditions.  \n")
        candidate = self.build([row])[0]
        self.assertEqual(candidate["quote"], row["text"].strip())
        self.assertIn("字符 [2,", candidate["locator"])

    def test_fallback_does_not_drop_third_paragraph_containing_limitation(self):
        text = "First observation with sufficient context.\nSecond observation with sufficient context.\nHowever, only a well-defined subset is supported, not all procedures."
        row = self.row(text); candidates = self.build([row])
        chosen = fallback([row], candidates)
        self.assertEqual(len(chosen), 3)
        self.assertIn("not all procedures", chosen[-1]["quote"])

    def test_fallback_keeps_raw_chunk_if_bounded_options_omit_long_paragraph(self):
        row = self.row("A short and complete source observation.\n" + "Critical limitations must not be silently omitted. " * 60)
        candidates = self.build([row])
        chosen = fallback([row], candidates)
        self.assertEqual(chosen[0]["quote"], row["text"])
        self.assertIsNone(chosen[0]["excerpt_id"])


if __name__ == "__main__": unittest.main()
