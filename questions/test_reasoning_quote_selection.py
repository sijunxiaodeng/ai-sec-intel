"""Keep relevant complete source sentences under a bounded multi-source budget."""
import unittest

from agents import general_reasoning as reasoning


def row(doc_id, text, *, start=0, field="abstract", suffix="one"):
    return {"document_id": doc_id, "citation_id": doc_id + "/" + suffix, "text": text,
            "locator": "%s；字符 [%d,%d)，相对于存档提取正文，非原网页行号" % (field, start, start + len(text))}


class ReasoningQuoteSelectionTest(unittest.TestCase):
    def test_full_academic_title_is_available_without_treating_it_as_quoted_evidence(self):
        title = "A long research title on provenance preservation across cooperating agents and independently enforced security boundaries"
        source = dict(row("DOC-A", "This complete sentence is the supporting evidence."), content_scope="abstract")
        evidence = {source["citation_id"]: source}
        payload = reasoning._compact_evidence_payload(evidence, {"DOC-A": {"title": title}},
                                                     reasoning._quote_options(evidence))
        self.assertEqual(payload["documents"][0]["title"], title)
        self.assertNotIn(title, str(payload["quote_options"]))

    def test_long_sentence_is_preserved_with_its_negation_and_conditions(self):
        text = ("The hypothetical Quartz boundary prevents writes only if the operation is explicitly "
                "authorized by the original task and every input has a verified provenance; it does not "
                "establish that independently protected components remain protected when they exchange "
                "untrusted information across organizational boundaries.")
        self.assertGreater(len(text), 240)
        self.assertLessEqual(len(text), reasoning.MAX_QUOTE)
        source = row("DOC-A", text)
        options = reasoning._quote_options({source["citation_id"]: source})
        self.assertEqual([option["quote"] for option in options.values()], [text])

    def test_relevant_middle_sentence_survives_irrelevant_opening_and_ending(self):
        target = "The Quartz authorization boundary requires an independently signed capability."
        sentences = ["This opening sentence introduces a generic research motivation.",
                     "Another sentence describes a broad historical background.", target,
                     "An unrelated appendix contains some experiment setup details.",
                     "The final sentence discusses possible future publication plans."]
        source = row("DOC-A", " ".join(sentences))
        options = reasoning._bounded_quote_options({source["citation_id"]: source},
                                                  query="Quartz authorization boundary capability")
        self.assertEqual(next(iter(options.values()))["quote"], target)

    def test_mid_sentence_chunk_opening_is_not_presented_as_a_complete_quote(self):
        first = row("DOC-A", "The protocol preserves trusted instructions while it passes untrusted ")
        second = row("DOC-A", "data through a separate channel. The next complete sentence remains available.",
                     start=len(first["text"]), suffix="two")
        options = reasoning._quote_options({r["citation_id"]: r for r in (first, second)})
        quotes = [option["quote"] for option in options.values()]
        self.assertNotIn("data through a separate channel.", quotes)
        self.assertIn("The next complete sentence remains available.", quotes)

    def test_proven_sentence_boundary_allows_next_chunk_first_sentence(self):
        first = row("DOC-A", "This is the complete preceding sentence. ")
        second = row("DOC-A", "The independent next sentence is also complete.", start=len(first["text"]), suffix="two")
        options = reasoning._quote_options({r["citation_id"]: r for r in (first, second)})
        self.assertIn(second["text"], [option["quote"] for option in options.values()])

    def test_missing_predecessor_does_not_assume_a_sentence_boundary(self):
        source = row("DOC-A", "fragment without the preceding conditions. A complete following sentence is available.", start=500)
        options = reasoning._quote_options({source["citation_id"]: source})
        self.assertEqual([option["quote"] for option in options.values()], ["A complete following sentence is available."])

    def test_other_field_or_document_cannot_supply_a_preceding_boundary(self):
        source = row("DOC-A", "fragment missing its antecedent. This later sentence is complete.", start=50)
        unrelated = row("DOC-B", "x" * 48 + ". ", field="abstract")
        options = reasoning._quote_options({r["citation_id"]: r for r in (source, unrelated)})
        self.assertNotIn("fragment missing its antecedent.", [option["quote"] for option in options.values()])

    def test_budget_shares_first_selection_across_sources_without_cutting_quotes(self):
        sources = [row("DOC-%d" % i, " ".join(
            "Quartz topic %d sentence %d preserves every qualifier in this complete source statement." % (i, j)
            for j in range(10))) for i in range(3)]
        evidence = {r["citation_id"]: r for r in sources}
        options = reasoning._bounded_quote_options(evidence, ["DOC-2", "DOC-1", "DOC-0"], "Quartz topic")
        selected = list(options.values())
        self.assertEqual([evidence[item["citation_id"]]["document_id"] for item in selected[:3]],
                         ["DOC-2", "DOC-1", "DOC-0"])
        self.assertLessEqual(len(selected), reasoning.MAX_LOCAL_QUOTE_OPTIONS)
        self.assertLessEqual(sum(len(item["quote"]) for item in selected), reasoning.MAX_LOCAL_QUOTE_CHARACTERS)
        for item in selected:
            self.assertIn(item["quote"], evidence[item["citation_id"]]["text"])
            self.assertTrue(item["quote"].endswith("."))


if __name__ == "__main__":
    unittest.main()
