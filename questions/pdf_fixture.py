"""Generate actual extractable ASCII PDF bytes for offline source-bound tests."""
from io import BytesIO
import textwrap

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject


def text_pdf(page_texts):
    """Each input string is one physical page, using a standard PDF font.

    These are clearly synthetic fixtures, never copies of the named source.
    Both ingest and subsequent integrity checks use the real PDF extractor.
    """
    writer = PdfWriter()
    for text in page_texts:
        text.encode("ascii")  # Keep PDF literal strings and extraction deterministic.
        lines = [line for paragraph in text.splitlines() for line in (textwrap.wrap(paragraph, 90) or [""])]
        if len(lines) > 65:
            raise ValueError("Synthetic PDF page exceeds the fixture line budget")
        page = writer.add_blank_page(width=612, height=792)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                                 NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
        commands = ["BT /F1 10 Tf 12 TL 30 760 Td"]
        for index, line in enumerate(lines):
            if index:
                commands.append("T*")
            escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.append("(%s) Tj" % escaped)
        commands.append("ET")
        stream = DecodedStreamObject()
        stream.set_data("\n".join(commands).encode("ascii"))
        page[NameObject("/Contents")] = writer._add_object(stream)
    if not writer.pages:
        raise ValueError("Synthetic PDF requires at least one page")
    output = BytesIO()
    writer.write(output)
    return output.getvalue()
