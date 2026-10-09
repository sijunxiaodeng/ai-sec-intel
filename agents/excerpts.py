"""按已验证存档的字符位置衔接段落；模型只能选择既有段落编号。"""
import json
import re

MAX_QUOTE = 2200
MAX_OPTIONS_PER_DOCUMENT = 12


def entry(row):
    return {"quote": row["text"], "rows": [row], "locator": row["locator"], "excerpt_id": None}


def options(retrieved, documents):
    priorities = {r["citation_id"]: i for i, r in reversed(list(enumerate(retrieved)))}
    result = []
    for doc_id, doc in documents.items():
        if doc["content_scope"] in {"catalog_only", "policy_articles"}:
            # 条文/目录保持检索片段；政策范围及施行条款由调用者强制补全。
            candidates = [entry(r) for r in retrieved if r["document_id"] == doc_id]
        else:
            parts = {}
            for row in doc["evidence"]:
                match = re.fullmatch(r"(.*?)；字符 \[(\d+),(\d+)\)，相对于存档提取正文，非原网页行号", row["locator"])
                if not match: continue
                part, start, end = match[1], int(match[2]), int(match[3])
                if end - start != len(row["text"]): continue
                parts.setdefault(part, []).append((start, end, row))
            candidates = []
            for part, spans in parts.items():
                runs = []
                for span in sorted(spans, key=lambda s: s[0]):
                    if not runs or runs[-1][-1][1] != span[0]: runs.append([])
                    runs[-1].append(span)
                for run in runs:
                    text = "".join(s[2]["text"] for s in run); offset = run[0][0]
                    for match in re.finditer(r"[^\n]+", text):
                        quote = match[0].strip()
                        if not 20 <= len(quote) <= MAX_QUOTE: continue
                        # 缺块时不把首尾截断的一行冒充完整段落，也不跨页/章节补字。
                        if (offset and match.start() == 0) or (run[-1][1] != max(s[1] for s in spans) and match.end() == len(text)):
                            continue
                        begin = offset + match.start() + len(match[0]) - len(match[0].lstrip())
                        end = begin + len(quote)
                        rows = [s[2] for s in run if s[0] < end and s[1] > begin]
                        if not any(r["citation_id"] in priorities for r in rows): continue
                        candidates.append({"quote": quote, "rows": rows, "excerpt_id": None,
                            "locator": "%s；字符 [%d,%d)，相对于存档提取正文，非原网页行号" % (part, begin, end)})
            candidates.sort(key=lambda c: min(priorities.get(r["citation_id"], len(priorities)) for r in c["rows"]))
        for candidate in candidates[:MAX_OPTIONS_PER_DOCUMENT]:
            candidate["excerpt_id"] = "EX-%02d" % (len(result) + 1)
            result.append(candidate)
    return result


class SelectionError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def select(raw, candidates, required_documents):
    try: data = json.loads(raw)
    except (ValueError, TypeError): raise SelectionError("invalid_json", "模型未返回有效 JSON") from None
    choices = data.get("selections") if isinstance(data, dict) and set(data) == {"selections"} else None
    if not isinstance(choices, list) or not 1 <= len(choices) <= 8:
        raise SelectionError("invalid_schema", "模型未返回有界 selections")
    lookup = {c["excerpt_id"]: c for c in candidates}; selected = []; seen = set()
    for choice in choices:
        if not isinstance(choice, dict) or set(choice) != {"excerpt_id"}:
            raise SelectionError("invalid_schema", "只能选择段落编号，不能新增或改写原文")
        identifier = choice["excerpt_id"]
        if not isinstance(identifier, str) or identifier not in lookup:
            raise SelectionError("unknown_excerpt", "段落编号不在本次候选中")
        if identifier in seen: continue
        seen.add(identifier); selected.append(lookup[identifier])
    if not required_documents <= {c["rows"][0]["document_id"] for c in selected}:
        raise SelectionError("missing_document", "遗漏指定资料的原文")
    return selected


def fallback(rows, candidates):
    result = []
    for doc_id in dict.fromkeys(r["document_id"] for r in rows):
        matches = [c for c in candidates if c["rows"][0]["document_id"] == doc_id]
        result.extend(matches[:2] if matches else [entry(r) for r in rows if r["document_id"] == doc_id][:2])
    return result
