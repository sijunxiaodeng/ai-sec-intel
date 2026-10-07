import re

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SCORE = re.compile(r"CVSS\s*(?:为|是|:|：)?\s*([0-9]+(?:\.[0-9]+)?)", re.I)


def run(answer, evidence):
    known = []
    scores = []
    for record in evidence or []:
        item = record.get("item") or {}
        cve_id = (item.get("cve_id") or "").upper()
        if cve_id:
            known.append(cve_id)
        cvss = record.get("cvss") or {}
        if cvss.get("score") is not None:
            scores.append(float(cvss["score"]))
    missing = []
    for found in CVE.findall(answer or ""):
        if found.upper() not in known:
            missing.append(found.upper())
    bad_scores = []
    for found in SCORE.findall(answer or ""):
        value = float(found)
        if not any(abs(value - score) < 0.05 for score in scores):
            bad_scores.append(found)
    passed = not missing and not bad_scores
    notes = []
    if missing:
        notes.append("回答里出现了证据中没有的编号：" + "、".join(missing))
    if bad_scores:
        notes.append("回答里的分数对不上证据：" + "、".join(bad_scores))
    if passed:
        notes.append("编号和分数都能在检索证据里找到，或回答没有写出这些字段。")
    return {
        "passed": passed,
        "notes": notes,
        "steps": [{
            "role": "核对",
            "action": "检查编号与分数",
            "detail": "通过" if passed else "；".join(notes),
        }],
    }
