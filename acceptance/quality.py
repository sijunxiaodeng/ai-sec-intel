"""Immutable evaluation runs and append-only, declared-identity quality reviews.

Hashes supplied by an importer are consistency evidence, not identity attestation.
No score in this module certifies competition acceptance or a blind evaluation.
"""
import hashlib
import json
import math
from pathlib import Path
import re

from .storage import canonical_hash, connect, now_iso


KINDS = {"single_fact", "comparison", "multi_hop", "multi_turn", "refusal", "other", "enrichment"}
COMPLEX = {"comparison", "multi_hop", "multi_turn", "other", "enrichment"}
CHECKS = ("correct", "citations_supported", "conditions_preserved", "reasoning_valid")
REVIEW_FIELDS = {"reviewer", "reviewer_type", "independent", "reasoning_kind", "note", "expected_revision", *CHECKS}
SHA = re.compile(r"^[0-9a-fA-F]{64}$")
SCORING_POLICY = {
    "unit": "one frozen case or fact unit; latest review only",
    "pass": "all necessary checks true; false is a failure and null is unreviewed",
    "required_checks": ["correct", "citations_supported", "conditions_preserved"],
    "reasoning_required_for": sorted(COMPLEX),
    "citation_exception": "refusal without any supplied evidence may use null",
    "independent_label": "按声明独立复核准确率",
    "identity": "reviewer identity and independence are declarations, not authenticated",
    "scope": "automatic checks and AI reviews are not independent human accuracy; no competition pass is inferred",
}


class RevisionConflict(ValueError):
    """The review changed since the client loaded it; reload before appending."""


def _dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _schema(connection):
    # Do not use executescript: it commits a caller's active transaction.
    statements = (
        "CREATE TABLE IF NOT EXISTS quality_runs (run_id TEXT PRIMARY KEY, imported_at TEXT NOT NULL, report_json TEXT NOT NULL, metadata_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS quality_cases (run_id TEXT NOT NULL REFERENCES quality_runs(run_id), case_id TEXT NOT NULL, ordinal INTEGER NOT NULL, case_json TEXT NOT NULL, PRIMARY KEY(run_id,case_id))",
        "CREATE TABLE IF NOT EXISTS quality_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, case_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), reviewed_at TEXT NOT NULL, review_json TEXT NOT NULL, UNIQUE(run_id,case_id,revision), FOREIGN KEY(run_id,case_id) REFERENCES quality_cases(run_id,case_id))",
        "CREATE TABLE IF NOT EXISTS quality_datasets (dataset_sha256 TEXT PRIMARY KEY, case_ids_json TEXT NOT NULL)",
    )
    for statement in statements:
        connection.execute(statement)
    for table in ("quality_runs", "quality_cases", "quality_reviews", "quality_datasets"):
        for operation in ("UPDATE", "DELETE"):
            connection.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'immutable quality record'); END")


def _finite(value, location="report"):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{location}: non-finite number")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{location}: object keys must be strings")
            _finite(item, f"{location}.{key}")
            if key.endswith("_sha256"):
                _sha(item, f"{location}.{key}")
    elif isinstance(value, list):
        for item in value:
            _finite(item, location)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError(f"{location}: must contain JSON values")


def _sha(value, location):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError(f"{location}: expected SHA-256 hex digest")
    return value.lower()


def _string(value, location, maximum=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{location}: expected a nonempty string (max {maximum})")
    return value.strip()


def _known_dataset(digest):
    source = Path(__file__).resolve().parents[1] / "questions" / "qa_evaluation.json"
    if not source.exists():
        return None
    raw = source.read_bytes()
    return json.loads(raw) if hashlib.sha256(raw).hexdigest() == digest else None


def _known_kind(case):
    category = case.get("category", "")
    if category in {"拒答", "资产不足"}:
        return "refusal"
    if "比较" in category:
        return "comparison"
    if case.get("history"):
        return "multi_turn"
    return "single_fact"


def _group(kind):
    if kind == "enrichment":
        return "enrichment"
    if kind == "multi_hop":
        return "multi_hop"
    if kind in {"comparison", "multi_turn"}:
        return "complex"
    if kind == "other":
        return "other"
    return "basic" if kind in {"single_fact", "refusal"} else "unclassified"


def _source_validation(report, cases, known):
    manifest = report.get("source_manifest", [])
    if not isinstance(manifest, list):
        raise ValueError("source_manifest must be an array")
    sources, complete = {}, bool(manifest)
    for item in manifest:
        if not isinstance(item, dict):
            raise ValueError("source_manifest entries must be objects")
        url = _string(item.get("url"), "source_manifest.url", 8000)
        digest = _sha(item.get("response_sha256"), "source_manifest.response_sha256")
        if url in sources and sources[url] != digest:
            raise ValueError("conflicting hashes for the same source URL")
        sources[url] = digest
        complete = complete and digest is not None
    if known:
        expected_urls = {s["url"] for s in known.get("sources", [])}
        expected_urls.update(u for s in known.get("sources", []) for u in s.get("extra_urls", []))
        complete = complete and expected_urls.issubset(sources)

    def walk(value):
        nonlocal complete
        if isinstance(value, dict):
            # Match citation snapshots to the frozen manifest, without fetching URLs.
            digest = None
            for key in ("source_response_sha256", "response_sha256"):
                if key in value:
                    current = _sha(value[key], key)
                    if current is None:
                        complete = False
                    if digest is not None and current != digest:
                        raise ValueError("conflicting source hashes in an evidence object")
                    digest = current
            if digest:
                url = value.get("url")
                if url is not None and not isinstance(url, str):
                    raise ValueError("evidence URL must be a string")
                if not url or not sources.get(url):
                    complete = False
                elif digest != sources[url]:
                    raise ValueError("evidence source hash does not match source_manifest")
            if "text_sha256" in value:
                text_hash = _sha(value["text_sha256"], "text_sha256")
                text = value.get("text")
                if text_hash and (not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != text_hash):
                    raise ValueError("evidence text_sha256 does not match text")
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for case in cases:
        walk(case)
    return bool(complete)


def _validate_import(payload):
    if not isinstance(payload, dict):
        raise ValueError("report must be an object")
    _finite(payload)
    wrapper = payload if "report" in payload else {}
    report = wrapper.get("report", payload)
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    report = json.loads(_dump(report))  # detach caller-owned mutable objects
    if "schema_version" in report and (type(report["schema_version"]) is not int or report["schema_version"] != 1):
        raise ValueError("unsupported report schema_version")
    rows = report.get("cases")
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise ValueError("cases must contain 1 to 10000 frozen cases")
    count = report.get("dataset_cases")
    if type(count) is not int or count != len(rows):
        raise ValueError("dataset_cases must equal the complete cases length")
    digest = _sha(report.get("dataset_sha256"), "dataset_sha256")
    known = _known_dataset(digest)
    expected = {c["id"]: c for c in known["cases"]} if known else {}
    kind = report.get("kind", "qa")
    if not isinstance(kind, str) or kind not in {"qa", "enrichment"}:
        raise ValueError("kind must be qa or enrichment")
    unit = report.get("evaluation_unit", "fact_unit" if kind == "enrichment" else "case")
    if unit != ("fact_unit" if kind == "enrichment" else "case"):
        raise ValueError("enrichment must use fact_unit; qa must use case")
    purpose = wrapper.get("purpose", report.get("purpose", "development"))
    if not isinstance(purpose, str) or purpose not in {"development", "acceptance"}:
        raise ValueError("purpose must be development or acceptance")
    title = _string(wrapper.get("title", report.get("title", "知识富化质量评测" if kind == "enrichment" else "问答质量评测")), "title", 200)
    commits = [source["source_commit"] for source in (report, wrapper) if source.get("source_commit") is not None]
    if any(not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit) for commit in commits):
        raise ValueError("source_commit must be the full 40-character Git SHA")
    if len({commit.lower() for commit in commits}) > 1:
        raise ValueError("wrapper source_commit differs from report source_commit")
    source_commit = commits[0].lower() if commits else None
    visibility = report.get("dataset_visibility", "unspecified")
    if not isinstance(visibility, str) or visibility not in {"public_development", "held_out", "unspecified"}:
        raise ValueError("invalid dataset_visibility")
    if known:
        visibility = "public_development"
        if kind != "qa":
            raise ValueError("known QA dataset cannot be imported as enrichment")
    ids, normalized = set(), []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each case must be an object")
        case_id = _string(row.get("id"), "case.id", 160)
        if case_id != row["id"] or case_id in ids:
            raise ValueError("case IDs must be unique and have no surrounding whitespace")
        ids.add(case_id)
        question = _string(row.get("question"), "case.question", 100000)
        if known and (case_id not in expected or row.get("question") != expected[case_id]["question"] or row.get("history", []) != expected[case_id].get("history", [])):
            raise ValueError("case differs from the frozen known dataset")
        seconds = row.get("seconds")
        if seconds is not None and (type(seconds) not in (int, float) or seconds < 0):
            raise ValueError("case.seconds must be a finite nonnegative number or null")
        automatic = row.get("automatic_passed")
        if automatic is not None and type(automatic) is not bool:
            raise ValueError("automatic_passed must be bool or null")
        failures = row.get("failures", [])
        if not isinstance(failures, list) or any(not isinstance(f, str) for f in failures):
            raise ValueError("failures must be an array of strings")
        if automatic is True and failures:
            raise ValueError("automatic_passed contradicts nonempty failures")
        reasoning = row.get("reasoning_kind")
        if reasoning is not None and (not isinstance(reasoning, str) or reasoning not in KINDS):
            raise ValueError("invalid case reasoning_kind")
        if known:
            reasoning = _known_kind(expected[case_id])
        elif kind == "enrichment":
            if reasoning not in (None, "enrichment"):
                raise ValueError("enrichment cases must use enrichment reasoning_kind")
            reasoning = "enrichment"
        elif reasoning == "enrichment":
            raise ValueError("QA cases cannot use enrichment reasoning_kind")
        response = row.get("response", {})
        if not isinstance(response, dict):
            raise ValueError("case.response must be an object")
        for source, key in ((row, "model_attempted"), (response, "model_attempted"), (response, "used_model")):
            if key in source and type(source[key]) is not bool:
                raise ValueError(f"{key} must be boolean when present")
        if kind == "enrichment" and any(key not in row for key in ("prediction", "reference", "context")):
            raise ValueError("enrichment fact units require prediction, reference and context")
        normalized.append({
            "id": case_id, "question": question, "category": row.get("category", ""),
            "prediction": row.get("prediction", response.get("answer")),
            "reference": row.get("reference", expected.get(case_id)),
            "context": row.get("context", response.get("evidence_chunks", [])),
            "response": response, "seconds": seconds, "automatic_passed": automatic,
            "failures": failures, "reasoning_kind": reasoning, "original_case": row,
        })
    if known and ids != set(expected):
        raise ValueError("missing cases from the frozen known dataset")
    manifest_ids = report.get("dataset_case_ids")
    manifest_complete = bool(known)
    if manifest_ids is not None:
        if not isinstance(manifest_ids, list) or any(not isinstance(i, str) for i in manifest_ids) or len(set(manifest_ids)) != len(manifest_ids) or set(manifest_ids) != ids:
            raise ValueError("dataset_case_ids must exactly match all unique case IDs")
        manifest_complete = True
    hashes_complete = _source_validation(report, rows, known)
    metadata = {
        "title": title, "purpose": purpose, "kind": kind,
        "source_commit": source_commit,
        "run_at": report.get("run_at"), "model": report.get("model"), "mode": report.get("mode"),
        "dataset_sha256": digest, "dataset_cases": len(rows), "dataset_visibility": visibility,
        "evaluation_unit": unit, "dataset_case_manifest_complete": manifest_complete,
        "source_hashes_complete": hashes_complete,
        "hash_verification": "provided digests checked for format and internal consistency; sources are not refetched",
    }
    # Summaries/imported reviews are not observations and cannot multiply a run.
    identity = {k: v for k, v in report.items() if k not in {"summary", "title", "purpose", "manual_review", "source_commit"}}
    identity["cases"] = sorted(({k: v for k, v in r.items() if k not in {"manual_review", "latest_review", "review_history"}} for r in rows), key=lambda r: r["id"])
    return report, metadata, normalized, canonical_hash(identity)


def import_report(payload, db_path=None):
    report, metadata, cases, run_id = _validate_import(payload)
    with connect(db_path) as connection:
        _schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        exists = connection.execute("SELECT metadata_json FROM quality_runs WHERE run_id=?", (run_id,)).fetchone()
        if exists and metadata["source_commit"] is not None and json.loads(exists[0]).get("source_commit") != metadata["source_commit"]:
            raise ValueError("source_commit differs from the immutable imported run; the original attribution cannot be replaced")
        if not exists:
            digest = metadata["dataset_sha256"]
            if digest:
                case_ids = _dump(sorted(c["id"] for c in cases))
                previous = connection.execute("SELECT case_ids_json FROM quality_datasets WHERE dataset_sha256=?", (digest,)).fetchone()
                if previous and previous[0] != case_ids:
                    raise ValueError("dataset SHA reused with a different case set")
                connection.execute("INSERT OR IGNORE INTO quality_datasets VALUES (?,?)", (digest, case_ids))
            connection.execute("INSERT INTO quality_runs VALUES (?,?,?,?)", (run_id, now_iso(), _dump(report), _dump(metadata)))
            connection.executemany("INSERT INTO quality_cases VALUES (?,?,?,?)", ((run_id, c["id"], i, _dump(c)) for i, c in enumerate(cases)))
    result = get_run(run_id, db_path)
    result["created"] = not bool(exists)
    return result


def _has_evidence(case):
    response = case.get("response", {})
    return bool(case.get("context") or response.get("evidence") or response.get("evidence_chunks"))


def _required(case, review):
    required = ["correct", "conditions_preserved"]
    if review["reasoning_kind"] != "refusal" or _has_evidence(case):
        required.append("citations_supported")
    if review["reasoning_kind"] in COMPLEX:
        required.append("reasoning_valid")
    return required


def _complete(case, review):
    return review is not None and all(type(review[key]) is bool for key in _required(case, review))


def _passed(case, review):
    return _complete(case, review) and all(review[key] is True for key in _required(case, review))


def _wilson(passed, total):
    z = 1.959963984540054
    rate = passed / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return {"method": "wilson", "lower": max(0.0, center - margin), "upper": min(1.0, center + margin), "n": total}


def _statistics(cases, metadata, unclassified=0, group_classification_frozen=True):
    reviews = [(c, c["latest_review"]) for c in cases if c["latest_review"] is not None]
    complete = [(c, r) for c, r in reviews if _complete(c, r)]
    independent = [(c, r) for c, r in complete if r["reviewer_type"] == "human" and r["independent"]]
    blockers = []
    if not cases:
        blockers.append("no_cases")
    if not metadata["dataset_sha256"]:
        blockers.append("dataset_hash_missing")
    if not metadata["dataset_case_manifest_complete"]:
        blockers.append("dataset_case_manifest_missing")
    if not metadata["source_hashes_complete"]:
        blockers.append("source_hashes_missing")
    if unclassified:
        blockers.append("unclassified_cases")
    if not group_classification_frozen:
        blockers.append("group_classification_not_frozen")
    if len(independent) != len(cases):
        blockers.append("independent_human_reviews_incomplete")
    eligible = not blockers
    passed = sum(_passed(c, r) for c, r in independent)
    subset_passed = sum(_passed(c, r) for c, r in complete)
    times = sorted(c["seconds"] for c in cases if c["seconds"] is not None)
    used_model = sum(c["response"].get("used_model") is True for c in cases)
    attempted = sum(c["original_case"].get("model_attempted") is True or c["response"].get("model_attempted") is True for c in cases)
    return {
        "cases": len(cases), "automatic_passed": sum(c["automatic_passed"] is True for c in cases),
        "automatic_failed": sum(c["automatic_passed"] is False for c in cases),
        "automatic_unchecked": sum(c["automatic_passed"] is None for c in cases),
        "reviewed_cases": len(reviews), "unreviewed_cases": len(cases) - len(reviews),
        "incomplete_review_cases": len(reviews) - len(complete),
        "independent_reviewed_cases": len(independent),
        "reviewed_subset_accuracy": subset_passed / len(complete) if complete else None,
        "reviewed_subset_denominator": len(complete), "reviewed_subset_passed": subset_passed,
        "reviewed_subset_by_reviewer_type": {t: sum(r["reviewer_type"] == t for _, r in complete) for t in ("human", "ai")},
        "independent_accuracy": passed / len(cases) if eligible else None,
        "independent_denominator": len(cases) if eligible else 0,
        "independent_passed": passed if eligible else None,
        "confidence_interval_95": _wilson(passed, len(cases)) if eligible else None,
        "independent_blockers": blockers,
        "status": "declared_independent_complete" if eligible else "incomplete",
        "identity_authenticated": False, "competition_pass": None,
        "used_model_cases": used_model, "model_attempted_cases": attempted,
        "timing": {"sample_count": len(times), "p95_seconds": times[math.ceil(len(times) * .95) - 1] if times else None,
                   "max_seconds": max(times) if times else None, "over_5_seconds": sum(t > 5 for t in times)},
    }


def _read(connection, run_id, include_cases=True):
    row = connection.execute("SELECT * FROM quality_runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        raise KeyError(run_id)
    metadata = json.loads(row["metadata_json"])
    metadata.setdefault("source_commit", None)
    cases = [json.loads(r[0]) for r in connection.execute("SELECT case_json FROM quality_cases WHERE run_id=? ORDER BY ordinal", (run_id,))]
    histories = {c["id"]: [] for c in cases}
    for review in connection.execute("SELECT case_id,revision,reviewed_at,review_json FROM quality_reviews WHERE run_id=? ORDER BY revision", (run_id,)):
        item = json.loads(review["review_json"])
        item.update(revision=review["revision"], reviewed_at=review["reviewed_at"])
        histories[review["case_id"]].append(item)
    for case in cases:
        case["review_history"] = histories[case["id"]]
        case["latest_review"] = case["review_history"][-1] if case["review_history"] else None
        case["revision"] = case["latest_review"]["revision"] if case["latest_review"] else 0
        case["effective_reasoning_kind"] = case["reasoning_kind"] or (case["latest_review"]["reasoning_kind"] if case["latest_review"] else None)
        case["required_checks"] = _required(case, case["latest_review"] or {"reasoning_kind": case["effective_reasoning_kind"] or "other"})
    unclassified = sum(c["effective_reasoning_kind"] is None for c in cases)
    unfrozen = sum(c["reasoning_kind"] is None for c in cases)
    statistics = _statistics(cases, metadata, unclassified)
    statistics["by_kind"] = {group: _statistics([c for c in cases if _group(c["effective_reasoning_kind"]) == group], metadata, unclassified, not unfrozen) for group in ("basic", "multi_hop", "complex", "other", "enrichment")}
    statistics["by_reasoning_kind"] = {kind: _statistics([c for c in cases if c["effective_reasoning_kind"] == kind], metadata, unclassified, not unfrozen) for kind in sorted(KINDS)}
    statistics["unclassified_cases"] = unclassified
    statistics["classification_not_frozen_cases"] = unfrozen
    result = {"run_id": run_id, "imported_at": row["imported_at"], **metadata, "statistics": statistics, "scoring_policy": SCORING_POLICY}
    if include_cases:
        result.update(cases=cases, original_report=json.loads(row["report_json"]))
    return result


def get_run(run_id, db_path=None):
    with connect(db_path) as connection:
        _schema(connection)
        return _read(connection, run_id)


def list_runs(db_path=None):
    with connect(db_path) as connection:
        _schema(connection)
        ids = [r[0] for r in connection.execute("SELECT run_id FROM quality_runs ORDER BY imported_at DESC,run_id")]
        runs = [_read(connection, run_id, False) for run_id in ids]
    return {"runs": runs, "total": len(runs)}


def review_case(run_id, case_id, payload, db_path=None):
    if not isinstance(payload, dict) or set(payload) != REVIEW_FIELDS:
        raise ValueError("review must contain exactly: " + ", ".join(sorted(REVIEW_FIELDS)))
    _finite(payload)
    review = dict(payload)
    review["reviewer"] = _string(review["reviewer"], "reviewer", 200)
    if not isinstance(review["reviewer_type"], str) or review["reviewer_type"] not in {"human", "ai"} or type(review["independent"]) is not bool:
        raise ValueError("reviewer_type and independent must be explicit declarations")
    if not isinstance(review["reasoning_kind"], str) or review["reasoning_kind"] not in KINDS:
        raise ValueError("invalid reasoning_kind")
    if any(review[k] is not None and type(review[k]) is not bool for k in CHECKS):
        raise ValueError("quality checks must be boolean or null")
    if not isinstance(review["note"], str) or len(review["note"]) > 20000:
        raise ValueError("note must be a string of at most 20000 characters")
    revision = review.pop("expected_revision")
    if type(revision) is not int or revision < 0:
        raise ValueError("expected_revision must be a nonnegative integer")
    with connect(db_path) as connection:
        _schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT c.case_json,r.metadata_json FROM quality_cases c JOIN quality_runs r ON r.run_id=c.run_id WHERE c.run_id=? AND c.case_id=?", (run_id, case_id)).fetchone()
        if row is None:
            raise KeyError((run_id, case_id))
        case = json.loads(row[0])
        kind = json.loads(row[1])["kind"]
        if (review["reasoning_kind"] == "enrichment") != (kind == "enrichment"):
            raise ValueError("reasoning_kind must match the run's QA or enrichment evaluation unit")
        if case["reasoning_kind"] and review["reasoning_kind"] != case["reasoning_kind"]:
            raise ValueError("reasoning_kind differs from the frozen case classification")
        current = connection.execute("SELECT COALESCE(MAX(revision),0) FROM quality_reviews WHERE run_id=? AND case_id=?", (run_id, case_id)).fetchone()[0]
        if current != revision:
            raise RevisionConflict(f"review revision conflict: expected {revision}, current {current}")
        reviewed_at = now_iso()
        connection.execute("INSERT INTO quality_reviews (run_id,case_id,revision,reviewed_at,review_json) VALUES (?,?,?,?,?)", (run_id, case_id, current + 1, reviewed_at, _dump(review)))
        summary = _read(connection, run_id, False)
    return {"run_id": run_id, "case_id": case_id, "revision": current + 1, "review": {**review, "revision": current + 1, "reviewed_at": reviewed_at}, "summary": summary}


def export_run(run_id, db_path=None):
    return {"schema_version": 1, "exported_at": now_iso(), "run": get_run(run_id, db_path)}
