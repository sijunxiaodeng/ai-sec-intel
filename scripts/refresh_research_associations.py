"""Backfill local research relations through revision-checked normal writes."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve", action="append", help="Repeat for explicit, already collected CVEs")
    group.add_argument("--limit", type=int, help="Maximum CVEs, 1–100, missing associations first")
    args = parser.parse_args()
    from database import store
    from enrichment.research_associations import refresh_and_save, KEY
    records = store.load_kb()
    records = [r for r in records if not (r["item"].get("raw_data") or {}).get("sample_mode")]
    if args.cve:
        requested = {value.upper() for value in args.cve}
        records = [r for r in records if r["item"]["cve_id"] in requested]
        missing = requested - {r["item"]["cve_id"] for r in records}
        if missing:
            parser.error("Unknown or demo CVE: " + ", ".join(sorted(missing)))
    else:
        if not 1 <= args.limit <= 100:
            parser.error("limit must be 1–100")
        records.sort(key=lambda r: (bool((r["item"].get("raw_data") or {}).get(KEY)), r["item"]["cve_id"]))
        records = records[:args.limit]
    for record in records:
        try:
            result = refresh_and_save(record)
            print(json.dumps({"cve_id": record["item"]["cve_id"], "status": result["status"],
                              "counts": result["counts"]}, ensure_ascii=False), flush=True)
        except Exception as exc:
            print(json.dumps({"cve_id": record["item"]["cve_id"], "error_type": type(exc).__name__}), flush=True)


if __name__ == "__main__":
    main()
