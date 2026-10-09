"""Create an offline demo intelligence.db so /api/intelligence/team returns rows.

No network. Synthetic CVE is for local compose only — not competition evidence.
Usage (from repository root or this directory):

    intelligence/.venv/bin/python intelligence/seed_demo_db.py
    INTELLIGENCE_DB_PATH=intelligence/data/intelligence.db \\
      intelligence/.venv/bin/python intelligence/run_intelligence_api_v6.py
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from collectors.base import IntelligenceItem
from storage.sqlite_store import SQLiteIntelligenceStore

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "data" / "intelligence.db"
# Use a non-issued year so offline seed never collides with live NVD/OSV rows.
DEMO_CVE = "CVE-2099-90001"


def build_item() -> IntelligenceItem:
    raw = {
        "id": DEMO_CVE,
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "0.1.34",
                }],
            }],
        }],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "source": "nvd@nist.gov",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            }],
        },
        "references": [
            {"url": "https://example.com/demo-ollama-advisory", "tags": ["Vendor Advisory"]},
        ],
    }
    return IntelligenceItem(
        source="NVD",
        source_id=DEMO_CVE,
        cve_id=DEMO_CVE,
        title="Demo offline fixture: Ollama related synthetic record",
        description=(
            "Synthetic Ollama regression input for team compose demos. "
            "Not a real NVD advisory; keyword ollama must match team search."
        ),
        url=f"https://nvd.nist.gov/vuln/detail/{DEMO_CVE}",
        published_at="2026-10-08T01:00:00Z",
        modified_at="2026-10-08T02:00:00Z",
        severity="CRITICAL",
        raw_data=raw,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Seed offline B demo DB for team API")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--force", action="store_true", help="Replace existing demo DB file")
    args = parser.parse_args(argv)
    db = Path(args.db).resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.is_file() and not args.force:
        print(json.dumps({"status": "exists", "db": str(db), "hint": "pass --force to recreate"},
                         ensure_ascii=False))
        return 0
    if db.is_file():
        db.unlink()
    store = SQLiteIntelligenceStore(db)
    counts = store.ingest_batch("NVD", [build_item()])
    rebuilt = subprocess.run(
        [sys.executable, str(ROOT / "run_rebuild_unified.py"), "--db", str(db)],
        cwd=ROOT.parent, text=True, capture_output=True, timeout=30,
    )
    if rebuilt.returncode != 0:
        print(rebuilt.stdout)
        print(rebuilt.stderr, file=sys.stderr)
        return rebuilt.returncode
    classified = subprocess.run(
        [sys.executable, str(ROOT / "run_ai_classification_v5.py"),
         "--db", str(db), "--max-items", "10", "--max-llm-calls", "0"],
        cwd=ROOT.parent, text=True, capture_output=True, timeout=60,
    )
    if classified.returncode != 0:
        print(classified.stdout)
        print(classified.stderr, file=sys.stderr)
        return classified.returncode
    print(json.dumps({
        "status": "ok",
        "db": str(db),
        "cve_id": DEMO_CVE,
        "ingest": counts,
        "note": "synthetic offline fixture; start API with this db path",
        "start": (
            f"INTELLIGENCE_DB_PATH={db} "
            f"{sys.executable} {ROOT / 'run_intelligence_api_v6.py'}"
        ),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
