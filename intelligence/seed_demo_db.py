"""Create an offline multi-source demo intelligence.db for three-party compose.

Labeled **demo / synthetic** — not competition evidence of live multi-source SLA.

- Several AI-security CVE rows with distinct upstream source labels
  (NVD / GITHUB_ADVISORY / CISA_KEV) so team API + overview are not OSV/NVD-only.
- Chinese titles/descriptions for the monitor UI (【演示】prefix).
- A few non-CVE knowledge documents across categories for library team-sync.

Usage:

    intelligence/.venv/bin/python intelligence/seed_demo_db.py --force
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from collectors.base import IntelligenceItem
from collectors.documents import KnowledgeDocument, document_id
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "data" / "intelligence.db"

# Non-issued years / synthetic IDs — must not collide with live NVD pulls.
DEMO_ITEMS = (
    {
        "cve": "CVE-2099-90001",
        "source": "NVD",
        "title": "【演示】Ollama 智能体授权绕过（合成）",
        "description": (
            "演示用合成记录：模拟 Ollama / LLM 智能体工具链相关漏洞。"
            "关键词：ollama、llm、agent。非真实 NVD 公告。"
        ),
        "product": "ollama",
        "end": "0.1.34",
        "score": 9.8,
    },
    {
        "cve": "CVE-2099-90002",
        "source": "GITHUB_ADVISORY",
        "title": "【演示】vLLM 推理服务提示注入（合成）",
        "description": (
            "演示用合成记录：模拟 vLLM / Hugging Face 推理场景的提示注入风险。"
            "关键词：vllm、huggingface、prompt injection、llm。"
        ),
        "product": "vllm",
        "end": "0.6.0",
        "score": 8.1,
    },
    {
        "cve": "CVE-2099-90003",
        "source": "CISA_KEV",
        "title": "【演示】LangChain 工具调用越狱链（合成）",
        "description": (
            "演示用合成记录：模拟 LangChain / OpenAI 兼容智能体的越狱与对抗利用。"
            "关键词：langchain、openai、jailbreak、adversarial。"
        ),
        "product": "langchain",
        "end": "0.2.10",
        "score": 7.5,
    },
    {
        "cve": "CVE-2099-90004",
        "source": "NVD",
        "title": "【演示】Hugging Face 模型供应链 pickle 风险（合成）",
        "description": (
            "演示用合成记录：模拟模型权重 / pickle 反序列化供应链风险。"
            "关键词：huggingface、pickle、supply chain。"
        ),
        "product": "transformers",
        "end": "4.40.0",
        "score": 8.8,
    },
)

DEMO_DOCS = (
    {
        "source": "TRAIL_OF_BITS_BLOG",
        "category": "security_blog",
        "content_type": "article",
        "sid": "demo-tob-prompt-injection",
        "title": "【演示】LLM 应用中间接提示注入（合成博客摘要）",
        "description": "演示用合成研报摘要，供资料库 team-sync。",
        "url": "https://blog.trailofbits.com/demo-ai-sec-intel-fixture-prompt-injection",
    },
    {
        "source": "ARXIV_AI_SECURITY",
        "category": "academic_paper",
        "content_type": "paper",
        "sid": "demo-arxiv-jailbreak",
        "title": "【演示】越狱与对抗提示（合成论文摘要）",
        "description": "演示用合成 arXiv 风格摘要。",
        "url": "https://arxiv.org/abs/2099.90001",
    },
    {
        "source": "NIST_CSRC_AI_STANDARDS",
        "category": "technical_standard",
        "content_type": "standard",
        "sid": "demo-nist-ai-rmf",
        "title": "【演示】AI 风险管理节选（合成标准）",
        "description": "演示用合成 NIST 风格标准摘要。",
        "url": "https://csrc.nist.gov/demo-ai-sec-intel-fixture-rmf",
    },
    {
        "source": "HF_SECURITY_COMMUNITY",
        "category": "security_community",
        "content_type": "post",
        "sid": "demo-hf-community",
        "title": "【演示】Hugging Face 安全讨论（合成社区帖）",
        "description": "演示用合成社区讨论摘要。",
        "url": "https://discuss.huggingface.co/demo-ai-sec-intel-fixture",
    },
)


def _vuln_item(row: dict) -> IntelligenceItem:
    cve = row["cve"]
    product = row["product"]
    source = row["source"]
    score = row["score"]
    end = row["end"]

    if source == "GITHUB_ADVISORY":
        raw = {
            "ghsa_id": f"GHSA-demo-{cve[-5:]}",
            "summary": row["title"],
            "description": row["description"],
            "severity": "HIGH",
            "demo_fixture": True,
            "cvss": {"score": score, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "version": "3.1"},
            "cvss_severities": {
                "cvss_v3": {
                    "score": score,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "version": "3.1",
                },
            },
            "vulnerabilities": [{
                "package": {"ecosystem": "pip", "name": product},
                "vulnerable_version_range": f"< {end}",
                "first_patched_version": {"identifier": end},
            }],
            "references": [{"url": f"https://github.com/advisories/GHSA-demo-{cve[-5:]}"}],
        }
        source_id = f"GHSA-demo-{cve[-5:]}"
    elif source == "CISA_KEV":
        raw = {
            "demo_fixture": True,
            "cveID": cve,
            "vendorProject": "demo",
            "vendor": "demo",
            "product": product,
            "dateAdded": "2026-10-08",
            "requiredAction": "演示用：请升级到供应商修复版本（合成）",
            "shortDescription": row["description"],
            "notes": "synthetic offline fixture",
        }
        source_id = cve
    else:
        raw = {
            "id": cve,
            "demo_fixture": True,
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": f"cpe:2.3:a:demo:{product}:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": end,
                    }],
                }],
            }],
            "metrics": {
                "cvssMetricV31": [{
                    "type": "Primary",
                    "source": "demo@ai-sec-intel",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": score,
                        "baseSeverity": "CRITICAL" if score >= 9 else "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }],
            },
            "references": [
                {"url": f"https://nvd.nist.gov/vuln/detail/{cve}", "tags": ["Vendor Advisory"]},
            ],
        }
        source_id = cve

    return IntelligenceItem(
        source=source,
        source_id=source_id,
        cve_id=cve,
        title=row["title"],
        description=row["description"],
        url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        published_at="2026-10-08T01:00:00Z",
        modified_at="2026-10-08T02:00:00Z",
        severity="HIGH",
        raw_data=raw,
        tags=["demo_fixture", "ai_security"],
    )


def _doc(row: dict) -> KnowledgeDocument:
    did = document_id(row["source"], row["sid"])
    return KnowledgeDocument(
        document_id=did,
        source=row["source"],
        source_category=row["category"],
        content_type=row["content_type"],
        title=row["title"],
        description=row["description"],
        url=row["url"],
        published_at="2026-10-08",
        modified_at=None,
        cve_ids=[],
        raw_data={"demo_fixture": True, "notice": "synthetic offline fixture"},
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Seed offline multi-source B demo DB")
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
        for suffix in ("-wal", "-shm"):
            side = Path(str(db) + suffix)
            if side.is_file():
                side.unlink()

    store = SQLiteIntelligenceStore(db)
    ingest_summary = []
    for row in DEMO_ITEMS:
        counts = store.ingest_batch(row["source"], [_vuln_item(row)])
        ingest_summary.append({"source": row["source"], "cve": row["cve"], **counts})
        # Companion NVD-shaped metrics so GHSA/CISA rows still carry product + CVSS
        # after fusion (their native adapters do not always populate those fields).
        if row["source"] != "NVD":
            companion = dict(row, source="NVD", title=row["title"], description=row["description"])
            extra = store.ingest_batch("NVD", [_vuln_item(companion)])
            ingest_summary.append({"source": "NVD+companion", "cve": row["cve"], **extra})

    docs = SQLiteDocumentStore(db)
    doc_summary = []
    for row in DEMO_DOCS:
        doc = _doc(row)
        counts = docs.ingest(row["source"], row["category"], [doc])
        doc_summary.append({"source": row["source"], "category": row["category"], **counts})

    rebuilt = subprocess.run(
        [sys.executable, str(ROOT / "run_rebuild_unified.py"), "--db", str(db)],
        cwd=ROOT.parent, text=True, capture_output=True, timeout=60,
    )
    if rebuilt.returncode != 0:
        print(rebuilt.stdout)
        print(rebuilt.stderr, file=sys.stderr)
        return rebuilt.returncode
    classified = subprocess.run(
        [sys.executable, str(ROOT / "run_ai_classification_v5.py"),
         "--db", str(db), "--max-items", "50", "--max-llm-calls", "0"],
        cwd=ROOT.parent, text=True, capture_output=True, timeout=120,
    )
    if classified.returncode != 0:
        print(classified.stdout)
        print(classified.stderr, file=sys.stderr)
        return classified.returncode

    print(json.dumps({
        "status": "ok",
        "db": str(db),
        "label": "demo_synthetic_offline_fixture",
        "vulns": ingest_summary,
        "documents": doc_summary,
        "note": "Not live multi-source SLA evidence; use run_monitor.py --once for real collection",
        "start": (
            f"INTELLIGENCE_DB_PATH={db} "
            f"{sys.executable} {ROOT / 'run_intelligence_api_v6.py'}"
        ),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
