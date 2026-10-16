"""Prepare labelled demo data and run the full local UI without external access.

Install requirements.txt once, then run: python scripts/offline_demo.py
Repeated starts reuse only this demo's isolated databases; production is untouched.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def prepare(directory):
    directory = Path(directory).resolve()
    marker = directory / ".offline-demo.json"
    if directory.exists() and not marker.exists() and any(directory.iterdir()):
        raise ValueError("请选择空的演示目录；不会覆盖已有数据库或正式数据")
    directory.mkdir(parents=True, exist_ok=True)
    if marker.exists():
        if json.loads(marker.read_text()).get("kind") != "synthetic-offline-demo-v1":
            raise ValueError("目录不是本工具创建的离线演示")
    else:
        marker.write_text(json.dumps({"kind": "synthetic-offline-demo-v1"}))
    b_db = directory / "b-data" / "intelligence.db"
    main_dir = directory / "main-data"
    main_dir.mkdir(exist_ok=True)
    os.environ.update({
        "OFFLINE_DEMO": "1", "TEAM_INTEL_MODE": "embed",
        "INTELLIGENCE_DB_PATH": str(b_db), "MAIN_DATA_DIR": str(main_dir),
        "MAIN_KB_DB_PATH": str(main_dir / "knowledge.sqlite3"), "MAIN_IMPORT_DEMO_CARDS": "0",
        "AUTO_MONITOR_ENABLED": "0", "AUTO_MONITOR_ON_START": "0",
        "AUTO_INGEST_ON_COLLECT": "0", "B_MONITOR_ENABLED": "0", "B_MONITOR_ON_REFRESH": "0",
        "ACTIONS_SYNC_ON_START": "0", "ACTIONS_SYNC_PULL": "0",
        "CLASSIFY_V4_MAX_LLM_CALLS": "0", "CLASSIFY_V5_MAX_LLM_CALLS": "0",
        "DEEPSEEK_REVIEW_ENABLED": "false", "DEEPSEEK_API_KEY": "",
    })
    from config.offline import install_guard
    install_guard()
    if not b_db.exists():
        # Separate process avoids the overlapping B/A collectors package names.
        # A guard also covers the seed and its rebuild/classification children.
        guard_dir = directory / "python-guard"
        guard_dir.mkdir(exist_ok=True)
        (guard_dir / "sitecustomize.py").write_text(
            "import sys\nsys.path.append(" + repr(str(ROOT)) + ")\n"
            "from config.offline import install_guard\ninstall_guard()\n")
        env = dict(os.environ, PYTHONPATH=str(guard_dir))
        subprocess.run([sys.executable, str(ROOT / "intelligence/seed_demo_db.py"), "--db", str(b_db)],
                       cwd=ROOT, env=env, check=True, capture_output=True, text=True, timeout=120)
    from agents.orchestrator import run_collect
    from rag.library import sync_team_drain, overview
    from database.store import load_kb
    run_collect()
    seeded_evidence = _seed_offline_nvd_evidence()
    result = sync_team_drain()
    if result.get("status") != "ok":
        raise RuntimeError("离线资料导入失败，请查看数据库权限和运行日志")
    return {"mode": "offline_demo", "synthetic": True, "external_network": False,
            "vulnerabilities": len(load_kb()), "documents": overview()["documents"],
            "nvd_evidence_seeded": seeded_evidence}


def _seed_offline_nvd_evidence():
    """Archive synthetic NVD JSON from the KB so asset matching can cite version ranges offline."""
    from database.store import load_kb
    from rag.ingest import ingest

    seeded = 0
    for record in load_kb():
        item = record.get("item") or {}
        cve_id = item.get("cve_id")
        raw_nvd = ((item.get("raw_data") or {}).get("raw_by_source") or {}).get("NVD")
        if not cve_id or not isinstance(raw_nvd, dict):
            continue
        # assess() expects the NVD 2.0 envelope; seed stores the inner CVE object.
        payload = {"vulnerabilities": [{"cve": raw_nvd}]}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        def fetcher(url, _body=body, _cve=cve_id):
            if "services.nvd.nist.gov" in url and _cve in url:
                return {"body": _body, "content_type": "application/json", "url": url}
            raise TimeoutError("offline demo keeps non-NVD fetches local-only")

        try:
            result = ingest(record, max_sources=1, fetcher=fetcher, update_index_on_ingest=False)
        except Exception as exc:
            raise RuntimeError("离线证据存档失败（%s）：%s" % (cve_id, exc)) from exc
        if result.get("ok", 0):
            seeded += 1
    return seeded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-directory", default=str(ROOT / ".demo/offline"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8023)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.data_directory), ensure_ascii=False), flush=True)
    if not args.prepare_only:
        import uvicorn
        print("离线演示已就绪：展示合成数据，不代表真实情报或比赛时效；Ctrl+C 停止。", flush=True)
        uvicorn.run("api.app:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
