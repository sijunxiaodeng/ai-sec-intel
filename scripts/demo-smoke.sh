#!/usr/bin/env bash
# Full demo chain against the composed env (fixed ports).
# Exit 0 only if health + multi-source team narrative + collect + enrich + ask + library succeed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

OUT="${DEMO_SMOKE_OUT:-$DEMO_DIR/smoke-last}"
mkdir -p "$OUT"
KEYWORD="${DEMO_KEYWORD:-llm}"
# Comma set for team breadth check (B API); collect uses KEYWORD primary + optional set.
COLLECT_KEYWORD="${DEMO_COLLECT_KEYWORD:-llm,vllm,langchain,huggingface,openai,ollama,jailbreak}"
ASK_CVE="${DEMO_ASK_CVE:-CVE-2099-90001}"

fail=0
check() {
  local name="$1"
  shift
  if "$@"; then
    log "PASS $name"
  else
    log "FAIL $name"
    fail=1
  fi
}

log "smoke against single entry main=$MAIN_URL keyword=$KEYWORD (TEAM_INTEL_MODE=${TEAM_INTEL_MODE:-embed}; no :8765 required)"

# Full chain via :8023 only — B is in-process; do not require :8765
curl -sf --max-time 5 "$MAIN_URL/api/intelligence/health" -o "$OUT/b-health.json"
check "b-health-via-8023" test -s "$OUT/b-health.json"
python3 - <<PY
import json,sys
h=json.load(open("$OUT/b-health.json"))
sys.exit(0 if h.get("database_available") is True else 1)
PY
check "b-database_available" true

# Multi-source seed / live: expect more than one AI CVE when fixtures present
curl -sf --max-time 5 "$MAIN_URL/api/intelligence/team?q=&ai_only=true&limit=20" -o "$OUT/b-team-all.json"
python3 - <<PY
import json,sys
t=json.load(open("$OUT/b-team-all.json"))
items=t.get("items") or []
sources=set()
for it in items:
    for s in (it.get("sources") or []):
        sources.add(s)
    if it.get("source"):
        sources.add(it["source"])
ok = t.get("total",0)>=2 and len(items)>=2
print("team_total", t.get("total"), "sources", sorted(sources))
sys.exit(0 if ok else 1)
PY
check "b-team-multi-cve" true

# Broader keyword hits (at least one of the AI set returns items)
python3 - <<PY
import json,urllib.parse,urllib.request,sys
base="$MAIN_URL"
keys=[k.strip() for k in "$AI_SECURITY_KEYWORDS".split(",") if k.strip()]
hits=[]
for kw in keys:
    q=urllib.parse.urlencode({"q":kw,"ai_only":"true","limit":3})
    try:
        with urllib.request.urlopen(base+"/api/intelligence/team?"+q, timeout=5) as r:
            t=json.load(r)
        if t.get("total",0)>=1:
            hits.append(kw)
    except Exception:
        pass
print("keyword_hits", hits)
sys.exit(0 if len(hits)>=3 else 1)
PY
check "b-team-keyword-breadth" true

curl -sf --max-time 5 "$MAIN_URL/api/documents/stats" -o "$OUT/b-documents-stats.json" || echo '{}' >"$OUT/b-documents-stats.json"
python3 - <<PY
import json,sys
s=json.load(open("$OUT/b-documents-stats.json"))
total=s.get("total_documents") or s.get("total") or s.get("documents") or 0
print("documents_stats", {k:s.get(k) for k in ("total_documents","source_record_counts","categories") if k in s})
sys.exit(0 if total>=1 else 1)
PY
check "b-documents-present" true

curl -sf --max-time 5 "$MAIN_URL/api/intelligence/coverage" -o "$OUT/b-coverage.json" || echo '{}' >"$OUT/b-coverage.json"

curl -sf --max-time 5 "$MAIN_URL/api/overview" -o "$OUT/overview.json"
check "main-overview" test -s "$OUT/overview.json"
python3 - <<PY
import json,sys
o=json.load(open("$OUT/overview.json"))
team=o.get("team_intel") or {}
lib=o.get("library") or {}
ok = team.get("reachable") is True and (lib.get("documents") or 0) >= 1
print("team_reachable", team.get("reachable"), "library_docs", lib.get("documents"),
      "sources", o.get("sources"), "team_total", team.get("team_total"))
sys.exit(0 if ok else 1)
PY
check "overview-team-and-library" true

curl -sf --max-time 5 "$MAIN_URL/" -o "$OUT/page.html"
check "main-page" grep -q "AI 安全知识情报" "$OUT/page.html"
check "ia-pipeline-rail" grep -q 'class="pipeline"' "$OUT/page.html"
check "ia-monitor-copy" grep -q "情报监测" "$OUT/page.html"
check "ia-library-copy" grep -q "资料库" "$OUT/page.html"
check "ia-enrich-copy" grep -q "情报富集" "$OUT/page.html"
check "ia-ask-copy" grep -q "证据问答" "$OUT/page.html"
check "ui-source-legend" grep -q 'class="source-legend"' "$OUT/page.html"
check "ui-source-filter" grep -q 'data-source-filter' "$OUT/page.html"
# Product UI must NOT show internal A/B/C / scoring / triad boards
python3 - <<PY
import sys
html=open("$OUT/page.html",encoding="utf-8").read()
banned_ui = [
  "vis-board", "mod-strip", "data-triad", "达标缺口", "整合健康 · A / B / C",
  "职责达标整合", "赛题达标", "评分规则", "A 平台架构",
]
hit=[b for b in banned_ui if b in html]
print("banned_hits", hit)
sys.exit(0 if not hit else 1)
PY
check "ui-no-abc-scoring-board" true
# Backend visibility API remains for 验收 docs (not rendered in product pages)
curl -sf --max-time 8 "$MAIN_URL/api/visibility" -o "$OUT/visibility.json"
python3 - <<PY
import json,sys
v=json.load(open("$OUT/visibility.json",encoding="utf-8"))
assert v.get("policy",{}).get("competition_passed") is None
mods={m["id"]:m for m in v.get("modules") or []}
assert set(mods)>= {"monitor","enrich","library","ask"}
print("visibility_api_ok modules", sorted(mods))
sys.exit(0)
PY
check "api-visibility-honest" true
python3 - <<PY
import sys
html=open("$OUT/page.html",encoding="utf-8").read()
sys.exit(0 if 'data-view="assets"' not in html else 1)
PY
check "ia-no-assets-nav" true
python3 - <<PY
import sys
html=open("$OUT/page.html",encoding="utf-8").read()
banned = ["START HERE", "任务工作台", "今日优先处置", "赛题九宫格", "一键流水线"]
sys.exit(0 if not any(b in html for b in banned) else 1)
PY
check "ia-no-competitor-clone" true
curl -sf --max-time 5 "$MAIN_URL/assets/app.js" -o "$OUT/app.js"
check "main-assets" test -s "$OUT/app.js"
check "ui-auto-monitor" grep -q "monitor/run" "$OUT/app.js"
check "ui-refresh-label" grep -q "立即刷新一轮" "$OUT/page.html"
check "ui-toast" grep -q 'id="toast"' "$OUT/page.html"
check "ui-toast-wiring" grep -q 'function showToast' "$OUT/app.js"
check "ui-enrich-toast" grep -q '正在批量富集' "$OUT/app.js"
check "ui-monitor-toast" grep -q '正在刷新一轮监测' "$OUT/app.js"

# Status endpoint: automatic continuous monitoring (no keyword required)
curl -sf --max-time 5 "$MAIN_URL/api/monitor/status" -o "$OUT/monitor-status.json"
python3 - <<PY
import json,sys
s=json.load(open("$OUT/monitor-status.json"))
print("status", {k:s.get(k) for k in ("mode","auto_on_start","interval_hours","last_run","last_count","running")})
print("team", s.get("team"))
sys.exit(0 if s.get("mode")=="automatic" else 1)
PY
check "monitor-status-automatic" true

# One-click refresh (broad AI scope, empty keyword) — must never be silent no-op
curl -sf --max-time 240 -X POST "$MAIN_URL/api/monitor/run" \
  -H 'Content-Type: application/json' \
  -d '{"keyword":"","sync_library":true,"max_documents":30}' \
  -o "$OUT/monitor-run.json"
python3 - "$OUT/monitor-run.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
steps=c.get("steps") or []
team_ok=any("团队情报" in (s.get("action") or "") and "得到" in (s.get("detail") or "") for s in steps)
team_fail=any("团队情报" in (s.get("action") or "") and "失败" in (s.get("action") or "") for s in steps)
print("mode", c.get("mode"), "keyword_head", (c.get("keyword") or "")[:48])
print("steps:")
for s in steps:
    print("-", s.get("action"), "|", (s.get("detail") or "")[:160])
sys.exit(0 if c.get("mode")=="auto" and team_ok and not team_fail else 1)
PY
python3 - <<PY
import json,sys
r=json.load(open("$OUT/monitor-run.json",encoding="utf-8"))
diag=r.get("source_diag") or {}
need=("nvd","osv","b_monitor","b_team","c_library_sync")
ok=all(k in diag for k in need) and isinstance(diag.get("written"), int)
bmon=(diag.get("b_monitor") or {}).get("status") or ""
# In-process B cycle may be 成功/部分/超时/跳过 — not "未请求" under default embed
print("source_diag", {k: (diag.get(k) or {}).get("status") for k in need}, "written", diag.get("written"))
sys.exit(0 if ok and bmon and bmon != "未请求" else 1)
PY
check "monitor-run-source-diag" true
check "auto-monitor-run-ok" true
# Single-process: no sidecar pid when embed
python3 - <<PY
import os, sys
pid = os.path.join(os.environ.get("DEMO_DIR", ".demo"), "b.pid")
mode = os.environ.get("TEAM_INTEL_MODE", "embed")
if mode == "embed" and os.path.isfile(pid):
    print("unexpected b.pid in embed mode", pid)
    sys.exit(1)
print("single_process_ok mode", mode, "b.pid", os.path.isfile(pid))
sys.exit(0)
PY
check "single-process-no-b-pid" true

curl -sf --max-time 5 "$MAIN_URL/api/monitor/feed?kind=all" -o "$OUT/monitor-feed.json"
python3 - <<PY
import json,sys
d=json.load(open("$OUT/monitor-feed.json"))
c=d.get("counts") or {}
kinds={i.get("kind") for i in (d.get("items") or [])}
print("counts", c, "kinds", sorted(kinds))
sys.exit(0 if c.get("document",0)>=1 and c.get("cve",0)>=1 and "document" in kinds else 1)
PY
check "monitor-feed-mixed" true

# Keyword must substring-filter the feed (not RAG-empty); llm should still show items after run
curl -sf --max-time 5 "$MAIN_URL/api/monitor/feed?kind=all&q=llm" -o "$OUT/monitor-feed-llm.json"
python3 - <<PY
import json,sys
d=json.load(open("$OUT/monitor-feed-llm.json"))
c=d.get("counts") or {}
print("llm_filter_counts", c)
sys.exit(0 if c.get("total",0)>=1 else 1)
PY
check "monitor-feed-keyword-not-empty" true

curl -sf --max-time 120 -X POST "$MAIN_URL/api/monitor/run" \
  -H 'Content-Type: application/json' \
  -d '{"keyword":"ollama","sync_library":false,"max_documents":5}' \
  -o "$OUT/monitor-run-ollama.json"
python3 - <<PY
import json,sys,urllib.request
run=json.load(open("$OUT/monitor-run-ollama.json"))
with urllib.request.urlopen("$MAIN_URL/api/monitor/feed?kind=all&q=ollama", timeout=10) as r:
    feed=json.load(r)
total=(feed.get("counts") or {}).get("total",0)
print("scoped_run_count", run.get("count"), "feed_ollama_total", total)
sys.exit(0 if run.get("mode")=="auto" and total>=1 else 1)
PY
check "monitor-run-with-keyword-shows-feed" true

# UI must wire keyword into monitor/run body (not always empty) and surface empty reasons
check "ui-keyword-passed-to-run" grep -q 'keyword: keyword' "$OUT/app.js"
check "ui-clear-empty-reason" grep -q '没有匹配' "$OUT/app.js"

# After collect, overview sources should include more than OSV-only narrative when team labels land
curl -sf --max-time 5 "$MAIN_URL/api/overview" -o "$OUT/overview-after-collect.json"
python3 - <<PY
import json,sys
o=json.load(open("$OUT/overview-after-collect.json"))
sources=set(o.get("sources") or [])
# Accept OSV/NVD plus any team upstream labels (GITHUB_ADVISORY / CISA_KEV / NVD)
print("sources_after", sorted(sources), "items", o.get("items"))
sys.exit(0 if o.get("items",0)>=1 and sources else 1)
PY
check "overview-has-vuln-sources" true

curl -sf --max-time 5 "$MAIN_URL/api/library" -o "$OUT/library.json"
python3 - <<PY
import json,sys
lib=json.load(open("$OUT/library.json"))
docs=(lib.get("overview") or {}).get("documents") or 0
print("library documents", docs, "categories", (lib.get("overview") or {}).get("source_categories"))
sys.exit(0 if docs>=1 else 1)
PY
check "library-has-documents" true

curl -sf --max-time 180 -X POST "$MAIN_URL/api/enrich" -o "$OUT/enrich.json"
check "enrich-http" test -s "$OUT/enrich.json"

curl -sf --max-time 60 -X POST "$MAIN_URL/api/ask" \
  -H 'Content-Type: application/json' \
  -d "{\"question\":\"${ASK_CVE} 的严重性如何？受影响产品？\",\"cve_id\":\"${ASK_CVE}\",\"session_id\":\"\"}" \
  -o "$OUT/ask.json"
python3 - <<PY
import json,sys
a=json.load(open("$OUT/ask.json"))
ok=bool(a.get("answer")) and (a.get("verdict") or {}).get("passed") is True
print("verdict", (a.get("verdict") or {}).get("passed"), "answer_head:", (a.get("answer") or "")[:160].replace("\n"," "))
sys.exit(0 if ok else 1)
PY
check "ask-demo-cve" true

# Secondary demo CVEs from multi-source seed (best-effort presence in B)
python3 - <<PY
import json,urllib.request,sys
base="$MAIN_URL"
need=["CVE-2099-90002","CVE-2099-90003"]
ok=0
for cve in need:
    try:
        with urllib.request.urlopen(base+"/api/intelligence/team?q="+cve+"&ai_only=true&limit=5", timeout=5) as r:
            t=json.load(r)
        if t.get("total",0)>=1:
            ok+=1
            print("found", cve)
    except Exception as e:
        print("miss", cve, e)
sys.exit(0 if ok>=1 else 1)
PY
check "b-secondary-demo-cves" true

if [[ "$fail" -ne 0 ]]; then
  log "SMOKE FAILED — artifacts in $OUT"
  exit 1
fi
log "SMOKE PASSED — artifacts in $OUT"
exit 0
