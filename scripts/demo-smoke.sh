#!/usr/bin/env bash
# Full demo chain against the composed env (fixed ports).
# Exit 0 only if health + collect(team) + enrich + ask succeed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

OUT="${DEMO_SMOKE_OUT:-$DEMO_DIR/smoke-last}"
mkdir -p "$OUT"
KEYWORD="${DEMO_KEYWORD:-ollama}"
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

log "smoke against B=$B_URL main=$MAIN_URL"

curl -sf --max-time 5 "$B_URL/api/intelligence/health" -o "$OUT/b-health.json"
check "b-health" test -s "$OUT/b-health.json"
python3 - <<PY
import json,sys
h=json.load(open("$OUT/b-health.json"))
sys.exit(0 if h.get("database_available") is True else 1)
PY
check "b-database_available" true

curl -sf --max-time 5 "$B_URL/api/intelligence/team?q=${KEYWORD}&ai_only=true&limit=5" -o "$OUT/b-team.json"
python3 - <<PY
import json,sys
t=json.load(open("$OUT/b-team.json"))
items=t.get("items") or []
sys.exit(0 if t.get("total",0)>=1 and items and items[0].get("cve_id") else 1)
PY
check "b-team-has-items" true

curl -sf --max-time 5 "$MAIN_URL/api/overview" -o "$OUT/overview.json"
check "main-overview" test -s "$OUT/overview.json"

curl -sf --max-time 5 "$MAIN_URL/" -o "$OUT/page.html"
check "main-page" grep -q "AI 安全知识情报" "$OUT/page.html"
curl -sf --max-time 5 "$MAIN_URL/assets/app.js" -o "$OUT/app.js"
check "main-assets" test -s "$OUT/app.js"

# collect — allow longer timeout (NVD/OSV may be slow; team must succeed)
curl -sf --max-time 180 -X POST "$MAIN_URL/api/collect" \
  -H 'Content-Type: application/json' \
  -d "{\"keyword\":\"${KEYWORD}\"}" \
  -o "$OUT/collect.json"
python3 - "$OUT/collect.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
steps=c.get("steps") or []
team_ok=any("团队情报" in (s.get("action") or "") and "得到" in (s.get("detail") or "") for s in steps)
team_fail=any("团队情报" in (s.get("action") or "") and "失败" in (s.get("action") or "") for s in steps)
print("steps:")
for s in steps:
    print("-", s.get("action"), "|", (s.get("detail") or "")[:120])
sys.exit(0 if team_ok and not team_fail else 1)
PY
check "collect-team-ok" true

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

if [[ "$fail" -ne 0 ]]; then
  log "SMOKE FAILED — artifacts in $OUT"
  exit 1
fi
log "SMOKE PASSED — artifacts in $OUT"
exit 0
