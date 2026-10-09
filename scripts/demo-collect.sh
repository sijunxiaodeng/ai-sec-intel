#!/usr/bin/env bash
# After B+main are up: try B multi-source monitor (network), keep seed fixtures,
# then sync C library from B /api/documents. Partial success is OK — never block forever.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

OUT="${DEMO_COLLECT_OUT:-$DEMO_DIR/collect-last}"
mkdir -p "$OUT"
: >"$OUT/summary.json"

B_MONITOR="${DEMO_B_MONITOR:-1}"
MONITOR_TIMEOUT="${DEMO_MONITOR_TIMEOUT:-180}"
SOURCE_TIMEOUT="${DEMO_SOURCE_TIMEOUT:-45}"
TEAM_SYNC_MAX="${DEMO_TEAM_SYNC_MAX:-30}"
LIBRARY_SYNC="${DEMO_LIBRARY_SYNC:-1}"

mode="$(cat "$DEMO_DIR/mode" 2>/dev/null || echo local)"
monitor_status="skipped"
monitor_detail=""
team_sync_status="skipped"
library_sync_status="skipped"
coverage_note=""

# Seed only when DB missing. Avoid DEMO_FORCE_SEED wipe after B API already started
# (demo-up seeds once before launching processes).
if [[ "$mode" == "local" ]]; then
  if [[ ! -f "$ROOT/intelligence/data/intelligence.db" ]]; then
    seed_local_db
  else
    log "B demo DB present — skip re-seed in demo-collect (set DEMO_FORCE_SEED before demo-up to recreate)"
  fi
elif [[ "${DEMO_FORCE_SEED:-0}" == "1" ]]; then
  log "compose mode: DEMO_FORCE_SEED=1 — recreate via docker b-seed if needed"
fi

if [[ "$B_MONITOR" == "1" ]]; then
  log "attempting B multi-source run_monitor --once (timeout=${MONITOR_TIMEOUT}s, source-timeout=${SOURCE_TIMEOUT}s)"
  set +e
  if [[ "$mode" == "compose" ]] && have_docker; then
    timeout --signal=TERM --kill-after=15s "$MONITOR_TIMEOUT" \
      docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/docker-compose.yml" run --rm --no-deps \
      -e INTELLIGENCE_DB_PATH=/app/data/intelligence.db \
      b-api python run_monitor.py --once \
      --source-timeout "$SOURCE_TIMEOUT" --workers 4 \
      >"$OUT/b-monitor.log" 2>&1
    rc=$?
  else
    ensure_venvs
    timeout --signal=TERM --kill-after=15s "$MONITOR_TIMEOUT" \
      env INTELLIGENCE_DB_PATH="$ROOT/intelligence/data/intelligence.db" \
      "$ROOT/intelligence/.venv/bin/python" "$ROOT/intelligence/run_monitor.py" --once \
      --db "$ROOT/intelligence/data/intelligence.db" \
      --source-timeout "$SOURCE_TIMEOUT" --workers 4 \
      >"$OUT/b-monitor.log" 2>&1
    rc=$?
  fi
  set -e
  if [[ "$rc" -eq 0 ]]; then
    monitor_status="ok"
    monitor_detail="run_monitor completed (see b-monitor.log)"
  elif [[ "$rc" -eq 124 ]]; then
    monitor_status="timeout"
    monitor_detail="run_monitor exceeded ${MONITOR_TIMEOUT}s — keeping seed/partial DB"
  else
    monitor_status="failed"
    monitor_detail="run_monitor exit=$rc — keeping seed fixtures (offline/rate-limit OK)"
  fi
  log "B monitor: $monitor_status — $monitor_detail"
else
  log "DEMO_B_MONITOR=0 — skip live multi-source; seed fixtures remain"
  monitor_status="disabled"
fi

# B coverage snapshot (best-effort)
if curl -sf --max-time 5 "$B_URL/api/intelligence/coverage" -o "$OUT/b-coverage.json" 2>/dev/null; then
  coverage_note="coverage written"
else
  coverage_note="coverage unavailable"
  echo '{}' >"$OUT/b-coverage.json"
fi
curl -sf --max-time 5 "$B_URL/api/documents/stats" -o "$OUT/b-documents-stats.json" 2>/dev/null \
  || echo '{}' >"$OUT/b-documents-stats.json"
curl -sf --max-time 5 "$B_URL/api/intelligence/health" -o "$OUT/b-health.json" 2>/dev/null \
  || echo '{}' >"$OUT/b-health.json"

# C: sync team documents from B into library (requires main API)
if [[ "$LIBRARY_SYNC" == "1" ]]; then
  log "POST /api/library/team-sync (max_documents=$TEAM_SYNC_MAX)"
  set +e
  curl -sf --max-time 120 -X POST "$MAIN_URL/api/library/team-sync" \
    -H 'Content-Type: application/json' \
    -d "{\"max_documents\":${TEAM_SYNC_MAX}}" \
    -o "$OUT/team-sync.json"
  ts_rc=$?
  set -e
  if [[ "$ts_rc" -eq 0 ]] && [[ -s "$OUT/team-sync.json" ]]; then
    team_sync_status="$(python3 -c "import json; print(json.load(open('$OUT/team-sync.json')).get('status','unknown'))" 2>/dev/null || echo unknown)"
  else
    team_sync_status="failed"
    echo '{"status":"failed"}' >"$OUT/team-sync.json"
  fi
  log "team-sync: $team_sync_status"

  # Optional light public library sync (seeds) — short timeout, ignore failure
  log "POST /api/library/sync (per_source=1, include_seeds=true) best-effort"
  set +e
  curl -sf --max-time 90 -X POST "$MAIN_URL/api/library/sync" \
    -H 'Content-Type: application/json' \
    -d '{"per_source":1,"include_seeds":true}' \
    -o "$OUT/library-sync.json"
  ls_rc=$?
  set -e
  if [[ "$ls_rc" -eq 0 ]] && [[ -s "$OUT/library-sync.json" ]]; then
    library_sync_status="ok"
  else
    library_sync_status="skipped_or_failed"
    echo '{}' >"$OUT/library-sync.json"
  fi
  log "library-sync: $library_sync_status"

  # Curated relation topics need arXiv HTML full text (abstract-only breaks injection graph).
  log "best-effort full-text for curated arXiv paper 2302.12173"
  set +e
  paper_id="$(python3 - <<'PY'
import json,urllib.request
base="'"$MAIN_URL"'"
try:
    with urllib.request.urlopen(base+"/api/library", timeout=10) as r:
        items=json.load(r).get("items") or []
except Exception:
    raise SystemExit(0)
for row in items:
    if (row.get("url") or "").rstrip("/") == "https://arxiv.org/abs/2302.12173":
        print(row["document_id"]); break
PY
)"
  if [[ -n "${paper_id:-}" ]]; then
    curl -sf --max-time 90 -X POST "$MAIN_URL/api/library/${paper_id}/full-text" \
      -o "$OUT/paper-full-text.json" && log "paper full-text: ok ($paper_id)" \
      || log "paper full-text: failed (relations may stay partial)"
  else
    log "paper full-text: abs document not found yet — skip"
  fi
  set -e
fi

AI_KEYWORDS_CSV="$AI_SECURITY_KEYWORDS" \
MONITOR_STATUS="$monitor_status" MONITOR_DETAIL="$monitor_detail" \
TEAM_SYNC_STATUS="$team_sync_status" LIBRARY_SYNC_STATUS="$library_sync_status" \
COVERAGE_NOTE="$coverage_note" MODE="$mode" OUT_DIR="$OUT" \
MAIN_URL="$MAIN_URL" B_URL="$B_URL" \
python3 - <<'PY'
import json, os
from pathlib import Path
out = Path(os.environ["OUT_DIR"])
summary = {
    "label": "demo_collect_partial_ok",
    "mode": os.environ["MODE"],
    "b_monitor": {"status": os.environ["MONITOR_STATUS"], "detail": os.environ["MONITOR_DETAIL"]},
    "team_sync": {"status": os.environ["TEAM_SYNC_STATUS"]},
    "library_sync": {"status": os.environ["LIBRARY_SYNC_STATUS"]},
    "coverage_note": os.environ["COVERAGE_NOTE"],
    "ai_keywords": [k.strip() for k in os.environ.get("AI_KEYWORDS_CSV", "").split(",") if k.strip()],
    "urls": {"main": os.environ["MAIN_URL"], "b": os.environ["B_URL"]},
    "note": "Live multi-source is best-effort; seed fixtures labeled demo/synthetic. Not SLA evidence.",
}
out.joinpath("summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

log "demo-collect done — artifacts in $OUT (partial success is OK)"
exit 0
