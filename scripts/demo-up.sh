#!/usr/bin/env bash
# One-click unified demo: ONE process, public entry ONLY http://127.0.0.1:8023
# Default TEAM_INTEL_MODE=embed — B query API runs in-process (no :8765 required).
# Legacy: TEAM_INTEL_MODE=sidecar DEMO_B_SIDECAR=1 starts a separate B on :8765.
# Prefer Docker Compose; fall back to local single-process if daemon unavailable.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

MODE="${DEMO_MODE:-auto}"
AUTO_INGEST_ON_COLLECT="${AUTO_INGEST_ON_COLLECT:-0}"
export AUTO_INGEST_ON_COLLECT
export TEAM_INTEL_MODE="${TEAM_INTEL_MODE:-embed}"
export B_MONITOR_ENABLED="${B_MONITOR_ENABLED:-1}"
export B_MONITOR_ON_REFRESH="${B_MONITOR_ON_REFRESH:-1}"
export B_MONITOR_SOURCE_TIMEOUT="${B_MONITOR_SOURCE_TIMEOUT:-45}"
export B_MONITOR_OVERALL_TIMEOUT="${B_MONITOR_OVERALL_TIMEOUT:-180}"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

# Sidecar legacy only when explicitly requested.
if [[ "$TEAM_INTEL_MODE" == "sidecar" || "${DEMO_B_SIDECAR:-0}" == "1" ]]; then
  export TEAM_INTEL_MODE=sidecar
  export TEAM_INTEL_UPSTREAM="${TEAM_INTEL_UPSTREAM:-http://127.0.0.1:${B_PORT}}"
  export TEAM_INTEL_BASE_URL="${TEAM_INTEL_BASE_URL:-$TEAM_INTEL_UPSTREAM}"
  export TEAM_INTEL_PROXY="${TEAM_INTEL_PROXY:-1}"
fi

start_compose() {
  log "starting via docker compose (project=$COMPOSE_PROJECT, mode=$TEAM_INTEL_MODE)"
  docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/docker-compose.yml" up -d --build
  wait_http "$MAIN_URL/api/overview" "main app" 90
  wait_http "$MAIN_URL/api/intelligence/health" "B via 8023 (in-process)" 30
  local health
  health="$(curl -sf "$MAIN_URL/api/intelligence/health")"
  echo "$health" | grep -q '"database_available": *true' \
    || die "B health (via 8023) reports database_available != true: $health"
  printf '%s\n' compose >"$DEMO_DIR/mode"
  log "URLs (single process / single entry):"
  log "  Open only:     $MAIN_URL"
  log "  B health:      $MAIN_URL/api/intelligence/health"
  log "  B team:        $MAIN_URL/api/intelligence/team?q=${DEMO_KEYWORD}"
  log "  mode:          $TEAM_INTEL_MODE (8765 not required)"
  log "Next: multi-source collect + library team-sync"
  "$SCRIPT_DIR/demo-collect.sh" || log "demo-collect reported issues (partial OK)"
  log "Triggering one automatic monitor cycle (no keyword required)…"
  curl -sf --max-time 240 -X POST "$MAIN_URL/api/monitor/run" \
    -H 'Content-Type: application/json' \
    -d '{"keyword":"","sync_library":true,"max_documents":30}' \
    -o "$DEMO_DIR/auto-monitor-boot.json" \
    && log "auto monitor OK → open $MAIN_URL （情报监测应已有流）" \
    || log "auto monitor soft-fail (UI still up; check $DEMO_DIR/auto-monitor-boot.json / logs)"
  log "Keep running: docker compose -p $COMPOSE_PROJECT logs -f"
  log "Stop:           ./scripts/demo-down.sh"
}

start_local_sidecar() {
  log "legacy sidecar mode — starting B on :$B_PORT + main on :$MAIN_PORT"
  seed_local_db
  if [[ -f "$DEMO_DIR/b.pid" ]] && kill -0 "$(cat "$DEMO_DIR/b.pid")" 2>/dev/null; then
    log "B already running pid=$(cat "$DEMO_DIR/b.pid")"
  else
    log "starting B on $B_URL"
    (
      cd "$ROOT"
      export INTELLIGENCE_DB_PATH="$ROOT/intelligence/data/intelligence.db"
      nohup "$ROOT/intelligence/.venv/bin/python" \
        "$ROOT/intelligence/run_intelligence_api_v6.py" \
        --host 127.0.0.1 --port "$B_PORT" \
        >"$DEMO_DIR/b-api.log" 2>&1 &
      echo $! >"$DEMO_DIR/b.pid"
    )
  fi
  if [[ -f "$DEMO_DIR/main.pid" ]] && kill -0 "$(cat "$DEMO_DIR/main.pid")" 2>/dev/null; then
    log "main already running pid=$(cat "$DEMO_DIR/main.pid")"
  else
    log "starting main on $MAIN_URL (proxy B ← $TEAM_INTEL_UPSTREAM)"
    (
      cd "$ROOT"
      export APP_HOST=127.0.0.1 APP_PORT="$MAIN_PORT"
      export TEAM_INTEL_MODE=sidecar
      export TEAM_INTEL_UPSTREAM="http://127.0.0.1:${B_PORT}"
      export TEAM_INTEL_BASE_URL="$TEAM_INTEL_UPSTREAM"
      export TEAM_INTEL_PROXY=1
      export AUTO_INGEST_ON_COLLECT
      "$ROOT/.venv/bin/python" -m rag.prepare >/dev/null 2>&1 || true
      nohup "$ROOT/.venv/bin/python" main.py \
        >"$DEMO_DIR/main-api.log" 2>&1 &
      echo $! >"$DEMO_DIR/main.pid"
    )
  fi
  wait_http "$B_URL/api/intelligence/health" "B upstream" 60
  wait_http "$MAIN_URL/api/overview" "main app" 60
  wait_http "$MAIN_URL/api/intelligence/health" "B via 8023 proxy" 30
}

start_local_embed() {
  log "Docker unavailable — starting SINGLE local process (embed B, no :8765)"
  seed_local_db
  # Stop leftover sidecar if any
  if [[ -f "$DEMO_DIR/b.pid" ]] && kill -0 "$(cat "$DEMO_DIR/b.pid")" 2>/dev/null; then
    log "stopping leftover B sidecar pid=$(cat "$DEMO_DIR/b.pid")"
    kill "$(cat "$DEMO_DIR/b.pid")" 2>/dev/null || true
    rm -f "$DEMO_DIR/b.pid"
  fi
  if [[ -f "$DEMO_DIR/main.pid" ]] && kill -0 "$(cat "$DEMO_DIR/main.pid")" 2>/dev/null; then
    log "main already running pid=$(cat "$DEMO_DIR/main.pid")"
  else
    log "starting main on $MAIN_URL (TEAM_INTEL_MODE=embed)"
    (
      cd "$ROOT"
      export APP_HOST=127.0.0.1 APP_PORT="$MAIN_PORT"
      export TEAM_INTEL_MODE=embed
      export INTELLIGENCE_DB_PATH="$ROOT/intelligence/data/intelligence.db"
      export B_MONITOR_ENABLED B_MONITOR_ON_REFRESH
      export B_MONITOR_SOURCE_TIMEOUT B_MONITOR_OVERALL_TIMEOUT
      export AUTO_INGEST_ON_COLLECT
      "$ROOT/.venv/bin/python" -m rag.prepare >/dev/null 2>&1 || true
      nohup "$ROOT/.venv/bin/python" main.py \
        >"$DEMO_DIR/main-api.log" 2>&1 &
      echo $! >"$DEMO_DIR/main.pid"
    )
  fi
  wait_http "$MAIN_URL/api/overview" "main app" 60
  wait_http "$MAIN_URL/api/intelligence/health" "B in-process via 8023" 30
}

start_local() {
  if [[ "${TEAM_INTEL_MODE:-embed}" == "sidecar" || "${DEMO_B_SIDECAR:-0}" == "1" ]]; then
    start_local_sidecar
  else
    start_local_embed
  fi
  local health
  health="$(curl -sf "$MAIN_URL/api/intelligence/health")"
  echo "$health" | grep -q '"database_available": *true' \
    || die "B health (via 8023) reports database_available != true: $health"
  printf '%s\n' local >"$DEMO_DIR/mode"
  log "URLs (single entry):"
  log "  Open only:     $MAIN_URL"
  log "  B health:      $MAIN_URL/api/intelligence/health"
  log "  B team:        $MAIN_URL/api/intelligence/team?q=${DEMO_KEYWORD}"
  log "  mode:          ${TEAM_INTEL_MODE:-embed}"
  if [[ "${TEAM_INTEL_MODE:-embed}" == "sidecar" ]]; then
    log "  (legacy B upstream localhost:$B_PORT — do not open in browser)"
  else
    log "  (no separate B process; :8765 not used)"
  fi
  log "Next: multi-source collect + library team-sync"
  "$SCRIPT_DIR/demo-collect.sh" || log "demo-collect reported issues (partial OK)"
  log "Triggering one automatic monitor cycle (no keyword required)…"
  curl -sf --max-time 240 -X POST "$MAIN_URL/api/monitor/run" \
    -H 'Content-Type: application/json' \
    -d '{"keyword":"","sync_library":true,"max_documents":30}' \
    -o "$DEMO_DIR/auto-monitor-boot.json" \
    && log "auto monitor OK → open $MAIN_URL （情报监测应已有流）" \
    || log "auto monitor soft-fail (UI still up; check $DEMO_DIR/auto-monitor-boot.json / logs)"
  log "Logs: $DEMO_DIR/main-api.log${TEAM_INTEL_MODE:+  $DEMO_DIR/b-api.log}"
  log "Stop: ./scripts/demo-down.sh"
}

case "$MODE" in
  compose)
    have_docker || die "DEMO_MODE=compose but Docker is not usable"
    start_compose
    ;;
  local)
    start_local
    ;;
  auto|*)
    if have_docker; then
      start_compose
    else
      start_local
    fi
    ;;
esac
