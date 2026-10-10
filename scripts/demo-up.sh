#!/usr/bin/env bash
# One-click unified demo: B :8765 + main :8023
# Prefer Docker Compose; fall back to local fixed-port processes if daemon unavailable.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

MODE="${DEMO_MODE:-auto}"
AUTO_INGEST_ON_COLLECT="${AUTO_INGEST_ON_COLLECT:-0}"
export AUTO_INGEST_ON_COLLECT
export TEAM_INTEL_BASE_URL="${TEAM_INTEL_BASE_URL:-http://127.0.0.1:${B_PORT}}"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

start_compose() {
  log "starting via docker compose (project=$COMPOSE_PROJECT)"
  docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/docker-compose.yml" up -d --build
  wait_http "$B_URL/api/intelligence/health" "B API" 90
  wait_http "$MAIN_URL/api/overview" "main app" 90
  # Verify B has a database
  local health
  health="$(curl -sf "$B_URL/api/intelligence/health")"
  echo "$health" | grep -q '"database_available": *true' \
    || die "B health reports database_available != true: $health"
  printf '%s\n' compose >"$DEMO_DIR/mode"
  log "URLs:"
  log "  Main UI / API: $MAIN_URL"
  log "  B health:      $B_URL/api/intelligence/health"
  log "  B team:        $B_URL/api/intelligence/team?q=${DEMO_KEYWORD}"
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

start_local() {
  log "Docker unavailable — starting local fixed-port processes"
  seed_local_db
  # Stop leftovers on our ports
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
    log "starting main on $MAIN_URL (AUTO_INGEST_ON_COLLECT=$AUTO_INGEST_ON_COLLECT)"
    (
      cd "$ROOT"
      export APP_HOST=127.0.0.1 APP_PORT="$MAIN_PORT"
      export TEAM_INTEL_BASE_URL="http://127.0.0.1:${B_PORT}"
      export AUTO_INGEST_ON_COLLECT
      # Prepare historical sample once (best-effort)
      "$ROOT/.venv/bin/python" -m rag.prepare >/dev/null 2>&1 || true
      nohup "$ROOT/.venv/bin/python" main.py \
        >"$DEMO_DIR/main-api.log" 2>&1 &
      echo $! >"$DEMO_DIR/main.pid"
    )
  fi
  wait_http "$B_URL/api/intelligence/health" "B API" 60
  wait_http "$MAIN_URL/api/overview" "main app" 60
  local health
  health="$(curl -sf "$B_URL/api/intelligence/health")"
  echo "$health" | grep -q '"database_available": *true' \
    || die "B health reports database_available != true: $health"
  printf '%s\n' local >"$DEMO_DIR/mode"
  log "URLs:"
  log "  Main UI / API: $MAIN_URL"
  log "  B health:      $B_URL/api/intelligence/health"
  log "  B team:        $B_URL/api/intelligence/team?q=${DEMO_KEYWORD}"
  log "Next: multi-source collect + library team-sync"
  "$SCRIPT_DIR/demo-collect.sh" || log "demo-collect reported issues (partial OK)"
  log "Triggering one automatic monitor cycle (no keyword required)…"
  curl -sf --max-time 240 -X POST "$MAIN_URL/api/monitor/run" \
    -H 'Content-Type: application/json' \
    -d '{"keyword":"","sync_library":true,"max_documents":30}' \
    -o "$DEMO_DIR/auto-monitor-boot.json" \
    && log "auto monitor OK → open $MAIN_URL （情报监测应已有流）" \
    || log "auto monitor soft-fail (UI still up; check $DEMO_DIR/auto-monitor-boot.json / logs)"
  log "Logs: $DEMO_DIR/b-api.log  $DEMO_DIR/main-api.log"
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
