#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

mode="$(cat "$DEMO_DIR/mode" 2>/dev/null || true)"
if [[ "$mode" == "offline-compose" ]]; then
  docker compose -p "$COMPOSE_PROJECT-offline" -f "$ROOT/docker-compose.offline.yml" down
  rm -f "$DEMO_DIR/mode"
  exit 0
fi
if [[ "$mode" == "compose" ]] || have_docker; then
  if have_docker; then
    log "stopping compose project $COMPOSE_PROJECT"
    docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/docker-compose.yml" down || true
  fi
fi
for name in b.pid main.pid; do
  if [[ -f "$DEMO_DIR/$name" ]]; then
    pid="$(cat "$DEMO_DIR/$name" || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      log "stopping pid $pid ($name)"
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$DEMO_DIR/$name"
  fi
done
# Only stop processes recorded by this demo; a shared port may belong to production.
rm -f "$DEMO_DIR/mode"
log "demo stopped"
