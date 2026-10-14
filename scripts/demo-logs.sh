#!/usr/bin/env bash
# Tail logs for the active demo started by demo-up / compose.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

mode="$(cat "$DEMO_DIR/mode" 2>/dev/null || true)"
case "$mode" in
  offline-compose)
    docker compose -p "$COMPOSE_PROJECT-offline" -f "$ROOT/docker-compose.offline.yml" logs -f
    ;;
  compose)
    docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/docker-compose.yml" logs -f
    ;;
  offline-local|local|"")
    if [[ -f "$DEMO_DIR/offline-demo.log" ]]; then
      tail -n 200 -f "$DEMO_DIR/offline-demo.log"
    elif [[ -f "$DEMO_DIR/main-api.log" ]]; then
      if [[ -f "$DEMO_DIR/b-api.log" ]]; then
        tail -n 100 -f "$DEMO_DIR/main-api.log" "$DEMO_DIR/b-api.log"
      else
        tail -n 200 -f "$DEMO_DIR/main-api.log"
      fi
    else
      die "无日志文件；请先启动演示（docker compose -f docker-compose.offline.yml up -d 或 ./scripts/demo-up.sh）。当前 mode=${mode:-unknown}"
    fi
    ;;
  *)
    die "未知 mode=$mode；请先启动演示"
    ;;
esac
