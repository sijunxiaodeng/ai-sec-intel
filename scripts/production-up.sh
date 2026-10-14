#!/usr/bin/env bash
# 正式数据进阶入口。日常演示请用 docker-compose.offline.yml 或 scripts/demo-up.sh。
# 对外产品面仍是 :8023；勿与演示 compose 同时启动。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-actions}"
case "$mode" in
  collector) compose_file="$ROOT/docker-compose.production.yml" ;;
  actions) compose_file="$ROOT/docker-compose.actions.yml" ;;
  *) printf 'Usage: %s [actions|collector]\n' "$0" >&2; exit 2 ;;
esac
# Both deployments use the same host ports; never start both at once.
other_project=ai-sec-intel-production
if [[ "$mode" == collector ]]; then other_project=ai-sec-intel-actions; fi
if [[ -n "$(docker ps -q --filter "label=com.docker.compose.project=$other_project")" ]]; then
  printf 'Stop the other production mode (%s) first; its data volume is preserved.\n' "$other_project" >&2
  exit 1
fi
# Refuse if the demo stack still owns :8023
if [[ -n "$(docker ps -q --filter "label=com.docker.compose.project=ai-sec-intel-demo" 2>/dev/null || true)" ]] \
  || [[ -n "$(docker ps -q --filter "label=com.docker.compose.project=ai-sec-intel-demo-offline" 2>/dev/null || true)" ]] \
  || [[ -n "$(docker ps -q --filter "label=com.docker.compose.project=ai-sec-intel-offline-demo" 2>/dev/null || true)" ]]; then
  printf 'Demo compose still running. Stop offline/demo compose first, then retry.\n' >&2
  printf '  docker compose -f docker-compose.offline.yml down\n' >&2
  printf '  # or ./scripts/demo-down.sh\n' >&2
  exit 1
fi
compose=(docker compose)
if [[ -f "$ROOT/.env.production" ]]; then
  compose+=(--env-file "$ROOT/.env.production")
fi
compose+=(-f "$compose_file")
"${compose[@]}" config --quiet
"${compose[@]}" up -d --build
printf 'Started %s mode. Logs: docker compose -f %s logs -f\n' "$mode" "$compose_file"
printf '产品入口: http://127.0.0.1:8023\n'
printf '内部健康（非产品入口）: http://127.0.0.1:8765/api/intelligence/health\n'
