#!/usr/bin/env bash
# Choose exactly one real data writer. Demo remains scripts/demo-up.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-actions}"
case "$mode" in
  collector) compose_file="$ROOT/docker-compose.production.yml" ;;
  actions) compose_file="$ROOT/docker-compose.actions.yml" ;;
  *) printf 'Usage: %s [actions|collector]\n' "$0" >&2; exit 2 ;;
esac
# Both deployments use the same API ports; never start both at once.
other_project=ai-sec-intel-production
if [[ "$mode" == collector ]]; then other_project=ai-sec-intel-actions; fi
if [[ -n "$(docker ps -q --filter "label=com.docker.compose.project=$other_project")" ]]; then
  printf 'Stop the other production mode (%s) first; its data volume is preserved.\n' "$other_project" >&2
  exit 1
fi
docker compose -f "$compose_file" config --quiet
docker compose -f "$compose_file" up -d --build
printf 'Started %s mode. Logs: docker compose -f %s logs -f\n' "$mode" "$compose_file"
printf 'API/data readiness: http://127.0.0.1:8765/api/intelligence/health\n'
printf 'Main application: http://127.0.0.1:8023\n'
