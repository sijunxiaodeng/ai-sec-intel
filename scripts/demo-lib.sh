#!/usr/bin/env bash
# Shared helpers for demo-up / demo-smoke / demo-down.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEMO_DIR="${DEMO_DIR:-$ROOT/.demo}"
B_PORT="${B_PORT:-8765}"
MAIN_PORT="${MAIN_PORT:-8023}"
B_URL="http://127.0.0.1:${B_PORT}"
MAIN_URL="http://127.0.0.1:${MAIN_PORT}"
# Default: B embedded in the main :8023 process (no separate :8765).
export TEAM_INTEL_MODE="${TEAM_INTEL_MODE:-embed}"
export B_MONITOR_ENABLED="${B_MONITOR_ENABLED:-1}"
export B_MONITOR_ON_REFRESH="${B_MONITOR_ON_REFRESH:-1}"
# Legacy sidecar vars (only used when TEAM_INTEL_MODE=sidecar).
export TEAM_INTEL_UPSTREAM="${TEAM_INTEL_UPSTREAM:-http://127.0.0.1:${B_PORT}}"
export TEAM_INTEL_PROXY="${TEAM_INTEL_PROXY:-0}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-ai-sec-intel-demo}"

# Broader AI-security keyword set for demos (comma-separated for multi-pass collect).
# Primary default for a single NVD/OSV call is "llm" (not only "ollama").
AI_SECURITY_KEYWORDS="${AI_SECURITY_KEYWORDS:-llm,vllm,langchain,huggingface,openai,ollama,adversarial,jailbreak,prompt injection}"
DEMO_KEYWORD="${DEMO_KEYWORD:-llm}"

mkdir -p "$DEMO_DIR"

log() { printf '[demo] %s\n' "$*"; }
die() { printf '[demo] ERROR: %s\n' "$*" >&2; exit 1; }

have_docker() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  docker compose version >/dev/null 2>&1 || return 1
  return 0
}

wait_http() {
  local url="$1" label="$2" tries="${3:-60}"
  local i
  for i in $(seq 1 "$tries"); do
    if curl -sf --max-time 3 "$url" >/dev/null 2>&1; then
      log "$label ready ($url)"
      return 0
    fi
    sleep 1
  done
  die "$label not ready after ${tries}s: $url"
}

ensure_venvs() {
  # One-venv story for demo: root .venv runs A + embedded B (query + monitor + seed).
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    log "creating root .venv (unified demo runtime)"
    python3 -m venv "$ROOT/.venv"
    "$ROOT/.venv/bin/python" -m pip install -U pip -q
    "$ROOT/.venv/bin/python" -m pip install -q -r "$ROOT/requirements.txt"
  fi
  # Legacy sidecar / B lockfile isolation only when explicitly requested.
  if [[ "${TEAM_INTEL_MODE:-embed}" == "sidecar" || "${DEMO_B_SIDECAR:-0}" == "1" ]]; then
    if [[ ! -x "$ROOT/intelligence/.venv/bin/python" ]]; then
      log "creating intelligence/.venv (legacy sidecar only)"
      python3 -m venv "$ROOT/intelligence/.venv"
      "$ROOT/intelligence/.venv/bin/python" -m pip install -U pip -q
      "$ROOT/intelligence/.venv/bin/python" -m pip install -q -r "$ROOT/intelligence/requirements.lock.txt"
    fi
  fi
}

pull_actions_state_if_configured() {
  # Real Actions → local DB sync (artifact download). Opt-in.
  # ACTIONS_SYNC_PULL=1 or ACTIONS_SYNC_ON_START=1 + GITHUB_TOKEN/GH_TOKEN/ACTIONS_SYNC_TOKEN
  local want="${ACTIONS_SYNC_PULL:-${ACTIONS_SYNC_ON_START:-0}}"
  case "$want" in
    1|true|yes|on) ;;
    *) return 1 ;;
  esac
  local token="${ACTIONS_SYNC_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
  if [[ -z "$token" ]]; then
    log "ACTIONS_SYNC_PULL set but no GITHUB_TOKEN/GH_TOKEN/ACTIONS_SYNC_TOKEN — skip pull"
    return 1
  fi
  ensure_venvs
  mkdir -p "$ROOT/intelligence/data"
  log "pulling latest GitHub Actions intelligence snapshot into intelligence/data …"
  if (
    cd "$ROOT"
    PYTHONPATH="$ROOT/intelligence" \
      "$ROOT/.venv/bin/python" "$ROOT/intelligence/deployment/actions_sync.py" pull \
        --directory "$ROOT/intelligence/data" \
        --repository "${ACTIONS_SYNC_REPOSITORY:-${GITHUB_REPOSITORY:-sijunxiaodeng/ai-sec-intel}}" \
        --branch "${ACTIONS_SYNC_BRANCH:-main}" \
        --token "$token"
  ); then
    log "Actions snapshot installed (skip synthetic seed)"
    return 0
  fi
  log "Actions pull failed — will fall back to seed if needed"
  return 1
}

seed_local_db() {
  ensure_venvs
  mkdir -p "$ROOT/intelligence/data"
  if pull_actions_state_if_configured; then
    return 0
  fi
  if [[ ! -f "$ROOT/intelligence/data/intelligence.db" || "${DEMO_FORCE_SEED:-0}" == "1" ]]; then
    log "seeding offline B demo DB (root .venv)"
    (
      cd "$ROOT/intelligence"
      PYTHONPATH="$ROOT/intelligence" \
        "$ROOT/.venv/bin/python" seed_demo_db.py --force
    )
  else
    log "B demo DB already present (set DEMO_FORCE_SEED=1 to recreate; ACTIONS_SYNC_PULL=1 to pull Actions)"
  fi
}
