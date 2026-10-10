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
# Public single entry: all demo/smoke client traffic uses MAIN_URL (B proxied under 8023).
# TEAM_INTEL_UPSTREAM is the localhost-only B process (avoid A↔8023 self-proxy deadlock).
export TEAM_INTEL_UPSTREAM="${TEAM_INTEL_UPSTREAM:-http://127.0.0.1:${B_PORT}}"
export TEAM_INTEL_PROXY="${TEAM_INTEL_PROXY:-1}"
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
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    log "creating root .venv"
    python3 -m venv "$ROOT/.venv"
    "$ROOT/.venv/bin/python" -m pip install -U pip -q
    "$ROOT/.venv/bin/python" -m pip install -q -r "$ROOT/requirements.txt"
  fi
  if [[ ! -x "$ROOT/intelligence/.venv/bin/python" ]]; then
    log "creating intelligence/.venv"
    python3 -m venv "$ROOT/intelligence/.venv"
    "$ROOT/intelligence/.venv/bin/python" -m pip install -U pip -q
    "$ROOT/intelligence/.venv/bin/python" -m pip install -q -r "$ROOT/intelligence/requirements.lock.txt"
  fi
}

seed_local_db() {
  ensure_venvs
  mkdir -p "$ROOT/intelligence/data"
  if [[ ! -f "$ROOT/intelligence/data/intelligence.db" || "${DEMO_FORCE_SEED:-0}" == "1" ]]; then
    log "seeding offline B demo DB"
    "$ROOT/intelligence/.venv/bin/python" "$ROOT/intelligence/seed_demo_db.py" --force
  else
    log "B demo DB already present (set DEMO_FORCE_SEED=1 to recreate)"
  fi
}
