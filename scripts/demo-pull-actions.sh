#!/usr/bin/env bash
# Download the latest GitHub Actions intelligence-state artifact into the local
# isolated, read-only Actions mirror used by embed mode.
#
# Requires: GITHUB_TOKEN or GH_TOKEN or ACTIONS_SYNC_TOKEN with actions:read.
# Usage:
#   ./scripts/demo-pull-actions.sh
#   ACTIONS_SYNC_REPOSITORY=owner/repo ./scripts/demo-pull-actions.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ACTIONS_SYNC_PULL=1
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

pull_actions_state_if_configured || die "failed to pull Actions snapshot"
log "done — the API follows current/intelligence.db on each query"
