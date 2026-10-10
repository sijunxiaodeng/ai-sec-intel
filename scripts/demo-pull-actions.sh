#!/usr/bin/env bash
# Download the latest GitHub Actions intelligence-state artifact into the local
# multi-source DB used by embed mode (intelligence/data/intelligence.db).
#
# Requires: GITHUB_TOKEN or GH_TOKEN or ACTIONS_SYNC_TOKEN with actions:read.
# Usage:
#   ./scripts/demo-pull-actions.sh
#   ACTIONS_SYNC_REPOSITORY=owner/repo ./scripts/demo-pull-actions.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

export ACTIONS_SYNC_PULL=1
pull_actions_state_if_configured || die "failed to pull Actions snapshot"
log "done — restart main app if it is already running so SQLite handles refresh"
