#!/usr/bin/env bash
# Probe single product surface :8023.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo-lib.sh
source "$SCRIPT_DIR/demo-lib.sh"

mode="$(cat "$DEMO_DIR/mode" 2>/dev/null || echo '(未记录)')"
printf 'mode: %s\n' "$mode"
printf 'probe: %s\n' "$MAIN_URL/api/overview"
if curl -sf --max-time 5 "$MAIN_URL/api/overview" -o /tmp/ai-sec-intel-overview.json; then
  python3 - <<'PY'
import json
o=json.load(open("/tmp/ai-sec-intel-overview.json",encoding="utf-8"))
lib=o.get("library") or {}
print("ok: overview")
print("  items:", o.get("items"))
print("  offline_demo:", o.get("offline_demo"))
print("  library.documents:", lib.get("documents"))
print("  open:", "http://127.0.0.1:8023")
PY
  exit 0
fi
printf 'fail: %s 未就绪\n' "$MAIN_URL" >&2
exit 1
