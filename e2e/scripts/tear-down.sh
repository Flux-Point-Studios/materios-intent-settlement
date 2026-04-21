#!/usr/bin/env bash
# tear-down.sh — clean up demo artifacts produced by full-demo.ts.
#
# SAFETY: this script does NOT revoke any on-chain state (Cardano txs are
# immutable, Materios intents TTL-expire on their own). Its only job is to
# sweep local artifacts:
#   - e2e/artifacts/* (captured tx hashes, logs, screenshots for the demo-reel)
#   - e2e/coverage/* (vitest coverage output)
#   - e2e/node_modules/.vite/* (vitest cache)
#
# Idempotent: safe to run twice in a row.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

color_ok()   { printf '\033[0;32m%s\033[0m\n' "$*"; }
color_dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

echo "── Materios E2E: local teardown ──────────────────────────────────────"
for path in "$E2E_DIR/artifacts" "$E2E_DIR/coverage" "$E2E_DIR/node_modules/.vite"; do
  if [ -d "$path" ]; then
    rm -rf "$path"
    color_ok  "  removed  $path"
  else
    color_dim "  skipped  $path (not present)"
  fi
done
color_ok "  ok"
echo ""
echo "note: on-chain state cannot be rolled back. Materios intents will"
echo "      TTL-expire (~1h) naturally if you left any in Pending."
