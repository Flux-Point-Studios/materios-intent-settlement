#!/usr/bin/env bash
# demo-reel.sh — runs full-demo.ts with verbose logging and captures
# tx hashes + cexplorer links to e2e/artifacts/demo-<timestamp>/ for
# the investor showcase.
#
# Outputs:
#   e2e/artifacts/demo-<ts>/run.log         — stdout + stderr
#   e2e/artifacts/demo-<ts>/tx-links.md     — extracted cexplorer URLs
#   e2e/artifacts/demo-<ts>/summary.json    — machine-readable recap
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$E2E_DIR/artifacts/demo-$TS"
mkdir -p "$OUT_DIR"

color_bold() { printf '\033[1;36m%s\033[0m\n' "$*"; }
color_ok()   { printf '\033[0;32m%s\033[0m\n' "$*"; }

color_bold "── demo-reel → $OUT_DIR ─────────────────────────────────────────"

# Run with verbose env; don't let failure stop capture.
set +e
cd "$E2E_DIR"
DEBUG='materios:*' LOG_LEVEL=debug \
  pnpm demo 2>&1 | tee "$OUT_DIR/run.log"
EXIT_CODE=${PIPESTATUS[0]}
set -e

# Extract cexplorer links from the log.
grep -oE 'https://(preprod\.)?cexplorer\.io/tx/[a-f0-9]+' "$OUT_DIR/run.log" \
  | sort -u > "$OUT_DIR/tx-links.md" || true

# Produce a summary.
{
  echo "{"
  echo "  \"timestamp\": \"$TS\","
  echo "  \"exitCode\": $EXIT_CODE,"
  echo "  \"logPath\": \"$OUT_DIR/run.log\","
  echo "  \"txLinkCount\": $(wc -l < "$OUT_DIR/tx-links.md" | tr -d ' '),"
  echo "  \"txLinksPath\": \"$OUT_DIR/tx-links.md\""
  echo "}"
} > "$OUT_DIR/summary.json"

color_ok "demo-reel complete. artifacts: $OUT_DIR"
exit $EXIT_CODE
