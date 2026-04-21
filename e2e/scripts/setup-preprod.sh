#!/usr/bin/env bash
# setup-preprod.sh — one-shot preprod environment setup for the Team D demo.
#
# Idempotent: safe to run twice in a row. Each step checks for existing state
# before making any changes.
#
# Steps:
#   1. npm/pnpm workspace install (drops nothing if deps unchanged)
#   2. check Materios preprod RPC reachable (wss://materios.fluxpointstudios.com/preprod-rpc)
#   3. check Cardano preprod Ogmios + Kupo reachable (Saturnswap.io)
#   4. warn if Team B validator addresses are still placeholders
#   5. warn if Team A pallet_intent_settlement extrinsics are missing from metadata
#
# Safety: this script NEVER submits transactions. It's read-only until the
# operator runs `pnpm demo` explicitly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$E2E_DIR/.." && pwd)"

color_ok()   { printf '\033[0;32m%s\033[0m\n' "$*"; }
color_warn() { printf '\033[0;33m%s\033[0m\n' "$*"; }
color_err()  { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
color_dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

echo "── Materios Intent-Settlement E2E: preprod setup ─────────────────────"
echo "  repo:    $REPO_ROOT"
echo "  e2e:     $E2E_DIR"
echo ""

# ────────────────────────────────────────────────────────────────────────────
# 1. Install deps (prefer pnpm if present; fall back to npm).
# ────────────────────────────────────────────────────────────────────────────
echo "[1/5] Install dependencies"
cd "$E2E_DIR"
if command -v pnpm >/dev/null 2>&1; then
  pnpm install --prefer-offline >/dev/null 2>&1 || pnpm install
  color_ok "  ok (pnpm)"
elif command -v npm >/dev/null 2>&1; then
  npm install --no-audit --no-fund >/dev/null 2>&1 || npm install
  color_ok "  ok (npm)"
else
  color_err "  neither pnpm nor npm found on PATH"
  exit 1
fi

# ────────────────────────────────────────────────────────────────────────────
# 2. Materios RPC reachability.
# ────────────────────────────────────────────────────────────────────────────
echo "[2/5] Materios preprod RPC reachability"
MATERIOS_WS="$(node -e "console.log(require('./config/preprod.json').materios.rpcWs)")"
MATERIOS_HTTP="${MATERIOS_WS/wss:/https:}"
MATERIOS_HTTP="${MATERIOS_HTTP/ws:/http:}"
if curl -fsS --max-time 5 -X POST -H "content-type: application/json" \
    --data '{"jsonrpc":"2.0","method":"system_chain","params":[],"id":1}' \
    "$MATERIOS_HTTP" >/dev/null 2>&1; then
  color_ok "  ok  ($MATERIOS_WS)"
else
  color_warn "  warn  ($MATERIOS_WS not reachable via HTTP probe; WS may still work)"
fi

# ────────────────────────────────────────────────────────────────────────────
# 3. Cardano preprod services reachability.
# ────────────────────────────────────────────────────────────────────────────
echo "[3/5] Cardano preprod (Ogmios + Kupo) reachability"
KUPO_URL="$(node -e "console.log(require('./config/preprod.json').cardano.kupoUrl)")"
OGMIOS_URL="$(node -e "console.log(require('./config/preprod.json').cardano.ogmiosUrl)")"
if curl -fsS --max-time 5 "$KUPO_URL/health" >/dev/null 2>&1; then
  color_ok "  ok  (kupo $KUPO_URL)"
else
  color_warn "  warn  (kupo $KUPO_URL not reachable; proxy may be down)"
fi
if curl -fsS --max-time 5 "$OGMIOS_URL/health" >/dev/null 2>&1; then
  color_ok "  ok  (ogmios $OGMIOS_URL)"
else
  color_warn "  warn  (ogmios $OGMIOS_URL not reachable)"
fi

# ────────────────────────────────────────────────────────────────────────────
# 4. Team B validator deployment status.
# ────────────────────────────────────────────────────────────────────────────
echo "[4/5] Team B validators (aegis-aiken-v1)"
if node -e "const c=require('./config/preprod.json'); process.exit(c.aegisValidators.aegisPolicyV1Address.startsWith('__')?1:0)"; then
  color_ok "  ok  (validator addresses populated)"
else
  color_warn "  pending  (edit config/preprod.json with Team B's deployed addresses)"
  color_dim "           see: https://github.com/Flux-Point-Studios/aegis-parametric-insurance-dev/pulls"
fi

# ────────────────────────────────────────────────────────────────────────────
# 5. Team A pallet registration status (best-effort via metadata fetch).
# ────────────────────────────────────────────────────────────────────────────
echo "[5/5] Team A pallet registration (best-effort)"
META=$(curl -fsS --max-time 10 -X POST -H "content-type: application/json" \
    --data '{"jsonrpc":"2.0","method":"state_getMetadata","params":[],"id":1}' \
    "$MATERIOS_HTTP" 2>/dev/null || true)
if echo "$META" | grep -qi "intentSettlement" 2>/dev/null; then
  color_ok "  ok  (pallet_intent_settlement found in runtime metadata)"
else
  color_warn "  pending  (pallet_intent_settlement not in runtime metadata — Team A runtime upgrade pending)"
  color_dim "           see: https://github.com/Flux-Point-Studios/materios-intent-settlement/pulls"
fi

echo ""
echo "── setup complete ────────────────────────────────────────────────────"
echo "  next:  pnpm --filter @materios/e2e demo"
