#!/usr/bin/env bash
# build-wasm.sh — build the spec-227 runtime WASM, verify spec_version
# + pallet-perp-engine rev pin, stage it for the sudo ceremony, and
# emit the blake2_256 code_hash.
#
# spec-227 ships (perp-engine polish PR):
#   - `pallet_perp_engine::governance_set_market` body landed —
#     12-gate validation, MarketRegistered event, duplicate-key reject.
#     Future markets register cleanly through the dispatchable; no more
#     Sudo.System.set_storage workaround like spec-226's ADA-PERP.
#   - `pallet_perp_engine::liquidate` sub-rate fee floor (PR-C
#     sec-review LOW 2). Keeper payout floors at 1 MOTRA when fee_e18
#     > 0; zero-fee liquidations still pay 0.
#   - spec_version bump 226 → 227; tx_version unchanged.
#
# Preconditions (must be live on chain BEFORE running this ceremony):
#   - Chain at spec_version 226 (spec-226 perp-engine v0 live).
#   - All prior Config constants intact (the build asserts in-source).
#   - The `perp/v0w` derived account already funded from spec-226 —
#     no fresh pre-fund required for spec-227.
#
# Outputs:
#   ${WASM_DST_DIR}/materios_runtime.compact.compressed.wasm.spec227
#   ${HASH_OUT_DIR}/materios-runtime-spec227.blake2_256.txt
#
# Configuration (all env-var-overridable; defaults are example paths):
#   REPO         — path to the materios-runtime / partnerchain checkout to build from
#   WASM_DST_DIR — directory where the compiled WASM gets staged
#   HASH_OUT_DIR — directory where the blake2_256 code_hash file gets written
#
# Companion script:
#   ceremony.py    — consumes both outputs above
#   register_matra_usd_feed.py — post-ceremony attestor + poke
#                                 (manual step, NOT auto-fired)

set -euo pipefail

REPO="${REPO:-${HOME}/work/materios-runtime}"
WASM_DST_DIR="${WASM_DST_DIR:-${HOME}/materios-preprod/runtime-overrides}"
HASH_OUT_DIR="${HASH_OUT_DIR:-/tmp}"
TARGET_SPEC=227
PRIOR_SPEC=226
WASM_SRC="${REPO}/target/release/wbuild/materios-runtime/materios_runtime.compact.compressed.wasm"
WASM_DST="${WASM_DST_DIR}/materios_runtime.compact.compressed.wasm.spec${TARGET_SPEC}"
HASH_OUT="${HASH_OUT_DIR}/materios-runtime-spec${TARGET_SPEC}.blake2_256.txt"

echo "=== build-wasm.sh: spec-227 (perp-engine polish) ==="
echo "repo:        ${REPO}"
echo "target spec: ${TARGET_SPEC}"
echo "wasm dst:    ${WASM_DST}"
echo "hash out:    ${HASH_OUT}"

if [[ ! -d "${REPO}" ]]; then
  echo "ERROR: ${REPO} does not exist." >&2
  exit 1
fi

mkdir -p "$(dirname "${WASM_DST}")"

# Step 1: source-tree spec_version sanity.
SRC_SPEC=$(grep -E '^\s*spec_version:\s*[0-9]+' "${REPO}/runtime/src/lib.rs" \
  | head -1 | sed -E 's/.*spec_version:\s*([0-9]+).*/\1/')
echo "source-tree spec_version: ${SRC_SPEC}"
if [[ "${SRC_SPEC}" != "${TARGET_SPEC}" ]]; then
  echo "ERROR: source spec_version (${SRC_SPEC}) != target (${TARGET_SPEC})" >&2
  echo "  Apply the spec-227 runtime-bump.md patch first." >&2
  exit 2
fi

# Step 2: pallet-perp-engine rev pin sanity. The polish PR's merge tip
# in `materios-intent-settlement` is the new pin; the build refuses to
# bake stale pallet code.
PE_REV=$(grep -E '^pallet-perp-engine\s*=' "${REPO}/Cargo.toml" \
  | head -1 | sed -E 's/.*rev\s*=\s*"([0-9a-f]+)".*/\1/')
echo "pallet-perp-engine rev: ${PE_REV}"
if [[ -z "${EXPECTED_PE_REV:-}" ]]; then
  echo "  (EXPECTED_PE_REV not set in env — pin assertion skipped.)"
  echo "  Set EXPECTED_PE_REV to the polish-PR merge tip and re-run for a"
  echo "  hard byte-match check before staging WASM for the ceremony."
else
  if [[ "${PE_REV}" != "${EXPECTED_PE_REV}" ]]; then
    echo "ERROR: pallet-perp-engine rev (${PE_REV}) != ${EXPECTED_PE_REV}" >&2
    exit 2
  fi
fi

# Step 3: cargo build.
if [[ -f "${WASM_SRC}" && "${WASM_SRC}" -nt "${REPO}/runtime/src/lib.rs" ]]; then
  echo
  echo "=== cargo build SKIPPED — WASM newer than runtime/src/lib.rs ==="
else
  echo
  echo "=== cargo build ==="
  ( cd "${REPO}" && cargo build --release --features=runtime-benchmarks -p materios-runtime )
fi

if [[ ! -f "${WASM_SRC}" ]]; then
  echo "ERROR: expected WASM at ${WASM_SRC} after build, not found" >&2
  exit 3
fi

WASM_SIZE=$(stat -c%s "${WASM_SRC}")
echo "WASM built: ${WASM_SRC} (${WASM_SIZE} bytes)"

# Step 4: subkey cross-check when available.
if command -v subkey >/dev/null 2>&1; then
  if subkey inspect-runtime --help >/dev/null 2>&1; then
    echo
    echo "=== subkey inspect-runtime cross-check ==="
    SUBKEY_SPEC=$(subkey inspect-runtime "${WASM_SRC}" 2>/dev/null \
      | grep -E 'spec_version' | head -1 | sed -E 's/.*[: =]([0-9]+).*/\1/' || true)
    if [[ -n "${SUBKEY_SPEC}" ]]; then
      echo "WASM spec_version (subkey): ${SUBKEY_SPEC}"
      if [[ "${SUBKEY_SPEC}" != "${TARGET_SPEC}" ]]; then
        echo "ERROR: WASM spec_version ${SUBKEY_SPEC} != target ${TARGET_SPEC}" >&2
        exit 4
      fi
    fi
  fi
fi

# Step 5: stage to override path.
cp -f "${WASM_SRC}" "${WASM_DST}"
echo "staged: ${WASM_DST} ($(stat -c%s "${WASM_DST}") bytes)"

# Step 6: blake2_256 → /tmp/...spec227.blake2_256.txt.
if command -v b2sum >/dev/null 2>&1; then
  CODE_HASH=0x$(b2sum -l 256 "${WASM_DST}" | awk '{print $1}')
else
  CODE_HASH=$(python3 - <<EOF
import hashlib
d = open("${WASM_DST}", "rb").read()
print("0x" + hashlib.blake2b(d, digest_size=32).hexdigest())
EOF
  )
fi

echo "${CODE_HASH}" > "${HASH_OUT}"
echo
echo "=== summary ==="
echo "WASM:      ${WASM_DST}"
echo "size:      ${WASM_SIZE} bytes"
echo "code_hash: ${CODE_HASH}"
echo "(written to ${HASH_OUT})"
echo
echo "Next: ./ceremony.py"
