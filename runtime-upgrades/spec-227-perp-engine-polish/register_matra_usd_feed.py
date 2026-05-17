#!/usr/bin/env python3
"""register_matra_usd_feed.py — post-spec-227 attestor + synthetic
poke for the MATRA/USD pair.

Closes the operational gap left after the spec-226 perp-engine ceremony:
ADA-PERP/USD trades use ADA/USD as the mark oracle, but margin
deposits/withdrawals + sub-rate fee accounting convert MOTRA ↔
pMATRA-USD at the MATRA/USD live rate. With no MATRA/USD feed live,
`deposit_margin` returns `OracleUnavailable` for every signed origin
(the only path that exercises it). This script populates both the
M-of-N attestor roster AND a synthetic seed price so the runtime can
accept deposits before the publisher pipeline is wired up.

**Production deployment** will replace the synthetic poke with the
real Aegis MATRA/USD publisher running on Node-2 (mirrors the spec-222
flow: register 3 attestor pubkeys, then start `aegis-publisher-preprod@
matra-usd.service`). The poke here is a development-loop bootstrap —
once the publisher is live the M-of-N quorum self-overwrites the
storage value on the next attestor tick.

This script is staged for the spec-227 ceremony but NOT auto-fired by
`ceremony.py`. Run it manually after the runtime upgrade has settled
(post `cargo run --release -p ceremony.py`).

Usage:
  ./register_matra_usd_feed.py [--rpc-url ws://...] [--skip-poke]

  --rpc-url    optional RPC URL override (default ws://127.0.0.1:9945)
  --skip-poke  register attestors only; do not write a synthetic price

Reuses the spec-222 `register_attestor.py` 2-of-3 multisig pattern.
The 3 attestor pubkeys below were generated via:
   `subkey generate-node-key --scheme Sr25519` × 3
and seeded into the operator vault on the 3 Aegis publisher hosts.

EXIT STATUS:
  0  success — 3 attestors in roster, (optional) synthetic price set
  1  preflight fail (wrong spec, multisig key mismatch, etc.)
  2  ceremony fail (sig rejected, multisig timepoint mismatch, etc.)
"""
REFERENCE CEREMONY — ADAPT TO YOUR OWN CHAIN.

See `ceremony.py` in this directory for the full caveat. The SS58s
below are FPS-operated PUBLIC multisig keys; the corresponding mnemonics
are NEVER in this repo. Override every constant via env-vars when
running on your own chain.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from hashlib import sha256
from pathlib import Path

from substrateinterface import SubstrateInterface, Keypair
from scalecodec.utils.ss58 import ss58_decode


DEFAULT_RPC_URL = os.environ.get("MATERIOS_RPC_URL", "ws://127.0.0.1:9945")

# Public SS58 addresses of the FPS 2-of-3 sudo multisig and its signers
# (override via MATERIOS_SUDO_MULTISIG / MATERIOS_SUDO_SIGNERS).
NATE_SS58 = "5E25rtEBkk8UXbAGPWsiwi82pmUtdmrFSCv7wQekSnSVpiZf"
K2_SS58 = "5DcwRUB9FBS7PQdTdkFtvj4ssc2FPVpxgumZsWjLMmhvzrTa"
K3_SS58 = "5HNAgGdHwaJQyCuZVQEHavQLb25XT3aYXcDBCGLe9hbpFiP2"
MULTISIG_ACCOUNT = os.environ.get(
    "MATERIOS_SUDO_MULTISIG",
    "5D1AnhuDNuvHbRzMeLGt235BMMcNSaB4wAad6us55xLGxUfM",
)

# 500M ref_time / 50K proof_size — same envelope as spec-222 attestor
# registration ceremonies; sudo + multisig wrappers fit comfortably.
AS_MULTI_WEIGHT = {"ref_time": 500_000_000, "proof_size": 50_000}

# Mnemonic table file — same format as ceremony.py. Lives in your local
# secret store, NOT this repository. Override via env-var.
MEMORY_FILE = Path(
    os.environ.get(
        "MATERIOS_MNEMONIC_FILE",
        str(Path.home() / ".materios" / "multisig-mnemonics.md"),
    )
)

# The 3 attestor sr25519 pubkeys for MATRA/USD. Each pubkey's matching
# seed is held in the operator vault on the publisher host; once the
# Aegis publisher service is started for matra-usd the daemon signs
# `submit_price` extrinsics from these keys.
MATRA_USD_ATTESTOR_PUBKEYS = (
    "0xc0413bdd9ae27ad0bf743be7712083fe78cf56a84d420ace5510844fc15fff1b",
    "0x5207cdcb2466b466d899fe8f663e1d75b0e7f540479f856596ae98b93968c910",
    "0x98cde690eff8d0eb6d4723af05c1d865f4be37a9e5511f4ca0cc7346d255ce04",
)

# Synthetic seed price for development bootstrapping. Production
# publisher overwrites this on the first attestor tick.
SYNTHETIC_PRICE_USD = 0.10
SYNTHETIC_PRICE_DECIMALS = 6
SYNTHETIC_PRICE_VALUE = int(SYNTHETIC_PRICE_USD * (10 ** SYNTHETIC_PRICE_DECIMALS))

PAIR_LABEL = b"MATRA/USD"


def load_mnemonic(role: str) -> str:
    text = MEMORY_FILE.read_text()
    pattern = rf"\|\s*{re.escape(role)}\s*\|\s*`([^`]+)`\s*\|"
    m = re.search(pattern, text)
    if not m:
        raise SystemExit(f"could not locate {role}'s mnemonic in {MEMORY_FILE}")
    return m.group(1).strip()


def pair_id_for(label: bytes) -> bytes:
    """sha256(label) — matches `Oracle.register_attestor` + `aegis-publisher`."""
    return sha256(label).digest()


def twox_128(b: bytes) -> bytes:
    import xxhash
    h0 = xxhash.xxh64(b, seed=0).intdigest().to_bytes(8, "little")
    h1 = xxhash.xxh64(b, seed=1).intdigest().to_bytes(8, "little")
    return h0 + h1


def blake2_128_concat(b: bytes) -> bytes:
    import hashlib as _h
    return _h.blake2b(b, digest_size=16).digest() + b


def prices_storage_key(label: bytes) -> bytes:
    """Storage key for Oracle.Prices[pair_id_for(label)]."""
    pid = pair_id_for(label)
    return twox_128(b"Oracle") + twox_128(b"Prices") + blake2_128_concat(pid)


def encode_price_feed(
    *, price: int, decimals: int, slot: int, block: int
) -> bytes:
    """SCALE-encode a PriceFeed struct (empty attestor_set).

    Layout (mirrors `aegis-publisher` + `materios-perp-tests` helpers):
      last_price        u64 LE   (8 bytes)
      last_decimals     u8       (1 byte)
      last_update_slot  u64 LE   (8 bytes)
      last_update_block u32 LE   (4 bytes)
      aggregation       u8       (Median = 0)
      attestor_set      Vec<H256>  (compact-length-prefixed, empty = 0x00)
    """
    return (
        price.to_bytes(8, "little")
        + bytes([decimals])
        + slot.to_bytes(8, "little")
        + block.to_bytes(4, "little")
        + bytes([0])  # aggregation Median = 0
        + bytes([0])  # empty Vec<H256> compact-length prefix
    )


def sudo_multisig_call(
    sub: SubstrateInterface, inner_call_value: dict, *, label: str
) -> None:
    """Fire a 2-of-3 multisig-wrapped Sudo call. Same shape as
    spec-225/spec-226 ceremony steps 2-3."""
    nate_kp = Keypair.create_from_mnemonic(load_mnemonic("Nate"))
    if nate_kp.ss58_address != NATE_SS58:
        raise SystemExit(
            f"Nate derived {nate_kp.ss58_address}, expected {NATE_SS58}"
        )

    sudo_call = sub.compose_call("Sudo", "sudo", {"call": inner_call_value})
    propose = sub.compose_call(
        "Multisig",
        "as_multi",
        {
            "threshold": 2,
            "other_signatories": [K2_SS58, K3_SS58],
            "maybe_timepoint": None,
            "call": sudo_call.value,
            "max_weight": AS_MULTI_WEIGHT,
        },
    )
    ext1 = sub.create_signed_extrinsic(call=propose, keypair=nate_kp)
    r1 = sub.submit_extrinsic(
        ext1, wait_for_inclusion=True, wait_for_finalization=False
    )
    print(f"  [{label}] propose block: {r1.block_hash}  ok={r1.is_success}")
    if not r1.is_success:
        raise SystemExit(f"propose failed: {r1.error_message}")

    block = sub.get_block(r1.block_hash)
    ext_idx = None
    for i, e in enumerate(block["extrinsics"]):
        eh = e.value.get("extrinsic_hash")
        if eh and eh.lower() == r1.extrinsic_hash.lower():
            ext_idx = i
            break
    if ext_idx is None:
        raise SystemExit("could not find Nate's ext index in block")
    timepoint = {"height": block["header"]["number"], "index": ext_idx}

    k2_kp = Keypair.create_from_mnemonic(load_mnemonic("K2"))
    if k2_kp.ss58_address != K2_SS58:
        raise SystemExit(
            f"K2 derived {k2_kp.ss58_address}, expected {K2_SS58}"
        )
    approve = sub.compose_call(
        "Multisig",
        "as_multi",
        {
            "threshold": 2,
            "other_signatories": [NATE_SS58, K3_SS58],
            "maybe_timepoint": timepoint,
            "call": sudo_call.value,
            "max_weight": AS_MULTI_WEIGHT,
        },
    )
    ext2 = sub.create_signed_extrinsic(call=approve, keypair=k2_kp)
    r2 = sub.submit_extrinsic(
        ext2, wait_for_inclusion=True, wait_for_finalization=True
    )
    print(f"  [{label}] approve block: {r2.block_hash}  ok={r2.is_success}")
    if not r2.is_success:
        raise SystemExit(f"approve failed: {r2.error_message}")

    saw_sudid_ok = False
    for e in r2.triggered_events:
        ev = e.value if hasattr(e, "value") else e
        mod = ev.get("module_id")
        evname = ev.get("event_id")
        attrs = ev.get("attributes")
        if mod == "Sudo" and evname == "Sudid":
            res = attrs.get("sudo_result") if isinstance(attrs, dict) else None
            if isinstance(res, dict) and "Ok" in res:
                saw_sudid_ok = True
    if not saw_sudid_ok:
        raise SystemExit(f"[{label}] Sudid did not return Ok — inspect logs")


def register_one_attestor(sub: SubstrateInterface, pubkey_hex: str) -> None:
    pair_id_hex = "0x" + pair_id_for(PAIR_LABEL).hex()
    existing = sub.query("Oracle", "Attestors", [pair_id_hex]).value or []
    existing_norm = [
        ("0x" + bytes(p).hex() if isinstance(p, list) else str(p)).lower()
        for p in existing
    ]
    if pubkey_hex.lower() in existing_norm:
        print(f"  pubkey {pubkey_hex[:18]}… already registered, skipping")
        return

    register = sub.compose_call(
        "Oracle",
        "register_attestor",
        {"pair_id": pair_id_hex, "pubkey": pubkey_hex},
    )
    sudo_multisig_call(sub, register.value, label=f"register {pubkey_hex[:18]}")


def poke_matra_usd_synthetic(sub: SubstrateInterface) -> None:
    head_hash = sub.get_chain_finalised_head()
    head_block = sub.get_block_header(head_hash)["header"]["number"]
    # See `feedback_oracle_poke_slot_units.md` — slot MUST track the
    # block number the next real attestor will submit. Setting `slot
    # = block * 10` or any future-proof multiplier silently wedges the
    # monotonicity check and kills every subsequent real submission
    # until the chain catches up to that block height.
    slot = head_block
    val = encode_price_feed(
        price=SYNTHETIC_PRICE_VALUE,
        decimals=SYNTHETIC_PRICE_DECIMALS,
        slot=slot,
        block=head_block,
    )
    key = prices_storage_key(PAIR_LABEL)
    print(
        f"  synthetic poke: price={SYNTHETIC_PRICE_USD} USD "
        f"slot={slot} block={head_block}"
    )

    set_storage = sub.compose_call(
        "System",
        "set_storage",
        {"items": [("0x" + key.hex(), "0x" + val.hex())]},
    )
    # System.set_storage is a fat dispatch — bump the weight envelope.
    global AS_MULTI_WEIGHT
    saved_weight = AS_MULTI_WEIGHT
    AS_MULTI_WEIGHT = {"ref_time": 2_000_000_000, "proof_size": 500_000}
    try:
        sudo_multisig_call(sub, set_storage.value, label="poke MATRA/USD")
    finally:
        AS_MULTI_WEIGHT = saved_weight


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Register MATRA/USD attestors + synthetic poke"
    )
    ap.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    ap.add_argument(
        "--skip-poke",
        action="store_true",
        help="register attestors only; skip synthetic price seed",
    )
    args = ap.parse_args()

    sub = SubstrateInterface(url=args.rpc_url)
    print(f"=== register_matra_usd_feed: {PAIR_LABEL.decode()} ===")
    print(f"  rpc:          {args.rpc_url}  ({sub.chain})")

    v = sub.get_block_runtime_version(sub.get_chain_finalised_head())
    print(f"  spec_version: {v['specVersion']}")
    if v["specVersion"] < 227:
        raise SystemExit(
            f"chain not yet at spec >= 227, got {v['specVersion']}. "
            "Run the spec-227 runtime upgrade first."
        )

    sudo_key = sub.query("Sudo", "Key")
    if ss58_decode(str(sudo_key.value)) != ss58_decode(MULTISIG_ACCOUNT):
        raise SystemExit(
            f"Sudo.Key {sudo_key.value} != multisig {MULTISIG_ACCOUNT}"
        )

    pair_id_hex = "0x" + pair_id_for(PAIR_LABEL).hex()
    print(f"  pair_id:      {pair_id_hex}  (sha256({PAIR_LABEL.decode()!r}))")

    print("\n=== Registering attestors (3 of N) ===")
    for pubkey in MATRA_USD_ATTESTOR_PUBKEYS:
        print(f"\n--- {pubkey} ---")
        register_one_attestor(sub, pubkey)

    print("\n=== Verifying roster ===")
    roster = sub.query("Oracle", "Attestors", [pair_id_hex]).value or []
    roster_norm = [
        ("0x" + bytes(p).hex() if isinstance(p, list) else str(p)).lower()
        for p in roster
    ]
    print(f"  Oracle.Attestors[MATRA/USD]: {roster_norm}")
    missing = [
        p for p in MATRA_USD_ATTESTOR_PUBKEYS if p.lower() not in roster_norm
    ]
    if missing:
        raise SystemExit(f"missing from roster post-registration: {missing}")
    print(f"  all 3 attestors registered.")

    if args.skip_poke:
        print("\n--skip-poke set — leaving Oracle.Prices[MATRA/USD] untouched")
    else:
        print("\n=== Synthetic price poke ===")
        poke_matra_usd_synthetic(sub)
        prices = sub.query("Oracle", "Prices", [pair_id_hex]).value
        print(f"  Oracle.Prices[MATRA/USD] now: {prices}")

    print("\n=== DONE ===")
    print(
        f"  Next: start `aegis-publisher-preprod@matra-usd.service` on the\n"
        f"  publisher host. The first attestor quorum tick overwrites the\n"
        f"  synthetic price with the live MATRA/USD market value. The\n"
        f"  attestor seeds matching the pubkeys above live in the operator\n"
        f"  vault — see the spec-222 attestor-onboarding runbook for the\n"
        f"  scp / systemctl restart sequence."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
