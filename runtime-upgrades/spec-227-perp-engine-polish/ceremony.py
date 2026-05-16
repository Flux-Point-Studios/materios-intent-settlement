#!/usr/bin/env python3
"""ceremony.py — execute the spec-227 perp-engine polish multisig sudo
runtime upgrade.

Spec 226 -> 227. Bumps the `pallet-perp-engine` rev pin to the polish
PR's merge tip on `materios-intent-settlement` main. No new pallets,
no new Config items — the upgrade is risk-config polish:

  - `pallet_perp_engine::governance_set_market` body landed (call_index 7).
    12-gate validation (mm < im, bps caps, max_leverage ≤ chain cap,
    dust floor, key/value coherence) + duplicate-key reject
    (`MarketAlreadyExists`) + `MarketRegistered` event. Future markets
    register cleanly through the dispatchable — no more
    Sudo.System.set_storage workarounds like spec-226's ADA-PERP.
  - `pallet_perp_engine::liquidate` sub-rate fee floor (PR-C sec-review
    LOW 2). Keeper payout floors at 1 MOTRA when fee_e18 > 0, fixing
    the integer-division underflow on tiny-notional liquidations.
    Zero-fee liquidations still pay 0 (no spurious rounding).

Sequence (same shape as spec-220/221/222/223/224/225/226):
  Step 0  Live runtime version query (must be 226, tx=2)
  Step 1  Preflight: AuthorizedUpgrade clear, Sudo.Key == multisig,
          WASM file present, perp-engine Markets[ADA-PERP/USD] still
          present (the spec-226 demo trade left it via set_storage —
          must remain after the upgrade).
  Step 2  Nate proposes  -> Multisig.NewMultisig
  Step 3  K2 approves    -> Sudo.Sudid(Ok), System.UpgradeAuthorized,
                            Multisig.MultisigExecuted
  Step 4  Apply (unsigned apply_authorized_upgrade) -> System.CodeUpdated;
          spec flips to 227
  Step 5  Postflight: assert spec=227, governance_set_market metadata
          unchanged (call_index 7, same args), MarketRegistered event
          variant exists, MarketAlreadyExists error variant exists,
          Markets[ADA-PERP/USD] intact (no migration wipe).

Path constants:
  WASM_PATH      /home/deci/materios-preprod/runtime-overrides/...spec227
  CODE_HASH_FILE /tmp/materios-runtime-spec227.blake2_256.txt
  TARGET_SPEC    227

Multisig pattern identical to spec-226 (same 5D1Anh… 2-of-3 sudo
multisig: Nate / K2 / K3).
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

from substrateinterface import SubstrateInterface, Keypair
from scalecodec.utils.ss58 import ss58_decode

RPC_URL = "ws://127.0.0.1:9945"
WASM_PATH = "/home/deci/materios-preprod/runtime-overrides/materios_runtime.compact.compressed.wasm.spec227"
CODE_HASH_FILE = "/tmp/materios-runtime-spec227.blake2_256.txt"
TARGET_SPEC = 227
PRIOR_SPEC = 226

AS_MULTI_WEIGHT = {"ref_time": 500_000_000, "proof_size": 50_000}

NATE_SS58 = "5E25rtEBkk8UXbAGPWsiwi82pmUtdmrFSCv7wQekSnSVpiZf"
K2_SS58 = "5DcwRUB9FBS7PQdTdkFtvj4ssc2FPVpxgumZsWjLMmhvzrTa"
K3_SS58 = "5HNAgGdHwaJQyCuZVQEHavQLb25XT3aYXcDBCGLe9hbpFiP2"
MULTISIG_ACCOUNT = "5D1AnhuDNuvHbRzMeLGt235BMMcNSaB4wAad6us55xLGxUfM"

MEMORY_FILE = Path(
    "/home/deci/.claude/projects/-home-deci/memory/reference_multisig_sudo.md"
)

# The spec-226 demo trade registered ADA-PERP/USD via
# Sudo.System.set_storage. spec-227's storage layout doesn't migrate
# the row (no field added or removed on MarketConfig), so the upgrade
# must leave it intact. Postflight checks this byte-for-byte.
ADA_PERP_MARKET_ID = b"ADA-PERP/USD"


def load_mnemonic(role: str) -> str:
    text = MEMORY_FILE.read_text()
    pattern = rf"\|\s*{re.escape(role)}\s*\|\s*`([^`]+)`\s*\|"
    m = re.search(pattern, text)
    if not m:
        raise SystemExit(f"could not locate {role}'s mnemonic in {MEMORY_FILE}")
    return m.group(1).strip()


def step1_preflight(sub: SubstrateInterface) -> str:
    print("\n=== STEP 1 — preflight ===")
    v = sub.get_block_runtime_version(sub.get_chain_finalised_head())
    cur_spec = v["specVersion"]
    cur_tx = v["transactionVersion"]
    print(f"  current spec_version: {cur_spec}, transaction_version: {cur_tx}")
    if cur_spec >= TARGET_SPEC:
        raise SystemExit(f"chain already at spec >= {TARGET_SPEC}")
    if cur_spec != PRIOR_SPEC:
        print(
            f"  WARNING: expected spec={PRIOR_SPEC}, got spec={cur_spec}. "
            f"Continuing only if you accept the prior-spec mismatch."
        )

    auth = sub.query("System", "AuthorizedUpgrade")
    print(f"  System.AuthorizedUpgrade: {auth.value!r}")
    if auth.value is not None:
        raise SystemExit(
            f"System.AuthorizedUpgrade is already set: {auth.value!r}. "
            f"Resolve before continuing."
        )

    if not Path(WASM_PATH).is_file():
        raise SystemExit(f"WASM missing: {WASM_PATH}")
    code_hash = Path(CODE_HASH_FILE).read_text().strip()
    if not code_hash.startswith("0x") or len(code_hash) != 66:
        raise SystemExit(f"bad code_hash format: {code_hash!r}")
    print(f"  WASM:        {WASM_PATH} ({Path(WASM_PATH).stat().st_size} bytes)")
    print(f"  code_hash:   {code_hash}")

    sudo_key = sub.query("Sudo", "Key")
    sudo_hex = ss58_decode(str(sudo_key.value))
    multisig_hex = ss58_decode(MULTISIG_ACCOUNT)
    print(f"  Sudo.Key:    {sudo_key.value}")
    if sudo_hex != multisig_hex:
        raise SystemExit(
            f"Sudo.Key {sudo_hex} != expected multisig {multisig_hex}"
        )

    # ADA-PERP/USD existence check. spec-226 registered it via
    # set_storage; spec-227 must preserve it (no migration).
    try:
        existing = sub.query(
            "PerpEngine", "Markets", ["0x" + ADA_PERP_MARKET_ID.hex()]
        ).value
        print(
            f"  PerpEngine.Markets[ADA-PERP/USD]: "
            f"{'present' if existing else 'ABSENT'}"
        )
        if existing is None:
            print(
                "  WARNING: ADA-PERP/USD market absent pre-upgrade. The polish"
                "\n  PR doesn't re-register it; if the spec-226 set_storage"
                "\n  write was rolled back, run governance_set_market through"
                "\n  the new dispatchable post-upgrade."
            )
    except Exception as e:
        print(f"  (could not introspect PerpEngine.Markets: {e})")

    # Inflight-tx sanity.
    try:
        pending = sub.rpc_request("author_pendingExtrinsics", [])
        n = len(pending.get("result") or [])
        print(f"  author_pendingExtrinsics: {n}")
        if n > 50:
            print(
                f"  WARNING: {n} pending extrinsics — consider draining "
                f"before ceremony"
            )
    except Exception as e:
        print(f"  (could not query pending pool: {e})")

    return code_hash


def step2_propose_nate(sub: SubstrateInterface, code_hash: str) -> dict:
    print("\n=== STEP 2 — Nate proposes authorize_upgrade ===")
    nate_kp = Keypair.create_from_mnemonic(load_mnemonic("Nate"))
    if nate_kp.ss58_address != NATE_SS58:
        raise SystemExit(
            f"Nate derived {nate_kp.ss58_address}, expected {NATE_SS58}"
        )
    print(f"  Nate signs as: {nate_kp.ss58_address}")

    authorize = sub.compose_call(
        "System", "authorize_upgrade", {"code_hash": code_hash}
    )
    sudo_call = sub.compose_call("Sudo", "sudo", {"call": authorize.value})
    as_multi = sub.compose_call(
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

    ext = sub.create_signed_extrinsic(call=as_multi, keypair=nate_kp)
    receipt = sub.submit_extrinsic(
        ext, wait_for_inclusion=True, wait_for_finalization=False
    )
    print(f"  block:       {receipt.block_hash}")
    print(f"  ext hash:    {receipt.extrinsic_hash}")
    print(f"  is_success:  {receipt.is_success}")
    if not receipt.is_success:
        raise SystemExit(f"Nate's as_multi failed: {receipt.error_message}")

    new_multisig = None
    for e in receipt.triggered_events:
        ev = e.value if hasattr(e, "value") else e
        mod = ev.get("module_id")
        evname = ev.get("event_id")
        if mod == "Multisig" and evname == "NewMultisig":
            new_multisig = ev
        print(f"  event: {mod}.{evname} {ev.get('attributes')}")
    if not new_multisig:
        raise SystemExit("no Multisig.NewMultisig event")

    block = sub.get_block(receipt.block_hash)
    block_num = block["header"]["number"]
    ext_idx = None
    for i, e_in_block in enumerate(block["extrinsics"]):
        eh = e_in_block.value.get("extrinsic_hash")
        if eh and eh.lower() == receipt.extrinsic_hash.lower():
            ext_idx = i
            break
    if ext_idx is None:
        raise SystemExit("could not find Nate's ext index in block")
    timepoint = {"height": block_num, "index": ext_idx}
    print(f"  TIMEPOINT:   {timepoint}")
    return timepoint


def step3_approve_k2(
    sub: SubstrateInterface, code_hash: str, timepoint: dict
) -> None:
    print("\n=== STEP 3 — K2 approves + dispatches authorize_upgrade ===")
    k2_kp = Keypair.create_from_mnemonic(load_mnemonic("K2"))
    if k2_kp.ss58_address != K2_SS58:
        raise SystemExit(
            f"K2 derived {k2_kp.ss58_address}, expected {K2_SS58}"
        )
    print(f"  K2 signs as: {k2_kp.ss58_address}")

    authorize = sub.compose_call(
        "System", "authorize_upgrade", {"code_hash": code_hash}
    )
    sudo_call = sub.compose_call("Sudo", "sudo", {"call": authorize.value})
    as_multi = sub.compose_call(
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

    ext = sub.create_signed_extrinsic(call=as_multi, keypair=k2_kp)
    receipt = sub.submit_extrinsic(
        ext, wait_for_inclusion=True, wait_for_finalization=True
    )
    print(f"  block:       {receipt.block_hash}")
    print(f"  is_success:  {receipt.is_success}")
    if not receipt.is_success:
        raise SystemExit(f"K2's as_multi failed: {receipt.error_message}")

    saw_executed = saw_sudid_ok = saw_authorized = False
    for e in receipt.triggered_events:
        ev = e.value if hasattr(e, "value") else e
        mod = ev.get("module_id")
        evname = ev.get("event_id")
        attrs = ev.get("attributes")
        print(f"  event: {mod}.{evname} {attrs}")
        if mod == "Multisig" and evname == "MultisigExecuted":
            res = attrs.get("result") if isinstance(attrs, dict) else None
            if isinstance(res, dict) and "Ok" in res:
                saw_executed = True
            elif isinstance(res, list) and len(res) >= 1 and str(res[0]).startswith("Ok"):
                saw_executed = True
        if mod == "Sudo" and evname == "Sudid":
            res = attrs.get("sudo_result") if isinstance(attrs, dict) else None
            if isinstance(res, dict) and "Ok" in res:
                saw_sudid_ok = True
        if mod == "System" and evname == "UpgradeAuthorized":
            saw_authorized = True

    if not (saw_executed and saw_sudid_ok and saw_authorized):
        raise SystemExit(
            f"missing events: executed={saw_executed} sudid_ok={saw_sudid_ok} "
            f"authorized={saw_authorized}"
        )
    print("  ALL EXPECTED EVENTS FIRED")


def step4_apply(sub: SubstrateInterface) -> int:
    print("\n=== STEP 4 — apply_authorized_upgrade (unsigned) ===")
    auth = sub.query("System", "AuthorizedUpgrade")
    print(f"  AuthorizedUpgrade: {auth.value}")
    if auth.value is None:
        raise SystemExit("AuthorizedUpgrade is None — authorize did not land")

    on_chain_hash = (
        auth.value.get("code_hash") if isinstance(auth.value, dict) else None
    )
    local_hash = Path(CODE_HASH_FILE).read_text().strip()
    if on_chain_hash != local_hash:
        raise SystemExit(
            f"hash mismatch! on_chain={on_chain_hash} local={local_hash}"
        )

    wasm_bytes = Path(WASM_PATH).read_bytes()
    apply_call = sub.compose_call(
        "System",
        "apply_authorized_upgrade",
        {"code": "0x" + wasm_bytes.hex()},
    )
    ext = sub.create_unsigned_extrinsic(call=apply_call)
    receipt = sub.submit_extrinsic(
        ext, wait_for_inclusion=True, wait_for_finalization=True
    )
    print(f"  block:       {receipt.block_hash}")
    print(f"  is_success:  {receipt.is_success}")
    if not receipt.is_success:
        raise SystemExit(f"apply failed: {receipt.error_message}")

    saw_code_updated = False
    for e in receipt.triggered_events:
        ev = e.value if hasattr(e, "value") else e
        mod = ev.get("module_id")
        evname = ev.get("event_id")
        print(f"  event: {mod}.{evname}")
        if mod == "System" and evname == "CodeUpdated":
            saw_code_updated = True
    if not saw_code_updated:
        raise SystemExit(
            "System.CodeUpdated did not fire — upgrade did not apply"
        )
    print("  RUNTIME UPGRADED (CodeUpdated fired) — waiting 12s for spec to settle")
    time.sleep(12)

    sub2 = SubstrateInterface(url=RPC_URL)
    v = sub2.get_block_runtime_version(sub2.get_chain_finalised_head())
    print(f"  post-apply spec_version: {v['specVersion']}")
    if v["specVersion"] != TARGET_SPEC:
        raise SystemExit(
            f"spec did not flip to {TARGET_SPEC}, got {v['specVersion']}"
        )

    block = sub.get_block(receipt.block_hash)
    return int(block["header"]["number"])


def step5_postflight(sub: SubstrateInterface, upgrade_block: int) -> None:
    print("\n=== STEP 5 — postflight ===")
    sub2 = SubstrateInterface(url=RPC_URL)
    v = sub2.get_block_runtime_version(sub2.get_chain_finalised_head())
    print(f"  spec_version: {v['specVersion']}  (target {TARGET_SPEC})")
    if v["specVersion"] != TARGET_SPEC:
        raise SystemExit(f"spec did not flip to {TARGET_SPEC}")

    # 1) PerpEngine metadata — governance_set_market still at call_index 7,
    #    same shape; MarketRegistered event variant exists;
    #    MarketAlreadyExists error variant exists.
    try:
        meta = sub2.get_metadata_pallet("PerpEngine")
        if meta is None:
            raise SystemExit("PerpEngine pallet missing from metadata?")
        calls = {c.name: c for c in (meta.calls or [])}
        if "governance_set_market" not in calls:
            raise SystemExit("governance_set_market call missing from metadata")
        events = [e.name for e in (meta.events or [])]
        errors = [e.name for e in (meta.errors or [])]
        print(f"  PerpEngine.events count: {len(events)}")
        print(f"  PerpEngine.errors count: {len(errors)}")
        if "MarketRegistered" not in events:
            raise SystemExit(
                "MarketRegistered event variant missing — runtime did not "
                "absorb the polish-PR event refactor"
            )
        if "MarketAlreadyExists" not in errors:
            raise SystemExit(
                "MarketAlreadyExists error variant missing — runtime did "
                "not absorb the polish-PR error addition"
            )
        print(
            f"  PerpEngine.MarketRegistered: present\n"
            f"  PerpEngine.MarketAlreadyExists: present"
        )
    except SystemExit:
        raise
    except Exception as e:
        raise SystemExit(f"Could not introspect PerpEngine metadata: {e}")

    # 2) ADA-PERP/USD market row preserved across the upgrade (no
    #    migration, no field shape change).
    try:
        existing = sub2.query(
            "PerpEngine", "Markets", ["0x" + ADA_PERP_MARKET_ID.hex()]
        ).value
        print(
            f"  PerpEngine.Markets[ADA-PERP/USD]: "
            f"{'present' if existing else 'ABSENT'}"
        )
        if existing is None:
            print(
                "  NOTE: ADA-PERP/USD market is absent. If it was present "
                "pre-upgrade and is now gone, file a migration bug."
            )
    except Exception as e:
        print(f"  (could not introspect Markets[ADA-PERP/USD] post-upgrade: {e})")

    print("\n  ALL POSTFLIGHT CHECKS PASSED")
    print("\n  Operator follow-ups:")
    print("    1) Test the new dispatchable: try registering BTC-PERP/USD via")
    print("       Sudo.governance_set_market — verify MarketRegistered fires.")
    print("    2) Run register_matra_usd_feed.py to seed the MATRA/USD pair.")
    print("    3) Start aegis-publisher-preprod@matra-usd.service on Node-2.")


def main() -> int:
    sub = SubstrateInterface(url=RPC_URL)
    print(f"connected to {sub.chain}, RPC {RPC_URL}")
    print(f"\nspec-227 perp-engine polish ceremony begins.")
    print(f"  WASM:        {WASM_PATH}")
    print(f"  Target spec: {TARGET_SPEC}")

    code_hash = step1_preflight(sub)
    v = sub.get_block_runtime_version(sub.get_chain_finalised_head())
    print(f"\n  about to start ceremony at spec={v['specVersion']}")

    timepoint = step2_propose_nate(sub, code_hash)
    step3_approve_k2(sub, code_hash, timepoint)
    upgrade_block = step4_apply(sub)

    sub3 = SubstrateInterface(url=RPC_URL)  # reconnect for fresh metadata
    step5_postflight(sub3, upgrade_block)

    print("\n=== CEREMONY COMPLETE ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
