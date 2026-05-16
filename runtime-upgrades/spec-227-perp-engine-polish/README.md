# spec-227 — perp-engine v0 polish

Polish-PR runtime upgrade. Bumps `spec_version` 226 → 227 to absorb
two `pallet-perp-engine` changes:

1. **`governance_set_market` body** (replaces the spec-226 stub).
   - Origin: `EnsureRoot` (sudo / 2-of-3 multisig at the runtime
     wire-up).
   - 12 validation gates (mm < im, all bps fields ≤ 10_000, max_leverage
     ≤ chain cap, dust floor non-zero, min ≤ max position size, oracle
     feed id non-empty, market_id key == config.id, mark_ema_window > 0,
     funding_epoch > 0).
   - Duplicate-key rejection via the new `Error::MarketAlreadyExists`.
     v0 is create-only; updates land via a separate timelock-gated
     extrinsic in v1 per design memo §9.3.
   - Emits the new `Event::MarketRegistered { market_id,
     oracle_feed_id, initial_margin_bps, maintenance_margin_bps,
     max_leverage_bps, paused }`. Replaces the old (under-specified)
     `MarketSet` event — no external consumers to migrate.

2. **`liquidate` sub-rate fee floor** (PR-C sec-review LOW 2).
   - Fix: `fee_motra_u128` floors at 1 when `fee_e18 > 0`. Pre-fix the
     integer division `fee_e18 / payout_rate_e18` rounded to 0 for
     tiny-notional liquidations, robbing the keeper of payout despite
     a successful close.
   - Fee is paid from the position's locked margin (already
     `.min(pos.locked_margin_e18)`), so the extra unit is collateral,
     not pot drain.
   - Zero-fee liquidations still pay 0 — the floor only fires when
     `fee_e18 > 0`.

No new pallets, no new storage maps, no new Config items. `MarketConfig`
struct shape is unchanged → no v1→v2 migration needed.

## Pre-merge dependencies (cross-repo)

This PR ships the pallet-side changes in `materios-intent-settlement`.
The runtime-side spec-version bump lives in `materios-task180` (the
chain repo). The handoff:

1. **Merge this PR.** Record the merge commit SHA — that becomes the
   `pallet-perp-engine` rev pin.
2. **In `materios-task180`**:
   - `partnerchain/runtime/Cargo.toml`: bump `pallet-perp-engine` rev
     to the polish-PR merge tip.
   - `partnerchain/runtime/src/lib.rs`: bump `spec_version: 226` →
     `spec_version: 227`. Leave `transaction_version` unchanged
     (no breaking dispatch signature change — only validation gates,
     event/error variants).
3. **Run `./build-wasm.sh`** from this directory (set `REPO=...` env if
   the chain repo lives elsewhere, and `EXPECTED_PE_REV=<merge SHA>`
   for the rev-pin check).
4. **Run `./ceremony.py`** to fire the multisig sudo upgrade.

## File index

- `README.md` (this file)
- `build-wasm.sh` — builds the spec-227 WASM, asserts source-tree
  `spec_version == 227`, stages the override file, emits the
  `blake2_256` code hash.
- `ceremony.py` — 5-step multisig sudo ceremony: preflight,
  Nate-proposes, K2-approves, apply, postflight.
- `register_matra_usd_feed.py` — **manual post-ceremony step**.
  Registers 3 sr25519 attestor pubkeys for the MATRA/USD pair_id and
  (by default) writes a synthetic $0.10 seed price via sudo
  `System.set_storage`. The synthetic poke is a dev bootstrap — the
  real Aegis MATRA/USD publisher overwrites it on the first attestor
  tick. Pinned slot units per `feedback_oracle_poke_slot_units.md`
  (slot = current head, NOT block × 10).

## Postflight checks

The ceremony postflight asserts:

- `spec_version == 227`.
- `PerpEngine.MarketRegistered` event variant present in metadata.
- `PerpEngine.MarketAlreadyExists` error variant present in metadata.
- `PerpEngine.Markets[ADA-PERP/USD]` row preserved across the upgrade
  (spec-226 registered it via `Sudo.System.set_storage`; no migration
  in spec-227 should disturb it).

## After the ceremony

- Test the new dispatchable end-to-end: try registering BTC-PERP/USD
  via `Sudo.governance_set_market`. Confirm `MarketRegistered` fires
  and `Markets[BTC-PERP/USD]` populates.
- Run `./register_matra_usd_feed.py` to seed MATRA/USD attestors and
  the synthetic price.
- Start `aegis-publisher-preprod@matra-usd.service` on the publisher
  host (Node-2). The first attestor quorum tick replaces the
  synthetic seed with the live market rate.
