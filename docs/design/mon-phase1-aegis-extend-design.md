# MON Phase 1 — Aegis-extend Design Memo

**Task:** #268
**Date:** 2026-05-15
**Status:** DESIGN — pre-impl. Phase 1B (this dispatch) ships the pallet skeleton + canonical PRIC payload. Phase 1C wires Aegis daemon. Phase 1D wires runtime.

**Strategic anchor:** This is the SEED of the Materios Oracle Network. Not MON itself. Pull-oracle composition, slashing, external attestor onboarding, trimmed-median aggregation are explicitly v2+.

**Framing rule (per `feedback_aegis_extend_for_mon_phase1.md`):** EXTEND Aegis publishers; do NOT port them, do NOT compose with Charli3/Orcfax. Each Aegis publisher already signs Cardano L1 datums with an NFT-attested identity; MON Phase 1 adds ONE more `await materios.submit(...)` per tick to the same daemon.

---

## §1. `pallet-oracle` on Materios (greenfield design)

### Storage

```rust
/// One canonical PriceFeed per pair. Updated atomically once an M-of-N
/// pending bundle crosses threshold inside `submit_price`.
#[pallet::storage]
pub type Prices<T: Config> = StorageMap<
    _, Blake2_128Concat, PairId,
    PriceFeed<T::BlockNumber>, OptionQuery,
>;

/// Per-pair attestor registry. Lex-sorted by pubkey for deterministic
/// round-robin aggregation in v2. Sudo-managed in v1 via `register_attestor`.
#[pallet::storage]
pub type Attestors<T: Config> = StorageMap<
    _, Blake2_128Concat, PairId,
    BoundedVec<AttestorPubkey, T::MaxAttestors>, ValueQuery,
>;

/// PendingAttestations[(pair_id, slot_observed)] -> bounded list of
/// `(pubkey, price, sig)`. Cleared on threshold-cross by the call that
/// flips PriceFeed[pair_id]. Stale entries are GC'd by `on_initialize`
/// when their slot_observed is older than `MaxStaleSlots`.
#[pallet::storage]
pub type PendingAttestations<T: Config> = StorageDoubleMap<
    _, Blake2_128Concat, PairId,
    _, Blake2_128Concat, u64, // slot_observed
    BoundedVec<PriceObservation, T::MaxAttestors>, ValueQuery,
>;

/// Idempotency: prevents a single attestor from submitting twice for the
/// same (pair, slot). Key = (pair_id, slot, pubkey).
#[pallet::storage]
pub type AttestorSubmitted<T: Config> = StorageMap<
    _, Blake2_128Concat, (PairId, u64, AttestorPubkey), (), OptionQuery,
>;
```

### Extrinsics (v1)

```rust
/// Per-attestor submission. ONE attestor, ONE sig per call. Mirrors the
/// spec-220 `attest_settle` pattern (NOT the batch M-of-N pattern of
/// `request_voucher`), because Aegis publishers don't coordinate — they
/// each submit independently as their tick fires. The pallet accumulates
/// PendingAttestations[(pair_id, slot_observed)] until threshold is met,
/// then computes the median, flips PriceFeed[pair_id], and emits.
fn submit_price(
    origin,
    pair_id: PairId,
    price: u64,
    decimals: u8,
    slot_observed: u64,
    pubkey: AttestorPubkey,
    sig: AttestorSig,
) -> DispatchResult { ... }

/// Sudo-only in v1. Adds an attestor pubkey to a pair's roster.
/// Phase 2+ replaces this with bonded permissionless registration.
fn register_attestor(origin, pair_id: PairId, pubkey: AttestorPubkey) -> DispatchResult;
```

### Events

```rust
PriceUpdated {
    pair_id: PairId,
    price: u64,
    decimals: u8,
    observed_at_slot: u64,
    attestor_count: u32,
    aggregation: AggregationMethod,  // Median (v1)
},
PriceAttestationSubmitted {
    pair_id: PairId,
    slot_observed: u64,
    attestor: AttestorPubkey,
    pending_count: u32,
},
AttestorRegistered {
    pair_id: PairId,
    pubkey: AttestorPubkey,
},
```

### Constants

| Constant | Default | Rationale |
|---|---|---|
| `MinAttestorThreshold` | 3 | M-of-N quorum. Matches the Aegis preprod fleet size today (5 pairs × 1 publisher each → 1; with a second SPO-paired attestor → 2; aim for 3 once Witness Network pool grows). For v1 launch we set this to 1 (single Aegis publisher) and bump as the pool widens. |
| `MaxAttestors` | 16 | Per-pair cap. Plenty of headroom over the current 1 per pair; matches the 16-validator backbone in `project_validator_growth_plan.md`. |
| `MaxStaleSlots` | 1200 | Freshness window in slots (~2h at the current ~6s slot target). `submit_price` rejects observations whose `slot_observed < last_update_slot - MaxStaleSlots`. Phase 2 will tighten. |
| `MaxFutureSlots` | 50 | Reject `slot_observed > current_slot + 50` so a malicious attestor can't front-run themselves into the future. |
| `MaxPendingAttestationsPerPair` | 64 | Bound on `PendingAttestations` rows per pair — caps storage if a malicious attestor sprays slot numbers. |

### Read API (consumed by perp-engine + mm-rebate downstream)

```rust
impl<T: Config> Pallet<T> {
    /// Returns (price, decimals, observed_at_slot) or None if no feed yet.
    pub fn get_price(pair_id: PairId) -> Option<(u64, u8, u64)> {
        Prices::<T>::get(pair_id).map(|f| (f.last_price, f.last_decimals, f.last_update_slot))
    }

    /// Returns true iff the latest update is within `max_age_slots` of
    /// `current_slot`. Used by consumers (#257 mm-rebate, #259 perp-engine)
    /// for freshness invariants — e.g. perp-engine refuses to settle a
    /// liquidation against a price older than 600 slots (~1h).
    pub fn is_price_fresh(pair_id: PairId, current_slot: u64, max_age_slots: u64) -> bool {
        match Prices::<T>::get(pair_id) {
            Some(f) => current_slot.saturating_sub(f.last_update_slot) <= max_age_slots,
            None => false,
        }
    }
}
```

### Canonical signing payload (the cross-team parity anchor)

```
PRIC payload = blake2_256(
    b"PRIC"                         // 4-byte domain tag
    || chain_id        (32B)        // T::MateriosChainId — preprod vs mainnet
    || pair_id         (32B)        // sha256("ADA/USD") | sha256("BTC/USD") | ...
    || price           (LE u64)     // raw integer
    || decimals        (1B)         // 0..=18; price / 10^decimals = real value
    || slot_observed   (LE u64)     // Materios slot the publisher observed at
)
```

**Domain-separation rationale:**
- `b"PRIC"` separates from the seven existing intent-settlement tags (CRDP / STCL / RVCH / STBA / ABIN / RVBN / SBIN / STCA / BSTA / EXPP / INTA / CMTT / VCHR / BFPR / POLY / INTT / CLAM).
- `chain_id` prevents cross-chain replay (preprod → mainnet).
- `pair_id` is the **sha256 of the canonical UTF-8 pair string**. `sha256("ADA/USD") = 0x50cd6650c96bf3c016e7ce6acd4659cb6fc648e091813433f17ed75842833993`. Each pair_id is fixed forever per pair; pair string changes require a new pair_id (intentional — defends against silent re-meaning).
- `slot_observed` prevents replay across slots and serves as the monotonicity gate (`submit_price` enforces `slot_observed > last_update_slot` once threshold is crossed).
- `decimals` is part of the preimage so a malicious attestor cannot rebind a 6-decimal sig to an 18-decimal feed (price 1_000_000 means $1 at 6 decimals but $0.000001 at 18).

**Pinned test vector (PR fixture):**

| Field | Value |
|---|---|
| `pair` (string) | `"ADA/USD"` |
| `pair_id` (sha256) | `0x50cd6650c96bf3c016e7ce6acd4659cb6fc648e091813433f17ed75842833993` |
| `chain_id` | `[0x73; 32]` (test fixture, mirrors `TestMateriosChainId` from intent-settlement) |
| `price` | `425_000_000` (= $0.425) |
| `decimals` | `9` |
| `slot_observed` | `173_709` (spec-219 activation block — meaningful Materios milestone) |
| **preimage (hex)** | `50524943` (PRIC) ‖ `73…73` (chain_id) ‖ `50cd6650…3993` (pair_id) ‖ `40fc541900000000` (price LE) ‖ `09` (decimals) ‖ `8da6020000000000` (slot LE) — 85 bytes total |
| **digest (hex)** | `0x74f1ade6b8cab0be3dcaf4edddedd9df16c665a1f154a8ec224bde470a454ba2` |

This digest is asserted byte-exact in `pallets/oracle/src/tests.rs::pric_payload_byte_exact`.

---

## §2. Aegis publisher-side changes (Phase 1C — separate PR)

The Aegis publisher at `aegis-publisher/publisher/main.py` currently:
1. Polls 3+ price sources (line 220-223 `data_sources.fetch_median`).
2. Decides whether to publish based on cadence ceiling + deviation (`should_publish`).
3. Builds + signs + submits a Cardano L1 tx via `tx_builder.publish_price` (line 253).
4. Records success/failure in `state.json`.

**Phase 1C additive change** — after step 3, BEFORE state save, add ONE new helper call:

```python
# publisher/materios_rail.py (new module, ~80 lines)
from substrateinterface import SubstrateInterface, Keypair
from hashlib import sha256, blake2b

PRIC_TAG = b"PRIC"

def pair_id_for(pair_str: str) -> bytes:
    return sha256(pair_str.encode("utf-8")).digest()

def pric_payload(chain_id: bytes, pair_id: bytes, price: int, decimals: int, slot: int) -> bytes:
    return blake2b(
        PRIC_TAG + chain_id + pair_id
        + price.to_bytes(8, "little")
        + bytes([decimals])
        + slot.to_bytes(8, "little"),
        digest_size=32,
    ).digest()

def submit_to_materios(rpc_url, keypair, chain_id, pair_str, price, decimals, slot) -> str:
    pair_id = pair_id_for(pair_str)
    digest = pric_payload(chain_id, pair_id, price, decimals, slot)
    sig = keypair.sign(digest)
    si = SubstrateInterface(url=rpc_url)
    call = si.compose_call(
        call_module="Oracle",
        call_function="submit_price",
        call_params={
            "pair_id": "0x" + pair_id.hex(),
            "price": price,
            "decimals": decimals,
            "slot_observed": slot,
            "pubkey": "0x" + keypair.public_key.hex(),
            "sig": "0x" + sig.hex(),
        },
    )
    extrinsic = si.create_signed_extrinsic(call=call, keypair=keypair)
    receipt = si.submit_extrinsic(extrinsic, wait_for_inclusion=False)
    return receipt.extrinsic_hash
```

Wired in `main.py::publish_cycle` after the existing publish_price success:

```python
if cfg.materios_rpc_url:                       # ← env-gated, opt-in
    try:
        mtx = submit_to_materios(
            cfg.materios_rpc_url, materios_keypair,
            cfg.materios_chain_id, cfg.pair,
            cur_scaled, PRICE_SCALE_DECIMALS,
            int(time.time()),  # placeholder; Phase 1C swaps for live Materios slot
        )
        logger.info("materios rail tx=%s", mtx)
        monitor.record_materios_rail_success()
    except Exception as e:
        logger.warning("materios rail FAILED (Cardano rail still primary): %s", e)
        monitor.record_materios_rail_failure()
```

**Critical design decisions on the daemon side:**

1. **Env-gated rollout.** `MATERIOS_RPC_URL` absent → second rail disabled. Same daemon binary runs on a pair that's been onboarded (Materios rail ON) and one that hasn't (Materios rail OFF). Lets us roll out one pair at a time. Mirrors the AEGIS_PRICE_FEED feature-flag pattern.

2. **Failure on the Materios rail must NOT fail the Cardano rail.** Wrap in try/except, log warning, never raise. Cardano publishes are the existing customer surface; Materios rail must be additive, never regressive.

3. **Same signing identity, different curve.** Each Aegis publisher already has an sr25519-shaped Materios committee key from the Materios committee growth (some publishers are already committee members; some aren't yet). Phase 1C onboarding step: ensure each of the 10 publisher processes (5 preprod + 5 mainnet) has a registered Materios sr25519 key. The 32-byte pubkey is the SAME identity that signs Cardano L1 datums — just used through the sr25519 ESS, not Ed25519.
   - Open implementation question: Aegis publishers currently sign Cardano with pycardano (Ed25519). Materios committee keys are sr25519. We do NOT reuse the literal key bytes — we generate an sr25519 key per pair-publisher process and register it via `register_attestor`. The "same identity" is a policy concept (one daemon process = one attestor identity = signs both rails), not a literal key reuse.

4. **Slot source.** Phase 1C v1 uses `int(time.time())` as a placeholder Materios slot (the pallet will accept any monotonically increasing u64). Phase 1D swaps for live RPC `chain.getHeader().number` once the runtime is wired.

5. **Wallet-lock contract.** The publisher's `_wallet_lock(cfg.wallet_lock_path)` serialises Cardano tx-building across the 5 templated instances on Node-2. The Materios rail does NOT take this lock — Materios extrinsics have no shared-UTxO contention (each attestor has its own substrate account, nonces are per-account). The rail submission runs in parallel with other pair daemons.

---

## §3. M-of-N composition: per-attestor submit, pallet-side aggregation

**Per-attestor submits, NOT batch.** Each Aegis publisher submits independently — no coordination layer. This matches the spec-220 `attest_settle` pattern (one signer per call → pallet accumulates → flips state on threshold).

Flow:
1. Publisher P1 (ADA/USD on Node-2 preprod) computes median price $0.425, scaled to `425_000_000` u64 with 9 decimals.
2. P1 calls `submit_price(pair_id_ada_usd, 425_000_000, 9, slot=173709, pk_p1, sig_p1)`.
3. Pallet validates: pk_p1 ∈ `Attestors[pair_id_ada_usd]`, sig_p1 verifies against PRIC payload, slot is fresh, P1 hasn't already submitted for (pair_id_ada_usd, 173709).
4. Pallet pushes `(pk_p1, 425_000_000, sig_p1)` into `PendingAttestations[(pair_id_ada_usd, 173709)]`.
5. If `bundle.len() >= MinAttestorThreshold`:
   - Compute aggregated price (v1: median; v2: 20/20 trimmed median per `materios-oracle-design.md` §4).
   - Insert `PriceFeed { last_price, last_decimals, last_update_slot: 173709, attestor_set: bundle_pubkeys }` into `Prices[pair_id_ada_usd]`.
   - Clear `PendingAttestations[(pair_id_ada_usd, 173709)]`.
   - Emit `PriceUpdated`.
6. If threshold not yet met: emit `PriceAttestationSubmitted` with `pending_count`.

**Why not batch-sigs?** The intent-settlement batch pattern (`request_batch_vouchers`) requires the keeper to collect M sigs off-chain before submitting. Oracle attestors are independent processes with NO out-of-band coordination — there's no keeper to batch. Per-attestor submits naturally match how the publishers run.

**Why not aggregate-then-attest?** That's the spec-205 model (proposer collects, signs once). Same problem — no proposer in the publisher fleet.

**Aggregation policy (v1 vs v2):**
- v1 (this scaffolding): plain median when threshold is crossed. If `MinAttestorThreshold == 1`, the lone submitter's price wins unchanged.
- v2: 20/20 trimmed median per `materios-oracle-design.md §4`. Requires M >= 5 to be useful; we ship plain median until the attestor pool grows.

---

## §4. Per-pair publisher identities

Each Aegis publisher process gets its own sr25519 Materios key and SS58. Total: **10 attestor identities** (5 preprod + 5 mainnet, since preprod and mainnet are different Materios chains — `MateriosChainId` differs, sigs are not cross-chain valid).

For v1 Phase 1C-1D, we onboard the **5 preprod** publishers first (Node-2):

| Pair | Service | Materios attestor SS58 | Cardano NFT policy |
|---|---|---|---|
| ADA/USD | `aegis-publisher-preprod@ada-usd.service` | TBD generated Phase 1C | `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f` |
| BTC/USD | `aegis-publisher-preprod@btc-usd.service` | TBD | `ae304e27...` |
| ETH/USD | `aegis-publisher-preprod@eth-usd.service` | TBD | `d80aa1a7...` |
| USDT/USD | `aegis-publisher-preprod@usdt-usd.service` | TBD | `a4093bfc...` |
| USDC/USD | `aegis-publisher-preprod@usdc-usd.service` | TBD | `860faa66...` |

**Registration ceremony (Phase 1C):** sudo runs `register_attestor(pair_id, attestor_pubkey)` for each of the 5 preprod pairs on the preprod runtime once `pallet-oracle` is wired into the runtime. Mnemonic for each attestor is generated on Node-2 and stored at `/home/aegis/aegis-publisher-preprod/keys/<pair>.mnemonic` (mode 0600, owner `aegis`). Public key is recorded in this memo for audit. Phase 2 hardens onboarding into a bonded permissionless flow.

**Mainnet rollout:** AFTER preprod soak >= 14 days at MinAttestorThreshold=1 with no divergence. Then expand fleet (Witness Network, Node-3, Hetzner) to M=3.

---

## §5. Threshold + slashing — v2 punt

**v1 (this PR + Phase 1C/D):**
- `MinAttestorThreshold = 1` at chain genesis. Single Aegis publisher → single source. **Honest gap-naming:** at `M=1` this is functionally a feed-mirror, NOT M-of-N consensus. The integrity guarantee is "this attestor said so, signed under PRIC, cross-chain replay-proof." That's strictly better than nothing — it's exactly the trust level the existing Cardano Aegis rail provides today.
- Sudo can bump threshold via a governance call (similar to `set_min_signer_threshold` in intent-settlement). Once Node-3 and Hetzner publishers are registered as attestors per pair, threshold rises to 3.

**v2 (separate task):**
- Equivocation slash: if attestor A submits two different prices for the SAME `(pair_id, slot_observed)`, both submissions become evidence in a permissionless slash call. Bond goes to slasher.
- Liveness slash: per-pair attestor that misses >50% of slots over rolling 7-day window loses bond pro-rata.
- Bond requirements: per `materios-oracle-design.md §7` — `max(10_000 MATRA, M × 100)` per pair.

---

## §6. Risk vectors (v1)

| # | Threat | Mitigation (v1) | Residual / v2 fix |
|---|---|---|---|
| R1 | Single publisher compromised → garbage price | Aggregation crosses threshold ONLY when `pending.len() >= MinAttestorThreshold`. At M=1 this is the trust model we're shipping with; at M>=3 the trimmed median absorbs 1 bad actor. | v2: trimmed median + slashing on equivocation |
| R2 | Replay across slots (resubmit yesterday's sig with new slot) | `slot_observed` is in the preimage; pallet enforces strict monotonicity — `PendingAttestations` rows where `slot_observed <= last_update_slot` are rejected on submit. Plus `MaxStaleSlots` GC. | None — fully fixed by design |
| R3 | Cross-chain replay (preprod sig accepted on mainnet) | `chain_id` is in the preimage. Mainnet runtime sets `T::MateriosChainId` to mainnet genesis hash; preprod sigs don't verify on mainnet's chain_id and vice versa. Same defense pattern as `feedback_chain_reset_committee_bond_starvation.md` (faucet ledger namespaced by genesis hash). | None — fully fixed |
| R4 | Cross-pair replay (ADA/USD sig accepted on BTC/USD) | `pair_id` is in the preimage. Different pair strings hash to different pair_ids; a signature over (sha256("ADA/USD"), 425_000_000, …) does not verify against (sha256("BTC/USD"), 425_000_000, …). | None — fully fixed |
| R5 | Cross-decimals replay (6-dec sig replays at 18-dec) | `decimals` is in the preimage. | None — fully fixed |
| R6 | Attestor sprays slot numbers to DoS `PendingAttestations` | `MaxPendingAttestationsPerPair` caps storage growth; `on_initialize` GC's stale rows; per-attestor `AttestorSubmitted` map blocks the same attestor submitting twice per slot. | None — bounded |
| R7 | sudo-only `register_attestor` is centralised | Yes — v1 is permissioned. Matches `project_validator_growth_plan.md` "lock backbone first, grow chunked." Aegis fleet IS the FPS-controlled initial backbone. | v2: bonded permissionless registration |
| R8 | Materios rail outage silently breaks consumer freshness | `is_price_fresh(pair_id, current, max_age)` API. Downstream pallets (#257 mm-rebate, #259 perp-engine) MUST gate on freshness. | None — pushed to consumers |
| R9 | Aegis publisher binary supply-chain compromise | OUT OF SCOPE for v1. Same risk surface exists today on Cardano-only Aegis. Mitigated by Aegis publisher repo signing, deploy-key rotation. | v3 (TEE-attested publishers; see `project_compute_portal_trust_roadmap.md` Wave 3) |

---

## §7. Out-of-scope for Phase 1

Explicitly NOT in this PR or the immediate follow-up Aegis-side PR:
1. **Slashing.** v2 task. Bond + slash via equivocation evidence + liveness pro-rata.
2. **On-chain pull-oracle composition.** Phase 2+. Consumers in this Phase 1 read via the `Oracle::get_price` runtime API, not a pull adapter.
3. **External attestor onboarding.** v3 task. Phase 1 = FPS-controlled Aegis publishers only. Bonded permissionless registration is the v2 economic gate; v3 adds the marketplace + KYC-free flow.
4. **Trimmed-median aggregation.** v2 task. v1 ships plain median (or single-value passthrough at M=1).
5. **Cardano rail interop with the Materios feed.** v2 task. For v1 the two rails are independent — Cardano consumers see the existing NFT datum, Materios consumers see `Prices[pair_id]`. No cross-rail "if Materios disagrees, slash" yet.
6. **Round-robin aggregator + Cardano-side republishing.** Per `materios-oracle-design.md §5`, the future architecture has Materios attestors picking a round-robin aggregator each slot to republish to Cardano. For Phase 1 the Aegis publisher itself does both publishes (Cardano L1 first, Materios second) so there's no aggregator role yet.
7. **Fee distribution to attestors.** v2. Reuses the pallet-billing reward-distribution pattern from `project_phase_2a_code_complete.md`.

---

## §8. Implementation phase plan

| Phase | What lands | DoD |
|---|---|---|
| **1A — this memo** | Scoping memo (this file) | All 7 sections present, concrete enough for next agent to impl from |
| **1B — this PR** | Pallet skeleton + canonical PRIC payload + 5 tests | `cargo build -p pallet-oracle` clean; tests pass; payload byte-vector pinned; PR draft opened |
| **1C — separate PR** | Aegis publisher Materios rail module + per-pair env wiring + monitor counters | All 5 preprod publishers running with `MATERIOS_RPC_URL` set; sr25519 keys generated + recorded; rail can be flipped on/off per pair |
| **1D — separate PR** | Pallet runtime wiring (materios chain) + dispatch impl (currently `Ok(())` stubs) + benchmarks + `register_attestor` ceremony script | All 5 preprod pairs have an attestor registered; ADA/USD ticks landing on preprod with `PriceUpdated` event; `Oracle::get_price(pair_id_ada_usd)` returns non-None |
| **1E — soak** | 14 days of preprod data, alerts dashboard, divergence counter | Zero divergence-counter increments over 14d; Materios rail uptime ≥ Cardano rail uptime |
| **1F — mainnet flip** | Repeat 1C onboarding for 5 mainnet publishers; flip `MATERIOS_RPC_URL` to mainnet endpoint | First mainnet `PriceUpdated` event |

After 1F: MON Phase 1 is shipped. Phase 2 (slashing, trimmed median, M=3) follows from real preprod+mainnet data.

---

## §9. Compounding-leverage accounting

What MON Phase 1 makes more valuable:
- **Aegis publisher fleet (5+5 live)** — gains a second revenue surface (MATRA-denominated attestation reward; today Aegis publishers cost ADA and earn nothing).
- **Materios chain** — gains a price oracle, unblocks perp-engine (#259) and mm-rebate (#257) and Saturnswap CLOB launch.
- **NFT-attested publisher identity** — same Cardano NFT policy (`f0f14cd0…` etc.) now identifies a publisher that ALSO attests on Materios. Cross-chain audit trail per publisher.
- **Committee governance pallet** — `Attestors[pair_id]` map is a natural extension of the committee-membership pattern; we reuse `pallet-committee-governance` traits (`IsCommitteeMember`-style) without rebuilding.
- **Witness Network APK fleet** — Phase 3+ candidate attestor pool. Each TEE-attested phone could run an oracle attestor module; same KeyMint-signed payload pattern as `project_witness_network_mvp_live_20260513.md`.

What MON Phase 1 does NOT replace:
- The Cardano Aegis rail. Cardano DeFi consumers keep their existing NFT datum feed. This is **additive**.

---

## §10. References

- `feedback_aegis_extend_for_mon_phase1.md` — framing rule (extend, not port).
- `project_materios_oracle_network.md` — Option A locked design (subset of what Phase 1 ships).
- `project_aegis_publisher_deploy.md` — existing 5+5 publisher fleet topology.
- `materios-oracle-design.md` — full 12-section product spec (Phase 1 is the first slice).
- `pallets/intent-settlement/src/lib.rs` — pattern source for `ensure_threshold_signatures`, domain-tagged payloads, M-of-N storage.
- `pallets/intent-settlement/src/types.rs` — pattern source for canonical payload helpers + tests.
- `feedback_mofn_hash_determinism.md` — rule applied: only chain-derived state in preimage; no operator-local fields.
