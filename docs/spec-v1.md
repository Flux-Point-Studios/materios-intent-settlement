# Materios Intent-Settlement Layer — Wave 1 Interface Contract Spec v1

**Status:** LOCKED spec, build-ready. Wave 2 TDD teams (A/B/C) code against this document.
**Date:** 2026-04-20
**Author agent:** `materios-wave-1-spec-2026-04-20`
**Predecessor:** `/home/deci/materios-intent-settlement-decisions.md` (6 product decisions + repo strategy locked by Nathaniel)
**Scope:** single source of truth for type layout, extrinsic surface, validator redeemers, keeper protocol, and cross-layer conventions.

> **Repo target matrix.** `pallet_intent_settlement` + `pallet_committee_governance` + keeper service + TS/Rust SDK land in a NEW repo `Flux-Point-Studios/materios-intent-settlement` (to be created by Wave 2 Team A as first PR). The Aiken validator library `aegis-aiken-v1` plus the Aegis dApp frontend land in the existing PRIVATE repo `Flux-Point-Studios/aegis-parametric-insurance-dev`. No code in either repo today — this spec predates both.

> **Live-state reminder.** Materios preprod v5 genesis `0xbc0531cb311281565036fb397a376f0e0fa37005589655f97a7924b2729a164c`; committee 4 validators + 3 attestors, threshold 2; cardano-mainnet-anchor wallet + `materios-anchor-worker` already in production for label-8746 checkpoints (`/home/deci/materios-anchor-worker/index.mjs`). Do not duplicate that infra — reuse it.

---

## 0. Terminology and Actors

| Term | Meaning |
|---|---|
| **Materios** | The Substrate partner chain. Where intents live. 6s blocks. |
| **Cardano** | Layer 1. Where ADA money actually settles. 20s blocks, 1s slots post-Shelley. |
| **Committee** | The M-of-N set of Materios validator+attestor SS58 keys authorized to sign attestations. Currently 2-of-7, expansion to 5-of-11 in flight. |
| **Intent** | A user's signed request ("I want coverage", "I want to claim", "refund my credit") stored in `pallet_intent_settlement::Intents`. |
| **Voucher** | A committee-signed permission slip that authorizes the keeper to redeem one or more claims against Cardano pool UTxOs. |
| **Keeper** | Permissionless off-chain actor. Polls Materios, builds Cardano txs, collects a fee. Anyone with ADA tx-building capacity can run one. |
| **Batch** | The set of intents a keeper bundles into one Cardano tx + its accompanying fairness proof. |
| **MATRA** | Materios capital token, 6 decimals, bridges 1:1 to cMATRA on Cardano. Not used in Aegis v1 user flow (ADA-only). |
| **MOTRA** | Non-transferable fee token, 15 decimals, auto-generated from MATRA holdings. All Materios extrinsics pay gas in MOTRA. |
| **Cert-daemon** | Existing Python daemon in `operator-kit@cdc35c2` that each committee member runs. Signs attestations, handles retries, writes to blob gateway. Aegis attestations reuse this process with a new payload type. |

---

## 1. Type Definitions — Single Source of Truth

The key cross-layer correctness property: **every bytestring that the Materios pallet hashes must be bytewise identical to the bytestring the Aiken validator hashes**. If the pallet encodes a field in little-endian u64 and Aiken decodes it as big-endian u64, committee sigs verify on-chain but the validator rejects them. We lock byte layout first, types second.

### 1.1 Hashing — Blake2b-256, canonical pre-image

- **Substrate side:** `sp_core::hashing::blake2_256` (a.k.a. `Blake2b-256`, 32-byte output).
- **Cardano side:** `aiken/crypto.blake2b_256` (same algorithm, same output length).
- **Endianness:** all integer fields encoded little-endian (SCALE default on Substrate side; Aiken side encodes via `cbor.serialise` and we pin CBOR encoders that emit definite-length little-endian bytes for u-ints wrapped in `bytes`).
- **Domain separation:** every hash pre-image is prefixed with a 4-byte ASCII domain tag so you can never mistake an `IntentId` for a `ClaimId` even in isolation.
    - `b"INTT"` → IntentId
    - `b"POLY"` → PolicyId
    - `b"CLAM"` → ClaimId
    - `b"VCHR"` → Voucher digest
    - `b"BFPR"` → BatchFairnessProof digest
    - `b"CMTT"` → CommitteePubkeySet digest

Rust:
```rust
pub fn domain_hash(tag: [u8; 4], body: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(body);
    sp_core::hashing::blake2_256(&buf)
}
```

Aiken:
```
fn domain_hash(tag: ByteArray, body: ByteArray) -> Hash<Blake2b_256, a> {
    blake2b_256(bytearray.concat(tag, body))
}
```

### 1.2 Encoding — SCALE is canonical, CBOR mirrors

All on-Materios storage and events use SCALE (Substrate default). The Aiken side must reproduce the SCALE pre-image for any field it hashes. **We do not hash CBOR on either side** — Aiken's own datum serialisation is CBOR for datum layout, but every hash-input is a raw SCALE-encoded byte blob that Aiken treats as opaque `ByteArray`. This avoids the "round-trip through Aiken CBOR decoder" correctness hazard.

Concretely: when the keeper submits a batch to Cardano, the Aiken validator receives the raw SCALE-encoded intent bytes as a `ByteArray` field in the redeemer, then calls `blake2b_256` on the domain-tagged byte slice exactly like the pallet did — and checks that the committee signatures verify over the same bytes. The Aiken validator does **not** reparse the intent fields; it treats them as an opaque blob secured by the committee signature.

Where the Aiken side needs semantic access (e.g. the `PolicyDatum` stored at the pool script) we define a native Aiken CBOR datum shape — those are Aiken-native and don't cross the bridge.

### 1.3 Primitive types

```rust
// Materios / SCALE
pub type IntentId = H256;        // 32-byte Blake2b-256
pub type PolicyId = H256;
pub type ClaimId = H256;
pub type BlockNumber = u32;
pub type Nonce = u64;             // per-account replay counter
pub type AdaLovelace = u64;       // 1 ADA = 1_000_000 lovelace, matches Cardano u64 cap
pub type MotraBalance = u128;     // 15-dec
pub type SlotNumber = u64;        // Cardano slot
pub type CommitteePubkey = [u8; 32];   // ed25519, see §1.5
pub type CommitteeSig = [u8; 64];      // ed25519
```

Aiken equivalents:
```
type IntentId      = Hash<Blake2b_256, ByteArray>
type PolicyId      = Hash<Blake2b_256, ByteArray>
type ClaimId       = Hash<Blake2b_256, ByteArray>
type AdaLovelace   = Int
type SlotNumber    = Int
type CommitteePubkey = VerificationKey
type CommitteeSig  = Signature
```

### 1.4 `Intent` — the atomic unit

```rust
#[derive(Encode, Decode, TypeInfo, Clone, Eq, PartialEq, Debug)]
pub struct Intent {
    pub submitter: AccountId,        // SS58, 32 bytes
    pub nonce: Nonce,                // u64 little-endian
    pub kind: IntentKind,            // enum, 1 byte discriminant + body
    pub submitted_block: BlockNumber,
    pub ttl_block: BlockNumber,      // absolute expiry, not delta
    pub status: IntentStatus,
}

#[derive(Encode, Decode, TypeInfo, Clone, Eq, PartialEq, Debug)]
pub enum IntentKind {
    /// User wants to open a new policy with paid premium.
    BuyPolicy {
        product_id: H256,              // identifies which aegis-policy-v1 instance
        strike: u64,                   // product-defined units (e.g. ADA/USD × 10^6)
        term_slots: u32,
        premium_ada: AdaLovelace,
        beneficiary_cardano_addr: BoundedVec<u8, ConstU32<114>>, // bech32 up to mainnet size
    },
    /// User wants to request a payout on an existing policy.
    RequestPayout {
        policy_id: PolicyId,
        oracle_evidence: BoundedVec<u8, ConstU32<512>>, // opaque; Aiken checks Charli3 at tx-time
    },
    /// User wants their pre-funded credit back.
    RefundCredit {
        amount_ada: AdaLovelace,
    },
}

#[derive(Encode, Decode, TypeInfo, Clone, Copy, Eq, PartialEq, Debug)]
pub enum IntentStatus {
    Pending   = 0,
    Attested  = 1,
    Vouchered = 2,
    Settled   = 3,
    Expired   = 4,
    Refunded  = 5,
}
```

**IntentId canonical pre-image:**
```
domain_hash(b"INTT",
    submitter (32B) || nonce (u64 LE) || scale_encode(IntentKind) || submitted_block (u32 LE))
```
Note that `ttl_block` and `status` are NOT in the pre-image — they're state that evolves; the IntentId must be stable across status transitions so the committee can sign it once and it stays valid.

Aiken mirror:
```
type Intent {
    submitter: ByteArray,           // 32B SS58 pubkey
    nonce: Int,
    kind_raw: ByteArray,            // raw SCALE-encoded IntentKind bytes; Aiken never reparses
    submitted_block: Int,
}

// Reconstruct IntentId inside validator:
// blake2b_256(#"494e5454" ++ intent.submitter ++ int_to_le_64(intent.nonce) ++ intent.kind_raw ++ int_to_le_32(intent.submitted_block))
```

### 1.5 `CommitteeSig` — ed25519 (justified)

**DECISION: ed25519.** Rationale:

1. Aiken / Plutus V3 ship `builtin.verify_ed25519_signature` natively; `sr25519` has no on-chain verifier on Cardano (would require a custom Plutus implementation, which nobody has audited).
2. Materios validator keys already include a `grandpa` ed25519 key alongside the sr25519 `aura` key. Committee members can reuse their existing grandpa key OR, cleaner, derive a dedicated `aegis_attestor` ed25519 key from their validator mnemonic at path `//aegis`.
3. Signing cost on Materios is trivially cheap either way; the only cost asymmetry is on-Cardano verification, which Aiken makes ed25519 cheap.

Trade-off acknowledged: sr25519 multisignature aggregation (Schnorr-linear) would be elegant but unusable by Aiken. Ed25519 sigs are verified individually inside the validator, M times per voucher. At M=2 today (rising to 5 post-expansion) this is ~5 ed25519 verifies = ~5k execution units, well under Cardano's limit.

Pallet storage uses `CommitteePubkey = [u8; 32]` (ed25519 raw pubkey). Each committee member registers their ed25519 pubkey via `pallet_committee_governance::propose_add_member`. The sr25519 Aura/SS58 key is still used for signing Materios extrinsics (as today); it is a **separate key** from the aegis-attestor ed25519 key. Cert-daemon needs both keys available.

### 1.6 `BatchFairnessProof`

```rust
#[derive(Encode, Decode, TypeInfo, Clone, Eq, PartialEq, Debug)]
pub struct BatchFairnessProof {
    pub batch_block_range: (BlockNumber, BlockNumber),   // inclusive
    pub sorted_intent_ids: BoundedVec<IntentId, ConstU32<256>>,    // FCFS ordering, tiebreak by IntentId
    pub requested_amounts_ada: BoundedVec<AdaLovelace, ConstU32<256>>, // parallel to sorted_intent_ids
    pub pool_balance_ada: AdaLovelace,                    // pool balance observed at tx-build time
    pub pro_rata_scale_bps: u32,                          // 10000 = 100% (no scaling), 3000 = 30% haircut
    pub awarded_amounts_ada: BoundedVec<AdaLovelace, ConstU32<256>>, // final payouts
}
```

**BatchFairnessProof digest:**
```
domain_hash(b"BFPR", scale_encode(BatchFairnessProof))
```

The committee signs the BFPR digest, not the full proof body. The digest + sigs go into the Cardano metadata (label 8746) payload; the full proof is recoverable from the Materios chain by any auditor (it's emitted as an event at attestation time).

Invariants enforced by the Aiken validator:
- `sum(awarded_amounts_ada) <= pool_balance_ada`
- `pro_rata_scale_bps <= 10000`
- For each `i`: `awarded_amounts_ada[i] == requested_amounts_ada[i] * pro_rata_scale_bps / 10000`
- `sorted_intent_ids` is strictly ascending (FCFS by submitted_block, tiebreak by IntentId bytes)

### 1.7 `Voucher`

```rust
#[derive(Encode, Decode, TypeInfo, Clone, Eq, PartialEq, Debug)]
pub struct Voucher {
    pub claim_id: ClaimId,
    pub policy_id: PolicyId,
    pub beneficiary_cardano_addr: BoundedVec<u8, ConstU32<114>>,
    pub amount_ada: AdaLovelace,
    pub batch_fairness_proof_digest: [u8; 32],    // ties voucher to an anchored BFPR
    pub issued_block: BlockNumber,
    pub expiry_slot_cardano: SlotNumber,           // redemption window on Cardano
    pub committee_sigs: BoundedVec<(CommitteePubkey, CommitteeSig), ConstU32<32>>,
}
```

**Voucher digest (signed by each committee member):**
```
domain_hash(b"VCHR",
    claim_id (32B) || policy_id (32B) || beneficiary_addr_bytes || amount_ada (u64 LE)
    || batch_fairness_proof_digest (32B) || issued_block (u32 LE) || expiry_slot_cardano (u64 LE))
```

The beneficiary address is included in the pre-image so the committee is committing to a specific payout destination, not just a claim amount — prevents a captured keeper from redirecting payouts.

### 1.8 Events on Materios

```rust
#[pallet::event]
pub enum Event<T: Config> {
    IntentSubmitted   { intent_id: IntentId, submitter: T::AccountId, nonce: Nonce },
    IntentAttested    { intent_id: IntentId, attestors: BoundedVec<CommitteePubkey, T::MaxCommittee> },
    VoucherIssued     { claim_id: ClaimId, voucher_digest: [u8; 32], fairness_proof_digest: [u8; 32] },
    ClaimSettled      { claim_id: ClaimId, cardano_tx_hash: [u8; 32], settled_direct: bool },
    IntentExpired     { intent_id: IntentId, reason: ExpiryReason },
    CreditRefundRequested { intent_id: IntentId, submitter: T::AccountId, amount_ada: AdaLovelace },
    CreditsCredited   { account: T::AccountId, delta_ada: AdaLovelace, source_cardano_tx: [u8; 32] },
    // Committee governance events (see §3)
    MemberAdded         { pubkey: CommitteePubkey, effective_block: BlockNumber },
    MemberRemoved       { pubkey: CommitteePubkey, effective_block: BlockNumber },
    ThresholdChanged    { old: u32, new: u32, effective_block: BlockNumber },
    RotationProposed    { schedule_digest: [u8; 32], timelock_expires: BlockNumber },
    RotationExecuted    { schedule_digest: [u8; 32] },
    CardanoMirrorUpdated{ committee_set_digest: [u8; 32], mirror_tx: [u8; 32] },
}
```

### 1.9 Committee event taxonomy

```rust
#[derive(Encode, Decode, TypeInfo, Clone, Eq, PartialEq, Debug)]
pub enum CommitteeEvent {
    Added { pubkey: CommitteePubkey },
    Removed { pubkey: CommitteePubkey },
    RotatedPubkey { old: CommitteePubkey, new: CommitteePubkey },
    ExpandedThreshold { old: u32, new: u32 },
}
```

---

## 2. `pallet_intent_settlement` — Wave 2 Team A

### 2.1 Storage

```rust
#[pallet::storage]
pub type Intents<T> = StorageMap<_, Blake2_128Concat, IntentId, Intent, OptionQuery>;

#[pallet::storage]
pub type Nonces<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Nonce, ValueQuery>;

/// ADA credits denominated in lovelace. Increases when keeper observes a Cardano deposit;
/// decreases when user consumes credit on a BuyPolicy or RefundCredit.
#[pallet::storage]
pub type Credits<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, AdaLovelace, ValueQuery>;

#[pallet::storage]
pub type Claims<T> = StorageMap<_, Blake2_128Concat, ClaimId, Claim, OptionQuery>;

#[pallet::storage]
pub type Vouchers<T> = StorageMap<_, Blake2_128Concat, ClaimId, Voucher, OptionQuery>;

/// Expiry queue: block -> list of intent_ids to sweep in on_initialize.
#[pallet::storage]
pub type ExpiryQueue<T> =
    StorageMap<_, Blake2_128Concat, BlockNumber, BoundedVec<IntentId, ConstU32<256>>, ValueQuery>;

/// Records which batches have been exported, so the keeper gets a resumable cursor.
#[pallet::storage]
pub type LastExportedBlock<T> = StorageValue<_, BlockNumber, ValueQuery>;

#[pallet::storage]
pub type IntentTTL<T> = StorageValue<_, BlockNumber, ValueQuery>;  // default 600 blocks (~1h)

#[pallet::storage]
pub type ClaimTTL<T> = StorageValue<_, BlockNumber, ValueQuery>;   // default 28_800 blocks (~48h)
```

### 2.2 Extrinsics

| # | Extrinsic | Origin | Purpose | Fee (MOTRA) |
|---|---|---|---|---|
| 1 | `submit_intent(kind: IntentKind)` | Signed | Persists a new Intent with auto-incremented nonce; writes to `Intents`, `ExpiryQueue`. For `BuyPolicy`: debits `Credits[who]` by `premium_ada`. For `RefundCredit`: debits credits immediately (atomic; prevents double-spend of credit). | ~500k MOTRA base; fee computed by weight × `length_fee_per_byte` |
| 2 | `attest_intent(intent_id, sigs: Vec<(CommitteePubkey, CommitteeSig)>)` | Committee member (via signed origin whose SS58 is in `Members`) | Verifies M-of-N ed25519 sigs over the IntentId pre-image; transitions Intent from `Pending → Attested`. First committee member to post a valid M-of-N bundle wins; subsequent calls are no-ops. | **0 MOTRA** (subsidized from pallet treasury) |
| 3 | `request_voucher(claim_id, voucher, fairness_proof)` | Committee member | Verifies all voucher-committee sigs, validates fairness proof invariants, transitions bound Intent from `Attested → Vouchered`, stores `Voucher` at `Vouchers[claim_id]`, emits `VoucherIssued`. | 0 MOTRA |
| 4 | `request_credit_refund(amount_ada)` | Signed | Sugar wrapper: auto-builds an `IntentKind::RefundCredit` and calls `submit_intent` internally. Enforces 1-epoch dwell (5 Cardano days = ~72000 Materios blocks; the dwell counter is per-account). Rejects if `Credits[who] < amount_ada`. | ~500k MOTRA |
| 5 | `settle_claim(claim_id, cardano_tx_hash: [u8;32], settled_direct: bool)` | Committee member | Mirrors back a completed Cardano settlement. Transitions `Claim` to `Settled`. The `settled_direct` flag indicates whether the settlement came via keeper batch (false) or user direct-path Claim (true). | 0 MOTRA |
| 6 | `credit_deposit(who, amount_ada, cardano_tx_hash)` | Committee member | Called by the committee after observing a confirmed Cardano deposit to the premium-collector script. Adds to `Credits[who]`. Idempotent via `(who, cardano_tx_hash)` deduplication in a `ProcessedDeposits` set. | 0 MOTRA |

**Why attestation extrinsics are free-on-Materios:** committee members are already running infrastructure, already MOTRA-funded via MATRA holdings. Charging them for each attestation creates a treadmill we don't need. The pallet holds a fixed MOTRA subsidy (seeded via multisig-sudo at v1 launch, replenished from receipts treasury thereafter) that covers attestation weight.

### 2.3 `on_initialize` — TTL sweep

```rust
fn on_initialize(n: BlockNumber) -> Weight {
    let mut weight = T::DbWeight::get().reads(1);
    if let Some(to_expire) = ExpiryQueue::<T>::take(n) {
        for intent_id in to_expire {
            if let Some(mut intent) = Intents::<T>::get(&intent_id) {
                if intent.status == IntentStatus::Pending || intent.status == IntentStatus::Attested {
                    intent.status = IntentStatus::Expired;
                    // Refund any reserved credit on expiry
                    if let IntentKind::BuyPolicy { premium_ada, .. } = &intent.kind {
                        Credits::<T>::mutate(&intent.submitter, |c| *c = c.saturating_add(*premium_ada));
                    }
                    Intents::<T>::insert(&intent_id, intent);
                    Self::deposit_event(Event::IntentExpired { intent_id, reason: ExpiryReason::TTL });
                }
            }
            weight += T::DbWeight::get().reads_writes(1, 1);
        }
    }
    weight
}
```

Bounded by `ConstU32<256>` max expiries per block — guarantees this hook is predictable-weight.

### 2.4 Runtime API — `IntentSettlementRuntimeApi`

```rust
sp_api::decl_runtime_apis! {
    pub trait IntentSettlementRuntimeApi {
        /// Return all intents attested-but-not-yet-vouchered since `since_block`, up to `max_count`.
        /// Payload includes the raw Intent, its current status, and (if attested) the committee sigs.
        fn get_pending_batches(since_block: BlockNumber, max_count: u32) -> Vec<BatchPayload>;

        /// Return the current committee state: members + threshold + last Cardano mirror tx.
        fn get_committee_state() -> CommitteeState;

        /// Return the full Voucher for a claim_id (keeper needs this to build the Cardano tx).
        fn get_voucher(claim_id: ClaimId) -> Option<Voucher>;
    }
}

pub struct BatchPayload {
    pub intent: Intent,
    pub intent_id: IntentId,
    pub attestation_sigs: BoundedVec<(CommitteePubkey, CommitteeSig), ConstU32<32>>,
}
```

RPC surface exposed via `sc_rpc::State::call`; keeper uses JSON-RPC `state_call("IntentSettlementRuntimeApi_get_pending_batches", 0x...since_block...max_count)`.

### 2.5 Replay protection + fee model

- Each `submit_intent` auto-increments `Nonces[submitter]`. The nonce is part of the IntentId pre-image — collisions impossible across accounts or within an account.
- Standard Substrate transaction-payment pallet handles MOTRA fees. `length_fee_per_byte` remains at 1000 (per `feedback_large_runtime_upgrade.md`). A 500-byte `submit_intent` costs ~500k MOTRA; well-calibrated against the 100M-MOTRA-per-keyholder typical balance from `reference_multisig_sudo.md` bootstrap.
- Committee extrinsics opt out of fees via `pallet::weight((0, DispatchClass::Operational))`.

### 2.6 Tests (acceptance criteria for Team A)

- ≥85% line coverage per `cargo tarpaulin`; 100% extrinsic coverage (every dispatch path exercised with happy + failure paths).
- Integration test spinning up a 2-validator testnet via `--dev` + injecting a pre-configured committee. End-to-end: `submit_intent → attest_intent × 2 → request_voucher → settle_claim` across 4 Materios blocks.
- Property-based test on nonce monotonicity (fuzz 10k random submit sequences).
- Property-based test on fairness-proof invariant validation.
- Concurrent `attest_intent` test: two committee members post M-of-N in the same block; first wins, second is a no-op (not an error).

---

## 3. `pallet_committee_governance` — Wave 2 Team A (new)

This pallet is the Materios-side record-of-truth for the committee pubkey set + threshold. The Cardano-side `aegis-policy-v1` validator reads `CommitteePubkeySet` as a protocol parameter; every time that set changes, we anchor the new digest to Cardano under metadata label 8746 so the validator's next compilation (on validator-version upgrade) can ingest it.

### 3.1 Storage

```rust
#[pallet::storage]
pub type Members<T: Config> =
    StorageValue<_, BoundedVec<CommitteePubkey, T::MaxCommittee>, ValueQuery>;

#[pallet::storage]
pub type Threshold<T> = StorageValue<_, u32, ValueQuery>;  // M in M-of-N

#[pallet::storage]
pub type PendingRotation<T> = StorageValue<_, Option<RotationSchedule>, ValueQuery>;

/// Last Cardano mirror tx — the anchor that published the current committee digest.
#[pallet::storage]
pub type CardanoMirrorState<T> = StorageValue<_, LastMirrorTx, ValueQuery>;

#[pallet::storage]
pub type RotationTimelock<T> = StorageValue<_, BlockNumber, ValueQuery>;  // default 28_800 (~24h @ 6s)
```

```rust
pub struct RotationSchedule {
    pub events: BoundedVec<CommitteeEvent, ConstU32<16>>,
    pub proposed_block: BlockNumber,
    pub effective_block: BlockNumber,                  // = proposed_block + RotationTimelock
    pub proposer: AccountId,                           // must be sudo_origin (multisig)
    pub schedule_digest: [u8; 32],                     // domain_hash(b"CMTT", scale_encode(events) || effective_block)
}

pub struct LastMirrorTx {
    pub committee_set_digest: [u8; 32],
    pub cardano_tx_hash: [u8; 32],
    pub mirrored_at_block: BlockNumber,
}
```

**`MaxCommittee` bound:** `ConstU32<32>`. Supports any foreseeable committee size (2-of-7 today, 5-of-11 target, generous headroom). Never hardcode N/M inside logic — always read from storage.

### 3.2 Extrinsics

| # | Extrinsic | Origin | Purpose |
|---|---|---|---|
| 1 | `propose_add_member(pubkey: CommitteePubkey)` | Root (via sudo multisig 2-of-3) | Appends a `CommitteeEvent::Added` to a new or existing `PendingRotation`. Starts or extends the 24h timelock. |
| 2 | `propose_remove_member(pubkey: CommitteePubkey)` | Root | Appends `CommitteeEvent::Removed`. |
| 3 | `propose_rotate_pubkey(old, new)` | Root | Appends `CommitteeEvent::RotatedPubkey`. |
| 4 | `propose_threshold_change(new_threshold: u32)` | Root | Appends `CommitteeEvent::ExpandedThreshold`. Validates `1 <= new_threshold <= Members.len() + pending_adds - pending_removes` after the schedule is applied. |
| 5 | `execute_rotation()` | Signed (anyone; permissionless) | Checks `now >= pending.effective_block`, applies the events in order to `Members`/`Threshold`, clears `PendingRotation`, emits `RotationExecuted`. |
| 6 | `mirror_to_cardano(cardano_tx_hash: [u8;32])` | Committee member (who submitted the anchor-worker tx) | Records that the current `Members`/`Threshold` digest has been anchored to Cardano. Used for audit trail and to warn dApps that validator-version upgrade is pending. |
| 7 | `cancel_pending_rotation()` | Root | Escape hatch: if a proposed rotation was a mistake, the multisig can cancel within the timelock window. |

### 3.3 Events

```rust
#[pallet::event]
pub enum Event<T: Config> {
    RotationProposed    { schedule_digest: [u8; 32], timelock_expires: BlockNumber, event_count: u32 },
    RotationExecuted    { schedule_digest: [u8; 32] },
    RotationCancelled   { schedule_digest: [u8; 32] },
    MemberAdded         { pubkey: CommitteePubkey, effective_block: BlockNumber },
    MemberRemoved       { pubkey: CommitteePubkey, effective_block: BlockNumber },
    MemberRotated       { old: CommitteePubkey, new: CommitteePubkey, effective_block: BlockNumber },
    ThresholdChanged    { old: u32, new: u32, effective_block: BlockNumber },
    CardanoMirrorUpdated{ committee_set_digest: [u8; 32], mirror_tx: [u8; 32] },
}
```

### 3.4 Cardano mirror mechanic

Every time `execute_rotation` completes:

1. The pallet emits an on-chain "new committee set digest" event.
2. The existing `materios-anchor-worker` (already running against label 8746 at `/home/deci/materios-anchor-worker/index.mjs`) picks up the event via its routine block-scan and constructs a Cardano metadata payload following the `materios-anchor-v2` schema with an extra field:

```json
{
  "p": "materios",
  "v": 2,
  "chain": "<materios-genesis-hex>",
  "blocks": [<from>, <to>],
  "leaves": 1,
  "root": "<merkle-root-of-just-this-event>",
  "manifest": "<manifest-hash>",
  "ext": {
    "committee_set_digest": "<32-byte-hex>",
    "threshold": <u32>,
    "member_count": <u32>
  }
}
```

3. Once the Cardano tx is confirmed, a committee member calls `mirror_to_cardano(cardano_tx_hash)` on Materios. This closes the loop.

The Aiken validator's `CommitteePubkeySet` parameter is updated via validator redeployment — not via the mirror tx itself. The mirror tx is an *attestation* that a redeployment is pending; the actual validator parameter change is done by the devops team deploying `aegis-policy-v1.vN+1`. This preserves the "Aiken parameters are compile-time" property while keeping Materios as source of truth.

### 3.5 Expansion 2-of-7 → 5-of-11 (data migration, not code)

Because `Members` and `Threshold` are storage values, the expansion is a sequence of `propose_add_member × 4` + `propose_threshold_change(5)` dispatched via multisig-sudo, with the standard 24h timelock. No pallet code changes, no runtime upgrade, no chain reset. This is the whole reason we encoded N and M as storage.

### 3.6 Initial authorization

- v1 launch: `Members = [<7 existing committee ed25519 pubkeys>]`, `Threshold = 2`. Seeded via `propose_add_member × 7 + propose_threshold_change(2)` dispatched as a single `sudo.batch` at genesis-ish time.
- 24h timelock is enforced **even for the initial seed** — this is a feature (public announcement window) not a bug.

### 3.7 Tests (Team A acceptance)

- Full rotation lifecycle test: propose → timelock → execute → mirror. Must show the Cardano mirror tx hash and the on-chain digest agree.
- Threshold-bounds test: reject `propose_threshold_change(0)` and `propose_threshold_change(N+1)`.
- Permissionless `execute_rotation` test: user Eve (not in Members) can trigger execute once timelock expires; confirms the extrinsic is permissionless-by-design.
- Cancellation test: multisig cancels a bad proposal within the window.
- Expansion test: programmatically seed 7 members, run the 2-of-7 → 5-of-11 data migration, verify no pallet code changed between snapshots.

---

## 4. `aegis-aiken-v1` Validator Library — Wave 2 Team B

Three validators: `aegis-policy-v1` (main), `premium-collector` (deposit script), `pool-custody` (pool+payout script). All under `/validators/` in `aegis-parametric-insurance-dev`.

### 4.1 `aegis-policy-v1`

**Parameters (baked in at compile time):**
```
type AegisPolicyParams {
    committee_pubkey_set: List<VerificationKey>,    // ed25519, mirrored from Materios
    committee_threshold: Int,
    min_fairness_proof_sig_count: Int,              // = committee_threshold
    charli3_oracle_ref: OutputReference,            // reference UTxO of the oracle feed
    charli3_feed_policy_id: PolicyId,
    charli3_feed_asset_name: AssetName,
    materios_chain_id: ByteArray,                   // 32B materios genesis hash
    pool_custody_script_hash: ScriptHash,
    premium_collector_script_hash: ScriptHash,
    settlement_version: Int,                        // bump per redeploy
}
```

**Datum on policy UTxOs:**
```
type PolicyDatum {
    policy_id: ByteArray,        // matches Materios PolicyId
    owner_cardano_addr: Address, // beneficiary
    strike: Int,
    term_start_slot: Int,
    term_end_slot: Int,
    premium_paid: Int,           // lovelace
    pool_ref: OutputReference,   // pointer to pool UTxO backing this policy
    product_id: ByteArray,       // 32B product identifier
}
```

**Redeemers:**
```
type AegisPolicyRedeemer {
    Mint { policy_id: ByteArray, premium_ada: Int, beneficiary: Address }
    Claim {
        oracle_utxo_ref: OutputReference,
        current_slot: Int,
    }  // direct-path, no committee needed
    BatchClaimVoucher {
        voucher: SerialisedVoucher,
        fairness_proof: SerialisedFairnessProof,
        committee_sigs: List<(VerificationKey, Signature)>,
    }
    Expire
    RefundCredit { voucher: SerialisedVoucher, committee_sigs: List<(VerificationKey, Signature)> }
}
```

Where `SerialisedVoucher` and `SerialisedFairnessProof` are `ByteArray` fields containing the raw SCALE-encoded Materios types — the validator does Blake2b-256 over the domain-tagged bytes and verifies committee sigs against the digest. The validator does **not** reparse the SCALE bytes (see §1.2 — SCALE is canonical, Aiken treats it as opaque).

Each redeemer's logic:

- **`Mint`:** verifies `premium_ada` lovelace lands at the `premium_collector` script, creates a PolicyDatum UTxO at the `pool_custody` script. No committee signature needed (premium was already paid on Cardano; intent on Materios is advisory).
- **`Claim` (direct-path):** verifies oracle UTxO is the Charli3 feed at `charli3_feed_policy_id` + `charli3_feed_asset_name`, oracle datum `publish_time` is within freshness bound (< 300 slots old), strike condition met, payout goes to `owner_cardano_addr`, policy UTxO consumed. **No committee signature required.** This is the 10-minute fallback path.
- **`BatchClaimVoucher`:** verifies M-of-N committee sigs over `voucher` digest AND over `fairness_proof` digest, verifies `voucher.batch_fairness_proof_digest == blake2b_256(b"BFPR" ++ fairness_proof_bytes)`, checks payout to `voucher.beneficiary_cardano_addr`, deducts from pool, allows keeper fee output (see §5.3). Enforces expiry: `current_slot <= voucher.expiry_slot_cardano`.
- **`Expire`:** verifies `current_slot > policy_datum.term_end_slot`, returns pool funds to pool custody (no payout), consumes policy UTxO.
- **`RefundCredit`:** verifies M-of-N sigs over a refund voucher (`voucher.claim_id` actually references a `RefundCredit` intent on Materios), returns `amount_ada` from premium-collector script to the beneficiary.

**Committee signature verification function (lib.aiken):**
```
fn verify_committee_sigs(
    digest: Hash<Blake2b_256, ByteArray>,
    sigs: List<(VerificationKey, Signature)>,
    pubkey_set: List<VerificationKey>,
    threshold: Int,
) -> Bool {
    // 1. Every (vk, sig) pair: vk ∈ pubkey_set
    // 2. sig verifies over digest for vk using builtin verify_ed25519_signature
    // 3. All vk are distinct (no double-counting)
    // 4. Count >= threshold
    ...
}
```

### 4.2 `premium-collector`

Collects ADA deposits from users. UTxOs sit here until spent by either `ApplyToPolicy` (upon policy mint) or `RefundCredit` (committee-vouched).

**Datum:**
```
type PremiumDepositDatum {
    depositor_materios_account: ByteArray,  // 32B SS58 pubkey; matches Materios AccountId
    deposited_at_slot: Int,
    deposit_id: ByteArray,                  // blake2b_256(tx_hash || output_index)
}
```

**Redeemers:**
```
type PremiumCollectorRedeemer {
    ApplyToPolicy { policy_mint_ref: OutputReference }
    RefundCredit { voucher: SerialisedVoucher, committee_sigs: List<(VerificationKey, Signature)> }
}
```

### 4.3 `pool-custody`

Holds LP deposits + claim payouts. `BatchClaimVoucher` and `Claim` redeemers on `aegis-policy-v1` both draw from a pool UTxO referenced by `policy_datum.pool_ref`.

**Datum:**
```
type PoolDatum {
    pool_id: ByteArray,
    lp_shares_total: Int,
    product_id: ByteArray,
    bond_amount_ada: Int,         // protocol-level minimum reserve
}
```

**Redeemers:**
```
type PoolCustodyRedeemer {
    DepositLP { lp_addr: Address }
    WithdrawLP { lp_addr: Address, shares_burned: Int }
    DrawClaim { policy_ref: OutputReference, amount_ada: Int }  // callable only by aegis-policy-v1 validator context
    SlashBond                                                    // committee-vouched slashing
}
```

### 4.4 CIP compliance

- **CIP-14 (asset fingerprinting):** LP share tokens MUST have fingerprints following CIP-14 so block explorers render them; the pool's `lp_shares_total` token uses asset name = hex(policy_id).
- **CIP-25 (NFT metadata):** Policy NFTs minted by `Mint` redeemer include CIP-25 metadata: `{name, description, image (optional), attributes: [{strike}, {term}, {beneficiary}]}`. This makes policies visible in wallets like Eternl/Typhon.
- **CIP-67 (asset-class label):** Not applicable (no fungible project tokens); keep in mind for v1.5 if we add MATRA-bond NFTs.

### 4.5 CBOR datum schema — byte-for-byte parity tests

For every datum type above, Team B ships a Rust test that:
1. Builds the Aiken CBOR bytes using `pallas-codec` or `plutus-codec`.
2. Builds the SCALE bytes that the corresponding Materios type would produce.
3. Asserts the Blake2b-256 over domain-tagged SCALE bytes equals the Blake2b-256 Aiken computes inside the validator (via property-based fuzzing, 1k cases per type).

**Correctness-by-construction target:** if Team A changes a SCALE field order on the Materios side, Team B's tests fail immediately — the two implementations can never drift silently.

### 4.6 Tests (Team B acceptance)

- Property-based tests on every redeemer branch.
- "Equivalence-vs-old-hackathon-Claim redeemer" test: existing hackathon `Claim` logic and new `aegis-policy-v1::Claim` are fed identical inputs and must produce identical verdicts. Regression shield.
- Reject-tests per forgery class:
  - Forged committee sig (valid ed25519 from a non-member pubkey) → reject.
  - Replayed voucher (same voucher digest used twice on different policy UTxOs) → second tx rejected because first consumed the policy UTxO.
  - Off-by-one fairness-proof math (`awarded != requested * scale / 10000`) → reject.
  - Wrong oracle policy_id in `Claim` → reject.
  - Expired voucher (`current_slot > voucher.expiry_slot_cardano`) → reject.

---

## 5. Keeper Service — Wave 2 Team C

### 5.1 Responsibilities

1. Poll Materios `IntentSettlementRuntimeApi::get_pending_batches` every block (6s) for newly-vouchered claims.
2. Build Cardano txs that consume policy UTxOs + pool UTxOs + produce payouts per the voucher.
3. Submit txs, monitor confirmation, on success call `settle_claim` back on Materios.
4. Handle retries, fee-spikes, orphan blocks, double-submission races.

### 5.2 Tech choice — **mesh-js**

**DECISION: mesh-js (JS/TS).** Rationale:

- Already a TypeScript house (anchor-worker is Node.js + Lucid; blob gateway is Node.js; explorer is NextJS). Keeping the keeper in TS minimizes cognitive-surface-area for on-call engineers.
- Lucid has a known bug-tail around reference scripts under complex Plutus V3 contexts; mesh-js's `MeshTxBuilder` handles Plutus V3 correctly as of v1.5.
- mesh-js has first-class Blockfrost + Kupmios provider abstractions; we already run Kupo/Ogmios on Saturnswap.io endpoints.

Acceptable alternative: the keeper could be a Rust service using PallasCodec. Don't pick this for v1; reassess at v2 if keeper perf becomes a concern.

### 5.3 Protocol flow

```
Materios RPC                         Keeper                                Cardano
    │                                   │                                     │
    │ ◄─── get_pending_batches ────────│                                     │
    │ ───► BatchPayload[] ─────────────►│                                     │
    │                                   │─── build tx (mesh-js) ──────────►  │
    │                                   │   • inputs: N policy UTxOs,        │
    │                                   │     pool UTxO, fee-input UTxO      │
    │                                   │   • outputs: payouts + keeper fee  │
    │                                   │   • redeemer: BatchClaimVoucher    │
    │                                   │     with voucher + fairness_proof  │
    │                                   │     + committee sigs               │
    │                                   │   • metadata: label 8746 payload   │
    │                                   │     including fairness_proof_digest│
    │                                   │─── submit ────────────────────────►│
    │                                   │ ◄── txHash ────────────────────────│
    │                                   │                                     │
    │                                   │─── poll for confirmation ─────────►│
    │                                   │ ◄── confirmed (at tip) ────────────│
    │                                   │                                     │
    │ ◄─── settle_claim(tx_hash) ──────│                                     │
```

### 5.4 Fee extraction

Per the Aiken `BatchClaimVoucher` redeemer, the keeper is allowed to produce one "fee output" at their own Cardano address, subject to:

```
keeper_fee_ada = min(
    2% * sum(awarded_amounts_ada),
    500_000 /* 0.5 ADA base */ + 5 * sum(awarded_amounts_ada) / 1000 /* 50 bps */
)
```

The validator verifies there's exactly one fee-output-to-any-address AND that its value ≤ `keeper_fee_ada`. Keepers are permissionless; there's no "registered keeper" storage — first to submit a valid tx wins the fee.

### 5.5 Permissioning

- Permissionless. Any entity with ADA for tx-building can run a keeper.
- Committee doesn't know who the keeper is. No keeper whitelist on Materios OR Cardano.
- Flux Point Studios operates a reference keeper (for liveness guarantee) but publishes the repo so third parties can spin up competing keepers. Competition drives fees down.

### 5.6 Failure modes + idempotency

| Failure | Handling |
|---|---|
| Double-submission (two keepers race for same batch) | Cardano tx inputs (policy UTxO) are single-use — one tx wins, other fails at submit. No on-Materios double-settle because `settle_claim(claim_id)` is idempotent. |
| Orphan block / rollback | Keeper must wait `k = 2160` slots (~6 min on Cardano preprod, 2160s on mainnet ≈ 36 min) before calling `settle_claim`. Kupo's `confirmed` endpoint with `after_slot=current-k` gives this for free. |
| Fee spike (Cardano protocol param change) | Retry with higher fee up to a cap; after 3 attempts, log + give up + let the 10-min direct-path fallback kick in on the user side. |
| Materios RPC unavailable | Exponential backoff; keeper is permitted to be offline — the pallet's TTL sweep handles it. |
| Committee sig invalid | This is a bug, not a runtime condition. Alert + abort. |
| Voucher expired (`current_slot > voucher.expiry_slot_cardano`) | Log, emit metric, call `settle_claim` with `cardano_tx_hash = all-zeros` + a new extrinsic variant `ClaimExpired` (add to §2.2 as extrinsic #7). |

### 5.7 API surface (HTTP on keeper, optional)

```
GET  /health               → 200 OK if Materios RPC reachable + Cardano provider reachable
GET  /metrics              → Prometheus format
GET  /pending              → list of vouchers the keeper has seen but not yet submitted
POST /submit/:claim_id     → admin-only; force-submit a specific voucher (for manual recovery)
```

### 5.8 Tests (Team C acceptance)

- **Integration tests run against live preprod.** Materios preprod RPC at `wss://materios.fluxpointstudios.com/preprod-rpc`, Cardano preprod via `https://preprod.saturnswap.io/ogmios` + `https://preprod.saturnswap.io/kupo`. Mocks ONLY for Charli3 oracle reads (for determinism).
- End-to-end test: submit a real intent, observe the committee attest, observe the voucher, watch the keeper submit, verify the Cardano tx landed via `verify_cardano_anchor` (orynq MCP tool), verify the Materios state updated.
- Failure-mode tests: simulate fee spike (mock Cardano provider), simulate Cardano provider 5xx, simulate committee sig missing.

---

## 6. Cross-Layer Conventions

### 6.1 Hashing — Blake2b-256 everywhere, domain-tagged pre-images

Already specified in §1.1. One more note: the SCALE-encoded body must be produced by `parity-scale-codec` (the canonical Substrate crate) and the equivalent Aiken-side byte blob is produced by the keeper's Rust SDK (in `materios-intent-settlement/sdk/`). The SDK exposes:

```rust
pub fn encode_intent_for_hashing(intent: &Intent) -> Vec<u8>;
pub fn intent_id(intent: &Intent) -> IntentId;
pub fn voucher_digest(voucher: &Voucher) -> [u8; 32];
pub fn fairness_proof_digest(bfpr: &BatchFairnessProof) -> [u8; 32];
```

Aiken-side equivalents are hand-written in `aegis-aiken-v1/lib/materios-scale.ak`. Cross-fuzz tested per §4.5.

### 6.2 Signature scheme — ed25519 for committee, sr25519 elsewhere

- Committee attestations (the thing Cardano verifies): **ed25519**.
- Regular Materios extrinsic signing (the thing nodes verify): **sr25519**, as today.
- Each committee member therefore has TWO keys: their validator sr25519 (existing) and a dedicated `aegis-attestor` ed25519 (new, derived from the same mnemonic at path `//aegis`).
- The cert-daemon code (Python) adds an ed25519 signing path alongside the existing sr25519 cert-signing path. Both signatures are produced for every attestation; the Materios-internal cert uses sr25519, the Cardano-visible voucher sig uses ed25519.

### 6.3 Timestamps — block numbers vs slot numbers

Materios block number `B` occurs roughly at unix time `T_genesis + B × 6`.
Cardano slot number `S` occurs at unix time `T_shelley_start + (S - S_shelley_start) × 1`.

Conversion table for the types the pallet stores:

| Pallet field | Unit | Cardano correspondent |
|---|---|---|
| `Intent.submitted_block` | Materios BlockNumber (u32) | — |
| `Intent.ttl_block` | Materios BlockNumber (u32) | — |
| `Voucher.issued_block` | Materios BlockNumber (u32) | — |
| `Voucher.expiry_slot_cardano` | Cardano SlotNumber (u64) | same |
| `Claim.expiry_slot_cardano` | Cardano SlotNumber (u64) | same |

Pallet never attempts to read Cardano time. Keeper reads both sides; pallet trusts the keeper's `cardano_tx_hash` after committee mirrors it via `settle_claim`.

### 6.4 Metadata label usage

| Label | Payload | Producer | Purpose |
|---|---|---|---|
| 8746 | materios-anchor-v2 (with optional `ext.committee_set_digest` or `ext.fairness_proof_digest`) | `materios-anchor-worker` | Batch-level anchors. Aegis reuses for claim-batch anchors. Committee rotation mirrors also land here. |
| 2222 | poi-anchor-v1 | orynq-sdk direct + optional Aegis per-high-value-claim anchor | Individual high-value claims (e.g. > 10k ADA payout) get an additional 2222 anchor for forensic traceability, in addition to the batch 8746 anchor. |

Fairness-proof digest goes in the 8746 `ext` block — the full BFPR bytes are *not* on Cardano (size + cost); auditors recover the full BFPR from Materios storage using the digest as a lookup key.

### 6.5 Oracle feed policy

Aegis v1 baked-in feeds:

| Product | Feed | policy_id | asset_name |
|---|---|---|---|
| ADA/USD parametric (v1 primary) | Charli3 ADA/USD | `<TO BE FETCHED from Charli3 docs before deploy>` | `ADAUSD` (CIP-67 prefixed) |

`[DECISION NEEDED]` Fetch the canonical Charli3 ADA/USD feed policy_id from `https://docs.charli3.io/` before Team B starts the Aiken validator. Default: assume `<placeholder>` and blocker before mainnet deploy. Team B's v1 deploy is against preprod; preprod Charli3 feed is at a different policy_id than mainnet (Charli3 redeployed for preprod) — both must be captured.

Feed rotation requires validator redeploy (new `AegisPolicyParams`); during transition, both old and new validators accept (compile a two-feed variant and deprecate old after all in-flight policies close). This rotation is distinct from committee pubkey rotation — they are independent axes.

### 6.6 Anchor-worker reuse clause

`materios-anchor-worker` at `/home/deci/materios-anchor-worker/index.mjs` is ALREADY in production signing to Cardano mainnet under label 8746 via the `cardano-mainnet-anchor.mnemonic` wallet. For Aegis v1:

- Target Cardano **preprod** initially (not mainnet) — preprod wallet: `cardano-preprod-anchor.mnemonic` (to be provisioned by ops; 500 tADA from preprod faucet should suffice for 6 months of batch anchoring).
- Extend anchor-worker's request body schema to accept an optional `ext` field carrying `committee_set_digest` / `fairness_proof_digest`. Additive, backward-compatible.
- Mainnet cutover for Aegis is gated on committee expansion to 5-of-11 (per the decisions doc).

### 6.7 Chain identifier

Every Cardano payload (label 8746) includes `"chain": "<materios-genesis-hex-no-0x>"`. v5 = `bc0531cb311281565036fb397a376f0e0fa37005589655f97a7924b2729a164c`. For Aegis preprod demo this is the value; mainnet will be a different genesis hash (whole new chain).

---

## 7. Build-Team Acceptance Criteria — Consolidated

### 7.1 Team A (Rust pallets)

- ≥ 85% line coverage (`cargo tarpaulin`), 100% extrinsic coverage.
- Integration test spinning up 2-validator testnet + exercising full submit→attest→voucher→settle lifecycle.
- Benchmarks for every extrinsic (`cargo run --release -- benchmark pallet`) — weights baked in via `WeightInfo`.
- `try-runtime` migration test for the chain-reset-less onboarding onto v5 (add the two pallets via runtime upgrade; no chain reset).
- Fuzz test on `verify_committee_sigs` helper: 10k cases including valid, invalid-sig, forged-pubkey, duplicate-pubkey.

### 7.2 Team B (Aiken validators)

- Property-based tests on every redeemer branch (`aiken check --fuzz`).
- Equivalence-vs-old-hackathon-Claim regression tests.
- Reject-tests per forgery class enumerated in §4.6.
- CBOR↔SCALE parity tests (§4.5) — 1k fuzz cases per type.
- Plutus V3 execution-unit budget measurement for the worst-case M=5, N=11 `BatchClaimVoucher` — must fit under Cardano mainnet limits.
- Property: validator accepts iff committee_threshold of distinct valid sigs provided.

### 7.3 Team C (keeper)

- Integration tests MUST run against live preprod (Materios + Cardano preprod). Mocks only for oracle reads.
- Failure-mode tests per §5.6.
- Prometheus metrics coverage: batch-build time, tx-submit latency, fee-spike recovery count, committee-sig-failure count.
- Continuous-deployment target: Docker image pushed to `ghcr.io/flux-point-studios/aegis-keeper:latest`, auto-deployed on Node-3 for preprod reference keeper.

### 7.4 Glue (cross-team E2E)

A separate "glue team" — one engineer from each of A/B/C pair-programming — owns a single end-to-end test in the monorepo-split integration layer:

1. Start on Materios preprod. User account `X` (drip-funded with 50 tADA worth of ADA-credits).
2. Submit intent: `BuyPolicy { product_id: ADA/USD, strike: 0.50 ADA, term_slots: 86400, premium_ada: 1_000_000 }`.
3. Wait for committee attestation (≤ 6 blocks).
4. Simulate oracle trigger: inject a mock low-price read into Charli3 preprod watcher.
5. User submits `RequestPayout { policy_id, oracle_evidence }`.
6. Keeper picks up vouchered claim, builds Cardano tx, submits.
7. Verify on cexplorer.io/preprod the tx lands with label-8746 metadata.
8. Verify `Claim.status == Settled` on Materios.
9. Test passes iff the user's Cardano wallet increases by `payout_ada - keeper_fee`.

This test is the "it all works" demo for investor/partner reviews.

---

## 8. Non-Goals for Wave 2

- **Frontend / dApp UI.** Wave 3 (separate spec, separate team). The keeper exposes enough HTTP + JSON surface for a minimal CLI verification; a polished dApp waits.
- **Midnight ZK integration.** Phase 2 — design doc in `project_midnight_poc_findings.md`, spec not written yet. The voucher/fairness-proof digests deliberately preserve information the ZK proof will need, but no ZK code ships in Wave 2.
- **MATRA-bonds.** v1.5 — gated on cMATRA market liquidity on SaturnSwap CLOB.
- **DAO governance.** v2 — for v1 the committee rotates via multisig-sudo + 24h timelock.
- **Multi-product validator registry.** `[DECISION NEEDED]` Logged in the v2 open-questions doc; not this wave. Current `aegis-policy-v1` deploys one validator per product (ADA/USD, later ADA/BTC, USDM-depeg, etc.).
- **Stablecoin-denominated premiums.** v1.5 — ADA-only for v1 per decision Q1.
- **Keeper fee in MOTRA.** v1.5 — ADA-only per decision Q9.

---

## 9. Open Items & Followups

These are items the spec makes a default choice on but flags for review:

1. **`[DECISION NEEDED]` Charli3 ADA/USD feed policy_id on preprod + mainnet.** Default: fetch from `https://docs.charli3.io/` and hardcode before Team B starts validator work. Spec is otherwise complete.

2. **`[DECISION NEEDED]` Keeper-fee protection when a batch contains only one small claim.** If `sum(awarded) < 25 ADA` the 2% cap gives the keeper < 0.5 ADA and the tx can't break even. Default proposal: the fee floor of 0.5 ADA comes out of pool even if it exceeds 2% of the batch — worst case pool absorbs tiny overhead, still cheaper than the user bailing to direct-path (~1.5 ADA). Team C to validate with cost model.

3. **`[DECISION NEEDED]` What happens if committee member's ed25519 key is lost (not leaked) mid-attestation?** Default: `propose_rotate_pubkey` can substitute new pubkey for old; until rotation executes, M-of-N continues with remaining members. If `Members.len() - lost < Threshold`, chain attestations stall — surfacing as intents-stuck-at-Pending-for-TTL. This is intentional: you can't silently drop below threshold. Operational runbook needed for Team A.

4. **Multi-product validator registry.** `[DEFERRED to v2 open-questions doc.]`

5. **Charli3 feed staleness bound.** Default 300 slots (5 min). Validate with Charli3 team — may be too strict for low-liquidity windows.

6. **Batch-size cap.** Voucher supports up to 256 claims per batch (`BoundedVec` cap). Plutus V3 exec-unit ceiling may lower this in practice. Team B to empirically determine the max on mainnet params.

---

## 10. Handoff to Wave 2

- This spec is the **single source of truth** for Wave 2. If something in the implementation disagrees with this spec, that's a bug — file an issue and fix the spec OR the implementation before merging.
- Changes to this spec require a PR to `Flux-Point-Studios/materios-intent-settlement` (when the repo exists) in `docs/spec-v1.md`, reviewed by at least one member of each of Teams A / B / C.
- Wave 2 kickoff is gated on: (a) this document approved by Nathaniel, (b) the two repos created (`materios-intent-settlement` + feature branch on `aegis-parametric-insurance-dev`), (c) Charli3 feed policy_ids resolved (Open Item #1).
- Related memory files (background context, non-authoritative): `project_materios_architecture.md`, `project_spo_crossvalidation.md`, `project_v5_chain.md`, `project_v5_1_tokenomics.md`, `project_cardano_l1_metadata_labels.md`, `feedback_cardano_explorer.md`, `feedback_materios_mempool_ops.md`, `feedback_iog_idp_none_panic.md`, `reference_multisig_sudo.md`, `reference_orynq_mcp.md`, `project_midnight_poc_findings.md`, `project_materios_intent_settlement_dapp.md`.
- Live infrastructure to reuse (do NOT duplicate):
  - `/home/deci/materios-anchor-worker/index.mjs` — label-8746 anchor worker (Gemtek native Node). Extend, don't replace.
  - `operator-kit@cdc35c2` cert-daemon — swap payload type, reuse signing/retry/blob-upload machinery.
  - Saturnswap.io Ogmios/Kupo endpoints for Cardano preprod and mainnet.
  - `wss://materios.fluxpointstudios.com/preprod-rpc` — Materios RPC.

— end spec —
