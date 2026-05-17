# settle_claim Cardano-tx Verification — Design Memo

**Task:** #78 (mis-sec P0) — close the L1 verification gap in
`pallet-intent-settlement::settle_claim`.
**Author:** Agent B (Materios intent-settlement fan-out, 2026-05-14).
**Status:** Locked. One mechanism (hybrid B + D). No "TBD between options."
**Scope:** Design memo only — no code, no PRs.
**Sister memo:** Agent E concurrently writing pull-oracle integration. As of
this writing no `pull-oracle-integration-design.md` / `pull-oracle-bridge-design.md`
exists in ``, so this memo assumes Materios Oracle Network
(MON, `materios-oracle-design.md`) is the canonical oracle source and is
NOT a hard dependency of the fix below. If Agent E's design lands and
proposes Pyth/Charli3-style integration, that becomes an alternate oracle
source for the same verification primitive — the pallet surface is
oracle-agnostic.

---

## 0. Compounding-leverage statement (CLAUDE.md doctrine)

This work compounds **two** existing Materios primitives in one shot:

1. **The cert-daemon attestor pool** — same 4 internal cert-daemon hosts
   (Gemtek, Node-2, Node-3, MacBook is validator-only) already do
   M-of-N attestation of `availability_cert_hash` for OrinqReceipts.
   We extend their job description by **one new attestation type**:
   `cardano_tx_confirmed(cardano_tx_hash, claim_id_binding, depth)`.
   No new daemon. No new key infrastructure. Same sr25519 committee key,
   same M-of-N threshold machinery
   (`pallet-intent-settlement::ensure_threshold_signatures` —
   already pub since task #174 for cross-extrinsic reuse).
2. **The Materios Oracle Network committee** — MON publishes Cardano
   datums via the round-robin aggregator. The same operators that sign
   `(pair, slot, price, ts)` already run a Cardano follower (Ogmios or
   pycardano + Blockfrost) and *prove* tx finality every 30s for
   price-feed updates. Adding `cardano_tx_observed_at_depth_k` to the
   committee's attestation surface is one new sig-payload tag, not a
   new operator class.

After the fix, cert-daemon attestors are doing *three* jobs (receipt
availability, TEE-attestation evidence, **Cardano-settlement
confirmation**) for the same bond. Each new attestation type increases
the per-attestor revenue floor (per `pallet-billing` 50% share of
operational revenue) → more attractive to recruit operator #5..N →
faster path to N≥10 trustless decentralization. **Network-effect prize:
the same N operators who already secure receipts also secure
settlements.**

Dormant value activated: the existing `vendor/db-sync-follower` crate
in `materios-task180/partnerchain/vendor/` — every validator already
embeds the Cardano DB-sync follower for partner-chains stake-snapshot
ingestion. That follower is, today, watched by no pallet. After this
fix, `pallet-intent-settlement` consumes it via an off-chain attestor
ride-along (mechanism B below), turning an existing dependency into a
load-bearing trust primitive.

---

## 1. The Trust Gap Today

### 1.1 Code reference

File: `pallets/intent-settlement/src/lib.rs`

The extrinsic at L1240–L1323 (`settle_claim`):

```rust
pub fn settle_claim(
    origin: OriginFor<T>,
    claim_id: ClaimId,
    cardano_tx_hash: [u8; 32],
    settled_direct: bool,
    signatures: Vec<(CommitteePubkey, CommitteeSig)>,
) -> DispatchResult {
    // ...
    let payload = settle_claim_payload(&chain_id, &claim_id,
                                       &cardano_tx_hash, settled_direct);
    Self::ensure_threshold_signatures(&payload, &who, &signatures)?;
    // ...
    claim.cardano_tx_hash = cardano_tx_hash;   // L1282 — stored unverified
    // ...
    Self::deposit_event(Event::ClaimSettled { claim_id, cardano_tx_hash,
                                              settled_direct });
}
```

Parallel surface at L1520–L1630 (`settle_batch_atomic`) — same gap, batched.

What `ensure_threshold_signatures` proves:
- M committee members signed the message
  `blake2_256(b"STCL" || chain_id || claim_id || cardano_tx_hash || settled_direct)`.
- The caller is one of those signers.
- All signers are current committee members.

What `ensure_threshold_signatures` does **not** prove:
- That `cardano_tx_hash` is a real Cardano transaction hash.
- That such a Cardano tx, if it exists, was confirmed at depth ≥ k.
- That the tx, if it exists, paid the claim's beneficiary the claim's
  `amount_ada`.
- That the tx, if it exists, references `claim_id` in its metadata or
  redeemer (i.e., that the on-chain payment is actually bound to *this*
  claim and not some other transfer).

The spec confirms this explicitly at `docs/spec-v1.md` L791:
*"Pallet never attempts to read Cardano time. Keeper reads both sides;
pallet trusts the keeper's `cardano_tx_hash` after committee mirrors it
via `settle_claim`."* That is the bug. The "after committee mirrors" is
a sig-bundle vote, not a Cardano-chain observation.

### 1.2 Attack scenarios

**A1 — M-of-N collusion, no L1 payout, false claim closure.** Threshold
M of the committee colludes, signs `settle_claim(claim_id, 0xDEADBEEF...,
true)`, calls the extrinsic. Pallet records the claim as settled, drains
`amount_ada` from `total_nav_ada` (L1314), emits `ClaimSettled`. No
Cardano tx exists. The user's claim is closed on Materios; they got
nothing on Cardano. **Capital is double-spent**: the pallet thinks the
ADA left the pool, the pool still has it, the user is out of pocket.

**A2 — M-of-N collusion, wrong recipient.** Committee signs against a
real Cardano tx hash, but that tx paid an attacker-controlled address
instead of the claim's beneficiary. Pallet has no view of the tx
contents, so the recipient-binding is purely social/honor.

**A3 — Single bad keeper resubmit-with-bad-hash, M-of-N rubber-stamps.**
The off-chain keeper (the actor that assembles the sig bundle) provides
a wrong `cardano_tx_hash`. Committee members sign without verifying
because the M-of-N protocol assumes someone else is checking. Same
result as A1.

**A4 — Equivocation via two-tx race.** Committee signs `settle_claim`
for a Cardano tx that is later orphaned in a rollback. Pallet has no
finality probe, so the orphan-then-replaced flow has no on-chain
remediation. The claim stays settled; the L1 didn't actually pay.

**A5 — Voucher recycling: right tx, wrong voucher.** Committee signs a
real, well-funded Cardano tx that paid the right beneficiary the right
amount, BUT that tx was already used to settle a different Materios
claim/voucher. The committee silently double-counts one Cardano
payment across multiple claims. Pallet has no view of which voucher a
given tx was meant to settle, so the binding is purely social.

Severity: P0. All five scenarios let a quorum of committee members
extract pool capital with no on-chain trace of the discrepancy. The
audit flagged this correctly.

### 1.3 What DOES exist that we can reuse

| Existing primitive | Where | How it relates |
|---|---|---|
| `vendor/db-sync-follower` | every Materios validator | gives validator process access to Cardano blocks/txs via Postgres |
| Ogmios + Kupo cluster | Saturn / Node-3 (LAN) | gives off-chain processes Cardano tx finality + utxo info |
| `cert-daemon` | 3 of 4 internal nodes | runs M-of-N attestation loop on Materios, builds sig bundles |
| `anchor-worker` | Gemtek (.131) | already submits to + reads from Cardano L1 (label 8746) |
| `orynq-sdk::verify_cardano_anchor` | tool MCP | k-depth Cardano verification primitive, already production |
| `ensure_threshold_signatures` | pallet (pub) | M-of-N sig-verify path, already audited as part of #174 |
| `ProcessedDeposits<(target, cardano_tx_hash)>` | pallet (L568) | idempotency-set pattern for "this Cardano tx already processed" |
| MON pallet (`materios-oracle-design.md`) | locked, not built | next layer of M-of-N attestation infra |

**This is the Spartan principle in action: don't reinvent. The fix
composes four of the seven primitives above. No new daemon, no new
key, no new RPC, no new transport.**

---

## 2. Mechanism Choice

### 2.1 The four candidates (from prompt)

- **A — M-of-N attested cardano_tx_hash via Materios Oracle Network.**
  MON publishers extend attestation payload to include
  `cardano_tx_confirmed`. Pallet verifies MON-sig threshold.
- **B — Cert-daemon co-sign of Cardano-tx confirmation.** cert-daemon
  attestors poll Ogmios/Kupo independently and sign a payload that
  includes `(claim_id, cardano_tx_hash, depth, beneficiary, amount_ada)`.
  Pallet verifies same sig-threshold path.
- **C — Cardano follower in materios-node runtime.** Every Materios
  validator runs a Cardano follower; verification happens at
  extrinsic-execution time via a runtime API call into the follower's
  read API. Determinism enforced by majority validators agreeing on the
  follower's read.
- **D — Split settle_claim into request + attest** (task #84). Two-phase
  extrinsic: anyone can `request_settle`, committee finalizes with
  `attest_settle`.

### 2.2 Evaluation matrix

| Dimension | A (MON) | **B (cert-daemon co-sign)** | C (in-node follower) | **D (split request/attest)** |
|---|---|---|---|---|
| Latency post-Cardano-finality | 30-60s (depends on MON cadence) | ~6 s (one Materios block + Kupo poll cycle) | ~6 s (synchronous in-block) | additive ~6-12s on top of A or B |
| Trust composition | MON attestor set (≥3 of 5) | cert-daemon attestors (≥M of N committee) | every Materios validator (full set) | same as the underlying mechanism |
| Implementation effort | ⚠️ blocked on MON Phase 1 (4-6 wk) | ✅ extends existing daemon | ❌ runtime-determinism nightmare | ✅ pure pallet refactor |
| Reuse of existing primitives | New pallet path | cert-daemon, ensure_threshold_signatures, ProcessedDeposits | db-sync-follower, but with new runtime API + consensus risk | none new; reuses M-of-N |
| Permissionless keeper | yes (MON ops bound) | partial (still committee-gated, but keeper can publish unsigned half) | yes | **yes** — request_settle is open |
| Failure-isolation | bad MON ≠ bad settlement | bad cert-daemon = bad settlement, but already trusted equiv | bad follower wedges whole chain | bond + slash on requester closes the gap |
| Aligns with spec §5.5 task #81 | no | partial | no | **yes — that's literally task #84/#81** |

### 2.3 Decision: **Hybrid B + D**

- **D is the extrinsic shape** — split `settle_claim` into
  `keeper_request_settle` + `committee_attest_settle`. This is what
  task #84/#81 was reaching for in the spec and unblocks the
  permissionless keeper role.
- **B is the verification mechanism inside `committee_attest_settle`** —
  the M committee members sign a payload that **commits to the
  observed Cardano tx contents**, not just the tx hash. Off-chain,
  each cert-daemon attestor independently consults its own Ogmios/Kupo
  (or the LAN Saturn cluster) before signing.

A and C are explicitly rejected:

- **A (MON) rejected** as the *primary* mechanism because MON is not
  shipped yet (Phase 1 is 4-6 weeks out per
  `project_materios_oracle_network.md`) and the audit P0 cannot wait
  for it. MON remains a future **upgrade path**: once MON pallet is
  live, the same attestation payload can be carried by MON's sig
  bundle, with the cert-daemon path remaining as a fallback. Pallet
  surface is signature-source-agnostic by design (B uses
  `ensure_threshold_signatures` which already accepts arbitrary
  committee pubkeys).

- **C (in-node Cardano follower as runtime API) rejected** because:
  1. Runtime determinism. If validator A's db-sync-follower has
     processed Cardano block N and validator B's has processed N-2,
     the same `settle_claim` extrinsic executes differently. Result:
     finality wedge. We have already lost a 17h chain finality window
     once (see `project_materios_watchdog.md`); we are not
     introducing a new class of state-divergence.
  2. The vendored `db-sync-follower` is Postgres-backed and async; it
     does NOT expose a sync runtime API today and retrofitting one
     would be a major substrate engineering project for a P0 audit
     fix.
  3. C does not unblock the permissionless keeper role from spec §5.5,
     so it doesn't earn the audit credit AND the product credit on
     one PR.

### 2.4 What B + D buys vs the gap

Mapping back to §1.2:

| Attack | B+D defense |
|---|---|
| A1 (no L1 payout) | Committee sig payload now includes `output_to_beneficiary_amount`; signer can only honestly produce that sig after observing the tx. Wallet-faking forces M attestors to lie in unison about an off-chain observable — cryptographically equivalent to the current trust model, but **bound to a verifiable fact** instead of an unverifiable hash. |
| A2 (wrong recipient) | Same — payload includes `beneficiary_address_hash` derived from the claim's `Voucher.beneficiary`. |
| A3 (bad keeper) | The keeper signs the `request_settle` half (open); committee sigs are on the `attest_settle` half (committee). A wrong-hash request gets rejected at attest time when M-of-N cannot reproduce the Cardano observation. |
| A4 (orphan/rollback) | Payload includes `observed_at_depth >= k` (default k=15 ≈ 5 minutes preprod, ~36 min mainnet — matches `docs/spec-v1.md` L731's existing keeper rule). Pallet rejects bundles where any attestor reports `depth < k`. |
| A5 (voucher-recycling: right tx, wrong voucher) | Payload includes chain-state `voucher_digest` from `Vouchers[claim_id]`. A colluding M cannot reuse one legitimate Cardano payment to close multiple Materios claims because each claim's `voucher_digest` is unique. The requester cannot lie about it (it's pulled from on-chain storage, not provided in `SettlementEvidence`). |

### 2.5 What B + D explicitly does NOT solve

- **Bribery resistance beyond M-1 honest attestors.** This is unchanged
  from today. The audit gap was "no observation at all"; we now have
  "M observations, each verifiable in the historical record." If the
  whole committee gets bribed, no purely-off-chain mechanism (A, B, C,
  D, or any hybrid) saves us. Only path forward there is on-chain ZK
  light-client of Cardano headers, which is `project_wave3_phase2_polychain_pallet.md`
  Wave 3+ territory — explicit non-goal here.
- **Cardano protocol fork.** If Cardano hardforks change the tx
  serialization, our attestor's hash computation must follow. This is
  no different from how anchor-worker depends on Lucid/Ogmios already.
- **Slashing of wrong attestation.** The bond+slash side of task #81 is
  in scope of #84, not #78. Section 5 below makes the integration
  point explicit.

---

## 3. Pallet Changes — Exact Extrinsic Surface

### 3.1 New extrinsics (replacing the old `settle_claim`)

```rust
// PHASE 1 — anyone with the tx info can post the request.
// NOT M-of-N gated. The signer pays the (negligible) extrinsic fee.
// Storage: new map ClaimSettlementRequests<ClaimId> -> SettlementRequest.
#[pallet::call_index(N+1)]
pub fn request_settle(
    origin: OriginFor<T>,
    claim_id: ClaimId,
    cardano_tx_hash: [u8; 32],
    settled_direct: bool,
    attestation_evidence: SettlementEvidence,  // see §3.3
) -> DispatchResult;

// PHASE 2 — committee finalises with M-of-N signatures over the canonical
// digest derived from BOTH the on-chain Voucher fields AND the
// SettlementEvidence in the matching pending request. Sig payload
// commits to enough of the Cardano-tx contents that a colluding M is
// committing to a falsifiable claim, not a vacuous hash.
#[pallet::call_index(N+2)]
pub fn attest_settle(
    origin: OriginFor<T>,
    claim_id: ClaimId,
    signatures: Vec<(CommitteePubkey, CommitteeSig)>,
) -> DispatchResult;
```

### 3.2 New canonical digest (replaces `settle_claim_payload`)

```rust
/// Domain tag: TAG_STCL retired. New tag TAG_STCA (settle-claim-attested).
pub const TAG_STCA: &[u8; 4] = b"STCA";

/// Pre-image is FAT — committee is committing to an observed Cardano fact:
///
/// blake2_256(
///     b"STCA" || chain_id (32B)
///     || claim_id (32B)
///     || voucher_digest (32B)               // canonical voucher hash from on-chain Vouchers[claim_id]
///     || cardano_tx_hash (32B)
///     || settled_direct (1B)
///     || beneficiary_addr_blake2_224 (28B)  // from claim.beneficiary
///     || amount_ada_lovelace_le (8B)        // from claim.amount_ada
///     || observed_at_depth_le (4B)          // attestor's k value, >= MinFinalityDepth
///     || observed_slot_le (8B)              // Cardano slot of the tx
///     || mainchain_genesis_hash (32B)       // pins network (preprod vs mainnet)
/// )
pub fn settle_claim_attested_payload(
    chain_id: &[u8; 32],
    claim_id: &ClaimId,
    voucher_digest: &[u8; 32],
    cardano_tx_hash: &[u8; 32],
    settled_direct: bool,
    beneficiary_hash: &[u8; 28],
    amount_ada: u64,
    depth: u32,
    slot: u64,
    mc_genesis: &[u8; 32],
) -> [u8; 32] { /* … */ }
```

The committee is no longer signing "trust me, this is a tx hash."
It is signing "I observed transaction `H` at slot `S` at depth `D` on
Cardano network `G`, paying `amount_ada` lovelace to address whose hash
is `beneficiary_hash`, settling voucher `V`." Each attestor cryptographically
commits to a falsifiable Cardano-record fact bound to the specific voucher
that originated the claim.

**`voucher_digest` is chain-state-derived** — the pallet looks it up from
`Vouchers::<T>::get(claim_id)` at `attest_settle` time and feeds it into the
preimage. The requester cannot influence this field (it is NOT part of
`SettlementEvidence`). This closes an attack class where a colluding M
could attest a real, well-funded Cardano tx paying the right beneficiary
the right amount, but bound to the wrong voucher/policy on Materios — i.e.,
"recycle one legitimate Cardano payment to close multiple Materios claims."

### 3.3 New `SettlementEvidence` struct

```rust
#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, Clone, PartialEq)]
pub struct SettlementEvidence {
    pub cardano_tx_hash: [u8; 32],
    pub observed_at_depth: u32,
    pub observed_slot: u64,
    pub beneficiary_addr_hash: [u8; 28],
    pub amount_lovelace: u64,
    pub mainchain_genesis_hash: [u8; 32],  // pin preprod vs mainnet
}
```

This is the **publishable, falsifiable** half. Once on chain it is a
permanent commitment by the requester. If a watcher proves the tx
hash + slot tuple does not match what the SettlementEvidence asserts,
that watcher slashes the bond posted by the requester (task #84 hook).

### 3.4 New runtime config items

```rust
trait Config {
    // ... existing ...

    /// Minimum Cardano confirmation depth before a settle request is
    /// eligible to be attested. Default 15 (≈ 5min preprod, ≈36min
    /// mainnet). Governance-tunable via root.
    type MinFinalityDepth: Get<u32>;

    /// Maximum age (in Materios blocks) of a pending settlement request
    /// before it expires and a fresh request_settle is required. Default
    /// 2400 blocks (~4h) — long enough for any attestor pool downtime,
    /// short enough that stale requests don't pin storage.
    type SettlementRequestTtl: Get<u32>;

    /// Pinned Cardano-network genesis hash. Verifying attestors must
    /// sign with this exact value or the bundle is rejected. Prevents
    /// preprod attestations landing on mainnet runtime and vice versa.
    type MainchainGenesisHash: Get<[u8; 32]>;
}
```

### 3.5 New storage

```rust
/// Phase 1 → Phase 2 hand-off slot. Bounded; idempotent on claim_id.
#[pallet::storage]
pub type ClaimSettlementRequests<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ClaimId,
    SettlementRequestRecord<T>,
    OptionQuery,
>;

#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, Clone)]
pub struct SettlementRequestRecord<T: Config> {
    pub requester: T::AccountId,            // for slash routing (#84)
    pub evidence: SettlementEvidence,
    pub settled_direct: bool,
    pub submitted_block: BlockNumberFor<T>,
}
```

### 3.6 New errors

```rust
SettlementRequestMissing,          // attest_settle before request_settle
SettlementRequestExpired,          // pending > SettlementRequestTtl blocks
SettlementEvidenceMismatch,        // claim fields ↔ evidence fields disagree
FinalityDepthBelowMinimum,         // depth < MinFinalityDepth
WrongMainchainGenesis,             // evidence pinned to wrong Cardano net
AlreadySettled,                    // claim.settled already true
```

### 3.7 What stays exactly the same

- `ensure_threshold_signatures`. Pure reuse, no changes. This is the
  Spartan/compounding payoff — the audited M-of-N path is unchanged.
- `claim.cardano_tx_hash` storage. Same field name, same semantics —
  just no longer settable by a vacuous hash.
- `BatchSettled` and `ClaimSettled` events. Same shape, same indices,
  same downstream tooling.
- `PoolUtilization` mutation arithmetic. Bit-for-bit identical.

### 3.8 Batch path

`settle_batch_atomic` gets the parallel split:

- `request_batch_settle(entries: BoundedVec<(ClaimId, SettlementEvidence, bool)>)`
- `attest_batch_settle(claim_ids, signatures)` — committee sigs over
  the batch digest of N `STCA`-style payloads, one per entry, all
  attested in a single sig-bundle.

Same Spartan rule: zero new sig-verify routines, one new digest schema.
The spec-207 / spec-208 batching wins are preserved.

### 3.9 In-flight on-chain state migration

See §4.

---

## 4. Migration Risks

### 4.1 Existing settled-but-unverified claims on preprod

Live state snapshot (per `project_intent_settlement_wave2_status.md`):
- Wave 2.5 / 2.6 demos landed on preprod block-range early May 2026.
- Real Cardano-tx `1dfb6f4b1f3275...` tied to claim_id
  `0x0ffec26ad9f9...` was settled in W2.3.
- Quantity of preprod settled claims at this writing: low single-digit
  per memory; **NO mainnet deploy of `pallet-intent-settlement` exists**
  per `project_intent_settlement_wave2_status.md` ("Mainnet pallet
  deploy depends on Materios mainnet existing").

### 4.2 Recommended policy: **grandfather + lock**

1. **Preprod existing settled claims:** flagged with a
   `pre_audit_settlement: bool` storage field (defaults false on new
   state; set true via one-time on-chain migration for the pre-fix
   settled IntentIds). UI / explorer surface a "unverified (legacy)"
   badge. Pool accounting is unchanged.
   - Spartan / DoD: a one-line `OnRuntimeUpgrade` migration that walks
     existing `Claims` where `settled = true` and sets
     `pre_audit_settlement = true`. Bounded (preprod settled claim
     count is small).
2. **No backfill of evidence.** It would require off-chain attestors
   to re-prove finality of weeks-old Cardano txs. Cost > value for a
   preprod-only set. Move on.
3. **No forfeit.** Users on preprod were testing; pool capital is
   FPS-funded play money. No real-money fairness issue.
4. **Cut-off block.** On the runtime upgrade that lands this fix
   (call it spec-N), a constant `STCA_CUTOVER_BLOCK = N+50` (~5 min
   grace) defines when the new path becomes mandatory. Before that
   block, both old and new paths coexist (the old path is deprecated
   but functional); after, the old `settle_claim` rejects with
   `Error::DeprecatedExtrinsic` and only `attest_settle` works.
5. **Keeper rollout window.** The 50-block grace lets the in-flight
   TS keeper PR #25 + cert-daemon get redeployed before the cutover
   hard-locks.

### 4.3 What if a mainnet ships before the fix?

Single biggest risk: spec-deploy timing collides with the audit fix.
Mitigation:
- This memo locks the design now. PR can be implemented in 1-2 weeks
  by a single engineer. Lands well ahead of any plausible mainnet
  deploy (per `project_iog_strategic_pitch.md` outreach starts at
  epoch 285, and the audit response is on the critical path).
- If a runtime-upgrade timeline does collide: ship the fix as
  spec-{mainnet+1} with the cutover at mainnet-genesis (i.e., the
  old path was never live on mainnet at all). No grandfather needed.
- Worst case (fix slips after mainnet): same migration recipe as
  preprod, but with FPS treasury earmarking 1% of pool NAV as a
  fund to make unverified-settlement-victims whole if any of the
  pre-fix claims turn out to have been fraudulent. Bounded blast
  radius.

### 4.4 SDK breakage

The TS SDK in `sdk/src/multisig.ts` (`settleClaimPayload`,
`buildSigBundle`) ships a versioned compatibility shim. Old payload
helpers are kept under a `legacy/` namespace, marked deprecated in
JSDoc. Keeper code in `keeper/` (PR #25, W2.7 backlog) gets a single
file patch.

### 4.5 Risks summary

| Risk | Likelihood | Mitigation |
|---|---|---|
| Cutover block too tight, keeper not redeployed | low | 50-block grace + redeploy in advance per runbook |
| Cardano attestor disagrees on `observed_slot` (race at tx finalization edge) | medium | `MinFinalityDepth = 15` is well past the historical-reorg ceiling; the trimmed-median pattern from MON spec §4 applies if we want to be strict (drop attestors disagreeing by > 1 slot) |
| `mainchain_genesis_hash` pinning breaks on Cardano hardfork | low-medium | governance-tunable per spec runtime upgrade; same exposure surface as Mainchain follower already has |
| Cert-daemon Postgres / Ogmios outage stalls settlements | medium | this is a liveness issue, not a safety issue; the pallet emits `SettlementRequestExpired` and the keeper retries with fresh evidence; falls back to per-host Saturn cluster (already redundant) |

---

## 5. Interaction with Task #84

### 5.1 Task #84 quick recap (per spec §5.5)

#84 = "split settle_claim into a permissionless `keeper_request_settle`
+ committee `attest_settle`" + the bond + slash side.

### 5.2 This memo's relationship

**This memo (#78) lands the Phase-1/Phase-2 *split* shape and the
verifiable-payload contract. It is the *enabling* substrate for #84's
bond + slash addition.**

Concretely:
- The new `SettlementRequestRecord::requester` field is the slash-
  target hook for #84.
- The new `SettlementEvidence` is the publishable, falsifiable claim
  by the requester. #84 adds a `slash_bad_settlement_evidence`
  permissionless dispatch: anyone proves the evidence is wrong (e.g.,
  by submitting a Cardano-tx-doesn't-exist proof or an
  amount-mismatch proof), the requester's bond is slashed.
- The new `MinFinalityDepth` config means #84 can implement bond
  cooldown tied to the same finality model (release bond at `2 ×
  MinFinalityDepth` post-attestation).

**This memo does NOT pre-empt #84.** It also does not require #84.
Even without bonds, the M-of-N requirement on the *attest* half is
the same trust assumption as today (M committee members vouching) —
just bound to a verifiable observable instead of a vacuous hash.

**Migration story is clean** because the storage and extrinsic surface
introduced here is forward-compatible with #84's additions:
- `SettlementRequestRecord` gains a `bond_amount: u128` field
  (additive, default 0).
- `request_settle` gains an optional `bond` parameter (None →
  pre-#84 behaviour, Some → #84 enforced bond).
- `slash_bad_settlement_evidence` is purely new — no surface conflict.

### 5.3 Build order recommendation

1. Land this memo's #78 fix in spec-N. **Trust gap closes.** Audit
   P0 satisfied.
2. Land #84 bond + slash in spec-N+1 or spec-N+2. **Permissionlessness
   delivered.** Keeper-pool decentralized.
3. Optionally migrate sig source to MON in spec-N+M (once MON Phase 1
   is live and consumer-tested). **Decentralization tightened.**

Single-engineer effort: #78 is ~600 LOC in pallet + ~150 LOC SDK +
~50 LOC keeper patch. #84 is another ~400 LOC pallet + bond storage
+ slashing dispatch. Both fit in one sprint each.

---

## 6. Open Questions

These are real open questions, not "TBDs in the design." The design is
locked; these are the decisions an implementor must make at code time.

1. **`MinFinalityDepth` default for mainnet.** Spec §5.6 uses k=2160
   slots (~36 min) which is the protocol-level finality bound on
   Cardano. The proposed default of 15 blocks here is the Materios-
   side equivalent for confidence, not the Cardano-side strict bound.
   Recommendation: bake the *Cardano-side* k=2160-slot rule into the
   attestor's local decision (it refuses to sign a fresh tx), and use
   `MinFinalityDepth = 15` Materios blocks for the *pallet*'s freshness
   gate. **Resolve at implementation:** which value is the on-chain
   `MinFinalityDepth` representing?

2. **Beneficiary hash format.** `blake2_224` of the Cardano address
   payment-key-hash, or full 32-byte hash of the full address bytes?
   The voucher already stores the Cardano address; the digest just
   needs *some* canonical form. Recommendation: blake2_256 of
   `Voucher.beneficiary` raw bytes (consistent with existing voucher-
   digest pattern, no new hash family).

3. **What does `attest_settle` do if `SettlementEvidence` disagrees
   with what M attestors signed?** Today's `ensure_threshold_signatures`
   verifies sigs over a single payload. With evidence pinned in
   storage, the attest-side payload is fully determined from chain
   state — so any disagreement is a sig-verify failure, not a new
   error variant. But: should attestors be allowed to overwrite the
   stored evidence if they have *better* observations (e.g., deeper
   depth)? Recommendation: **no** — stored evidence is canonical from
   `request_settle`; if it's wrong, request_settle reverts and a fresh
   one is needed. Simpler invariant. Slash side (#84) gives the
   requester an economic incentive to publish correct evidence.

4. **Should `attest_settle` allow committee to provide *additional*
   evidence beyond what the requester posted?** E.g., a higher-depth
   observation. Recommendation: **no, v1** — keep the payload pinned
   to stored evidence so the sig-verify is deterministic from chain
   state alone. v2 can add `attest_settle_with_evidence_upgrade`
   if a real use case emerges.

5. **What happens to `expire_policy_mirror`?** It has the same
   trust-gap shape (committee declares "policy expired on Cardano"
   with no on-chain evidence). Recommendation: same B+D treatment in
   a follow-up PR. Out of scope for #78 (different code path, same
   pattern). File as task #78b.

6. **Sig-verify ceiling.** New payload is 32 + 32 + 32 + 32 + 1 + 28 + 8 +
   4 + 8 + 32 = **209 bytes** preimage vs current 32 + 32 + 32 + 1 =
   **97 bytes**. Net cost = one extra blake2 round per signer (blake2
   processes 64-byte blocks, so 97→209 crosses from 2 blocks to 4 blocks).
   With M=3 and committee=64, the per-block additional weight is ~300 ns,
   negligible. **Note in benchmarking.rs:** rerun `cargo benchmark`
   to capture the new weight constants.

7. **MON co-existence.** When MON Phase 1 lands (4-6 wk), MON
   publishers gain the ability to publish `SettlementEvidence` as a
   committee-equivalent sig source. Question: same `MinSignerThreshold`
   or separate? Recommendation: separate config item
   `MonSettlementThreshold` so the two attestor pools can have
   independent quorum requirements (cert-daemon: M=3 of internal,
   MON: M=3 of 5 publishers).

8. **TEE-attestation interaction.** `pallet-tee-attestation`
   (per `project_wave3_phase2_polychain_pallet.md`) is live. Should
   `request_settle` require a TEE-attested evidence blob? Out of
   scope for v1 (the M-of-N attestation already provides the trust
   layer; TEE-evidence is a bonus). Open for v2.

9. **Permissionless watcher (#84 slash incentive).** The slash payout
   to a watcher proving fraudulent evidence — what's the curve? E.g.,
   "watcher receives X% of slashed bond, FPS treasury receives Y%."
   Concrete numbers belong in #84, not here, but the storage hooks
   exist post-#78.

10. **Re-entrancy of the cert-daemon attestor pool.** cert-daemon
    today runs one global attestation loop. Adding a second
    attestation type (cardano-tx-confirmed) means it needs to
    coordinate two M-of-N sig flows. Operationally: simple Python
    dispatch on pending event types. **Open:** does this need
    rate-limiting to prevent the daemon from being overwhelmed by a
    settle-storm? Recommendation: yes, cap concurrent attestation
    submissions per attestor at 8 (matches spec-207 batching ceiling).

---

## Decisions captured

| Decision | Value |
|---|---|
| Mechanism | **Hybrid B + D** (cert-daemon co-sign + split extrinsic) |
| Old `settle_claim` | retired at `STCA_CUTOVER_BLOCK = upgrade_block + 50` |
| New extrinsics | `request_settle` (open) + `attest_settle` (M-of-N) |
| Batch parallel | `request_batch_settle` + `attest_batch_settle` |
| New domain tag | `STCA` (replaces `STCL`) |
| New payload size | 209 bytes preimage (vs 97 today) — includes chain-state-derived `voucher_digest` |
| `MinFinalityDepth` default | 15 Materios blocks (+ attestor's own Cardano k=2160-slot rule, attestor-local) |
| `SettlementRequestTtl` | 2400 Materios blocks (~4h) |
| Mainchain pinning | `MainchainGenesisHash` runtime config |
| Migration | grandfather preprod, no backfill, cutover block |
| Sig source v1 | cert-daemon attestor pool (reuse) |
| Sig source v2 (future) | MON publishers (additive) |
| Sig source rejected | runtime API into in-node Cardano follower (determinism risk) |
| Task #84 relationship | this PR enables #84 (bond + slash) but does not require it |
| Migration policy for #78b (expire_policy_mirror) | same pattern, separate PR, separate task |

---

## Appendix A — Why the FAT payload is the actual safety property

The naive read of this design is: "we replace one hash with one hash;
why is that safer?"

The answer is that the *attestor's sig is now a falsifiable claim about
the Cardano chain*. Before: M attestors signed "I vouch this hash" —
which they could do without consulting Cardano at all. After: M
attestors sign "I observed Cardano tx H at slot S at depth D paying
amount A to beneficiary B on genesis G." Any single one of those
facts can be cross-checked later by a watcher (or an external auditor,
or the user themselves) against any Cardano archival node. If any
mismatch is found, the signing attestor has cryptographic evidence
linking their committee key to a false claim.

The previous design did not have this property because the payload was
purely an identifier — there was nothing to be wrong about. The new
design ties each sig to seven observable Cardano facts that a future
watcher dispatch (#84 slash route) can prosecute.

**This is the audit fix.** Not "we added a sig" — we already had M
sigs. The fix is "the sigs now commit to something checkable."

---

## Appendix B — Why we did not reach for MON first

The first-instinct answer to "we need on-chain Cardano-tx verification"
in a Materios architecture is "use the Oracle Network." MON publishes
to Cardano L1 every 30s; it has an aggregator that polls Cardano;
attestors sign Cardano-derived facts.

Three reasons MON is the wrong primary mechanism:

1. **MON is unbuilt.** Phase 1 is 4-6 weeks out. P0 audit fix needs
   to land before mainnet, not after MON gets through its 12-16 week
   Phase 3 audit. The Spartan rule: research-before-reinvent applies
   to *existing* primitives, not future ones.

2. **MON is a price oracle.** Its payload schema is `(asset_pair, price,
   timestamp)`. Bolting a `cardano_tx_confirmed` schema onto MON is a
   scope creep that delays both MON Phase 1 AND the audit fix. Better:
   ship the audit fix with cert-daemon (a primitive that already
   exists and signs arbitrary M-of-N payloads), then add MON as an
   alternate sig source once both are mature.

3. **MON publishers will be ~5-7 external operators**; cert-daemon is
   the internal 4 + onboarding pipeline. For a P0 *audit fix* the
   internal pool is the right starting trust set. For *production
   decentralization* MON co-signing is great. Decouple the timelines.

So MON is the right *next step* but not the right *first step*. The
new pallet surface is signature-source-agnostic precisely so MON can
slot in later without another migration.
