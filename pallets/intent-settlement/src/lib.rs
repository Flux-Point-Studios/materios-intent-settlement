//! # `pallet_intent_settlement`
//!
//! Materios-side pallet implementing Wave 2 of the Aegis intent-settlement
//! protocol per `docs/spec-v1.md §2`.
//!
//! Responsibilities:
//! - Store and expire user intents (`submit_intent`, `on_initialize` sweep).
//! - Accept committee M-of-N attestations (`attest_intent`).
//! - Issue vouchers (`request_voucher`) bound to a `BatchFairnessProof`.
//! - Mirror Cardano-side settlements (`settle_claim`, `expire_policy_mirror`).
//! - Track per-account ADA credits, consumed at BuyPolicy time and returned on
//!   expiry.
//! - Enforce the Aegis v2 Q1 pool-utilization cap at `submit_intent` time.
//!
//! All cross-layer types and hash pre-images are defined in [`types`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
mod signature_weights;
pub mod types;
pub mod voucher_canonicalize;
pub mod weights;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration;

#[cfg(test)]
mod proptest;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use types::*;
pub use weights::WeightInfo;

use parity_scale_codec::Encode;

/// Convert an `AccountId` into the 32-byte bag we hash into IntentId. The
/// pallet is generic over AccountId but we require it to be 32-byte
/// encodable (the usual Substrate assumption: `AccountId32`).
pub fn account_to_bytes<A: Encode>(account: &A) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bytes = account.encode();
    // AccountId32 encodes as 32 raw bytes; u64 (in test runtimes) encodes as 8.
    // We left-pad shorter representations so test-mode hashes are still
    // deterministic and do not collide across runtimes with 32-byte ids.
    let len = bytes.len().min(32);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Issue #7: domain tag for the `credit_deposit` multisig payload.
pub const TAG_CRDP: &[u8; 4] = b"CRDP";
/// Issue #7: domain tag for the `settle_claim` multisig payload.
pub const TAG_STCL: &[u8; 4] = b"STCL";
/// Task #174: domain tag for the `request_voucher` multisig payload. Closes
/// the M-of-N gap on the voucher-mint stage of the intent pipeline so a
/// single committee member can no longer unilaterally mint a voucher with
/// an attestation bundle they posted earlier.
pub const TAG_RVCH: &[u8; 4] = b"RVCH";
/// Task #177: domain tag for the `settle_batch_atomic` multisig payload. The
/// digest is computed once over the FULL ordered batch; one committee
/// signature bundle authorises N settlements. This is the central weight
/// optimisation that lifts user-TPS from ~0.07 to ~10+ by removing the
/// per-claim sig-verify cost.
pub const TAG_STBA: &[u8; 4] = b"STBA";
/// Task #211: domain tag for the `attest_batch_intents` multisig payload.
/// The digest is computed once over the FULL ordered list of intent_ids;
/// one committee signature bundle authorises N attestation transitions
/// (Pending -> Attested). Pre-spec-207 a 3-of-3 committee posted 3*N
/// `attest_intent` extrinsics per batch — at N=256 that's 768 sig-verify
/// rounds per epoch. Post-spec-207 the cost is ONE sig-verify per batch.
/// Domain-separated from STBA / STCL / CRDP / RVCH / SBIN so an ABIN
/// signature can never be replayed against any other call's pre-image.
pub const TAG_ABIN: &[u8; 4] = b"ABIN";
/// Task #212: domain tag for the `request_batch_vouchers` multisig
/// payload. The digest is computed once over the FULL ordered list of
/// (claim_id, intent_id, voucher_digest, bfpr_digest) tuples; one
/// committee signature bundle authorises N voucher mints. Pre-spec-207
/// each voucher mint required its own M-of-N round (per PR #26's RVCH
/// gate); post-spec-207 N mints collapse to one sig-verify. Domain-
/// separated from RVCH / STBA / STCL / CRDP / SBIN / ABIN so a batch-
/// voucher signature can never be replayed against any other pallet
/// pre-image.
pub const TAG_RVBN: &[u8; 4] = b"RVBN";
/// Task #210: domain tag for the `submit_batch_intents` event digest. There
/// is NO M-of-N gate on this extrinsic (it's user-side, not committee-side),
/// but emitting a canonical batch digest in the `BatchIntentsSubmitted`
/// event lets indexers correlate the on-chain landing with the keeper's
/// observed batch. Domain-separates from STBA/RVCH/STCL/CRDP and the
/// upcoming ABIN/RVBN tags so a SBIN digest can never be replayed onto a
/// committee-signed pre-image.
pub const TAG_SBIN: &[u8; 4] = b"SBIN";
/// Task #266 (mis-sec P0): grace period (in Materios blocks) between the
/// spec-N migration running and the cutover at which the legacy
/// `settle_claim` / `settle_batch_atomic` extrinsics hard-reject with
/// `DeprecatedExtrinsic`. 50 blocks ~= 5 minutes at the spec-204 6-second
/// block target, long enough for the in-flight TS keeper to redeploy onto
/// the new request_settle + attest_settle path before the old route
/// closes (per design memo §4.2 step 4-5).
pub const STCA_CUTOVER_GRACE: u32 = 50;

/// Task #267 (mis-sec P0): grace period (in Materios blocks) between the
/// spec-N migration running and the cutover at which the legacy
/// `expire_policy_mirror` extrinsic hard-rejects with `DeprecatedExtrinsic`.
/// Mirrors `STCA_CUTOVER_GRACE` exactly — same operational rationale (50
/// blocks ~= 5 minutes at the 6-second block target lets the in-flight
/// keeper redeploy onto the new request_expire_policy + attest_expire_policy
/// path before the old route closes).
pub const EXPP_CUTOVER_GRACE: u32 = 50;

/// `SettlementStorageVersion` written at genesis and by the final migration step.
pub const SETTLEMENT_STORAGE_VERSION: u32 = 4;

/// Balances named-reserve identifier holding every settlement bond. Refunds
/// and slashes move at most this reserve's amount, never another pallet's.
pub const SETTLEMENT_BOND_RESERVE_ID: [u8; 8] = *b"settbond";

/// Largest `observed_at_depth` that settlement evidence may claim: Cardano's
/// security parameter k (2160 blocks on mainnet and preprod). A transaction
/// k blocks deep is immutable, so deeper claims add no finality, and a
/// requester whose transaction is deeper claims k.
pub const MAX_OBSERVED_DEPTH: u32 = 2160;

/// Task #266 (mis-sec P0): domain tag for the **attested** `settle_claim`
/// payload (split into `request_settle` + `attest_settle`). Replaces the
/// legacy `STCL` tag with a payload that commits to the FAT observation
/// (voucher_digest + beneficiary + amount + depth + slot + Cardano genesis),
/// not just `(claim_id, cardano_tx_hash, settled_direct)`. Domain-separated
/// from `STCL` so a pre-fix sig can never be replayed onto the new path
/// even if the per-claim_id/tx_hash inputs are identical.
pub const TAG_STCA: &[u8; 4] = b"STCA";
/// Task #266 (mis-sec P0): domain tag for the **batch** parallel of
/// `attest_settle`. The committee signs one digest over N STCA-style
/// per-entry payloads, all attested in a single bundle. Domain-separated
/// from `STBA` (legacy `settle_batch_atomic`) so a pre-fix batch sig can
/// never replay onto the new attested-batch path.
pub const TAG_BSTA: &[u8; 4] = b"BSTA";

/// Task #267 (mis-sec P0): domain tag for the **attested** `expire_policy_mirror`
/// payload (split into `request_expire_policy` + `attest_expire_policy`).
/// Closes the SAME class of audit gap as STCA: the legacy
/// `expire_policy_mirror` accepted a single committee member's word with
/// ZERO evidence — any single signer could unilaterally flip any intent to
/// `Expired` and grief a live policyholder before settlement.
///
/// `EXPP` is verified absent from the other six pallet tags
/// (CRDP/STCL/RVCH/STBA/ABIN/RVBN/SBIN/STCA/BSTA/INTA) so a bundle signed
/// for an Expire request can never replay onto any settle/attest/voucher
/// pre-image, and vice versa. Domain-separation also extends backward in
/// time: the legacy `expire_policy_mirror` had NO domain tag and was
/// signature-free, so EXPP is structurally a fresh namespace.
pub const TAG_EXPP: &[u8; 4] = b"EXPP";

/// Task #74 (sec-review): domain tag for the per-call `attest_intent`
/// signature pre-image. Pre-fix `attest_intent` accepted a `(pubkey, sig)`
/// bundle and crossed threshold based on length alone — Substrate trusted
/// Cardano to verify the sig later. That meant the chain transitioned
/// intent state on UNVERIFIED bundles. This domain tag binds the signed
/// payload to the specific `intent_id` that's being attested so the runtime
/// can sr25519-verify each signature locally before incrementing the
/// pending bundle. Domain-separated from ABIN (the batch path) so a per-
/// call signature can never replay onto a batch payload.
pub const TAG_INTA: &[u8; 4] = b"INTA";

/// Canonical digest signed by committee members when authorizing a
/// `credit_deposit(target, amount, cardano_tx_hash)` call (Issue #7).
///
/// Pre-image now begins with a 32-byte Materios chain-identity prefix (#73)
/// so a bundle signed on preprod is structurally invalid on mainnet/testnet
/// or after a chain reset:
///
/// `blake2_256(b"CRDP" || materios_chain_id (32B)
///             || target_bytes (32B) || amount_ada (LE u64)
///             || cardano_tx_hash (32B))`
pub fn credit_deposit_payload(
    materios_chain_id: &[u8; 32],
    target_bytes: &[u8; 32],
    amount_ada: u64,
    cardano_tx_hash: &[u8; 32],
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32 + 8 + 32);
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(target_bytes);
    body.extend_from_slice(&amount_ada.to_le_bytes());
    body.extend_from_slice(cardano_tx_hash);
    crate::types::domain_hash(*TAG_CRDP, &body)
}

/// Canonical digest signed by committee members when authorizing a
/// `settle_claim(claim_id, cardano_tx_hash, settled_direct)` call (Issue #7).
///
/// Pre-image now begins with a 32-byte Materios chain-identity prefix (#73).
///
/// `blake2_256(b"STCL" || materios_chain_id (32B)
///             || claim_id (32B) || cardano_tx_hash (32B)
///             || settled_direct (1B))`
pub fn settle_claim_payload(
    materios_chain_id: &[u8; 32],
    claim_id: &IntentId,
    cardano_tx_hash: &[u8; 32],
    settled_direct: bool,
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32 + 32 + 1);
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(cardano_tx_hash);
    body.push(if settled_direct { 1u8 } else { 0u8 });
    crate::types::domain_hash(*TAG_STCL, &body)
}

/// Task #174: canonical digest signed by committee members when authorizing
/// a `request_voucher(claim_id, intent_id, voucher, fairness_proof)` call.
///
/// Pre-image now begins with a 32-byte Materios chain-identity prefix (#73).
///
/// `blake2_256(b"RVCH" || materios_chain_id (32B)
///             || claim_id (32B) || intent_id (32B)
///             || voucher_digest (32B) || bfpr_digest (32B))`
///
/// `voucher_digest` here is the chain-identity-bound CBOR form computed by
/// [`crate::voucher_canonicalize::compute_voucher_digest_with_address`]
/// (legacy SCALE form deleted, #79). All inputs are deterministic functions
/// of state visible to every honest operator at the moment of voucher mint.
///
/// Per `feedback_mofn_hash_determinism.md` no operator-local state (wall
/// clock, Cardano epoch, locally-computed verification level) appears in
/// the pre-image. Replay-across-epoch protection comes from the live
/// committee-membership check in `ensure_threshold_signatures`: rotated-out
/// members can no longer pass `is_member`, so old bundles can't be replayed
/// after a committee rotation.
pub fn request_voucher_payload(
    materios_chain_id: &[u8; 32],
    claim_id: &ClaimId,
    intent_id: &IntentId,
    voucher_digest: &[u8; 32],
    bfpr_digest: &[u8; 32],
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(intent_id.as_bytes());
    body.extend_from_slice(voucher_digest);
    body.extend_from_slice(bfpr_digest);
    crate::types::domain_hash(*TAG_RVCH, &body)
}

/// Canonical digest signed by committee members when authorizing a
/// `settle_batch_atomic(entries)` call (Task #177).
///
/// Pre-image now begins with a 32-byte Materios chain-identity prefix (#73).
///
/// `blake2_256(b"STBA" || materios_chain_id (32B)
///   || u32_le(entries.len())
///   || for each entry e: e.claim_id (32B) || e.cardano_tx_hash (32B)
///                        || (e.settled_direct as u8))`
///
/// Note this is a flat byte stream (NOT SCALE-encoded BoundedVec) so the
/// digest is independent of the wire-format quirks called out in
/// `feedback_substrate_interface_boundedvec_wrap.md`. The Aiken / TS keeper
/// mirror reconstructs the same byte stream from raw fields.
///
/// Per `feedback_mofn_hash_determinism.md` rule: only chain-derived inputs
/// (claim_ids, cardano_tx_hashes, settled_direct flags) appear in the
/// pre-image — no operator-local state.
pub fn settle_batch_atomic_payload(
    materios_chain_id: &[u8; 32],
    entries: &[SettleBatchEntry],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body =
        alloc::vec::Vec::with_capacity(32 + 4 + entries.len() * (32 + 32 + 1));
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(&n.to_le_bytes());
    for e in entries.iter() {
        body.extend_from_slice(e.claim_id.as_bytes());
        body.extend_from_slice(&e.cardano_tx_hash);
        body.push(if e.settled_direct { 1u8 } else { 0u8 });
    }
    crate::types::domain_hash(*TAG_STBA, &body)
}

/// Task #211: canonical digest signed by committee members when authorizing
/// an `attest_batch_intents(intent_ids)` call. Pre-image now begins with a
/// 32-byte Materios chain-identity prefix (#73).
///
/// `blake2_256(b"ABIN" || materios_chain_id (32B)
///             || u32_le(N) || N×intent_id (32B each))`
///
/// Flat byte stream — NOT SCALE — so the digest is independent of the
/// substrate-interface BoundedVec wrapping quirk
/// (`feedback_substrate_interface_boundedvec_wrap.md`). The Aiken / TS
/// keeper mirror reconstructs the same stream from raw bytes.
///
/// Per `feedback_mofn_hash_determinism.md`: only chain-derived intent_ids
/// appear in the pre-image (no operator-local state). All committee
/// members independently compute the same digest from the keeper's
/// announced intent_ids list, so threshold can never wedge from divergent
/// pre-images.
pub fn attest_batch_intents_payload(
    materios_chain_id: &[u8; 32],
    intent_ids: &[IntentId],
) -> [u8; 32] {
    let n = intent_ids.len() as u32;
    let mut body = alloc::vec::Vec::with_capacity(32 + 4 + intent_ids.len() * 32);
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(&n.to_le_bytes());
    for iid in intent_ids.iter() {
        body.extend_from_slice(iid.as_bytes());
    }
    crate::types::domain_hash(*TAG_ABIN, &body)
}

/// Task #212: canonical digest signed by committee members when
/// authorizing a `request_batch_vouchers(entries)` call. Pre-image now
/// begins with a 32-byte Materios chain-identity prefix (#73).
///
/// `blake2_256(b"RVBN" || materios_chain_id (32B) || u32_le(N)
///             || N x (claim_id (32B) || intent_id (32B)
///                     || voucher_digest (32B) || bfpr_digest (32B)))`
///
/// Each per-entry tuple's `voucher_digest` is the chain-identity-bound CBOR
/// form computed by `compute_voucher_digest_with_address` (#79). The pallet
/// re-derives this digest deterministically from each entry's `voucher`
/// before hashing, so the keeper and committee always see the same
/// pre-image.
///
/// Per `feedback_mofn_hash_determinism.md`: only chain-derived state
/// (claim_ids, intent_ids, deterministic Voucher + BFPR digests) appears
/// in the pre-image — no operator-local fields.
pub fn request_batch_vouchers_payload(
    materios_chain_id: &[u8; 32],
    entries: &[(ClaimId, IntentId, [u8; 32], [u8; 32])],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body =
        alloc::vec::Vec::with_capacity(32 + 4 + entries.len() * (32 + 32 + 32 + 32));
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(&n.to_le_bytes());
    for (claim_id, intent_id, voucher_d, bfpr_d) in entries.iter() {
        body.extend_from_slice(claim_id.as_bytes());
        body.extend_from_slice(intent_id.as_bytes());
        body.extend_from_slice(voucher_d);
        body.extend_from_slice(bfpr_d);
    }
    crate::types::domain_hash(*TAG_RVBN, &body)
}

/// Task #210: canonical batch digest emitted in the `BatchIntentsSubmitted`
/// event. There is NO M-of-N gate on `submit_batch_intents` (it's the
/// user-side stage), so this digest is purely an indexer-facing identity
/// for the batch — it does NOT serve as a sig pre-image. Pre-image is now
/// chain-id-bound (#73) for parity with the M-of-N family.
///
/// `blake2_256(b"SBIN" || materios_chain_id (32B)
///             || u32_le(N) || N×scale(IntentKind))`
///
/// The IntentKind SCALE encoding is identical to what the pallet hashes into
/// IntentId (modulo the per-intent submitter/nonce/block fields), so a
/// keeper that observed the batch off-chain can recompute this digest and
/// correlate with the on-chain `BatchIntentsSubmitted{batch_digest}`. The
/// included N prefix prevents trivial digest collision between two batches
/// that share a kind list of different lengths.
pub fn submit_batch_intents_payload(
    materios_chain_id: &[u8; 32],
    entries: &[SubmitIntentEntry],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body = alloc::vec::Vec::new();
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(&n.to_le_bytes());
    for e in entries.iter() {
        body.extend_from_slice(&e.kind.encode());
    }
    crate::types::domain_hash(*TAG_SBIN, &body)
}

/// Task #266 (mis-sec P0): canonical digest signed by committee members
/// when authorizing the second-phase `attest_settle(claim_id, signatures)`
/// call. Replaces the legacy `settle_claim_payload` 97-byte preimage.
///
/// Pre-image (209 bytes):
///
/// `blake2_256(
///     b"STCA" || materios_chain_id (32B)
///     || claim_id (32B)
///     || voucher_digest (32B)              // chain-state-derived from Vouchers[claim_id]
///     || cardano_tx_hash (32B)
///     || settled_direct (1B)
///     || beneficiary_addr_hash (28B)       // 28-byte payment-key hash from voucher addr
///     || amount_lovelace (LE u64, 8B)      // from claim.amount_ada
///     || observed_at_depth (LE u32, 4B)    // attestor's k value, >= MinFinalityDepth
///     || observed_slot (LE u64, 8B)        // Cardano slot of the tx
///     || mainchain_genesis_hash (32B)      // pins preprod vs mainnet
/// )`
///
/// The committee is no longer signing "trust me, this is a tx hash." Each
/// attestor cryptographically commits to a falsifiable Cardano-record fact
/// bound to the specific voucher that originated the claim — closing the
/// audit P0 gap where colluding M signers could rubber-stamp a vacuous hash.
///
/// `voucher_digest` is **chain-state-derived**: the pallet looks it up from
/// `Vouchers::<T>::get(claim_id)` at attest time and feeds it into the
/// preimage. The requester cannot influence this field (it is NOT part of
/// `SettlementEvidence`). This closes attack class A5 (voucher recycling).
///
/// Field order is FROZEN — bumping any field requires `settlement_version`
/// bump in the voucher digest, which propagates here.
#[allow(clippy::too_many_arguments)]
pub fn settle_claim_attested_payload(
    materios_chain_id: &[u8; 32],
    claim_id: &ClaimId,
    voucher_digest: &[u8; 32],
    cardano_tx_hash: &[u8; 32],
    settled_direct: bool,
    beneficiary_hash: &[u8; 28],
    amount_ada: u64,
    depth: u32,
    slot: u64,
    mc_genesis: &[u8; 32],
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(
        32 + 32 + 32 + 32 + 1 + 28 + 8 + 4 + 8 + 32,
    );
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(voucher_digest);
    body.extend_from_slice(cardano_tx_hash);
    body.push(if settled_direct { 1u8 } else { 0u8 });
    body.extend_from_slice(beneficiary_hash);
    body.extend_from_slice(&amount_ada.to_le_bytes());
    body.extend_from_slice(&depth.to_le_bytes());
    body.extend_from_slice(&slot.to_le_bytes());
    body.extend_from_slice(mc_genesis);
    crate::types::domain_hash(*TAG_STCA, &body)
}

/// Task #267 (mis-sec P0): canonical digest signed by committee members
/// when authorizing the second-phase `attest_expire_policy(intent_id,
/// signatures)` call. Replaces the legacy ZERO-evidence
/// `expire_policy_mirror` path with a falsifiable Cardano observation.
///
/// Pre-image (172 bytes):
///
/// `blake2_256(
///     b"EXPP" || materios_chain_id (32B)
///     || intent_id (32B)
///     || policy_id (32B)               // chain-state-derived from intent.kind (BuyPolicy.product_id) or 0 fallback
///     || cardano_tx_hash (32B)         // requester-asserted; #84 slash route prosecutes fakes
///     || observed_at_depth (LE u32, 4B)// attestor's k value, >= MinFinalityDepth
///     || observed_slot (LE u64, 8B)    // Cardano slot of the Expire-redeemer tx
///     || mainchain_genesis_hash (32B)  // pins preprod vs mainnet
/// )`
///
/// The committee is no longer signing "trust me, this intent expired."
/// Each attestor cryptographically commits to a falsifiable Cardano-record
/// fact bound to the specific intent — closing the audit P0 gap where a
/// single colluding signer could prematurely flip any intent to Expired.
///
/// `policy_id` is the IntentId fallback when the intent's kind is not a
/// `BuyPolicy` (RequestPayout carries a PolicyId field; RefundCredit has
/// none). The pallet resolves this deterministically at attest time from
/// `Intents::<T>::get(intent_id)`, so the requester cannot influence the
/// field — closing the recycling attack class (use one Cardano Expire tx
/// to flip a different Materios intent).
///
/// All inputs are either chain-state-derived (`materios_chain_id`,
/// `intent_id`, `policy_id` from on-chain Intent, `mainchain_genesis_hash`
/// from runtime config) or requester-committed in the matching
/// `PolicyExpireRequests[intent_id]` record (cardano_tx_hash, depth, slot),
/// so honest attestors independently recompute the same digest from chain
/// state alone (per `feedback_mofn_hash_determinism.md`).
///
/// Field order is FROZEN — bumping any field requires `settlement_version`
/// bump in the voucher digest pre-image, which propagates here.
pub fn expire_policy_attested_payload(
    materios_chain_id: &[u8; 32],
    intent_id: &IntentId,
    policy_id: &PolicyId,
    cardano_tx_hash: &[u8; 32],
    depth: u32,
    slot: u64,
    mc_genesis: &[u8; 32],
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32 + 32 + 32 + 4 + 8 + 32);
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(intent_id.as_bytes());
    body.extend_from_slice(policy_id.as_bytes());
    body.extend_from_slice(cardano_tx_hash);
    body.extend_from_slice(&depth.to_le_bytes());
    body.extend_from_slice(&slot.to_le_bytes());
    body.extend_from_slice(mc_genesis);
    crate::types::domain_hash(*TAG_EXPP, &body)
}

/// Task #266 (mis-sec P0): canonical digest signed by committee members when
/// authorizing `attest_batch_settle(claim_ids, signatures)`. ONE sig-verify
/// pass over the WHOLE batch, mirroring the spec-207 batching win for the
/// new attested-settlement path.
///
/// Pre-image:
///
/// `blake2_256(
///     b"BSTA" || materios_chain_id (32B) || u32_le(N)
///     || for each claim_id in claim_ids:
///         claim_id (32B)
///         || voucher_digest (32B)         // chain-state-derived
///         || cardano_tx_hash (32B)
///         || settled_direct (1B)
///         || beneficiary_addr_hash (28B)
///         || amount_lovelace (LE u64, 8B)
///         || observed_at_depth (LE u32, 4B)
///         || observed_slot (LE u64, 8B)
///         || mainchain_genesis_hash (32B)
/// )`
///
/// Flat byte stream — NOT SCALE-encoded — so the digest is independent of
/// substrate-interface BoundedVec wrapping quirks
/// (`feedback_substrate_interface_boundedvec_wrap.md`). The keeper / Aiken
/// mirror reconstructs the same byte stream from raw bytes per entry.
///
/// All per-entry inputs are either chain-state-derived (`voucher_digest` from
/// `Vouchers[claim_id]`, `mainchain_genesis_hash` from runtime config) or
/// requester-committed in the matching `ClaimSettlementRequests[claim_id]`
/// record, so committee members independently compute the same digest from
/// the chain state at attest time.
///
/// `EntryBytes` shape (209 bytes/entry) is identical to the single-call
/// `settle_claim_attested_payload`'s body, so an attentive operator can
/// recompose the per-entry digest from the same fields they signed once.
pub fn attest_batch_settle_payload(
    materios_chain_id: &[u8; 32],
    entries: &[BatchAttestEntryBytes],
) -> [u8; 32] {
    let n = entries.len() as u32;
    let mut body = alloc::vec::Vec::with_capacity(
        32 + 4 + entries.len() * (32 + 32 + 32 + 1 + 28 + 8 + 4 + 8 + 32),
    );
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(&n.to_le_bytes());
    for e in entries.iter() {
        body.extend_from_slice(e.claim_id.as_bytes());
        body.extend_from_slice(&e.voucher_digest);
        body.extend_from_slice(&e.cardano_tx_hash);
        body.push(if e.settled_direct { 1u8 } else { 0u8 });
        body.extend_from_slice(&e.beneficiary_hash);
        body.extend_from_slice(&e.amount_ada.to_le_bytes());
        body.extend_from_slice(&e.depth.to_le_bytes());
        body.extend_from_slice(&e.slot.to_le_bytes());
        body.extend_from_slice(&e.mc_genesis);
    }
    crate::types::domain_hash(*TAG_BSTA, &body)
}

/// Plain-bytes view of one attested-batch entry used by
/// [`attest_batch_settle_payload`]. The pallet hydrates this struct at
/// attest time from on-chain state (`ClaimSettlementRequests`,
/// `Vouchers`, `MainchainGenesisHash`) so all attestors recompute the
/// same byte stream without trusting any requester-supplied digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchAttestEntryBytes {
    pub claim_id: ClaimId,
    pub voucher_digest: [u8; 32],
    pub cardano_tx_hash: [u8; 32],
    pub settled_direct: bool,
    pub beneficiary_hash: [u8; 28],
    pub amount_ada: u64,
    pub depth: u32,
    pub slot: u64,
    pub mc_genesis: [u8; 32],
}

/// Task #74 (sec-review): canonical digest signed by a single committee
/// member when authorizing one increment of an `attest_intent(intent_id, ...)`
/// pending bundle. Pre-image:
///
/// `blake2_256(b"INTA" || intent_id (32B))`
///
/// Pre-fix the runtime accepted the `(pubkey, sig)` bundle on `attest_intent`
/// without verifying the signature (the comment claimed Cardano would
/// re-verify later). The chain still advanced state — Pending -> Attested —
/// based on bundle LENGTH alone, so any committee member could submit
/// garbage signatures and walk the threshold. This pre-image domain-tags
/// the signed payload with `INTA` and binds it to the specific `intent_id`
/// the caller is voting on, so the runtime can sr25519-verify the
/// signature locally via `T::SigVerifier::verify` before mutating storage.
///
/// Per `feedback_mofn_hash_determinism.md` rule: only chain-derived
/// `intent_id` appears in the pre-image — no operator-local state.
///
// TODO(sec-review): chain-id binding lands in #73. Once the chain-id
// hardening pass merges, the pre-image grows to:
//   `blake2_256(b"INTA" || materios_chain_id || intent_id || ...)`
// matching the same pattern landing on CRDP/STCL/RVCH/STBA/ABIN/RVBN.
// Coordinate with the #73 worktree before bumping this digest — Aiken /
// keeper / SDK fixtures must update in lockstep.
pub fn attest_intent_payload(
    materios_chain_id: &[u8; 32],
    intent_id: &IntentId,
) -> [u8; 32] {
    let mut body = alloc::vec::Vec::with_capacity(32 + 32);
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(intent_id.as_bytes());
    crate::types::domain_hash(*TAG_INTA, &body)
}

/// Task #84 (mis-sec P1): canonical digest signed by committee members when
/// authorizing a `slash_bad_settlement_evidence(claim_id, fraud_proof,
/// signatures)` call. The committee is attesting that the watcher's
/// `fraud_proof` is truthful — i.e., that the requester's stored
/// `SettlementEvidence` lied about a falsifiable Cardano fact.
///
/// Pre-image:
///
/// `blake2_256(b"FRV2" || chain_id || claim_id || request_id || SCALE(proof))`.
/// Request identity binds the requester, normalized u64 submission block,
/// evidence and settlement mode. A replacement cannot inherit old allegations.
pub fn slash_bad_settlement_evidence_payload<A: Encode, B: Copy + Into<u64>>(
    materios_chain_id: &[u8; 32],
    claim_id: &ClaimId,
    request: &SettlementRequestRecord<A, B>,
    fraud_proof: &FraudProof,
) -> [u8; 32] {
    let request_id = settlement_request_id(request);
    let encoded = fraud_proof.encode();
    let mut body = alloc::vec::Vec::with_capacity(96 + encoded.len());
    body.extend_from_slice(materios_chain_id);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(&request_id);
    body.extend_from_slice(&encoded);
    crate::types::domain_hash(*TAG_FRV2, &body)
}

pub fn settlement_request_id<A: Encode, B: Copy + Into<u64>>(
    request: &SettlementRequestRecord<A, B>,
) -> [u8; 32] {
    let submitted: u64 = request.submitted_block.into();
    sp_io::hashing::blake2_256(
        &(
            account_to_bytes(&request.requester),
            submitted,
            request.evidence,
            request.settled_direct,
        )
            .encode(),
    )
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec::Vec;
    use frame_support::{
        dispatch::DispatchResultWithPostInfo,
        pallet_prelude::*,
        traits::{tokens::BalanceStatus, Currency, NamedReservableCurrency, ReservableCurrency},
        BoundedVec, PalletId,
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::{AccountIdConversion, SaturatedConversion, Saturating, Zero};

    /// Task #84 (mis-sec P1): currency-balance alias for the bond surface.
    /// Aliased here so the pallet body can stay in terms of `BalanceOf<T>`
    /// without restating the full associated-type chain at every call site.
    pub type BalanceOf<T> = <<T as Config>::Currency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

    // ---------------------------------------------------------------------
    // Config
    // ---------------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Upper bound on committee size; `MaxCommittee = 32` per spec §3.1.
        #[pallet::constant]
        type MaxCommittee: Get<u32>;

        /// Max intents expired in a single block (TTL sweep bound).
        #[pallet::constant]
        type MaxExpirePerBlock: Get<u32>;

        /// Default intent TTL in blocks (`600 ≈ 1h` at 6s).
        #[pallet::constant]
        type DefaultIntentTTL: Get<BlockNumber>;

        /// Default claim TTL in blocks (`28_800 ≈ 48h`).
        #[pallet::constant]
        type DefaultClaimTTL: Get<BlockNumber>;

        /// Source of truth for who's on the committee (read-only from this
        /// pallet). We accept an abstract predicate so in tests we can swap it
        /// without wiring the full `pallet_committee_governance`.
        type CommitteeMembership: IsCommitteeMember<Self::AccountId>;

        /// Upper bound on the `PendingBatches` index (intents live in the
        /// index until terminal status). Prevents unbounded growth while also
        /// capping the `get_pending_batches` RPC worst-case. Per spec §2.7
        /// keepers poll in small chunks so 10_000 is ample headroom.
        #[pallet::constant]
        type MaxPendingBatches: Get<u32>;

        /// Genesis default for the `MinSignerThreshold` (number of distinct
        /// committee signatures required to authorize `credit_deposit` and
        /// `settle_claim`). Runtime governance (`set_min_signer_threshold`)
        /// can bump this post-launch without a code upgrade.
        #[pallet::constant]
        type DefaultMinSignerThreshold: Get<u32>;

        /// Signature verifier used by the M-of-N gate on `credit_deposit`
        /// and `settle_claim` (Issue #7). In prod this wires to sr25519; in
        /// tests we substitute a deterministic stub (see `MockSigVerifier`)
        /// so fixtures aren't forced to sign full sr25519 payloads.
        type SigVerifier: VerifyCommitteeSignature;

        /// Task #177: maximum number of claims settled in a single
        /// `settle_batch_atomic` call. The runtime configures this; the
        /// canonical default is `types::MAX_SETTLE_BATCH = 256`. The bound
        /// must fit in the normal-class block budget along with the M-of-N
        /// signature bundle.
        #[pallet::constant]
        type MaxSettleBatch: Get<u32>;

        /// Task #211: maximum number of intents attested in a single
        /// `attest_batch_intents` call. Canonical default is
        /// `types::MAX_ATTEST_BATCH = 256`. Enables collapsing M*N per-epoch
        /// committee extrinsics into ONE batch call.
        #[pallet::constant]
        type MaxAttestBatch: Get<u32>;

        /// Task #212: maximum number of vouchers issued in a single
        /// `request_batch_vouchers` call. Canonical default is
        /// `types::MAX_VOUCHER_BATCH = 256`.
        #[pallet::constant]
        type MaxVoucherBatch: Get<u32>;

        /// Task #210: maximum number of intents submitted in a single
        /// `submit_batch_intents` call. The runtime configures this; the
        /// canonical default is `types::MAX_SUBMIT_BATCH = 256`. Only
        /// constrained by per-block normal-class extrinsic budget plus the
        /// PendingBatches index headroom (so the largest realistic batch
        /// stays well within `MaxPendingBatches`).
        #[pallet::constant]
        type MaxSubmitBatch: Get<u32>;

        /// Task #73: 32-byte Materios chain identity (genesis hash). Pinned
        /// into every committee-signed pre-image so a bundle signed on
        /// preprod is structurally invalid on mainnet/testnet/post-reset.
        /// In the production runtime, plumb the actual genesis hash via
        /// `parameter_types! { pub MateriosChainId: H256 = ... }`.
        #[pallet::constant]
        type MateriosChainId: Get<sp_core::H256>;

        /// Task #73: Cardano network magic (1 = preprod, 764824073 = mainnet,
        /// 2 = preview). Encoded LE u32 in the voucher digest pre-image so a
        /// preprod-signed voucher can never settle on mainnet (or vice versa).
        #[pallet::constant]
        type NetworkMagic: Get<u32>;

        /// Task #73: 28-byte blake2b224 hash of the deployed `aegis_policy_v1`
        /// Aiken validator. Pinned into the voucher digest pre-image so a
        /// signed voucher is bound to the SPECIFIC policy script that's
        /// currently the on-chain source of truth — pre/post Aiken redeploy
        /// or pre/post `aiken blueprint apply` changes domain-separate
        /// automatically.
        #[pallet::constant]
        type AegisPolicyV1ScriptHash: Get<[u8; 28]>;

        /// Task #73: Settlement-protocol semver. Bumped on any breaking
        /// pre-image change so pre-bump and post-bump bundles are
        /// domain-separated even when all other fields collide.
        #[pallet::constant]
        type SettlementVersion: Get<u32>;

        /// Task #43: hook for runtime-benchmarks runs to bootstrap state
        /// that `T::CommitteeMembership` and `T::SigVerifier` would otherwise
        /// gate. Production runtimes wire this to a no-op for any
        /// non-bench feature flag; the runtime-benchmarks build injects a
        /// stub that registers the bench caller as a committee member and
        /// makes signature verification permissive. Only compiled under
        /// `feature = "runtime-benchmarks"` so it has zero on-chain cost.
        #[cfg(feature = "runtime-benchmarks")]
        type BenchmarkHelper: BenchmarkHelper<Self::AccountId>;

        /// Task #43: weight surface for the auto-generated frame-benchmarking
        /// output. Production runtimes wire this to the `SubstrateWeight`
        /// impl in `pallet_intent_settlement::weights` (auto-generated via
        /// `frame-omni-bencher`). Test runtimes default to `()` which
        /// returns a hand-tuned slope mirroring the generated curve.
        type WeightInfo: crate::weights::WeightInfo;

        /// Task #266 (mis-sec P0): minimum Cardano confirmation depth before
        /// a `request_settle` is eligible to be attested. Default 15 Materios
        /// blocks (~5 min preprod, ~36 min mainnet — matches the legacy
        /// keeper rule at `docs/spec-v1.md` L731). Governance-tunable via the
        /// same path used for `MinSignerThreshold`. The attestor's own
        /// Cardano-side k=2160-slot rule is enforced off-chain in
        /// cert-daemon; this constant is the **pallet's** freshness gate
        /// (attest_settle rejects bundles whose evidence reports
        /// `observed_at_depth < MinFinalityDepth`).
        #[pallet::constant]
        type MinFinalityDepth: Get<u32>;

        /// Task #266 (mis-sec P0): maximum age (in Materios blocks) of a
        /// pending settlement request before `attest_settle` rejects it
        /// with `SettlementRequestExpired`. Default 2400 blocks (~4h) — long
        /// enough for any attestor-pool downtime, short enough that stale
        /// requests don't pin storage.
        #[pallet::constant]
        type SettlementRequestTtl: Get<u32>;

        /// Task #266 (mis-sec P0): pinned 32-byte Cardano-network genesis
        /// hash. `attest_settle` rejects bundles whose
        /// `SettlementEvidence.mainchain_genesis_hash` does not match this
        /// constant, preventing preprod attestations landing on mainnet
        /// runtime and vice versa.
        #[pallet::constant]
        type MainchainGenesisHash: Get<[u8; 32]>;

        /// Currency holding settlement bonds under the
        /// `SETTLEMENT_BOND_RESERVE_ID` named reserve. `pallet_balances`
        /// qualifies when its `ReserveIdentifier` is `[u8; 8]` and
        /// `MaxReserves` is at least one.
        type Currency: NamedReservableCurrency<Self::AccountId, ReserveIdentifier = [u8; 8]>;

        /// Task #84 (mis-sec P1): basis-point share of a slashed bond paid
        /// out to the watcher who proved the fraud. `5000` (= 50%) is the
        /// test default and the design-memo §6 #9 starting point;
        /// governance-tunable post-launch. Values outside `[0, 10_000]`
        /// are clamped at the call site so a misconfigured runtime can
        /// never pay out more than the bond.
        #[pallet::constant]
        type SlashWatcherShareBps: Get<u32>;

        /// Minimum number of Materios blocks between `attest_settle` and
        /// `release_settlement_bond` for an attested request. This is a
        /// liquidity hold, not a challenge period: attestation consumes the
        /// pending request and no slash path exists afterwards. Tests use
        /// `30` so `release_settlement_bond_rejects_too_early` can be
        /// exercised inside a single block-stepped harness.
        #[pallet::constant]
        type BondReleaseDelayBlocks: Get<u32>;

        /// Minimum reserve per settlement request. Requests also require a
        /// positive bond when the host configures a zero minimum.
        #[pallet::constant]
        type MinSettlementBond: Get<u128>;

        /// Task #84 (mis-sec P1): pallet-id used to derive the treasury
        /// account that receives the non-watcher share of a slashed bond
        /// via `repatriate_reserved`. Per the task spec, production
        /// runtimes wire this to `PalletId(*b"mat/trsy")` so the
        /// slashed-bond destination matches the Materios treasury
        /// convention.
        #[pallet::constant]
        type SettlementTreasuryPalletId: Get<PalletId>;
    }

    /// Bench-only setup hook (see `Config::BenchmarkHelper`).
    #[cfg(feature = "runtime-benchmarks")]
    pub trait BenchmarkHelper<AccountId> {
        /// Add the supplied account to whatever committee-membership backing
        /// store the runtime uses, and make the M-of-N signature check
        /// pass-through for the duration of the benchmark.
        fn whitelist_as_committee(who: &AccountId);
    }

    /// Abstraction for verifying an `sr25519` signature over a committee
    /// pubkey / payload pair.
    pub trait VerifyCommitteeSignature {
        fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, msg: &[u8]) -> bool;
    }

    /// Production verifier: delegates to sr25519 via sp-io crypto host fn.
    pub struct Sr25519Verifier;
    impl VerifyCommitteeSignature for Sr25519Verifier {
        fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, msg: &[u8]) -> bool {
            let pk = sp_core::sr25519::Public::from_raw(*pubkey);
            let sg = sp_core::sr25519::Signature::from_raw(*sig);
            sp_io::crypto::sr25519_verify(&sg, msg, &pk)
        }
    }

    /// Task #43: bench-only verifier that accepts ANY signature. Compiled
    /// only under `feature = "runtime-benchmarks"` so it CANNOT be wired
    /// into a production binary by accident — the runtime's
    /// `type SigVerifier` flips to this struct via a `cfg(runtime-benchmarks)`
    /// guard in `runtime/src/lib.rs`. With the bench `sigverify` removed,
    /// the weight measurement reflects per-claim storage cost; downstream
    /// runtimes typically RE-ADD a fixed `sr25519_verify` weight charge in
    /// `weights.rs` to account for the production sig-verify cost.
    #[cfg(feature = "runtime-benchmarks")]
    pub struct BenchAllowAnyVerifier;
    #[cfg(feature = "runtime-benchmarks")]
    impl VerifyCommitteeSignature for BenchAllowAnyVerifier {
        fn verify(_pubkey: &CommitteePubkey, _sig: &CommitteeSig, _msg: &[u8]) -> bool {
            true
        }
    }

    /// Abstracts "is this account a member of the current committee?" plus
    /// the bidirectional `AccountId <-> CommitteePubkey` mapping that binds
    /// the caller of `attest_intent` to the pubkey they submit, closing the
    /// attestation-spoofing vector (Issue #4).
    pub trait IsCommitteeMember<AccountId> {
        fn is_member(who: &AccountId) -> bool;
        fn threshold() -> u32;
        fn member_count() -> u32;
        /// Derive the on-chain committee pubkey (`[u8; 32]`) from an
        /// `AccountId`. For `AccountId32` this is the raw 32 bytes of the
        /// account; for test runtimes with `AccountId = u64` we left-pad into
        /// a 32-byte buffer to keep the mapping injective.
        fn pubkey_of(who: &AccountId) -> CommitteePubkey;
        /// Reverse mapping (used to look up the "caller" account when we
        /// only have a pubkey, e.g. a signature in a multisig envelope).
        /// Returns `None` when the pubkey isn't in the current committee.
        fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<AccountId>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    #[pallet::storage]
    pub type Intents<T: Config> =
        StorageMap<_, Blake2_128Concat, IntentId, Intent<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    pub type Nonces<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Nonce, ValueQuery>;

    #[pallet::storage]
    pub type Credits<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, AdaLovelace, ValueQuery>;

    #[pallet::storage]
    pub type Claims<T: Config> =
        StorageMap<_, Blake2_128Concat, ClaimId, Claim, OptionQuery>;

    #[pallet::storage]
    pub type Vouchers<T: Config> =
        StorageMap<_, Blake2_128Concat, ClaimId, Voucher, OptionQuery>;

    /// Tracks committee signatures accumulated per intent during the
    /// `Pending -> Attested` transition.
    #[pallet::storage]
    pub type PendingAttestations<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IntentId,
        BoundedVec<(CommitteePubkey, CommitteeSig), <T as Config>::MaxCommittee>,
        ValueQuery,
    >;

    /// Final attestation bundles (frozen once threshold is reached). Exposed
    /// via the runtime-API for the keeper.
    #[pallet::storage]
    pub type AttestationSigs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IntentId,
        BoundedVec<(CommitteePubkey, CommitteeSig), <T as Config>::MaxCommittee>,
        OptionQuery,
    >;

    /// `block -> intents to sweep`. Bounded size guarantees predictable
    /// `on_initialize` weight.
    #[pallet::storage]
    pub type ExpiryQueue<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BlockNumber,
        BoundedVec<IntentId, ConstU32<MAX_EXPIRE_PER_BLOCK>>,
        ValueQuery,
    >;

    /// Idempotency set for `credit_deposit`. Key = (account, cardano_tx_hash).
    #[pallet::storage]
    pub type ProcessedDeposits<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, [u8; 32]), (), OptionQuery>;

    #[pallet::storage]
    pub type LastExportedBlock<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type IntentTTL<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type ClaimTTL<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type PoolUtilization<T: Config> =
        StorageValue<_, PoolUtilizationParams, ValueQuery>;

    /// Index of non-terminal intents (Issue #6). Maintained in lockstep with
    /// the `Intents` map:
    /// - `submit_intent` appends on success
    /// - `settle_claim`, `expire_policy_mirror`, TTL sweep, and the
    ///   `request_voucher` transition (Attested -> Vouchered) remove
    ///
    /// `get_pending_batches` now reads this index and status-filters in-memory
    /// instead of `Intents::<T>::iter()`, replacing the prior O(N) scan with
    /// O(index_len) which is itself bounded by `MaxPendingBatches`.
    #[pallet::storage]
    pub type PendingBatches<T: Config> = StorageValue<
        _,
        BoundedVec<IntentId, <T as Config>::MaxPendingBatches>,
        ValueQuery,
    >;

    /// Governance-tunable minimum number of distinct committee signatures
    /// required to authorize `credit_deposit` or `settle_claim` (Issue #7).
    /// A value of 0 means "not yet initialized — fall back to
    /// `DefaultMinSignerThreshold`"; the effective threshold in-flight is
    /// always `max(stored, 1)`, and further bounded by the committee size.
    #[pallet::storage]
    pub type MinSignerThreshold<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Pending settlement evidence. Successful attestation or slash removes
    /// the row. Past the inclusive TTL it may be replaced, refunding any bond,
    /// or removed by permissionless expired-bond release. Failed attestation
    /// does not remove it; there is no automatic historical-storage sweep.
    #[pallet::storage]
    pub type ClaimSettlementRequests<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        ClaimId,
        SettlementRequestRecord<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Task #266 (mis-sec P0): flag set by the spec-N OnRuntimeUpgrade
    /// migration on existing settled claims (the "grandfather + lock" policy
    /// from design memo §4.2). New settlements never set this — the per-
    /// claim absence is the canonical signal that the settlement followed
    /// the new STCA path with falsifiable Cardano evidence. Indexers /
    /// explorers surface a "unverified (legacy)" badge for entries flagged
    /// here.
    #[pallet::storage]
    pub type PreAuditSettlement<T: Config> =
        StorageMap<_, Blake2_128Concat, ClaimId, bool, ValueQuery>;

    /// Task #266 (mis-sec P0): Materios block at which the legacy
    /// `settle_claim` / `settle_batch_atomic` extrinsics flip to
    /// `Error::DeprecatedExtrinsic`. Set to `upgrade_block + 50` by the
    /// upgrade hook. Zero means immediately closed at storage version >= 1,
    /// or not yet scheduled on an older chain.
    #[pallet::storage]
    pub type StcaCutoverBlock<T: Config> =
        StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// Task #266 (mis-sec P0): storage version pin so the OnRuntimeUpgrade
    /// migration is idempotent. v0 = pre-fix (no `pre_audit_settlement`
    /// flags + legacy settle_claim path live); v1 = post-fix (legacy
    /// settlements grandfathered, STCA path live + cutover scheduled);
    /// v2 = post-#267 (legacy expire_policy_mirror grandfathered + EXPP
    /// path live + expire-cutover scheduled); v3 includes settlement bonds;
    /// v4 holds them under `SETTLEMENT_BOND_RESERVE_ID`. Fresh genesis
    /// starts at `SETTLEMENT_STORAGE_VERSION` with both legacy paths closed.
    #[pallet::storage]
    pub type SettlementStorageVersion<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Pending policy-expiry evidence, consumed on successful attestation.
    /// Requests may be replaced after the inclusive TTL; a failed attestation
    /// leaves the old row intact. There is no automatic expiry sweep.
    #[pallet::storage]
    pub type PolicyExpireRequests<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IntentId,
        ExpiryRequestRecord<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Task #267 (mis-sec P0): Materios block at which the legacy
    /// `expire_policy_mirror` extrinsic flips to
    /// `Error::DeprecatedExtrinsic`. Set to `upgrade_block + 50` by the
    /// upgrade hook. Zero means immediately closed at storage version >= 2,
    /// or not yet scheduled on an older chain.
    #[pallet::storage]
    pub type PolicyExpireCutoverBlock<T: Config> =
        StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// Task #267 (mis-sec P0): flag set by the spec-N+1 OnRuntimeUpgrade
    /// migration on intents already in `Expired` state at the moment the
    /// migration ran (the "grandfather + lock" policy mirroring the STCA
    /// path). New expirations via `attest_expire_policy` never set this —
    /// the per-intent absence is the canonical signal that the expiration
    /// followed the new EXPP path with falsifiable Cardano evidence.
    /// Indexers / explorers surface a "unverified (legacy)" badge for
    /// entries flagged here.
    ///
    /// Note: this flags both legacy-path expirations AND TTL-sweep
    /// expirations, since the on-chain `Intent.status = Expired` value
    /// alone does not distinguish them. Audit tooling that needs to split
    /// "expired-by-Cardano-mirror" from "expired-by-TTL" already has the
    /// `ExpiryReason` discriminator in the `IntentExpired` event log,
    /// which is the canonical source of truth.
    #[pallet::storage]
    pub type PreAuditExpiry<T: Config> =
        StorageMap<_, Blake2_128Concat, IntentId, bool, ValueQuery>;

    /// Claim-wide slash tombstones written before slashes became
    /// request-scoped. Dispatches no longer read or write it, so existing
    /// entries do not block new requests; the declaration keeps them
    /// decodable.
    #[pallet::storage]
    pub type BondSlashedRequests<T: Config> =
        StorageMap<_, Blake2_128Concat, ClaimId, (), OptionQuery>;

    /// `(claim_id, settlement_request_id)` of every slashed request. An
    /// FRV2 bundle commits to one request id, and only an identical repost
    /// in the slashing block can recreate it, so refusing those reposts
    /// lets each signed allegation slash once. Other requests for the
    /// claim are unaffected.
    #[pallet::storage]
    pub type SlashedSettlementRequests<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, ClaimId, Blake2_128Concat, [u8; 32], (), OptionQuery>;

    /// Task #84 (mis-sec P1): per-claim Materios block at which the
    /// matching `ClaimSettlementRequests` entry was attested via
    /// `attest_settle` (i.e., the claim flipped to `settled`). Required by
    /// `release_settlement_bond` so the `BondReleaseDelayBlocks` gate has
    /// a concrete attested-at value to compare against — pinning this at
    /// attest time avoids re-deriving from a downstream `Claim` mutation.
    ///
    /// Set ONLY when a bond was previously posted (i.e., the matching
    /// request's `bond_amount > 0`). New attest_settle calls on
    /// non-bonded requests never write this storage — saves a slot.
    #[pallet::storage]
    pub type BondedClaimAttestedAt<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        ClaimId,
        BlockNumberFor<T>,
        OptionQuery,
    >;

    /// Task #84 (mis-sec P1): per-claim `(requester, bond_amount)` side
    /// record pinned at attest time when the matching request carried a
    /// positive bond. The pending `ClaimSettlementRequests` entry is
    /// consumed by `attest_settle`, so we need a separate slot to keep
    /// the unreserve target + amount visible to
    /// `release_settlement_bond` (which can be called by anyone). Pruned
    /// on release.
    #[pallet::storage]
    pub type BondedClaimRequester<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        ClaimId,
        (T::AccountId, u128),
        OptionQuery,
    >;

    /// Task #84 (mis-sec P1): cursor that tracks which claim_ids the
    /// v2→v3 migration walk has already rewritten. Used to drive
    /// truncation-recovery — the second `on_runtime_upgrade` invocation
    /// after a truncated first run reads this set and skips the rows
    /// already touched, so the version bump deterministically reaches
    /// the tail without re-processing the head. Cleared once v2→v3
    /// completes; never written outside the migration path.
    ///
    /// Bound: `MAX_SETTLE_BATCH` is the per-block envelope; on mainnet
    /// the live pending-request set is bounded by the keeper-throughput
    /// times TTL, which stays under 256 in steady state. A larger
    /// pending set would force more than one chunked migration block,
    /// which is exactly the recovery property we're preserving.
    #[pallet::storage]
    pub type BondMigrationProgress<T: Config> = StorageValue<
        _,
        BoundedVec<ClaimId, ConstU32<MAX_SETTLE_BATCH>>,
        ValueQuery,
    >;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        IntentSubmitted {
            intent_id: IntentId,
            submitter: T::AccountId,
            nonce: Nonce,
        },
        IntentAttested {
            intent_id: IntentId,
            attestor_count: u32,
        },
        VoucherIssued {
            claim_id: ClaimId,
            voucher_digest: [u8; 32],
            fairness_proof_digest: [u8; 32],
        },
        ClaimSettled {
            claim_id: ClaimId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
        },
        IntentExpired {
            intent_id: IntentId,
            reason: ExpiryReason,
        },
        CreditRefundRequested {
            intent_id: IntentId,
            submitter: T::AccountId,
            amount_ada: AdaLovelace,
        },
        CreditsCredited {
            account: T::AccountId,
            delta_ada: AdaLovelace,
            source_cardano_tx: [u8; 32],
        },
        PoolUtilizationUpdated {
            total_nav_ada: AdaLovelace,
            outstanding_coverage_ada: AdaLovelace,
        },
        /// Task #177: a `settle_batch_atomic` call landed and settled `count`
        /// claims under one committee-signature verification. `batch_digest`
        /// is the canonical pre-image hash (b"STBA" || ...) so off-chain
        /// observers can correlate the on-chain event with the keeper's
        /// signed batch object. `settled_direct_count` lets indexers split
        /// keeper-batch vs direct-path settlements without iterating the
        /// claims map.
        BatchSettled {
            count: u32,
            batch_digest: [u8; 32],
            settled_direct_count: u32,
        },
        /// Sec-review LOW #1 hardening: the `on_runtime_upgrade` migration
        /// that flags pre-audit settled claims iterates `Claims` with a
        /// per-block cap (`MAX_MIGRATE_CLAIMS = 1024`). If the cap is hit,
        /// the migration emits this event AND skips the storage-version
        /// bump so a follow-up call drains the remaining tail. Empty
        /// preprod state (low single-digit claims) never trips this; it's
        /// a planning hazard for mainnet-scale `Claims` storage.
        PreAuditMigrationTruncated {
            migrated_count: u32,
        },
        /// Task #211: an `attest_batch_intents` call landed and transitioned
        /// `attested_count` intents from Pending -> Attested under ONE
        /// committee-signature verification. `submitted_count` is the total
        /// number of intent_ids in the call (some may have been attested
        /// already, in which case they're idempotent no-ops and not
        /// counted as freshly attested). `batch_digest` is the canonical
        /// ABIN pre-image hash so indexers can correlate the on-chain
        /// landing with the keeper's signed batch. The legacy per-intent
        /// `IntentAttested` events are STILL emitted for every transitioned
        /// intent, so existing indexer paths keep working unchanged —
        /// `BatchIntentsAttested` is purely additive.
        BatchIntentsAttested {
            submitted_count: u32,
            attested_count: u32,
            batch_digest: [u8; 32],
            signer_count: u32,
        },
        /// Task #212: a `request_batch_vouchers` call landed and minted
        /// `count` vouchers under ONE committee-signature verification.
        /// The legacy per-voucher `VoucherIssued` events are STILL emitted
        /// inside the batch (one per entry) so existing indexer paths keep
        /// working unchanged. `batch_digest` is the canonical RVBN
        /// pre-image hash so off-chain observers can correlate the on-chain
        /// landing with the keeper's signed batch object.
        BatchVouchersIssued {
            count: u32,
            batch_digest: [u8; 32],
            total_amount_ada: AdaLovelace,
        },
        /// Task #210: a `submit_batch_intents` call landed and registered
        /// `count` user intents in one extrinsic. `batch_digest` is the
        /// canonical SBIN pre-image (`blake2_256(b"SBIN" || N || kinds)`)
        /// so off-chain observers can correlate the on-chain landing with
        /// the keeper's observed batch. The individual `IntentSubmitted`
        /// events are STILL emitted for every entry (one per intent), so
        /// downstream indexers tracking single-intent flow keep working
        /// without changes — `BatchIntentsSubmitted` is purely additive.
        BatchIntentsSubmitted {
            submitter: T::AccountId,
            count: u32,
            batch_digest: [u8; 32],
            total_premium_ada: AdaLovelace,
        },
        /// Task #266 (mis-sec P0): `request_settle` landed and pinned a
        /// pending request. Carries the requester (slash target for #84),
        /// the claim_id, the asserted Cardano tx hash, and the settled-
        /// direct flag. The committee's M-of-N follow-up signs over the
        /// canonical STCA digest (rebuilt from chain state + the stored
        /// evidence) before the claim flips to settled.
        SettlementRequested {
            claim_id: ClaimId,
            requester: T::AccountId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
        },
        /// Task #266 (mis-sec P0): a `request_batch_settle` call pinned N
        /// pending settlement requests under one extrinsic. Per-entry
        /// `SettlementRequested` events are NOT emitted (the batch event
        /// carries the requester + count; indexers can fan out via the
        /// `ClaimSettlementRequests` storage map if per-claim event lines
        /// are needed).
        BatchSettlementRequested {
            count: u32,
            requester: T::AccountId,
        },
        /// Task #267 (mis-sec P0): `request_expire_policy` landed and
        /// pinned a pending expire request. Carries the requester (slash
        /// target for #84), the intent_id, the asserted Cardano tx hash,
        /// and the policy_id witness. The committee's M-of-N follow-up
        /// signs over the canonical EXPP digest (rebuilt from chain state
        /// + the stored evidence) before the intent flips to Expired.
        ExpiryRequested {
            intent_id: IntentId,
            requester: T::AccountId,
            cardano_tx_hash: [u8; 32],
            policy_id_witness: PolicyId,
        },
        /// Currency reserved atomically with a request, or posted to a legacy request.
        SettlementBondPosted {
            claim_id: ClaimId,
            requester: T::AccountId,
            amount: u128,
        },
        /// Task #84 (mis-sec P1): a `slash_bad_settlement_evidence` call
        /// succeeded. The reserved bond is split: `watcher_share` units
        /// go to the caller (the watcher who posted the fraud proof);
        /// `treasury_share` units go to the
        /// `SettlementTreasuryPalletId`-derived treasury account. The
        /// `fraud_proof` discriminant is surfaced so explorers can
        /// distinguish WrongAmount vs TxNotFound vs WrongBeneficiary
        /// without re-decoding the pre-image.
        SettlementBondSlashed {
            claim_id: ClaimId,
            requester: T::AccountId,
            watcher: T::AccountId,
            watcher_share: u128,
            treasury_share: u128,
            fraud_proof: FraudProof,
        },
        /// Task #84 (mis-sec P1): a `release_settlement_bond` call
        /// succeeded — the requester's reserved units are unreserved and
        /// returned to their free balance. Emits in both the
        /// requester-initiated and the keeper-initiated release path
        /// (anyone can call once the delay has elapsed and the request
        /// wasn't slashed).
        SettlementBondReleased {
            claim_id: ClaimId,
            requester: T::AccountId,
            amount: u128,
        },
        /// A shared-reserve deficit was observed while returning a bond.
        SettlementBondReserveDeficit {
            claim_id: ClaimId,
            requester: T::AccountId,
            missing_amount: u128,
        },
        /// The committee settled the claim on its own evidence and displaced
        /// this requester's pending request, refunding its bond.
        SettlementRequestSuperseded {
            claim_id: ClaimId,
            requester: T::AccountId,
        },
    }

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// Intent already exists at this id (should be statistically impossible).
        DuplicateIntent,
        /// Account has insufficient ADA credit to cover a `BuyPolicy` premium
        /// or a `RefundCredit` request.
        InsufficientCredit,
        /// Caller is not a current committee member.
        NotCommitteeMember,
        /// Attestation signature did not verify against the IntentId digest.
        BadAttestationSig,
        /// The provided pubkey isn't in the current committee set.
        UnknownCommitteePubkey,
        /// Caller tried to add a duplicate pubkey to the attestation bundle.
        DuplicatePubkey,
        /// The intent is not in the expected status for this extrinsic.
        IntentStatusMismatch,
        /// Intent not found.
        IntentNotFound,
        /// Claim not found.
        ClaimNotFound,
        /// Voucher already exists for this claim.
        DuplicateVoucher,
        /// Fairness-proof invariant violated (sum, scale, ordering).
        InvalidFairnessProof,
        /// Voucher-proof binding: voucher.bfpr_digest doesn't match.
        FairnessDigestMismatch,
        /// Submitted past TTL window.
        TTLElapsed,
        /// Pool utilization would exceed hard cap.
        PoolUtilizationExceeded,
        /// Dwell period for credit refund not yet satisfied.
        DwellNotSatisfied,
        /// Deposit already processed (idempotency guard).
        DepositAlreadyProcessed,
        /// Expire-policy-mirror called on an unknown policy.
        UnknownPolicy,
        /// Committee bundle size exceeds configured MaxCommittee.
        TooManySigs,
        /// Issue #4: `attest_intent` was called with a `pubkey` argument that
        /// does not derive back to the signed origin. Blocks a single caller
        /// from spoofing N attestations via N different pubkeys.
        CallerPubkeyMismatch,
        /// Issue #5: accumulating the batch's fairness-proof amount into
        /// `outstanding_coverage_ada` would overflow `u64`. Rejected rather
        /// than silently wrapping.
        CoverageOverflow,
        /// Issue #6: `PendingBatches` index is at `MaxPendingBatches` capacity.
        /// Caller must wait for pending intents to terminalize before
        /// submitting another. Never hits in steady state — the bound is
        /// sized (10k) for well behind the keeper-poll watermark.
        PendingBatchesFull,
        /// Issue #7: the multisig envelope did not contain enough distinct
        /// valid signatures (threshold check). Carries no details to avoid
        /// leaking which specific signer was missing.
        InsufficientSignatures,
        /// Issue #7: a duplicate pubkey appeared in the multisig signer list.
        /// Treated as a hard reject (not a de-dup) so that replay attacks are
        /// unambiguously surfaced.
        DuplicateSigner,
        /// Issue #7: a signature in the multisig envelope failed sr25519
        /// verification against the canonical payload digest.
        InvalidSignature,
        /// Issue #7: a pubkey in the multisig envelope is not a current
        /// committee member.
        SignerNotCommitteeMember,
        /// Task #177: `settle_batch_atomic` was called with an empty batch.
        /// Trivially-rejecting an empty batch keeps the weight model honest
        /// (we charge ~baseline + N*per-entry; N=0 must not slip through as
        /// "free").
        EmptyBatch,
        /// Task #177: a single batch contained the same `claim_id` twice.
        /// The batch is rejected atomically; no settlements are applied.
        DuplicateClaimInBatch,
        /// Task #177: a claim in the batch was already settled before the
        /// batch landed. Atomic rejection preserves the all-or-nothing
        /// semantic that lets keepers retry the whole batch deterministically.
        BatchClaimAlreadySettled,
        /// Task #211: `attest_batch_intents` was called with an empty
        /// intent_ids vec. Atomically rejected (no fee/state movement) so
        /// the weight model stays honest.
        EmptyAttestBatch,
        /// Task #211: a single batch contained the same `intent_id` twice.
        /// Atomic rejection — pallet must surface the keeper bug rather
        /// than silently dedup.
        DuplicateIntentInBatch,
        /// Task #212: `request_batch_vouchers` was called with an empty
        /// entries vec. Atomically rejected.
        EmptyVoucherBatch,
        /// Task #212: a single batch contained the same `claim_id` twice.
        /// Atomically rejected — pallet must surface the keeper bug.
        DuplicateClaimInVoucherBatch,
        /// Task #210: `submit_batch_intents` was called with an empty entries
        /// vec. Atomically rejected (no fee/credit movement) so the weight
        /// model stays honest (we charge ~baseline + N*per-entry; N=0 must
        /// not slip through as "free").
        EmptyIntentBatch,
        /// Task #210: summing per-entry `BuyPolicy.premium_ada` across the
        /// batch overflows `u64`. Cheaper to reject than to silently wrap,
        /// matching the Issue #5 `CoverageOverflow` precedent on the
        /// voucher-mint stage.
        SubmitBatchPremiumOverflow,
        /// Task #79: the voucher's `beneficiary_cardano_addr` is not a valid
        /// CIP-0019 type-0 (payment VK + stake VK inline) address. The
        /// canonical voucher digest only supports this shape in v1; vouchers
        /// issued to script-payment / pointer / type-1+ addresses MUST be
        /// rejected here so the keeper's mirror digest cannot diverge.
        InvalidBeneficiaryAddress,
        /// Task #75 (sec-review): caller submitted a `signatures` Vec longer
        /// than `MaxCommittee`. Pre-fix the unbounded Vec walked into
        /// `ensure_threshold_signatures` and ran a full sr25519 verify pass
        /// over EVERY entry before the BoundedVec-storage truncate ever
        /// fired — a 1024-entry submission burned 1024 verifies before
        /// bailing. Capping at the top of every M-of-N extrinsic makes the
        /// DoS surface a constant `MaxCommittee` worth of work.
        TooManySignatures,
        /// Task #74 (sec-review): `set_min_signer_threshold` rejected because
        /// the requested floor exceeds the live committee threshold (which
        /// is the chain's authoritative source for "how many distinct
        /// committee sigs exist"). Without this clamp, a root caller could
        /// brick every M-of-N extrinsic by requiring more sigs than the
        /// committee has members.
        ThresholdAboveCommittee,
        /// Task #266 (mis-sec P0): `attest_settle` was called without a
        /// matching `request_settle` having landed first (or after it expired).
        /// The keeper must re-post `request_settle` before retrying.
        SettlementRequestMissing,
        /// Task #266 (mis-sec P0): the pending `ClaimSettlementRequests` entry
        /// is older than `Config::SettlementRequestTtl` blocks. The keeper
        /// must re-post `request_settle` with fresh evidence (the legacy
        /// observation may be stale — Cardano could have re-orged or the
        /// attestor pool was offline too long).
        SettlementRequestExpired,
        /// Task #266 (mis-sec P0): the `SettlementEvidence` posted in
        /// `request_settle` disagrees with the on-chain `Voucher`. Specifically
        /// one of (`amount_lovelace != voucher.amount_ada`,
        /// `beneficiary_addr_hash != payment_key_hash(voucher.beneficiary)`)
        /// is wrong. The requester is on the hook to publish correct evidence;
        /// task #84 bond + slash makes this economically costly.
        SettlementEvidenceMismatch,
        /// Task #266 (mis-sec P0): the requester reported
        /// `observed_at_depth < Config::MinFinalityDepth`. Cardano finality
        /// is depth-bounded; an attestor signing below this depth is
        /// vulnerable to a same-epoch rollback (attack A4 in the design memo).
        FinalityDepthBelowMinimum,
        /// Task #266 (mis-sec P0): the requester's
        /// `mainchain_genesis_hash` disagrees with `Config::MainchainGenesisHash`.
        /// A preprod sig bundle cannot settle a mainnet claim and vice versa —
        /// this is the network-isolation guarantee #73 establishes for the
        /// Materios side, extended here to the Cardano side.
        WrongMainchainGenesis,
        /// Task #266 (mis-sec P0): the underlying `Claim` is already in the
        /// settled state. Surfaced as an explicit error (rather than silent
        /// no-op) so a colluding M can't slip a duplicate settlement past a
        /// future watcher dispatch.
        AlreadySettled,
        /// Task #266 (mis-sec P0): the legacy `settle_claim` /
        /// `settle_batch_atomic` extrinsics are gated by a cutover block.
        /// Post-cutover (`STCA_CUTOVER_BLOCK = upgrade_block + 50`) any call
        /// to the legacy path is hard-rejected so old keepers cannot ride
        /// the deprecated trust-vacuous path past the audit fix.
        DeprecatedExtrinsic,
        /// Task #266 (mis-sec P0): the underlying `Voucher` for this claim
        /// is missing from storage. Either the keeper called `attest_settle`
        /// before `request_voucher` landed, or a downstream storage migration
        /// rolled the voucher back. Surfaced separately from `ClaimNotFound`
        /// so the keeper can distinguish "voucher gone" from "claim gone."
        VoucherMissing,
        /// Task #266 (mis-sec P0): a pending settlement request already
        /// exists for this claim_id. The legacy semantic of "last-write-wins
        /// on the keeper's resubmit" is replaced with strict idempotency —
        /// the requester must wait for `SettlementRequestExpired` before
        /// re-posting. Prevents a request-flapper from cycling stale evidence
        /// while M-of-N attestors are still gathering sigs over the prior
        /// observation.
        SettlementRequestAlreadyExists,
        /// Task #266 (mis-sec P0): batch attest payload's per-entry list
        /// disagreed with the stored requests. Either a `claim_id` is missing
        /// its `ClaimSettlementRequests` entry, or two `claim_id`s appear
        /// twice in the batch. Atomic rejection — the whole batch must be
        /// reconstructed from the live pending-requests set.
        BatchAttestEntryInvalid,
        /// Task #267 (mis-sec P0): `attest_expire_policy` was called without
        /// a matching `request_expire_policy` having landed first (or after
        /// it expired). The keeper must re-post `request_expire_policy`
        /// before retrying.
        ExpiryRequestMissing,
        /// Task #267 (mis-sec P0): the pending `PolicyExpireRequests` entry
        /// is older than `Config::SettlementRequestTtl` blocks. The keeper
        /// must re-post `request_expire_policy` with fresh evidence (the
        /// legacy observation may be stale — Cardano could have re-orged
        /// or the attestor pool was offline too long).
        ExpiryRequestExpired,
        /// Task #267 (mis-sec P0): a pending expire-policy request already
        /// exists for this intent_id. The legacy semantic of "last-write-
        /// wins on the keeper's resubmit" is replaced with strict
        /// idempotency — the requester must wait for `ExpiryRequestExpired`
        /// before re-posting. Prevents a request-flapper from cycling
        /// stale evidence while M-of-N attestors are still gathering sigs
        /// over the prior observation.
        ExpiryRequestAlreadyExists,
        /// Task #267 (mis-sec P0): the intent is not eligible for the
        /// expire-policy path. Either it is already settled (terminal
        /// — flipping to Expired would corrupt accounting) or it is a
        /// `RefundCredit` intent (which never represents a Cardano-side
        /// policy and therefore can't be expired by the Aegis Expire
        /// redeemer). Distinct from `UnknownPolicy` so the requester can
        /// distinguish "intent gone" from "intent here but wrong state."
        IntentNotEligibleForExpiry,
        /// Task #267 (mis-sec P0): the `ExpiryEvidence.policy_id_witness`
        /// disagrees with the on-chain intent's resolved policy id
        /// (`product_id` for BuyPolicy, `policy_id` for RequestPayout, zero
        /// hash for RefundCredit). Defends against recycling attack — a
        /// colluding requester can't bind one Cardano Expire tx to a
        /// different Materios intent.
        ExpiryEvidenceMismatch,
        /// Task #84 (mis-sec P1): `release_settlement_bond` /
        /// `slash_bad_settlement_evidence` was called on a request whose
        /// `bond_amount == 0` — no reserved funds to act on. Requesters
        /// must call `post_settlement_bond` first; pre-#84 records
        /// migrated from v2 land with `bond_amount = 0` so this error
        /// surfaces cleanly.
        BondNotReserved,
        /// Task #84 (mis-sec P1): `post_settlement_bond` was called a
        /// second time against the same claim. Bonds are single-shot —
        /// the requester picks one amount and commits. Re-bonding would
        /// either require unreserving the prior amount (race window with
        /// a watcher) or stacking reserves (NAV double-counting), so we
        /// hard-reject.
        BondAlreadyReserved,
        /// The pending request has not expired, or its attested liquidity hold has not ended.
        BondReleaseTooEarly,
        /// The alleged fraud contradicts the stored evidence's own fields.
        FraudProofInvalid,
        /// The fraud bundle contains fewer signatures than the configured threshold.
        FraudThresholdNotMet,
        /// An attested request can no longer receive a bond.
        RequestAlreadyAttested,
        /// This request instance was already prosecuted and cannot be reposted.
        BondSlashedNoRelease,
        /// Task #84 (mis-sec P1): `post_settlement_bond` was called by
        /// an origin that does not match the `requester` field on the
        /// stored `ClaimSettlementRequests` entry. Only the original
        /// requester can post a bond against their own request — there
        /// is no use case for a third party bonding someone else's
        /// claim.
        NotRequester,
        /// Task #84 (mis-sec P1): `post_settlement_bond` was called with
        /// an `amount` below `Config::MinSettlementBond`. The minimum
        /// bond floor stops a requester from posting a notional bond
        /// (e.g., 1 unit) just to claim the audit narrative of being
        /// "bonded" while economically not at risk.
        BondBelowMinimum,
        /// Task #84 (mis-sec P1): the supplied bond amount overflowed
        /// the runtime's `Balance` type at conversion time. Surfaced
        /// distinctly from a general arithmetic error so the requester
        /// can tell their `u128` input simply doesn't fit the chain's
        /// configured balance width.
        BondAmountConversionOverflow,
        /// Settlement evidence claims a depth above `MAX_OBSERVED_DEPTH`.
        FinalityDepthAboveMaximum,
        /// The pending request already carries this evidence and mode;
        /// attest it with `attest_settle` instead.
        SupersedeMatchesRequest,
    }

    // ---------------------------------------------------------------------
    // Genesis — seed sensible defaults for IntentTTL/ClaimTTL/PoolUtilization
    // ---------------------------------------------------------------------

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub intent_ttl: BlockNumber,
        pub claim_ttl: BlockNumber,
        pub pool_utilization: PoolUtilizationParams,
        /// Issue #7: M-of-N bar for `credit_deposit`/`settle_claim`. Zero
        /// means "use DefaultMinSignerThreshold from Config".
        pub min_signer_threshold: u32,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let ttl_intent = if self.intent_ttl == 0 {
                T::DefaultIntentTTL::get()
            } else {
                self.intent_ttl
            };
            let ttl_claim = if self.claim_ttl == 0 {
                T::DefaultClaimTTL::get()
            } else {
                self.claim_ttl
            };
            IntentTTL::<T>::put(ttl_intent);
            ClaimTTL::<T>::put(ttl_claim);
            PoolUtilization::<T>::put(self.pool_utilization);
            let mst = if self.min_signer_threshold == 0 {
                T::DefaultMinSignerThreshold::get()
            } else {
                self.min_signer_threshold
            };
            MinSignerThreshold::<T>::put(mst);
            SettlementStorageVersion::<T>::put(SETTLEMENT_STORAGE_VERSION);
            StcaCutoverBlock::<T>::put(BlockNumberFor::<T>::from(0u32));
            PolicyExpireCutoverBlock::<T>::put(BlockNumberFor::<T>::from(0u32));
        }
    }

    // ---------------------------------------------------------------------
    // Hooks — bounded TTL sweep
    // ---------------------------------------------------------------------

    /// Domain tags exposed in metadata so off-chain signers can detect the
    /// digest protocol a runtime verifies. Each getter returns the constant
    /// its digest function hashes.
    #[pallet::extra_constants]
    impl<T: Config> Pallet<T> {
        /// See [`MAX_OBSERVED_DEPTH`].
        #[pallet::constant_name(MaxObservedDepth)]
        fn max_observed_depth() -> u32 {
            MAX_OBSERVED_DEPTH
        }

        /// Committee-signed digest for `credit_deposit`.
        #[pallet::constant_name(CreditDepositTag)]
        fn credit_deposit_tag() -> [u8; 4] {
            *TAG_CRDP
        }

        /// Committee-signed digest for the legacy `settle_claim`.
        #[pallet::constant_name(SettleClaimTag)]
        fn settle_claim_tag() -> [u8; 4] {
            *TAG_STCL
        }

        /// Committee-signed digest for `request_voucher`.
        #[pallet::constant_name(RequestVoucherTag)]
        fn request_voucher_tag() -> [u8; 4] {
            *TAG_RVCH
        }

        /// Committee-signed digest for the legacy `settle_batch_atomic`.
        #[pallet::constant_name(SettleBatchAtomicTag)]
        fn settle_batch_atomic_tag() -> [u8; 4] {
            *TAG_STBA
        }

        /// Committee-signed digest for `attest_batch_intents`.
        #[pallet::constant_name(AttestBatchIntentsTag)]
        fn attest_batch_intents_tag() -> [u8; 4] {
            *TAG_ABIN
        }

        /// Committee-signed digest for `request_batch_vouchers`.
        #[pallet::constant_name(RequestBatchVouchersTag)]
        fn request_batch_vouchers_tag() -> [u8; 4] {
            *TAG_RVBN
        }

        /// Committee-signed STCA digest for `attest_settle` and `supersede_settlement_request`.
        #[pallet::constant_name(AttestSettleTag)]
        fn attest_settle_tag() -> [u8; 4] {
            *TAG_STCA
        }

        /// Committee-signed digest for `attest_batch_settle`.
        #[pallet::constant_name(AttestBatchSettleTag)]
        fn attest_batch_settle_tag() -> [u8; 4] {
            *TAG_BSTA
        }

        /// Committee-signed digest for `attest_expire_policy`.
        #[pallet::constant_name(AttestExpirePolicyTag)]
        fn attest_expire_policy_tag() -> [u8; 4] {
            *TAG_EXPP
        }

        /// Committee-signed digest for `attest_intent`.
        #[pallet::constant_name(AttestIntentTag)]
        fn attest_intent_tag() -> [u8; 4] {
            *TAG_INTA
        }

        /// Committee-signed digest for `slash_bad_settlement_evidence`; `FRV2` binds the request id.
        #[pallet::constant_name(SlashSettlementTag)]
        fn slash_settlement_tag() -> [u8; 4] {
            *TAG_FRV2
        }

        /// Unsigned batch digest emitted by `submit_batch_intents`.
        #[pallet::constant_name(SubmitBatchIntentsTag)]
        fn submit_batch_intents_tag() -> [u8; 4] {
            *TAG_SBIN
        }

        /// Intent id derivation.
        #[pallet::constant_name(IntentIdTag)]
        fn intent_id_tag() -> [u8; 4] {
            *TAG_INTT
        }

        /// Batch fairness proof digest, bound into voucher digests.
        #[pallet::constant_name(FairnessProofTag)]
        fn fairness_proof_tag() -> [u8; 4] {
            *TAG_BFPR
        }

        /// Committee set digest for the Cardano mirror.
        #[pallet::constant_name(CommitteeSetTag)]
        fn committee_set_tag() -> [u8; 4] {
            *TAG_CMTT
        }

        /// Voucher digest, bound into the voucher, STCA and BSTA digests.
        #[pallet::constant_name(VoucherTag)]
        fn voucher_tag() -> [u8; 4] {
            *TAG_VCHR
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
    {
        fn integrity_test() {
            assert!(
                T::MinFinalityDepth::get() <= MAX_OBSERVED_DEPTH,
                "MinFinalityDepth exceeds MAX_OBSERVED_DEPTH, so no evidence is acceptable"
            );
        }

        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Convert to u32 block for the expiry key. Saturating-cast avoids
            // panics on tests that burn through block numbers.
            let n_u32: u32 = n.into().try_into().unwrap_or(u32::MAX);
            let mut total = Weight::from_parts(10_000, 0);
            let to_expire = ExpiryQueue::<T>::take(n_u32);
            for intent_id in to_expire {
                total = total.saturating_add(Weight::from_parts(10_000, 0));
                if let Some(mut intent) = Intents::<T>::get(intent_id) {
                    if matches!(
                        intent.status,
                        IntentStatus::Pending | IntentStatus::Attested
                    ) {
                        intent.status = IntentStatus::Expired;
                        // Refund any reserved credit on expiry.
                        if let IntentKind::BuyPolicy { premium_ada, .. } = &intent.kind {
                            Credits::<T>::mutate(&intent.submitter, |c| {
                                *c = c.saturating_add(*premium_ada)
                            });
                        }
                        Intents::<T>::insert(intent_id, intent);
                        // Issue #6: drop from PendingBatches index on TTL
                        // expiry — terminal status.
                        Self::remove_from_pending_batches(intent_id);
                        Self::deposit_event(Event::IntentExpired {
                            intent_id,
                            reason: ExpiryReason::TTL,
                        });
                    }
                }
            }
            total
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            Self::try_state(frame_system::Pallet::<T>::block_number())?;
            let settled: Vec<ClaimId> = Claims::<T>::iter()
                .filter_map(|(id, claim)| claim.settled.then_some(id))
                .collect();
            let expired: Vec<IntentId> = Intents::<T>::iter()
                .filter_map(|(id, intent)| (intent.status == IntentStatus::Expired).then_some(id))
                .collect();
            Ok((
                SettlementStorageVersion::<T>::get(),
                StcaCutoverBlock::<T>::get(),
                PolicyExpireCutoverBlock::<T>::get(),
                Self::settlement_storage_digest(),
                settled,
                expired,
            )
                .encode())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            let mut input = &state[..];
            let (before, stca, expp, digest, settled, expired) = <(
                u32,
                BlockNumberFor<T>,
                BlockNumberFor<T>,
                [u8; 32],
                Vec<ClaimId>,
                Vec<IntentId>,
            )>::decode(&mut input)
            .map_err(|_| "invalid settlement pre-upgrade state")?;
            ensure!(
                input.is_empty() && before <= SETTLEMENT_STORAGE_VERSION,
                "invalid settlement pre-upgrade state"
            );
            let now = frame_system::Pallet::<T>::block_number();
            Self::try_state(now)?;
            let after = SettlementStorageVersion::<T>::get();
            ensure!(after >= before, "settlement storage version regressed");
            if before == SETTLEMENT_STORAGE_VERSION {
                ensure!(
                    Self::settlement_storage_digest() == digest,
                    "current-version settlement upgrade mutated settlement storage"
                );
            }
            let expected_stca = if before == 0 && stca.is_zero() {
                now.saturating_add(STCA_CUTOVER_GRACE.into())
            } else {
                stca
            };
            let expected_expp = if before < 2 && after > 0 && expp.is_zero() {
                now.saturating_add(EXPP_CUTOVER_GRACE.into())
            } else {
                expp
            };
            ensure!(
                StcaCutoverBlock::<T>::get() == expected_stca,
                "STCA cutover changed unexpectedly"
            );
            ensure!(
                PolicyExpireCutoverBlock::<T>::get() == expected_expp,
                "EXPP cutover changed unexpectedly"
            );
            if before == 0 && after > 0 {
                ensure!(
                    settled.iter().all(PreAuditSettlement::<T>::get),
                    "legacy settlement audit flags missing"
                );
            }
            if before < 2 && after > 1 {
                ensure!(
                    expired.iter().all(PreAuditExpiry::<T>::get),
                    "legacy expiry audit flags missing"
                );
            }
            Ok(())
        }

        #[cfg(feature = "try-runtime")]
        fn try_state(_now: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            let version = SettlementStorageVersion::<T>::get();
            ensure!(
                version <= SETTLEMENT_STORAGE_VERSION,
                "unknown settlement storage version"
            );
            ensure!(
                version == 2 || BondMigrationProgress::<T>::get().is_empty(),
                "bond migration progress outside version 2"
            );
            let stca = StcaCutoverBlock::<T>::get();
            let expp = PolicyExpireCutoverBlock::<T>::get();
            ensure!(
                match version {
                    0 => expp.is_zero(),
                    1 => !stca.is_zero(),
                    2 => !stca.is_zero() && !expp.is_zero(),
                    3 | SETTLEMENT_STORAGE_VERSION => stca.is_zero() == expp.is_zero(),
                    _ => false,
                },
                "settlement cutovers inconsistent with storage version"
            );
            if version == SETTLEMENT_STORAGE_VERSION {
                let mut owed = alloc::collections::BTreeMap::<T::AccountId, u128>::new();
                let pending = ClaimSettlementRequests::<T>::iter_values()
                    .map(|request| (request.requester, request.bond_amount));
                for (requester, bond) in pending.chain(BondedClaimRequester::<T>::iter_values()) {
                    let total = owed.entry(requester).or_default();
                    *total = total.saturating_add(bond);
                }
                for (requester, bond) in owed {
                    let reserved: u128 =
                        T::Currency::reserved_balance_named(&SETTLEMENT_BOND_RESERVE_ID, &requester)
                            .saturated_into();
                    ensure!(reserved >= bond, "settlement bonds exceed the settlement reserve");
                }
            }
            Ok(())
        }

        /// Spec-N / Spec-N+1 chained storage migration.
        ///
        /// **v0 → v1 (Task #266, mis-sec P0)**: walks the existing `Claims`
        /// map and flags every claim where `settled = true` with
        /// `PreAuditSettlement[claim_id] = true`. These entries pre-date
        /// the falsifiable-evidence path and ride the "grandfather + lock"
        /// policy from the design memo §4.2 — pool accounting unchanged,
        /// UI / explorer can surface a "unverified (legacy)" badge. Also
        /// stamps `StcaCutoverBlock = block + 50`, scheduling the legacy
        /// `settle_claim` / `settle_batch_atomic` cutover.
        ///
        /// **v1 → v2 (Task #267, mis-sec P0)**: walks the existing
        /// `Intents` map and flags every intent where `status = Expired`
        /// with `PreAuditExpiry[intent_id] = true`. These entries pre-
        /// date the EXPP path and could have been Expired via the
        /// legacy `expire_policy_mirror` (or via TTL sweep — the audit
        /// tooling distinguishes via the `IntentExpired` event log's
        /// `ExpiryReason` field, which is the canonical source). Also
        /// stamps `PolicyExpireCutoverBlock = block + 50`, scheduling the
        /// legacy `expire_policy_mirror` cutover.
        ///
        /// Both migrations are idempotent — they early-return once the
        /// version is at or past the target. The v0→v1 and v1→v2 phases
        /// run on the SAME `on_runtime_upgrade` invocation when the
        /// pallet upgrades from a pre-#266 runtime; on a pre-#267
        /// runtime that already ran the #266 migration, only the
        /// v1→v2 phase runs.
        ///
        /// Bounded — preprod settled-claim and expired-intent counts
        /// are single-digit. The MAX_MIGRATE caps prevent the
        /// migration from approaching the per-block weight ceiling
        /// even if mainnet `Claims` / `Intents` storage grows.
        fn on_runtime_upgrade() -> Weight {
            let mut total = Weight::from_parts(50_000, 0);
            // Production cap = 1024 (single normal-class block at preprod
            // scale + sub-block at low-thousands settled/expired entries).
            // Tests override to 2 so truncation-recovery is exercisable
            // with a handful of records (sec-review LOW #1/#2 regression
            // coverage for v0→v1, plus the matching v1→v2 case).
            #[cfg(not(test))]
            const MAX_MIGRATE_CLAIMS: usize = 1024;
            #[cfg(test)]
            const MAX_MIGRATE_CLAIMS: usize = 2;
            #[cfg(not(test))]
            const MAX_MIGRATE_INTENTS: usize = 1024;
            #[cfg(test)]
            const MAX_MIGRATE_INTENTS: usize = 2;

            // ----- v0 → v1: PreAuditSettlement + StcaCutoverBlock -----
            let current = SettlementStorageVersion::<T>::get();
            if current == 0 {
                let mut migrated: usize = 0;
                let mut truncated = false;
                for (claim_id, claim) in Claims::<T>::iter() {
                    if migrated >= MAX_MIGRATE_CLAIMS {
                        truncated = true;
                        break;
                    }
                    if !claim.settled {
                        continue;
                    }
                    if PreAuditSettlement::<T>::contains_key(claim_id) {
                        continue;
                    }
                    PreAuditSettlement::<T>::insert(claim_id, true);
                    total = total.saturating_add(Weight::from_parts(15_000, 0));
                    migrated = migrated.saturating_add(1);
                }
                if truncated {
                    Self::deposit_event(Event::PreAuditMigrationTruncated {
                        migrated_count: migrated as u32,
                    });
                }
                if StcaCutoverBlock::<T>::get() == BlockNumberFor::<T>::from(0u32) {
                    let now = <frame_system::Pallet<T>>::block_number();
                    let cutover = now
                        .saturating_add(BlockNumberFor::<T>::from(STCA_CUTOVER_GRACE));
                    StcaCutoverBlock::<T>::put(cutover);
                }
                if !truncated {
                    SettlementStorageVersion::<T>::put(1u32);
                }
                // Fall through to v1 → v2 if we successfully bumped.
                // Truncation in v0→v1 keeps the version at 0 so a
                // follow-up call drains the tail before v1→v2 ever
                // starts — same recovery semantic as the #266 fix.
                if truncated {
                    return total;
                }
            }

            // ----- v1 → v2: PreAuditExpiry + PolicyExpireCutoverBlock -----
            let current = SettlementStorageVersion::<T>::get();
            if current == 1 {
                let mut migrated: usize = 0;
                let mut truncated = false;
                for (intent_id, intent) in Intents::<T>::iter() {
                    if migrated >= MAX_MIGRATE_INTENTS {
                        truncated = true;
                        break;
                    }
                    // Only flag terminal-Expired intents. Pending /
                    // Attested / Vouchered / Settled / Refunded are not
                    // legacy-expire candidates (Settled is terminal but
                    // the flag is for the expire-side audit narrative,
                    // not settle — that's PreAuditSettlement's job).
                    if !matches!(intent.status, IntentStatus::Expired) {
                        continue;
                    }
                    // Skip already-flagged (recovery from a truncated run
                    // OR a legacy `expire_policy_mirror` call in the
                    // grace window that already set the flag at expire
                    // time — same skip-already-flagged pattern as v0→v1).
                    if PreAuditExpiry::<T>::contains_key(intent_id) {
                        continue;
                    }
                    PreAuditExpiry::<T>::insert(intent_id, true);
                    total = total.saturating_add(Weight::from_parts(15_000, 0));
                    migrated = migrated.saturating_add(1);
                }
                if truncated {
                    Self::deposit_event(Event::PreAuditMigrationTruncated {
                        migrated_count: migrated as u32,
                    });
                }
                if PolicyExpireCutoverBlock::<T>::get()
                    == BlockNumberFor::<T>::from(0u32)
                {
                    let now = <frame_system::Pallet<T>>::block_number();
                    let cutover = now
                        .saturating_add(BlockNumberFor::<T>::from(EXPP_CUTOVER_GRACE));
                    PolicyExpireCutoverBlock::<T>::put(cutover);
                }
                if !truncated {
                    SettlementStorageVersion::<T>::put(2u32);
                }
                // Same chained-fall-through gate as v0→v1: if we
                // truncated, hold the version at 1 so the next
                // `on_runtime_upgrade` invocation drains the tail
                // before v2→v3 ever starts.
                if truncated {
                    return total;
                }
            }

            // ----- v2 → v3: SettlementRequestRecord gains bond_amount ---
            //
            // Task #84 (mis-sec P1): the on-disk shape of
            // `SettlementRequestRecord` grew one field (`bond_amount: u128`,
            // LAST so the SCALE prefix is additive). Pre-#84 records
            // serialise as 4-field tuples; once the runtime loads the new
            // pallet binary, the decoder canonicalises them to the new
            // 5-field shape with `bond_amount: 0` automatically (additive
            // SCALE migration — the trailing field is absent so the
            // codec rejects, then we re-encode each row explicitly).
            //
            // Walk `ClaimSettlementRequests` in bounded chunks, tracking
            // progress via a cursor `BondMigrationCursor` so a truncated
            // run can pick up where it left off without re-processing
            // the head. Cap is per-block, so the migration drains the
            // tail across N blocks for any realistic pending-set size.
            //
            // For preprod scale (single-digit pending requests) this is
            // a no-op past the version bump. The cap keeps a runaway
            // pending-set on mainnet honest.
            #[cfg(not(test))]
            const MAX_MIGRATE_REQUESTS: usize = 1024;
            #[cfg(test)]
            const MAX_MIGRATE_REQUESTS: usize = 2;
            let current = SettlementStorageVersion::<T>::get();
            if current == 2 {
                let mut migrated: usize = 0;
                let mut truncated = false;
                // Cursor of already-rewritten keys. Persisted across
                // truncated runs so the second invocation skips the
                // head and reaches the tail (same recovery semantic
                // as v0→v1's skip-already-flagged pattern).
                let mut processed = BondMigrationProgress::<T>::get();
                let keys: alloc::vec::Vec<ClaimId> = ClaimSettlementRequests::<
                    T,
                >::iter_keys()
                .collect();
                for cid in keys {
                    if migrated >= MAX_MIGRATE_REQUESTS {
                        truncated = true;
                        break;
                    }
                    if processed.iter().any(|k| k == &cid) {
                        continue;
                    }
                    let existing = match ClaimSettlementRequests::<T>::get(cid) {
                        Some(r) => r,
                        None => continue, // raced away — fine
                    };
                    // Canonical zero-value rewrite. If a prior
                    // `post_settlement_bond` already set the field
                    // (impossible pre-v3, defensive for re-runs after
                    // an upgrade cycle), preserve it.
                    let preserved_bond = existing.bond_amount;
                    ClaimSettlementRequests::<T>::insert(
                        cid,
                        SettlementRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                            requester: existing.requester,
                            evidence: existing.evidence,
                            settled_direct: existing.settled_direct,
                            submitted_block: existing.submitted_block,
                            bond_amount: preserved_bond,
                        },
                    );
                    let _ = processed.try_push(cid);
                    total = total.saturating_add(Weight::from_parts(15_000, 0));
                    migrated = migrated.saturating_add(1);
                }
                // Persist progress (or clear on completion).
                if truncated {
                    BondMigrationProgress::<T>::put(processed);
                    Self::deposit_event(Event::PreAuditMigrationTruncated {
                        migrated_count: migrated as u32,
                    });
                } else {
                    BondMigrationProgress::<T>::kill();
                    SettlementStorageVersion::<T>::put(3u32);
                }
            }

            // ----- v3 → v4: bonds move to the settlement named reserve ---
            //
            // Every outstanding bond, pending or attested, is unreserved
            // from the anonymous pool and reserved again under
            // `SETTLEMENT_BOND_RESERVE_ID` in one pass. The pass must not
            // truncate: a refund through the named reserve cannot return
            // an anonymous bond. Its length is the number of outstanding
            // bonds, zero at a fresh genesis.
            let current = SettlementStorageVersion::<T>::get();
            if current == 3 {
                let pending = ClaimSettlementRequests::<T>::iter()
                    .filter(|(_, request)| request.bond_amount > 0)
                    .map(|(claim_id, request)| (claim_id, request.requester, request.bond_amount));
                let attested = BondedClaimRequester::<T>::iter()
                    .map(|(claim_id, (requester, bond))| (claim_id, requester, bond));
                let bonds: Vec<_> = pending.chain(attested).collect();
                total = total.saturating_add(T::DbWeight::get().reads(bonds.len() as u64 + 2));
                for (claim_id, requester, bond) in bonds {
                    total = total.saturating_add(T::DbWeight::get().reads_writes(2, 3));
                    let named = bond
                        .try_into()
                        .ok()
                        .map(|balance: BalanceOf<T>| {
                            let moved =
                                balance.saturating_sub(T::Currency::unreserve(&requester, balance));
                            match T::Currency::reserve_named(
                                &SETTLEMENT_BOND_RESERVE_ID,
                                &requester,
                                moved,
                            ) {
                                Ok(()) => moved.saturated_into::<u128>(),
                                Err(_) => 0,
                            }
                        })
                        .unwrap_or(0);
                    if named < bond {
                        Self::deposit_event(Event::SettlementBondReserveDeficit {
                            claim_id,
                            requester,
                            missing_amount: bond - named,
                        });
                    }
                }
                SettlementStorageVersion::<T>::put(SETTLEMENT_STORAGE_VERSION);
            }

            total
        }
    }

    // ---------------------------------------------------------------------
    // Extrinsics
    // ---------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
        T::AccountId: Encode,
    {
        /// Submit a new intent. Auto-increments `Nonces[who]`, schedules
        /// expiry, and (for `BuyPolicy`/`RefundCredit`) atomically debits
        /// `Credits[who]` by the premium/refund amount.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(500_000_000, 0))]
        pub fn submit_intent(origin: OriginFor<T>, kind: IntentKind) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_submit_intent(who, kind).map(|_| ())
        }

        /// Committee member posts one signature toward the M-of-N bundle for
        /// `intent_id`. First bundle to cross threshold transitions state to
        /// Attested and stores the final `AttestationSigs`. Subsequent calls
        /// are no-ops.
        ///
        /// Task #74 (sec-review):
        /// - Adds runtime sr25519 verification of `(pubkey, sig)` against the
        ///   canonical INTA pre-image (`b"INTA" || intent_id`). Pre-fix the
        ///   pallet trusted Cardano to verify later, so the chain transitioned
        ///   state on UNVERIFIED bundles. Now every signature must verify
        ///   locally via `T::SigVerifier::verify` before its slot in the
        ///   pending bundle counts.
        /// - Duplicate pubkey is now a HARD error (`Error::DuplicatePubkey`)
        ///   instead of a silent `Ok(())` — replay attempts must be visible
        ///   in failed-extrinsic counters, not absorbed.
        /// - Bundle-grow + threshold-cross logic runs inside
        ///   `with_storage_layer` so two `attest_intent` calls in the same
        ///   block can't race past threshold mid-mutation: the second call
        ///   either sees the first's committed state or rolls back atomically.
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(50_000_000, 0)
            .saturating_add(T::WeightInfo::threshold_signatures(1))
            .saturating_add(T::DbWeight::get().reads_writes(4, 4)), DispatchClass::Operational, Pays::No))]
        pub fn attest_intent(
            origin: OriginFor<T>,
            intent_id: IntentId,
            pubkey: CommitteePubkey,
            sig: CommitteeSig,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );

            // Issue #4: bind the `pubkey` argument to the signed origin.
            // Previously any committee member could post an attestation
            // "from" any other pubkey, letting one caller spoof N
            // attestations toward threshold. The derivation is runtime-
            // provided (`PubkeyOf`) so `AccountId32` maps to its raw 32-byte
            // public key while test runtimes with `u64` accounts left-pad.
            ensure!(
                T::CommitteeMembership::pubkey_of(&who) == pubkey,
                Error::<T>::CallerPubkeyMismatch
            );

            // If already Attested (or terminal), make this a no-op
            // (idempotent). Done BEFORE sig-verify so a stale call from a
            // late-arriving signer doesn't waste verify cycles.
            let intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::IntentNotFound)?;
            if intent.status != IntentStatus::Pending {
                return Ok(());
            }

            let mut bundle = PendingAttestations::<T>::get(intent_id);
            ensure!(
                !bundle.iter().any(|(p, _)| p == &pubkey),
                Error::<T>::DuplicatePubkey
            );

            let chain_id = Self::materios_chain_id_bytes();
            let payload = attest_intent_payload(&chain_id, &intent_id);
            ensure!(
                T::SigVerifier::verify(&pubkey, &sig, &payload),
                Error::<T>::InvalidSignature
            );

            // Task #74: bundle accumulation + threshold transition runs
            // inside one transactional storage layer so two concurrent
            // attest_intent calls in the same block can't both transition
            // state from a stale read of PendingAttestations. The closure
            // either commits both the bundle insert AND any threshold-
            // crossing intent flip, or rolls back atomically.
            frame_support::storage::with_storage_layer::<(), sp_runtime::DispatchError, _>(|| {
                bundle
                    .try_push((pubkey, sig))
                    .map_err(|_| Error::<T>::TooManySigs)?;
                PendingAttestations::<T>::insert(intent_id, bundle.clone());

                let threshold = T::CommitteeMembership::threshold();
                if bundle.len() as u32 >= threshold {
                    let mut intent = Intents::<T>::get(intent_id)
                        .ok_or(Error::<T>::IntentNotFound)?;
                    // Re-check status inside the storage layer in case a
                    // sibling call already crossed threshold. Idempotent
                    // no-op if so.
                    if intent.status == IntentStatus::Pending {
                        intent.status = IntentStatus::Attested;
                        Intents::<T>::insert(intent_id, intent);
                        AttestationSigs::<T>::insert(intent_id, bundle.clone());
                        PendingAttestations::<T>::remove(intent_id);
                        Self::deposit_event(Event::IntentAttested {
                            intent_id,
                            attestor_count: bundle.len() as u32,
                        });
                    }
                }
                Ok(())
            })?;
            Ok(())
        }

        /// Committee member submits a voucher + fairness proof. The voucher
        /// itself carries the full M-of-N signature bundle; this pallet
        /// checks the fairness-proof invariants and the voucher-to-proof
        /// binding, stores the voucher, and flips the bound intent from
        /// `Attested -> Vouchered`. The Cardano validator re-verifies the
        /// ed25519 signatures.
        ///
        /// Task #174: a `signatures` envelope of M-of-N committee sr25519
        /// signatures over the canonical `request_voucher_payload` digest is
        /// now required. Without this, any single committee member could
        /// unilaterally mint a voucher (bypassing the M-of-N threshold) and
        /// only `settle_claim` would re-check sigs — but by then the audit
        /// story is already broken because the voucher exists. Verification
        /// reuses the same `ensure_threshold_signatures` helper used by
        /// `settle_claim` and `credit_deposit` (caller MUST be one of the
        /// signers, distinct signers, all in the current committee, all sigs
        /// must verify). **Breaking on-chain change**: the previous 4-arg
        /// signature is gone; keepers must upgrade in lockstep with the
        /// runtime spec bump.
        #[pallet::call_index(2)]
        #[pallet::weight((Weight::from_parts(100_000_000, 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn request_voucher(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            intent_id: IntentId,
            voucher: Voucher,
            fairness_proof: BatchFairnessProof,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(Weight::from_parts(100_000_000, 0), |checked| {
                let who = ensure_signed(origin)?;
                ensure!(
                    T::CommitteeMembership::is_member(&who),
                    Error::<T>::NotCommitteeMember
                );
                // Task #75 (sec-review): cap unbounded `signatures` len at
                // MaxCommittee BEFORE any sig-verify cycle. Pre-fix an attacker
                // could submit a 1024-entry Vec and burn 1024 sr25519 verifies
                // in `ensure_threshold_signatures` before the BoundedVec
                // truncate ever fired — a trivial DoS once the chain is public.
                ensure!(
                    signatures.len() <= T::MaxCommittee::get() as usize,
                    Error::<T>::TooManySignatures
                );

                // Check duplicate-voucher first so callers get an unambiguous error
                // when they retry with the same claim_id.
                ensure!(
                    !Vouchers::<T>::contains_key(claim_id),
                    Error::<T>::DuplicateVoucher
                );
                let mut intent = Intents::<T>::get(intent_id).ok_or(Error::<T>::IntentNotFound)?;
                ensure!(
                    intent.status == IntentStatus::Attested,
                    Error::<T>::IntentStatusMismatch
                );

                Self::validate_fairness_proof(&fairness_proof)?;
                let bfpr_digest = compute_fairness_proof_digest(&fairness_proof);
                ensure!(
                    voucher.batch_fairness_proof_digest == bfpr_digest,
                    Error::<T>::FairnessDigestMismatch
                );

                // Task #174: M-of-N gate on voucher mint. We compute the canonical
                // pre-image *after* the fairness-proof and digest-binding checks
                // pass, so honest operators all see the same `(voucher_digest,
                // bfpr_digest)` pair the pallet just validated — no operator-local
                // state slips in. The same `ensure_threshold_signatures` routine
                // used by settle_claim/credit_deposit gives us caller-binding,
                // distinct-signer, member-only, and per-sig sr25519 verification.
                //
                // #79: voucher_digest is the chain-identity-bound CBOR form (the
                // legacy SCALE form is gone). The pallet computes from voucher
                // fields + chain-config so the keeper's mirror digest cannot
                // diverge.
                let chain_id = Self::materios_chain_id_bytes();
                let aegis_script_hash = T::AegisPolicyV1ScriptHash::get();
                let beneficiary_cbor =
                    Self::beneficiary_cbor_for(&voucher.beneficiary_cardano_addr)?;
                let voucher_digest_pre =
                    crate::voucher_canonicalize::compute_voucher_digest_with_address(
                        crate::voucher_canonicalize::ChainIdentity {
                            materios_chain_id: &chain_id,
                            network_magic: T::NetworkMagic::get(),
                            aegis_policy_script_hash: &aegis_script_hash,
                            settlement_version: T::SettlementVersion::get(),
                        },
                        &voucher.claim_id,
                        &voucher.policy_id,
                        &beneficiary_cbor,
                        voucher.amount_ada,
                        &voucher.batch_fairness_proof_digest,
                        voucher.issued_block,
                        voucher.expiry_slot_cardano,
                    );
                let voucher_payload = request_voucher_payload(
                    &chain_id,
                    &claim_id,
                    &intent_id,
                    &voucher_digest_pre,
                    &bfpr_digest,
                );
                Self::verify_threshold_signatures::<T::SigVerifier>(
                    &voucher_payload,
                    &who,
                    &signatures,
                    checked,
                )?;

                // Issue #5: pre-check the `outstanding_coverage_ada` increment
                // BEFORE mutating storage (checked_add -> CoverageOverflow) so
                // that a craft-a-batch overflow attempt cannot leave state in a
                // half-updated shape. We only account for this single claim's
                // `voucher.amount_ada`, matching the symmetric `settle_claim`
                // decrement in the same unit — the prior batch-sum semantics
                // drifted the counter for every partial batch (+10*, -1*).
                let pool = PoolUtilization::<T>::get();
                let new_outstanding = pool
                    .outstanding_coverage_ada
                    .checked_add(voucher.amount_ada)
                    .ok_or(Error::<T>::CoverageOverflow)?;

                // Reuse the digest we already computed for the M-of-N pre-image.
                let voucher_digest = voucher_digest_pre;
                let voucher_amount = voucher.amount_ada;

                // Store claim + voucher, flip intent state.
                let claim = Claim {
                    intent_id,
                    policy_id: voucher.policy_id,
                    amount_ada: voucher_amount,
                    issued_block: voucher.issued_block,
                    expiry_slot_cardano: voucher.expiry_slot_cardano,
                    settled: false,
                    settled_direct: false,
                    cardano_tx_hash: [0u8; 32],
                };
                Claims::<T>::insert(claim_id, claim);
                Vouchers::<T>::insert(claim_id, voucher);
                intent.status = IntentStatus::Vouchered;
                Intents::<T>::insert(intent_id, intent);
                // Issue #6: once Vouchered the intent is out of the keeper's
                // attested-batch window. Drop from the index so get_pending_batches
                // doesn't re-surface it, and the index doesn't grow unboundedly.
                Self::remove_from_pending_batches(intent_id);

                // Issue #5: write the pre-checked value; `outstanding_coverage_ada`
                // is now maintained symmetrically against `settle_claim`.
                PoolUtilization::<T>::mutate(|u| {
                    u.outstanding_coverage_ada = new_outstanding;
                });

                Self::deposit_event(Event::VoucherIssued {
                    claim_id,
                    voucher_digest,
                    fairness_proof_digest: bfpr_digest,
                });
                Ok(())
            })
        }

        /// Sugar wrapper around `submit_intent(IntentKind::RefundCredit { .. })`.
        /// Enforces `Credits[who] >= amount`.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(500_000_000, 0))]
        pub fn request_credit_refund(
            origin: OriginFor<T>,
            amount_ada: AdaLovelace,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let credit = Credits::<T>::get(&who);
            ensure!(credit >= amount_ada, Error::<T>::InsufficientCredit);
            let kind = IntentKind::RefundCredit { amount_ada };
            let intent_id = Self::do_submit_intent(who.clone(), kind)?;
            Self::deposit_event(Event::CreditRefundRequested {
                intent_id,
                submitter: who,
                amount_ada,
            });
            Ok(())
        }

        /// Committee mirrors a completed Cardano settlement. Transitions claim
        /// to `settled` and flips the bound intent to `Settled`. `settled_direct`
        /// distinguishes keeper-batch vs direct-path 10-minute fallback.
        #[pallet::call_index(4)]
        #[pallet::weight((Weight::from_parts(50_000_000, 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn settle_claim(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(Weight::from_parts(50_000_000, 0), |checked| {
                let who = ensure_signed(origin)?;
                // Task #266 (mis-sec P0): cutover gate. Once the spec-N migration
                // schedules `StcaCutoverBlock`, any subsequent call to the legacy
                // path is hard-rejected. The 50-block grace gives keepers time to
                // redeploy to the new request_settle + attest_settle path.
                Self::ensure_legacy_settle_path_open()?;
                ensure!(
                    T::CommitteeMembership::is_member(&who),
                    Error::<T>::NotCommitteeMember
                );
                // Task #75 (sec-review): cap unbounded `signatures` len at
                // MaxCommittee BEFORE any sig-verify cycle.
                ensure!(
                    signatures.len() <= T::MaxCommittee::get() as usize,
                    Error::<T>::TooManySignatures
                );

                let mut claim = Claims::<T>::get(claim_id).ok_or(Error::<T>::ClaimNotFound)?;
                if claim.settled {
                    return Ok(()); // idempotent
                }

                // Issue #7: require M-of-N distinct committee signatures over the
                // canonical payload. The origin itself MUST sign (otherwise any
                // member could replay stale signature bundles), so we build the
                // digest including who and verify inclusion.
                //
                // #73: pre-image is now bound to the Materios chain-id so a bundle
                // signed on preprod cannot land on mainnet.
                let chain_id = Self::materios_chain_id_bytes();
                let payload =
                    settle_claim_payload(&chain_id, &claim_id, &cardano_tx_hash, settled_direct);
                Self::verify_threshold_signatures::<T::SigVerifier>(
                    &payload,
                    &who,
                    &signatures,
                    checked,
                )?;

                claim.settled = true;
                claim.settled_direct = settled_direct;
                claim.cardano_tx_hash = cardano_tx_hash;
                let intent_id = claim.intent_id;
                let amount = claim.amount_ada;
                Claims::<T>::insert(claim_id, claim);
                // Sec-review LOW #2: legacy settle uses the trust-vacuous STCL
                // payload. Tag the resulting claim so audit/explorer tooling
                // can distinguish "trust-vacuous" from STCA-attested settles
                // even when the settle landed in the 50-block grace window
                // (i.e., post-upgrade but pre-cutover). Migration only flags
                // claims that were ALREADY settled at upgrade time; this line
                // covers the grace window.
                PreAuditSettlement::<T>::insert(claim_id, true);

                if let Some(mut intent) = Intents::<T>::get(intent_id) {
                    intent.status = IntentStatus::Settled;
                    Intents::<T>::insert(intent_id, intent);
                }
                // Issue #6: intent is now terminal; drop from index.
                Self::remove_from_pending_batches(intent_id);

                // Decrement outstanding coverage AND total NAV.
                //
                // Task #82 (sec-review): pre-fix `credit_deposit` grew
                // `total_nav_ada` 1:1 on every deposit but no path EVER
                // decremented it on payout. NAV monotonically grew, pool
                // utilization (= outstanding / nav) drifted toward zero forever,
                // and the 75% cap effectively disabled itself after enough
                // payouts. Now: settling a claim drains the actual `amount`
                // from NAV (capital really is gone — it was paid out on
                // Cardano). `expire_policy_mirror` does NOT touch NAV — the
                // unclaimed premium still belongs to the pool.
                //
                // Saturating_sub keeps the runtime panic-free. If we ever hit
                // the saturating floor, the post-state is honest (zero) and
                // the `BatchSettled` / `ClaimSettled` event records the real
                // payout amount, so off-chain monitors can flag the divergence
                // for forensic follow-up.
                PoolUtilization::<T>::mutate(|u| {
                    u.outstanding_coverage_ada = u.outstanding_coverage_ada.saturating_sub(amount);
                    u.total_nav_ada = u.total_nav_ada.saturating_sub(amount);
                });

                Self::deposit_event(Event::ClaimSettled {
                    claim_id,
                    cardano_tx_hash,
                    settled_direct,
                });
                Ok(())
            })
        }

        /// Committee reports that a policy expired on Cardano (Expire redeemer
        /// was executed). Cleans up any bound Materios intent that's still
        /// open.
        ///
        /// Task #267 (mis-sec P0): this is the LEGACY path with the same
        /// class of trust gap that `settle_claim` had pre-spec-220 — only
        /// WORSE: a single committee signer with NO evidence at all could
        /// unilaterally flip any intent to `Expired`. The path is now
        /// gated by `PolicyExpireCutoverBlock`: keepers must migrate to
        /// `request_expire_policy` + `attest_expire_policy` (the new EXPP
        /// pair) before the cutover lands or callers get
        /// `Error::DeprecatedExtrinsic`.
        ///
        /// The legacy path also flags `PreAuditExpiry[intent_id] = true`
        /// at expire time so audit/explorer tooling can distinguish
        /// "trust-vacuous" from EXPP-attested expiries even when the
        /// expiry landed in the 50-block grace window (post-upgrade but
        /// pre-cutover). Mirrors the LOW #2 fix on `settle_claim` exactly.
        #[pallet::call_index(5)]
        #[pallet::weight((Weight::from_parts(30_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn expire_policy_mirror(
            origin: OriginFor<T>,
            intent_id: IntentId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // Task #267: cutover gate. Once the spec-N+1 migration
            // schedules `PolicyExpireCutoverBlock`, any subsequent call to
            // the legacy path is hard-rejected. The 50-block grace gives
            // keepers time to redeploy onto the new request/attest pair.
            Self::ensure_legacy_expire_path_open()?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            let mut intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::UnknownPolicy)?;
            if matches!(
                intent.status,
                IntentStatus::Expired | IntentStatus::Settled
            ) {
                return Ok(());
            }
            intent.status = IntentStatus::Expired;
            Intents::<T>::insert(intent_id, intent);
            // Issue #6: terminal → drop from PendingBatches.
            Self::remove_from_pending_batches(intent_id);
            // Task #267: tag the resulting expiry as trust-vacuous so audit
            // tooling can split "Cardano-attested expiry" from
            // "legacy committee-trusted expiry" even in the grace window
            // between upgrade and cutover (mirror of LOW #2 fix on
            // settle_claim).
            PreAuditExpiry::<T>::insert(intent_id, true);
            Self::deposit_event(Event::IntentExpired {
                intent_id,
                reason: ExpiryReason::PolicyExpiredOnCardano,
            });
            Ok(())
        }

        /// Committee registers a confirmed Cardano deposit to the premium
        /// collector script. Idempotent on `(who, cardano_tx_hash)`.
        #[pallet::call_index(6)]
        #[pallet::weight((Weight::from_parts(30_000_000, 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn credit_deposit(
            origin: OriginFor<T>,
            target: T::AccountId,
            amount_ada: AdaLovelace,
            cardano_tx_hash: [u8; 32],
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(Weight::from_parts(30_000_000, 0), |checked| {
                let who = ensure_signed(origin)?;
                ensure!(
                    T::CommitteeMembership::is_member(&who),
                    Error::<T>::NotCommitteeMember
                );
                // Task #75 (sec-review): cap unbounded `signatures` len at
                // MaxCommittee BEFORE any sig-verify cycle.
                ensure!(
                    signatures.len() <= T::MaxCommittee::get() as usize,
                    Error::<T>::TooManySignatures
                );

                let key = (target.clone(), cardano_tx_hash);
                ensure!(
                    !ProcessedDeposits::<T>::contains_key(&key),
                    Error::<T>::DepositAlreadyProcessed
                );

                // Issue #7: M-of-N gate. Previously any single committee member
                // could unilaterally credit any ADA amount onto any account —
                // trivial pool drain. We now require `MinSignerThreshold`
                // distinct committee signatures over the canonical payload
                // (target, amount, tx_hash) and verify each at runtime.
                //
                // #73: pre-image is now bound to the Materios chain-id so a bundle
                // signed on preprod cannot land on mainnet.
                let chain_id = Self::materios_chain_id_bytes();
                let target_bytes = crate::account_to_bytes(&target);
                let payload =
                    credit_deposit_payload(&chain_id, &target_bytes, amount_ada, &cardano_tx_hash);
                Self::verify_threshold_signatures::<T::SigVerifier>(
                    &payload,
                    &who,
                    &signatures,
                    checked,
                )?;

                ProcessedDeposits::<T>::insert(&key, ());
                Credits::<T>::mutate(&target, |c| *c = c.saturating_add(amount_ada));

                // Track NAV for pool utilization.
                PoolUtilization::<T>::mutate(|u| {
                    u.total_nav_ada = u.total_nav_ada.saturating_add(amount_ada);
                });

                Self::deposit_event(Event::CreditsCredited {
                    account: target,
                    delta_ada: amount_ada,
                    source_cardano_tx: cardano_tx_hash,
                });
                Ok(())
            })
        }

        /// Governance knob — update pool NAV/utilization parameters. Root-only.
        #[pallet::call_index(7)]
        #[pallet::weight((Weight::from_parts(10_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn set_pool_utilization(
            origin: OriginFor<T>,
            params: PoolUtilizationParams,
        ) -> DispatchResult {
            ensure_root(origin)?;
            PoolUtilization::<T>::put(params);
            Self::deposit_event(Event::PoolUtilizationUpdated {
                total_nav_ada: params.total_nav_ada,
                outstanding_coverage_ada: params.outstanding_coverage_ada,
            });
            Ok(())
        }

        /// Issue #7: Root-only governance knob to tune the M-of-N floor at
        /// runtime (preprod launches with 2, mainnet bumps to 3 via this
        /// extrinsic). Setting 0 resets to `DefaultMinSignerThreshold`.
        ///
        /// Task #74 (sec-review): enforces the invariant `MinSignerThreshold
        /// <= committee_threshold` so the local pallet floor cannot diverge
        /// above the committee-governance pallet's authoritative threshold.
        /// Without this, a root call could lock all M-of-N extrinsics by
        /// requiring more sigs than the committee has members. The committee
        /// threshold itself is rotated via `pallet_committee_governance::
        /// propose_threshold_change` + `execute_rotation` — that path
        /// already validates `1 <= new <= members.len()`. This extrinsic is
        /// the OTHER lever; clamping here keeps both knobs consistent.
        #[pallet::call_index(8)]
        #[pallet::weight((Weight::from_parts(10_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn set_min_signer_threshold(
            origin: OriginFor<T>,
            new_threshold: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let v = if new_threshold == 0 {
                T::DefaultMinSignerThreshold::get()
            } else {
                new_threshold
            };
            // Task #74 (sec-review) — threshold consolidation invariant.
            // Reject any value that exceeds the live committee threshold
            // (the source of truth for "how many distinct committee
            // signatures exist"). If the local floor were allowed to
            // exceed it, every M-of-N extrinsic would dead-lock with
            // InsufficientSignatures forever (the committee couldn't
            // produce that many sigs).
            let committee_threshold = T::CommitteeMembership::threshold();
            ensure!(
                v <= committee_threshold,
                Error::<T>::ThresholdAboveCommittee
            );
            MinSignerThreshold::<T>::put(v);
            Ok(())
        }

        /// Task #177: settle N already-vouchered claims in a SINGLE extrinsic
        /// under ONE committee-signature verification.
        ///
        /// Cost model:
        /// - One sig-verify pass over the batch digest (the dominant ~weight
        ///   per existing `settle_claim`)
        /// - N * (storage_read(Claims) + storage_write(Claims)
        ///        + storage_read(Intents) + storage_write(Intents)
        ///        + storage_mutate(PoolUtilization)
        ///        + remove_from_pending_batches)
        ///
        /// At N=256 the storage-write cost is comparable to a single
        /// `settle_claim`'s sig-verify cost, so the total weight is roughly
        /// `~1.5–2x weight_of(settle_claim)` — the exact slope is captured
        /// by the runtime-benchmarks recipe (`benchmarking.rs`).
        ///
        /// Atomic semantics: any per-entry failure (claim not found, claim
        /// already settled, duplicate claim_id within the batch) reverts
        /// every storage mutation in this call — no partial settlements.
        ///
        /// Backward compatibility: this extrinsic is purely additive. The
        /// existing 5-stage flow (`submit_intent` + `attest_intent` × M +
        /// `request_voucher` + `settle_claim`) is unchanged. Only the final
        /// `settle_claim` × N step collapses into one batch call.
        ///
        /// Idempotency: callers MUST ensure unique `claim_id`s within a
        /// batch (the pallet rejects duplicates). Across batches, attempting
        /// to settle an already-settled claim is rejected (rather than
        /// silently no-op'd) so the keeper's retry logic stays
        /// deterministic — split the batch and resubmit only the
        /// not-yet-settled subset.
        #[pallet::call_index(9)]
        #[pallet::weight((T::WeightInfo::settle_batch_atomic(entries.len() as u32)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn settle_batch_atomic(
            origin: OriginFor<T>,
            entries: BoundedVec<SettleBatchEntry, <T as Config>::MaxSettleBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(
                T::WeightInfo::settle_batch_atomic(entries.len() as u32),
                |checked| {
                    let who = ensure_signed(origin)?;
                    // Task #266 (mis-sec P0): cutover gate — same shape as the
                    // single-call `settle_claim` legacy path. Post-`StcaCutoverBlock`
                    // the keeper MUST switch to `request_batch_settle` +
                    // `attest_batch_settle` (call_index 15 / 16) which carry the
                    // falsifiable Cardano evidence.
                    Self::ensure_legacy_settle_path_open()?;
                    ensure!(
                        T::CommitteeMembership::is_member(&who),
                        Error::<T>::NotCommitteeMember
                    );
                    // Task #75 (sec-review): cap unbounded `signatures` len at
                    // MaxCommittee BEFORE any sig-verify cycle.
                    ensure!(
                        signatures.len() <= T::MaxCommittee::get() as usize,
                        Error::<T>::TooManySignatures
                    );
                    ensure!(!entries.is_empty(), Error::<T>::EmptyBatch);

                    // Compute batch digest ONCE over all entries. Single sig-verify
                    // pass below — this is where the ~100x throughput unlock lives.
                    //
                    // #73: pre-image is now bound to the Materios chain-id.
                    let chain_id = Self::materios_chain_id_bytes();
                    let payload = settle_batch_atomic_payload(&chain_id, entries.as_slice());

                    // Pass 1: detect duplicate claim_ids INSIDE the batch up-front
                    // (cheaper than discovering it mid-loop after we've already
                    // mutated state). O(N^2) with N <= 256 — ~32k comparisons worst
                    // case, well below sig-verify cost.
                    let n = entries.len();
                    for i in 0..n {
                        for j in (i + 1)..n {
                            ensure!(
                                entries[i].claim_id != entries[j].claim_id,
                                Error::<T>::DuplicateClaimInBatch,
                            );
                        }
                    }

                    let mut hydrated_claims = Vec::with_capacity(n);
                    for entry in entries.iter() {
                        let claim =
                            Claims::<T>::get(entry.claim_id).ok_or(Error::<T>::ClaimNotFound)?;
                        ensure!(!claim.settled, Error::<T>::BatchClaimAlreadySettled);
                        hydrated_claims.push(claim);
                    }

                    Self::verify_threshold_signatures::<T::SigVerifier>(
                        &payload,
                        &who,
                        &signatures,
                        checked,
                    )?;

                    // Atomic mutation phase — apply all settlements in a transactional
                    // storage layer so any per-entry failure rolls the whole call back.
                    // Any error returned from this closure is bubbled up as the
                    // extrinsic's DispatchError; on Ok the changes commit.
                    let (count, settled_direct_count) = frame_support::storage::with_storage_layer::<
                        (u32, u32),
                        sp_runtime::DispatchError,
                        _,
                    >(|| {
                        let mut total_amount_unsettled: u64 = 0;
                        let mut direct_count: u32 = 0;

                        for (entry, mut claim) in entries.iter().zip(hydrated_claims) {
                            claim.settled = true;
                            claim.settled_direct = entry.settled_direct;
                            claim.cardano_tx_hash = entry.cardano_tx_hash;
                            let intent_id = claim.intent_id;
                            let amount = claim.amount_ada;
                            Claims::<T>::insert(entry.claim_id, claim);
                            // Sec-review LOW #2: legacy batch path uses STBA
                            // (trust-vacuous batch digest). Flag each settled
                            // claim so audit tooling can distinguish from
                            // STCA-attested settles even in the 50-block grace
                            // window. See `settle_claim` for the rationale.
                            PreAuditSettlement::<T>::insert(entry.claim_id, true);

                            if let Some(mut intent) = Intents::<T>::get(intent_id) {
                                intent.status = IntentStatus::Settled;
                                Intents::<T>::insert(intent_id, intent);
                            }
                            Self::remove_from_pending_batches(intent_id);

                            if entry.settled_direct {
                                direct_count = direct_count.saturating_add(1);
                            }
                            total_amount_unsettled = total_amount_unsettled.saturating_add(amount);
                        }

                        // Decrement outstanding coverage AND total NAV in ONE
                        // mutate call (vs N separate mutates) — same storage-
                        // write economics as `settle_claim` summed across N
                        // calls, but cheaper.
                        //
                        // Task #82 (sec-review): NAV decrement matches
                        // `settle_claim`'s post-fix behaviour. Capital really
                        // is gone (paid out on Cardano), so it must leave the
                        // NAV bucket too. Pre-fix this site only updated
                        // `outstanding_coverage_ada`, leaving NAV monotonically
                        // growing across settlements.
                        PoolUtilization::<T>::mutate(|u| {
                            u.outstanding_coverage_ada = u
                                .outstanding_coverage_ada
                                .saturating_sub(total_amount_unsettled);
                            u.total_nav_ada =
                                u.total_nav_ada.saturating_sub(total_amount_unsettled);
                        });

                        Ok((n as u32, direct_count))
                    })?;

                    Self::deposit_event(Event::BatchSettled {
                        count,
                        batch_digest: payload,
                        settled_direct_count,
                    });
                    Ok(())
                },
            )
        }

        /// Task #211: attest N intents in ONE extrinsic under ONE M-of-N
        /// signature verification.
        ///
        /// Pre-spec-207 the attest stage ran `attest_intent` once per
        /// (signer, intent) pair: a 3-of-3 committee at N=256 issued 768
        /// chain extrinsics per epoch, each with its own per-call sig-
        /// verify. Post-spec-207 this collapses to a single
        /// `attest_batch_intents(intent_ids, signatures)` call with ONE
        /// sig-verify pass over the whole batch — the largest single-pallet
        /// TPS unlock in the v5.1 plan.
        ///
        /// Per-intent semantics:
        /// - Each intent must currently be `Pending`. If it's `Attested`
        ///   already (raced by another attestation extrinsic), this entry
        ///   is treated as an idempotent no-op (does not contribute to the
        ///   `attested_count` event field) — matches `attest_intent`'s
        ///   prior behaviour. If it's in any other terminal state
        ///   (Vouchered/Settled/Expired), the batch atomically rejects
        ///   with `IntentStatusMismatch`.
        /// - Each intent's `AttestationSigs` storage map is overwritten
        ///   with the call's signature bundle on the Pending -> Attested
        ///   transition. The bundle stored is exactly the `signatures`
        ///   argument truncated to MaxCommittee (the legacy single-call
        ///   `attest_intent` accumulated sigs across calls; the batch path
        ///   posts the full M-of-N envelope in one shot, so the storage
        ///   write is direct).
        ///
        /// Caller binding: same as `settle_batch_atomic`. The caller's
        /// pubkey MUST appear in `signatures` (origin-binding via
        /// `ensure_threshold_signatures`). Subsequent batch calls from the
        /// same committee are idempotent on intents already in Attested
        /// state, so there's no replay-attack window.
        ///
        /// Backward compatibility: the existing per-intent `attest_intent`
        /// (call_index 1) is unchanged. Mixed-mode (some intents attested
        /// via single-call, others via batch) is supported within the same
        /// epoch.
        ///
        /// Atomic semantics: any per-intent failure (intent not found,
        /// terminal status mismatch, duplicate intent_id within the batch)
        /// reverts every storage mutation in this call.
        ///
        /// Cost model:
        /// - Base ~50M ref_time (M-of-N sig-verify pass)
        /// - Plus N * ~3M ref_time (per-intent storage read for `Intents`,
        ///   one storage write each for `Intents` + `AttestationSigs`).
        /// - At N=256 the per-intent cost ~768M dwarfs the sig-verify
        ///   pass — but it's still ~3x cheaper than the legacy 768
        ///   `attest_intent` calls each at ~50M = 38B total.
        #[pallet::call_index(11)]
        #[pallet::weight((Weight::from_parts(50_000_000u64.saturating_add((intent_ids.len() as u64).saturating_mul(3_000_000)), 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn attest_batch_intents(
            origin: OriginFor<T>,
            intent_ids: BoundedVec<IntentId, <T as Config>::MaxAttestBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(
                Weight::from_parts(
                    50_000_000u64
                        .saturating_add((intent_ids.len() as u64).saturating_mul(3_000_000)),
                    0,
                ),
                |checked| {
                    let who = ensure_signed(origin)?;
                    ensure!(
                        T::CommitteeMembership::is_member(&who),
                        Error::<T>::NotCommitteeMember
                    );
                    // Task #75 (sec-review): cap unbounded `signatures` len at
                    // MaxCommittee BEFORE the per-sig verify pass below. Pre-fix the
                    // BoundedVec::try_from truncate ran AFTER ensure_threshold_signatures
                    // (so a 1024-entry attacker bundle burned 1024 sr25519 verifies
                    // before bailing). Capping here makes the DoS surface a constant
                    // MaxCommittee worth of work.
                    ensure!(
                        signatures.len() <= T::MaxCommittee::get() as usize,
                        Error::<T>::TooManySignatures
                    );
                    ensure!(!intent_ids.is_empty(), Error::<T>::EmptyAttestBatch);

                    // Compute the canonical ABIN digest ONCE over all intent_ids,
                    // then verify the M-of-N sig bundle against it ONCE — the
                    // throughput unlock.
                    //
                    // #73: pre-image is now bound to the Materios chain-id.
                    let chain_id = Self::materios_chain_id_bytes();
                    let payload = attest_batch_intents_payload(&chain_id, intent_ids.as_slice());

                    // Pass 1: detect duplicate intent_ids inside the batch up-front
                    // (cheaper than discovering it mid-loop after we've mutated
                    // state). O(N^2) with N <= 256 ~32k comparisons worst case,
                    // well below sig-verify cost.
                    let n = intent_ids.len();
                    for i in 0..n {
                        for j in (i + 1)..n {
                            ensure!(
                                intent_ids[i] != intent_ids[j],
                                Error::<T>::DuplicateIntentInBatch,
                            );
                        }
                    }

                    let mut hydrated_intents = Vec::with_capacity(n);
                    for iid in intent_ids.iter() {
                        let intent = Intents::<T>::get(iid).ok_or(Error::<T>::IntentNotFound)?;
                        ensure!(
                            matches!(
                                intent.status,
                                IntentStatus::Pending | IntentStatus::Attested
                            ),
                            Error::<T>::IntentStatusMismatch
                        );
                        hydrated_intents.push(intent);
                    }

                    if hydrated_intents
                        .iter()
                        .all(|intent| intent.status == IntentStatus::Attested)
                    {
                        return Ok(());
                    }

                    Self::verify_threshold_signatures::<T::SigVerifier>(
                        &payload,
                        &who,
                        &signatures,
                        checked,
                    )?;

                    // Truncate the call-level sigs vec into the storage-bound
                    // BoundedVec for AttestationSigs. The storage type uses
                    // `MaxCommittee` (=32 in prod), and `ensure_threshold_signatures`
                    // already proved `signatures.len() >= threshold` — so any
                    // overflow here would mean the caller submitted MORE than
                    // MaxCommittee sigs, which we treat as an error rather than
                    // silently truncate.
                    let sigs_bv: BoundedVec<
                        (CommitteePubkey, CommitteeSig),
                        <T as Config>::MaxCommittee,
                    > = BoundedVec::try_from(signatures.clone())
                        .map_err(|_| Error::<T>::TooManySigs)?;

                    let signer_count = signatures.len() as u32;

                    // Atomic mutation phase. Any per-intent failure reverts the
                    // whole call — same all-or-nothing semantics as PR #27.
                    let attested_count = frame_support::storage::with_storage_layer::<
                        u32,
                        sp_runtime::DispatchError,
                        _,
                    >(|| {
                        let mut freshly_attested: u32 = 0;
                        for (iid, mut intent) in intent_ids.iter().zip(hydrated_intents) {
                            match intent.status {
                                IntentStatus::Attested => {
                                    // Idempotent — already past the threshold from a
                                    // prior batch / single-call. Silently skip.
                                    continue;
                                }
                                IntentStatus::Pending => {
                                    intent.status = IntentStatus::Attested;
                                    Intents::<T>::insert(iid, intent);
                                    AttestationSigs::<T>::insert(iid, sigs_bv.clone());
                                    // Drop any partial single-call accumulation —
                                    // the batch's M-of-N envelope is the canonical
                                    // bundle now.
                                    PendingAttestations::<T>::remove(iid);
                                    Self::deposit_event(Event::IntentAttested {
                                        intent_id: *iid,
                                        attestor_count: signer_count,
                                    });
                                    freshly_attested = freshly_attested.saturating_add(1);
                                }
                                _ => {
                                    // Vouchered / Settled / Expired / Refunded —
                                    // can't be re-attested. Reject the batch
                                    // atomically; keeper must split the next batch
                                    // and exclude this intent.
                                    return Err(Error::<T>::IntentStatusMismatch.into());
                                }
                            }
                        }
                        Ok(freshly_attested)
                    })?;

                    Self::deposit_event(Event::BatchIntentsAttested {
                        submitted_count: n as u32,
                        attested_count,
                        batch_digest: payload,
                        signer_count,
                    });
                    Ok(())
                },
            )
        }

        /// Task #212: mint N vouchers in ONE extrinsic under ONE M-of-N
        /// signature verification.
        ///
        /// Pre-spec-207 each voucher mint required its own M-of-N round
        /// (per PR #26's `request_voucher` RVCH gate). At N=256 vouchers
        /// per epoch that's 256 separate sig-verifies. Post-spec-207 those
        /// collapse to one RVBN sig-verify pass over the canonical batch
        /// digest.
        ///
        /// Per-entry semantics (identical to single-call `request_voucher`):
        /// - `intent_id` must be in `Attested` status; transitions to
        ///   `Vouchered`.
        /// - `claim_id` must not already have a Voucher in storage
        ///   (`DuplicateVoucher`).
        /// - `fairness_proof` must satisfy `validate_fairness_proof`
        ///   (`InvalidFairnessProof` on violation).
        /// - `voucher.batch_fairness_proof_digest` must equal the digest
        ///   of `fairness_proof` (`FairnessDigestMismatch`).
        /// - `voucher.amount_ada` adds to `outstanding_coverage_ada`; the
        ///   total batch increment is checked-add-checked at the top so a
        ///   craft-an-overflow attempt cannot leave state half-updated.
        ///
        /// After the per-entry checks pass, the canonical RVBN digest is
        /// computed once over the WHOLE batch's `(claim_id, intent_id,
        /// voucher_digest, bfpr_digest)` tuples and the M-of-N envelope is
        /// verified ONCE against it.
        ///
        /// Backward compatibility: the existing 5-arg `request_voucher`
        /// (call_index 2) is unchanged.
        ///
        /// Atomic semantics: any per-entry failure (intent missing/wrong
        /// status, claim already vouchered, invalid fairness proof, digest
        /// mismatch, duplicate claim_id within batch, coverage overflow)
        /// reverts every storage mutation in this call.
        ///
        /// Cost model:
        /// - Base ~50M ref_time (M-of-N sig-verify + duplicate-claim scan)
        /// - Plus N * ~10M ref_time (per-entry voucher_digest +
        ///   bfpr_digest computation + storage writes for `Claims`,
        ///   `Vouchers`, `Intents`, `PendingBatches` removal,
        ///   `outstanding_coverage_ada` increment).
        /// - At N=256 ~2.6B ref_time. Versus 256 single `request_voucher`
        ///   calls at ~100M each = 25.6B ref_time, the batch path is
        ///   ~10x cheaper.
        #[pallet::call_index(12)]
        #[pallet::weight((Weight::from_parts(50_000_000u64.saturating_add((entries.len() as u64).saturating_mul(10_000_000)), 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn request_batch_vouchers(
            origin: OriginFor<T>,
            entries: BoundedVec<RequestVoucherEntry, <T as Config>::MaxVoucherBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(
                Weight::from_parts(
                    50_000_000u64.saturating_add((entries.len() as u64).saturating_mul(10_000_000)),
                    0,
                ),
                |checked| {
                    let who = ensure_signed(origin)?;
                    ensure!(
                        T::CommitteeMembership::is_member(&who),
                        Error::<T>::NotCommitteeMember
                    );
                    // Task #75 (sec-review): cap unbounded `signatures` len at
                    // MaxCommittee BEFORE any sig-verify cycle.
                    ensure!(
                        signatures.len() <= T::MaxCommittee::get() as usize,
                        Error::<T>::TooManySignatures
                    );
                    ensure!(!entries.is_empty(), Error::<T>::EmptyVoucherBatch);

                    // Pass 0: detect duplicate claim_ids inside the batch up-front.
                    // O(N^2) at N <= 256 ~32k comparisons, well below sig-verify cost.
                    let n = entries.len();
                    for i in 0..n {
                        for j in (i + 1)..n {
                            ensure!(
                                entries[i].claim_id != entries[j].claim_id,
                                Error::<T>::DuplicateClaimInVoucherBatch,
                            );
                        }
                    }

                    // Pass 1: per-entry digest computation + per-entry digest
                    // binding check. We do this BEFORE the M-of-N sig-verify so
                    // honest operators all see the same `(voucher_digest,
                    // bfpr_digest)` pair the pallet just validated — no operator-
                    // local state slips into the canonical pre-image (per
                    // `feedback_mofn_hash_determinism.md`).
                    //
                    // #79: voucher_digest uses the chain-identity-bound CBOR form
                    // (legacy SCALE form is gone) so the keeper's mirror digest is
                    // guaranteed to match.
                    let chain_id = Self::materios_chain_id_bytes();
                    let aegis_script_hash = T::AegisPolicyV1ScriptHash::get();
                    let chain_identity = crate::voucher_canonicalize::ChainIdentity {
                        materios_chain_id: &chain_id,
                        network_magic: T::NetworkMagic::get(),
                        aegis_policy_script_hash: &aegis_script_hash,
                        settlement_version: T::SettlementVersion::get(),
                    };
                    let mut tuples: alloc::vec::Vec<(ClaimId, IntentId, [u8; 32], [u8; 32])> =
                        alloc::vec::Vec::with_capacity(n);
                    for entry in entries.iter() {
                        ensure!(
                            !Vouchers::<T>::contains_key(entry.claim_id),
                            Error::<T>::DuplicateVoucher
                        );
                        Self::validate_fairness_proof(&entry.fairness_proof)?;
                        let bfpr_digest = compute_fairness_proof_digest(&entry.fairness_proof);
                        ensure!(
                            entry.voucher.batch_fairness_proof_digest == bfpr_digest,
                            Error::<T>::FairnessDigestMismatch
                        );
                        let beneficiary_cbor =
                            Self::beneficiary_cbor_for(&entry.voucher.beneficiary_cardano_addr)?;
                        let voucher_digest =
                            crate::voucher_canonicalize::compute_voucher_digest_with_address(
                                chain_identity,
                                &entry.voucher.claim_id,
                                &entry.voucher.policy_id,
                                &beneficiary_cbor,
                                entry.voucher.amount_ada,
                                &entry.voucher.batch_fairness_proof_digest,
                                entry.voucher.issued_block,
                                entry.voucher.expiry_slot_cardano,
                            );
                        tuples.push((entry.claim_id, entry.intent_id, voucher_digest, bfpr_digest));
                    }

                    // ONE sig-verify pass over the whole batch — the throughput
                    // unlock. Domain-tagged with RVBN so a per-entry RVCH
                    // signature can never replay onto the batch path.
                    //
                    // #73: pre-image is bound to the Materios chain-id.
                    let payload = request_batch_vouchers_payload(&chain_id, &tuples);
                    Self::verify_threshold_signatures::<T::SigVerifier>(
                        &payload,
                        &who,
                        &signatures,
                        checked,
                    )?;

                    // Atomic mutation phase. Each per-entry mutation mirrors the
                    // single-call `request_voucher` body (issue #5 ordering
                    // preserved: pre-check coverage overflow on the WHOLE batch
                    // sum before mutating, mirror that per-entry as we walk).
                    let (count, total_amount_unsettled) =
                        frame_support::storage::with_storage_layer::<
                            (u32, u64),
                            sp_runtime::DispatchError,
                            _,
                        >(|| {
                            let mut running_total: u64 = 0;
                            for (idx, entry) in entries.iter().enumerate() {
                                let mut intent = Intents::<T>::get(entry.intent_id)
                                    .ok_or(Error::<T>::IntentNotFound)?;
                                ensure!(
                                    intent.status == IntentStatus::Attested,
                                    Error::<T>::IntentStatusMismatch
                                );

                                // Coverage overflow check — same checked-add as
                                // request_voucher (issue #5).
                                let pool = PoolUtilization::<T>::get();
                                let new_outstanding = pool
                                    .outstanding_coverage_ada
                                    .checked_add(entry.voucher.amount_ada)
                                    .ok_or(Error::<T>::CoverageOverflow)?;

                                let voucher_amount = entry.voucher.amount_ada;
                                let claim = Claim {
                                    intent_id: entry.intent_id,
                                    policy_id: entry.voucher.policy_id,
                                    amount_ada: voucher_amount,
                                    issued_block: entry.voucher.issued_block,
                                    expiry_slot_cardano: entry.voucher.expiry_slot_cardano,
                                    settled: false,
                                    settled_direct: false,
                                    cardano_tx_hash: [0u8; 32],
                                };
                                Claims::<T>::insert(entry.claim_id, claim);
                                Vouchers::<T>::insert(entry.claim_id, entry.voucher.clone());
                                intent.status = IntentStatus::Vouchered;
                                Intents::<T>::insert(entry.intent_id, intent);
                                Self::remove_from_pending_batches(entry.intent_id);

                                PoolUtilization::<T>::mutate(|u| {
                                    u.outstanding_coverage_ada = new_outstanding;
                                });

                                // Per-voucher event still emitted for indexer
                                // back-compat — same shape as single-call. The
                                // `voucher_digest` + `fairness_proof_digest` were
                                // computed in pass 1 and stashed in `tuples`.
                                let (_cid, _iid, vd, bd) = tuples[idx];
                                Self::deposit_event(Event::VoucherIssued {
                                    claim_id: entry.claim_id,
                                    voucher_digest: vd,
                                    fairness_proof_digest: bd,
                                });

                                running_total = running_total.saturating_add(voucher_amount);
                            }
                            Ok((n as u32, running_total))
                        })?;

                    Self::deposit_event(Event::BatchVouchersIssued {
                        count,
                        batch_digest: payload,
                        total_amount_ada: total_amount_unsettled,
                    });
                    Ok(())
                },
            )
        }

        /// Task #210: register N user intents in ONE extrinsic.
        ///
        /// User-side burst submission. Pre-spec-207 each intent required its
        /// own `submit_intent` extrinsic — at 256 intents that's 256
        /// signatures, 256 fee debits, and 256 round trips through the
        /// mempool. Post-spec-207 a single `submit_batch_intents(entries)`
        /// debits the user's fee once, takes ONE pre-image of the batch (for
        /// indexer correlation, NOT for sig-verify — the user origin is the
        /// only authority needed here), and runs the same per-intent state
        /// transitions inside a single transactional storage layer.
        ///
        /// Atomic semantics: the entire batch reverts on the FIRST per-entry
        /// failure (insufficient credit, pool-utilization cap, duplicate
        /// intent collision, or PendingBatches index overflow). No partial
        /// debit, no partial intents stored. Callers can retry the batch
        /// deterministically after fixing whichever entry tripped the
        /// rejection.
        ///
        /// Idempotency: the existing single-call `submit_intent` enforces
        /// `DuplicateIntent` via the IntentId pre-image (which already
        /// includes the user's nonce). Inside the batch each entry consumes
        /// nonce+i, so two identical entries in the same batch produce
        /// different IntentIds and BOTH commit (they're not duplicates from
        /// the chain's perspective). Two identical batches submitted twice
        /// (same nonce starting point) hit `DuplicateIntent` on the second
        /// call's first entry and atomically revert — the legacy guarantee.
        ///
        /// Backward compatibility: the existing 1-arg `submit_intent` is
        /// unchanged. Callers can mix single and batch in the same block.
        ///
        /// Cost model:
        /// - Base ~50M ref_time (signature verify + envelope decode)
        /// - Plus N*~5M ref_time (per-entry pool-utilization check +
        ///   IntentId derivation + storage writes for `Intents`, `Nonces`,
        ///   `PendingBatches`, `ExpiryQueue`)
        /// - Plus the standard `submit_intent` per-call weight (500M from
        ///   the legacy single-call) but consumed ONCE per batch, not per
        ///   entry — that's the throughput unlock.
        #[pallet::call_index(10)]
        #[pallet::weight({
            // Base weight ~50M (single-call submit_intent's amortised cost)
            // plus per-entry storage cost ~5M. Tuned to match the sublinear
            // pattern proven in PR #27 (settle_batch_atomic) — actual numbers
            // are pinned by the runtime-benchmarks recipe in benchmarking.rs.
            //
            // Task #221 (PR #28 pre-merge security review): proof_size is no
            // longer 0. Per-entry proof footprint ~5KB worst case (one
            // `Intents::insert` value + one `Nonces::mutate` + one
            // `PendingBatches::try_push` + one `ExpiryQueue::insert` + the
            // SCALE-encoded `IntentKind` itself, dominated by BuyPolicy's
            // 114-byte beneficiary_cardano_addr). Plus a 16KB base for the
            // M-of-N free zone, header reads, and pool-utilization fetch.
            // The bench-cli wiring (#190) is still pending so this remains
            // a hand-tuned upper bound — the runtime-benchmarks pass will
            // replace this whole expression with the generated WeightInfo
            // entry when #190 lands. Until then, this estimate keeps the
            // per-block normal-class budget honest at N=256
            // (~16KB + 256*5KB ~1.3MB proof_size, well under the 5MB limit
            // documented in types.rs::MAX_SUBMIT_BATCH).
            const BASE_PROOF_SIZE: u64 = 16_384;
            const PER_ENTRY_PROOF_SIZE: u64 = 5_120;
            let n = entries.len() as u64;
            Weight::from_parts(
                50_000_000u64.saturating_add(n.saturating_mul(5_000_000)),
                BASE_PROOF_SIZE.saturating_add(n.saturating_mul(PER_ENTRY_PROOF_SIZE)),
            )
        })]
        pub fn submit_batch_intents(
            origin: OriginFor<T>,
            entries: BoundedVec<SubmitIntentEntry, <T as Config>::MaxSubmitBatch>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!entries.is_empty(), Error::<T>::EmptyIntentBatch);

            // Compute the canonical SBIN digest BEFORE consuming entries —
            // this is purely for indexer correlation (no sig-verify), so
            // it's safe to do up-front. Costs O(sum of SCALE-encoded kinds)
            // which is dominated by the BoundedVec encoding the user already
            // paid to land.
            //
            // #73: pre-image is bound to the Materios chain-id for parity
            // with the M-of-N family.
            let chain_id = Self::materios_chain_id_bytes();
            let batch_digest =
                submit_batch_intents_payload(&chain_id, entries.as_slice());

            // Pre-flight: sum BuyPolicy premiums across the batch. Reject
            // overflow before mutating storage so a craft-an-overflow
            // attempt cannot leave state half-updated. The per-entry credit
            // and pool-utilization checks STILL run inside `do_submit_intent`
            // (we don't pre-check them here — letting the per-entry path run
            // keeps semantics identical to a sequence of single-call
            // `submit_intent`s, just collapsed into one origin/fee).
            let mut total_premium_ada: AdaLovelace = 0;
            for entry in entries.iter() {
                if let IntentKind::BuyPolicy { premium_ada, .. } = &entry.kind {
                    total_premium_ada = total_premium_ada
                        .checked_add(*premium_ada)
                        .ok_or(Error::<T>::SubmitBatchPremiumOverflow)?;
                }
            }

            // Atomic mutation phase. Any per-entry error from
            // `do_submit_intent` (insufficient credit, pool-cap exceeded,
            // duplicate intent, pending-batches full) bubbles up and rolls
            // back EVERY mutation in this call — including any entries that
            // already debited credits. This matches the all-or-nothing
            // semantics PR #27 established for `settle_batch_atomic`.
            let count = entries.len() as u32;
            frame_support::storage::with_storage_layer::<
                (),
                sp_runtime::DispatchError,
                _,
            >(|| {
                for entry in entries.into_iter() {
                    Self::do_submit_intent(who.clone(), entry.kind)?;
                }
                Ok(())
            })?;

            Self::deposit_event(Event::BatchIntentsSubmitted {
                submitter: who,
                count,
                batch_digest,
                total_premium_ada,
            });
            Ok(())
        }

        // -------------------------------------------------------------
        // Task #266 (mis-sec P0) — split settle_claim into a permissionless
        // `request_settle` phase + a committee-attested `attest_settle`
        // phase. The new path commits each M-of-N signature to a FAT,
        // verifiable Cardano observation (`SettlementEvidence`) rather
        // than the legacy vacuous tx-hash, closing attack scenarios A1–A5
        // from the design memo §1.2.
        // -------------------------------------------------------------

        /// Task #266 (mis-sec P0): Phase 1 of the new attested settlement
        /// pipeline. Anyone can submit `request_settle` once they observe
        /// the matching Cardano transaction; the signer pays the (negligible)
        /// extrinsic fee. The pallet stores the `SettlementEvidence` keyed
        /// by `claim_id` and waits for a follow-up `attest_settle` call
        /// carrying M-of-N committee signatures over the canonical STCA
        /// payload (which mixes the stored evidence with chain-state-derived
        /// fields like `voucher_digest`).
        ///
        /// The requester is NOT required to be a committee member — this is
        /// the permissionless-keeper hand-off contemplated by task #84.
        /// Bond + slash on bad evidence is added in #84 (`requester` is
        /// stored here precisely as the slash target).
        ///
        /// Per-call invariants:
        /// - `evidence.observed_at_depth >= Config::MinFinalityDepth`
        ///   (`FinalityDepthBelowMinimum`).
        /// - `evidence.mainchain_genesis_hash == Config::MainchainGenesisHash`
        ///   (`WrongMainchainGenesis`).
        /// - Claim must exist (`ClaimNotFound`) and not already be settled
        ///   (`AlreadySettled`).
        /// - Voucher must exist (`VoucherMissing`) — we cross-check the
        ///   amount + beneficiary now, not just at attest time, so a
        ///   provably-bad request never even pins storage.
        /// - An existing request must be past `SettlementRequestTtl`.
        ///   Replacement refunds its bond to the original requester.
        /// - `bond_amount` is positive and at least `MinSettlementBond`,
        ///   reserved atomically before the request becomes visible.
        #[pallet::call_index(13)]
        #[pallet::weight((T::WeightInfo::request_settle(), DispatchClass::Operational, Pays::Yes))]
        pub fn request_settle(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
            attestation_evidence: SettlementEvidence,
            bond_amount: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // The requester's cardano_tx_hash is recorded in two places:
            // the extrinsic argument (for backward-compat with the legacy
            // event shape) and the evidence struct (for the canonical sig
            // pre-image). Reject any mismatch up-front so the two views can
            // never drift.
            ensure!(
                attestation_evidence.cardano_tx_hash == cardano_tx_hash,
                Error::<T>::SettlementEvidenceMismatch
            );

            Self::checked_settlement_target(claim_id, &attestation_evidence)?;
            Self::store_settlement_request(
                claim_id,
                SettlementRequestRecord {
                    requester: who.clone(),
                    evidence: attestation_evidence,
                    settled_direct,
                    submitted_block: <frame_system::Pallet<T>>::block_number(),
                    bond_amount,
                },
            )?;

            Self::deposit_event(Event::SettlementRequested {
                claim_id,
                requester: who,
                cardano_tx_hash,
                settled_direct,
            });
            Ok(())
        }

        /// Task #266 (mis-sec P0): Phase 2 of the new attested settlement
        /// pipeline. The committee submits M-of-N signatures over the
        /// canonical STCA payload, which the pallet rebuilds from the
        /// stored `ClaimSettlementRequests` entry + the on-chain
        /// `voucher_digest` + the pinned `MainchainGenesisHash`. The
        /// requester cannot influence the digest after `request_settle`
        /// landed — it's wholly determined by chain state.
        ///
        /// Per-call invariants:
        /// - A `ClaimSettlementRequests` entry must exist for this
        ///   claim_id (`SettlementRequestMissing`).
        /// - The pending entry must be fresh
        ///   (`now - submitted_block <= Config::SettlementRequestTtl`,
        ///   otherwise `SettlementRequestExpired`).
        /// - Claim + Voucher must still be in storage
        ///   (`ClaimNotFound` / `VoucherMissing`).
        /// - Claim must not already be settled (`AlreadySettled`) — this
        ///   path is strict, not idempotent, so a double-attest from a
        ///   colluding M surfaces in failed-extrinsic counters.
        /// - M-of-N sig bundle verifies via
        ///   `Self::ensure_threshold_signatures` against the rebuilt STCA
        ///   digest (caller-binding, distinct-signer, member-only).
        ///
        /// On success, the claim flips to `settled`, the bound intent flips
        /// to `Settled`, NAV + outstanding coverage decrement, and the
        /// pending request is removed. The `cardano_tx_hash` recorded on
        /// `Claim` is the requester-asserted one — but it's now bound to a
        /// committee attestation. Fraud slashing only applies while the
        /// request is pending; attestation consumes that request.
        #[pallet::call_index(14)]
        #[pallet::weight((Weight::from_parts(60_000_000, 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn attest_settle(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(Weight::from_parts(60_000_000, 0), |checked| {
                let who = ensure_signed(origin)?;
                ensure!(
                    T::CommitteeMembership::is_member(&who),
                    Error::<T>::NotCommitteeMember
                );
                ensure!(
                    signatures.len() <= T::MaxCommittee::get() as usize,
                    Error::<T>::TooManySignatures
                );

                // Hydrate the pending request — every attestor signs over a
                // payload derived from these stored bytes plus chain state.
                let request = ClaimSettlementRequests::<T>::get(claim_id)
                    .ok_or(Error::<T>::SettlementRequestMissing)?;

                // TTL gate. Expired requests can't be attested; the keeper must
                // post fresh evidence (a stale observation could be stale because
                // the Cardano tx got reorged or the attestor pool was offline,
                // either way we don't want to settle on it).
                let now = <frame_system::Pallet<T>>::block_number();
                // `BlockNumberFor<T>` is `Into<u64> + Copy` per the impl's where
                // clause, so we coerce both sides to u64 for the saturating sub.
                let now_u64: u64 = now.into();
                let submitted_u64: u64 = request.submitted_block.into();
                let age = now_u64.saturating_sub(submitted_u64);
                let ttl_u64: u64 = T::SettlementRequestTtl::get().into();
                ensure!(age <= ttl_u64, Error::<T>::SettlementRequestExpired);

                // Claim + voucher hydration. Both still needed even though
                // request_settle already cross-checked — a settle that races
                // an `expire_policy_mirror` could land here with the claim
                // already terminalized, so re-check.
                let claim = Claims::<T>::get(claim_id).ok_or(Error::<T>::ClaimNotFound)?;
                ensure!(!claim.settled, Error::<T>::AlreadySettled);
                let voucher = Vouchers::<T>::get(claim_id).ok_or(Error::<T>::VoucherMissing)?;

                // Re-derive voucher_digest from the on-chain voucher. Same
                // canonical pre-image as `request_voucher` / RVCH, so all
                // committee members see the same bytes.
                let voucher_digest = Self::compute_canonical_voucher_digest(&voucher)?;

                // Re-derive payment-key hash from the on-chain voucher address.
                // We already cross-checked this against the requester's
                // evidence in request_settle, but the digest must commit to
                // chain state, so we compute it here too.
                let (payment_hash, _stake_hash) =
                    crate::voucher_canonicalize::split_type0_address_bytes(
                        voucher.beneficiary_cardano_addr.as_slice(),
                    )
                    .map_err(|_| Error::<T>::InvalidBeneficiaryAddress)?;

                // Build the canonical STCA payload + run the M-of-N gate.
                let chain_id = Self::materios_chain_id_bytes();
                let mc_genesis = T::MainchainGenesisHash::get();
                let payload = settle_claim_attested_payload(
                    &chain_id,
                    &claim_id,
                    &voucher_digest,
                    &request.evidence.cardano_tx_hash,
                    request.settled_direct,
                    &payment_hash,
                    claim.amount_ada,
                    request.evidence.observed_at_depth,
                    request.evidence.observed_slot,
                    &mc_genesis,
                );
                Self::verify_threshold_signatures::<T::SigVerifier>(
                    &payload,
                    &who,
                    &signatures,
                    checked,
                )?;

                Self::settle_attested_claim(
                    claim_id,
                    claim,
                    request.evidence.cardano_tx_hash,
                    request.settled_direct,
                );

                // Task #84 (mis-sec P1): if a bond was posted on this
                // request, pin the attested-at block + a (requester, amount)
                // side record so the release-delay gate + unreserve target
                // are visible to `release_settlement_bond` after the
                // pending `ClaimSettlementRequests` row is removed below.
                // Storage writes are conditional on `bond_amount > 0` so the
                // unbonded legacy path costs zero extra slots.
                if request.bond_amount > 0 {
                    BondedClaimAttestedAt::<T>::insert(
                        claim_id,
                        <frame_system::Pallet<T>>::block_number(),
                    );
                    BondedClaimRequester::<T>::insert(
                        claim_id,
                        (request.requester.clone(), request.bond_amount),
                    );
                }

                // Consume the pending request — the canonical post-state is
                // "claim settled, no pending entry."
                ClaimSettlementRequests::<T>::remove(claim_id);
                Ok(())
            })
        }

        /// Settles `claim_id` on M-of-N STCA signatures over evidence the
        /// committee supplies, displacing a pending request whose evidence
        /// or settlement mode differs. The displaced bond is refunded, not
        /// slashed: an unattestable request may be honest but wrong, and no
        /// fraud is alleged. This clears requests that no `FraudProof` can
        /// slash, such as a wrong slot or an unreachable depth.
        ///
        /// The STCA digest is the one `attest_settle` verifies for a
        /// request carrying the same evidence. The evidence passes the
        /// checks `request_settle` applies; a request whose evidence and
        /// mode already match must be attested instead
        /// (`SupersedeMatchesRequest`).
        #[pallet::call_index(22)]
        #[pallet::weight((T::WeightInfo::supersede_settlement_request()
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn supersede_settlement_request(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            settled_direct: bool,
            evidence: SettlementEvidence,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(
                T::WeightInfo::supersede_settlement_request(),
                |checked| {
                    let who = ensure_signed(origin)?;
                    ensure!(
                        T::CommitteeMembership::is_member(&who),
                        Error::<T>::NotCommitteeMember
                    );
                    ensure!(
                        signatures.len() <= T::MaxCommittee::get() as usize,
                        Error::<T>::TooManySignatures
                    );
                    let (claim, voucher) = Self::checked_settlement_target(claim_id, &evidence)?;
                    let request = ClaimSettlementRequests::<T>::get(claim_id)
                        .ok_or(Error::<T>::SettlementRequestMissing)?;
                    ensure!(
                        request.evidence != evidence || request.settled_direct != settled_direct,
                        Error::<T>::SupersedeMatchesRequest
                    );

                    let payload = settle_claim_attested_payload(
                        &Self::materios_chain_id_bytes(),
                        &claim_id,
                        &Self::compute_canonical_voucher_digest(&voucher)?,
                        &evidence.cardano_tx_hash,
                        settled_direct,
                        &evidence.beneficiary_addr_hash,
                        claim.amount_ada,
                        evidence.observed_at_depth,
                        evidence.observed_slot,
                        &T::MainchainGenesisHash::get(),
                    );
                    Self::verify_threshold_signatures::<T::SigVerifier>(
                        &payload,
                        &who,
                        &signatures,
                        checked,
                    )?;

                    Self::discard_settlement_request(claim_id, request.clone())?;
                    Self::deposit_event(Event::SettlementRequestSuperseded {
                        claim_id,
                        requester: request.requester,
                    });
                    Self::settle_attested_claim(
                        claim_id,
                        claim,
                        evidence.cardano_tx_hash,
                        settled_direct,
                    );
                    Ok(())
                },
            )
        }

        /// Task #266 (mis-sec P0): batch parallel of `request_settle`. The
        /// keeper assembles N per-entry `SettlementEvidence` records and
        /// posts them in a single extrinsic. Each entry is validated
        /// independently against the per-claim on-chain voucher — atomic
        /// rejection on any bad entry, mirroring `submit_batch_intents`
        /// semantics.
        ///
        /// Atomic semantics: any per-entry failure
        /// (`SettlementRequestAlreadyExists`, `ClaimNotFound`,
        /// `AlreadySettled`, `VoucherMissing`, mismatch, wrong genesis,
        /// below-finality-depth) reverts EVERY storage mutation in the
        /// call. The keeper retries by removing the offending entry and
        /// resubmitting.
        #[pallet::call_index(15)]
        #[pallet::weight((
            T::WeightInfo::request_batch_settle(entries.len() as u32),
            DispatchClass::Operational,
            Pays::Yes,
        ))]
        pub fn request_batch_settle(
            origin: OriginFor<T>,
            entries: BoundedVec<SettleAttestedBatchEntry, <T as Config>::MaxSettleBatch>,
            bond_amount: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!entries.is_empty(), Error::<T>::EmptyBatch);

            // Pass 0: duplicate claim_id detection. O(N^2) at N<=256 is well
            // below the per-entry voucher-hydration cost.
            let n = entries.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    ensure!(
                        entries[i].claim_id != entries[j].claim_id,
                        Error::<T>::DuplicateClaimInBatch,
                    );
                }
            }

            let now = <frame_system::Pallet<T>>::block_number();
            let count = n as u32;

            frame_support::storage::with_storage_layer::<
                (),
                sp_runtime::DispatchError,
                _,
            >(|| {
                for entry in entries.iter() {
                    Self::checked_settlement_target(entry.claim_id, &entry.evidence)?;
                    Self::store_settlement_request(
                        entry.claim_id,
                        SettlementRequestRecord {
                            requester: who.clone(),
                            evidence: entry.evidence,
                            settled_direct: entry.settled_direct,
                            submitted_block: now,
                            bond_amount,
                        },
                    )?;
                }
                Ok(())
            })?;

            Self::deposit_event(Event::BatchSettlementRequested {
                count,
                requester: who,
            });
            Ok(())
        }

        /// Task #266 (mis-sec P0): batch parallel of `attest_settle`. The
        /// committee signs ONE digest over N STCA-style entries (the BSTA
        /// pre-image), the pallet hydrates each entry from the matching
        /// `ClaimSettlementRequests` + `Vouchers` + chain config, verifies
        /// the sig bundle once, then settles all N claims atomically.
        ///
        /// Same TTL + presence + evidence-match invariants as the single
        /// `attest_settle`, applied per-entry. Atomic rollback on first
        /// failure.
        #[pallet::call_index(16)]
        #[pallet::weight((Weight::from_parts(60_000_000u64.saturating_add((claim_ids.len() as u64).saturating_mul(15_000_000)), 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn attest_batch_settle(
            origin: OriginFor<T>,
            claim_ids: BoundedVec<ClaimId, <T as Config>::MaxSettleBatch>,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(
                Weight::from_parts(
                    60_000_000u64
                        .saturating_add((claim_ids.len() as u64).saturating_mul(15_000_000)),
                    0,
                ),
                |checked| {
                    let who = ensure_signed(origin)?;
                    ensure!(
                        T::CommitteeMembership::is_member(&who),
                        Error::<T>::NotCommitteeMember
                    );
                    ensure!(
                        signatures.len() <= T::MaxCommittee::get() as usize,
                        Error::<T>::TooManySignatures
                    );
                    ensure!(!claim_ids.is_empty(), Error::<T>::EmptyBatch);

                    // Pass 0: duplicate claim_id detection.
                    let n = claim_ids.len();
                    for i in 0..n {
                        for j in (i + 1)..n {
                            ensure!(
                                claim_ids[i] != claim_ids[j],
                                Error::<T>::DuplicateClaimInBatch,
                            );
                        }
                    }

                    // Pass 1: hydrate per-entry bytes BEFORE the sig-verify pass so
                    // honest operators all see the same flat byte stream the pallet
                    // is about to hash. Any missing/expired request fails the batch
                    // before any sig verifications run.
                    let chain_id = Self::materios_chain_id_bytes();
                    let mc_genesis = T::MainchainGenesisHash::get();
                    let now = <frame_system::Pallet<T>>::block_number();
                    let now_u64: u64 = now.into();
                    let ttl_u64: u64 = T::SettlementRequestTtl::get().into();

                    let mut entry_bytes: alloc::vec::Vec<BatchAttestEntryBytes> =
                        alloc::vec::Vec::with_capacity(n);
                    let mut hydrated_amounts: alloc::vec::Vec<u64> =
                        alloc::vec::Vec::with_capacity(n);
                    let mut hydrated_direct: alloc::vec::Vec<bool> =
                        alloc::vec::Vec::with_capacity(n);
                    let mut hydrated_intent_ids: alloc::vec::Vec<IntentId> =
                        alloc::vec::Vec::with_capacity(n);
                    // Task #84 (mis-sec P1): per-entry bond amount so the batch
                    // can pin `BondedClaimAttestedAt` at attest time for entries
                    // that opted in via `post_settlement_bond`.
                    let mut hydrated_bonds: alloc::vec::Vec<u128> =
                        alloc::vec::Vec::with_capacity(n);
                    for cid in claim_ids.iter() {
                        let request = ClaimSettlementRequests::<T>::get(*cid)
                            .ok_or(Error::<T>::SettlementRequestMissing)?;
                        let submitted_u64: u64 = request.submitted_block.into();
                        let age = now_u64.saturating_sub(submitted_u64);
                        ensure!(age <= ttl_u64, Error::<T>::SettlementRequestExpired);
                        let claim = Claims::<T>::get(*cid).ok_or(Error::<T>::ClaimNotFound)?;
                        ensure!(!claim.settled, Error::<T>::AlreadySettled);
                        let voucher = Vouchers::<T>::get(*cid).ok_or(Error::<T>::VoucherMissing)?;
                        let voucher_digest = Self::compute_canonical_voucher_digest(&voucher)?;
                        let (payment_hash, _stake_hash) =
                            crate::voucher_canonicalize::split_type0_address_bytes(
                                voucher.beneficiary_cardano_addr.as_slice(),
                            )
                            .map_err(|_| Error::<T>::InvalidBeneficiaryAddress)?;
                        // No need to re-check amount/beneficiary against evidence
                        // here — request_settle already enforced that at the time
                        // the entry was pinned, and the per-entry record is
                        // immutable for its lifetime.
                        entry_bytes.push(BatchAttestEntryBytes {
                            claim_id: *cid,
                            voucher_digest,
                            cardano_tx_hash: request.evidence.cardano_tx_hash,
                            settled_direct: request.settled_direct,
                            beneficiary_hash: payment_hash,
                            amount_ada: claim.amount_ada,
                            depth: request.evidence.observed_at_depth,
                            slot: request.evidence.observed_slot,
                            mc_genesis,
                        });
                        hydrated_amounts.push(claim.amount_ada);
                        hydrated_direct.push(request.settled_direct);
                        hydrated_intent_ids.push(claim.intent_id);
                        hydrated_bonds.push(request.bond_amount);
                    }

                    // ONE sig-verify pass over the canonical BSTA digest — the
                    // throughput unlock.
                    let payload = attest_batch_settle_payload(&chain_id, &entry_bytes);
                    Self::verify_threshold_signatures::<T::SigVerifier>(
                        &payload,
                        &who,
                        &signatures,
                        checked,
                    )?;

                    // Atomic mutation phase. Settle every claim under the same
                    // transactional storage layer so a mid-loop runtime error
                    // rolls the whole batch back.
                    let (count, settled_direct_count, total_amount) =
                        frame_support::storage::with_storage_layer::<
                            (u32, u32, u64),
                            sp_runtime::DispatchError,
                            _,
                        >(|| {
                            let mut direct_count: u32 = 0;
                            let mut total_amount_unsettled: u64 = 0;
                            for (idx, cid) in claim_ids.iter().enumerate() {
                                let mut claim =
                                    Claims::<T>::get(*cid).ok_or(Error::<T>::ClaimNotFound)?;
                                // Re-check inside the storage layer in case a sibling
                                // extrinsic in the same block already settled it.
                                ensure!(!claim.settled, Error::<T>::AlreadySettled);
                                let tx_hash = entry_bytes[idx].cardano_tx_hash;
                                let settled_direct = hydrated_direct[idx];
                                let amount = hydrated_amounts[idx];
                                let intent_id = hydrated_intent_ids[idx];
                                claim.settled = true;
                                claim.settled_direct = settled_direct;
                                claim.cardano_tx_hash = tx_hash;
                                Claims::<T>::insert(*cid, claim);
                                if let Some(mut intent) = Intents::<T>::get(intent_id) {
                                    intent.status = IntentStatus::Settled;
                                    Intents::<T>::insert(intent_id, intent);
                                }
                                Self::remove_from_pending_batches(intent_id);
                                // Task #84 (mis-sec P1): pin attested-at block +
                                // (requester, amount) side-record for bonded
                                // entries so the release-delay gate + unreserve
                                // target resolve later. We re-read the pending
                                // request to grab the requester field (cheaper
                                // than threading it through hydrated_* vecs and
                                // matches the single-call site's shape).
                                if hydrated_bonds[idx] > 0 {
                                    BondedClaimAttestedAt::<T>::insert(
                                        *cid,
                                        <frame_system::Pallet<T>>::block_number(),
                                    );
                                    if let Some(pending) = ClaimSettlementRequests::<T>::get(*cid) {
                                        BondedClaimRequester::<T>::insert(
                                            *cid,
                                            (pending.requester, hydrated_bonds[idx]),
                                        );
                                    }
                                }
                                ClaimSettlementRequests::<T>::remove(*cid);
                                if settled_direct {
                                    direct_count = direct_count.saturating_add(1);
                                }
                                total_amount_unsettled =
                                    total_amount_unsettled.saturating_add(amount);
                            }
                            PoolUtilization::<T>::mutate(|u| {
                                u.outstanding_coverage_ada = u
                                    .outstanding_coverage_ada
                                    .saturating_sub(total_amount_unsettled);
                                u.total_nav_ada =
                                    u.total_nav_ada.saturating_sub(total_amount_unsettled);
                            });
                            Ok((n as u32, direct_count, total_amount_unsettled))
                        })?;

                    let _ = total_amount; // surface to optional future event field
                    Self::deposit_event(Event::BatchSettled {
                        count,
                        batch_digest: payload,
                        settled_direct_count,
                    });
                    Ok(())
                },
            )
        }

        // -------------------------------------------------------------
        // Task #267 (mis-sec P0) — split expire_policy_mirror into a
        // permissionless `request_expire_policy` phase + a committee-
        // attested `attest_expire_policy` phase. The new path commits
        // each M-of-N signature to a FAT, verifiable Cardano observation
        // (`ExpiryEvidence`) rather than the legacy ZERO-evidence path
        // where any single committee signer could unilaterally flip any
        // intent to Expired. Mirrors the spec-220 design memo §4.2 exactly,
        // adapted for the expire side of the lifecycle.
        // -------------------------------------------------------------

        /// Task #267 (mis-sec P0): Phase 1 of the new attested expire
        /// pipeline. Anyone can submit `request_expire_policy` once they
        /// observe the matching Cardano `Expire` redeemer transaction;
        /// the signer pays the (negligible) extrinsic fee. The pallet
        /// stores the `ExpiryEvidence` keyed by `intent_id` and waits for
        /// a follow-up `attest_expire_policy` call carrying M-of-N
        /// committee signatures over the canonical EXPP payload (which
        /// mixes the stored evidence with chain-state-derived fields like
        /// the on-chain intent's resolved policy id).
        ///
        /// The requester is NOT required to be a committee member — this
        /// is the permissionless-keeper hand-off contemplated by task #84.
        /// Bond + slash on bad evidence is added in #84 (`requester` is
        /// stored here precisely as the slash target).
        ///
        /// Per-call invariants:
        /// - `evidence.observed_at_depth >= Config::MinFinalityDepth`
        ///   (`FinalityDepthBelowMinimum`).
        /// - `evidence.mainchain_genesis_hash == Config::MainchainGenesisHash`
        ///   (`WrongMainchainGenesis`).
        /// - `evidence.cardano_tx_hash == cardano_tx_hash` argument
        ///   (`ExpiryEvidenceMismatch`).
        /// - Intent must exist (`UnknownPolicy`) and not be terminal
        ///   (`IntentNotEligibleForExpiry`); already-expired is treated as
        ///   idempotent no-op `Ok(())` to match the legacy contract.
        /// - Intent kind must be `BuyPolicy` or `RequestPayout` (the only
        ///   intent shapes that bind to a Cardano-side policy); a
        ///   `RefundCredit` intent is rejected with
        ///   `IntentNotEligibleForExpiry` since it has no Cardano-side
        ///   Expire redeemer.
        /// - `evidence.policy_id_witness` must match the on-chain
        ///   resolved policy id (`product_id` for BuyPolicy,
        ///   `policy_id` for RequestPayout) — defends against recycling
        ///   one Expire tx onto the wrong intent.
        /// - No pending expire request for this intent_id can exist
        ///   (`ExpiryRequestAlreadyExists`). The requester waits out
        ///   `SettlementRequestTtl` before re-posting; this preempts a
        ///   request-flapper attack.
        #[pallet::call_index(17)]
        #[pallet::weight((Weight::from_parts(35_000_000, 0), DispatchClass::Operational, Pays::Yes))]
        pub fn request_expire_policy(
            origin: OriginFor<T>,
            intent_id: IntentId,
            cardano_tx_hash: [u8; 32],
            attestation_evidence: ExpiryEvidence,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // The requester's cardano_tx_hash is recorded in two places:
            // the extrinsic argument (for event correlation) and the
            // evidence struct (for the canonical sig pre-image). Reject
            // any mismatch up-front so the two views can never drift.
            ensure!(
                attestation_evidence.cardano_tx_hash == cardano_tx_hash,
                Error::<T>::ExpiryEvidenceMismatch
            );

            // Mainchain genesis pin — preprod attestor's evidence cannot
            // expire a mainnet intent and vice versa.
            ensure!(
                attestation_evidence.mainchain_genesis_hash
                    == T::MainchainGenesisHash::get(),
                Error::<T>::WrongMainchainGenesis
            );

            // Finality depth gate — the attestor's k value must clear
            // the pallet's freshness floor.
            ensure!(
                attestation_evidence.observed_at_depth >= T::MinFinalityDepth::get(),
                Error::<T>::FinalityDepthBelowMinimum
            );

            // Intent presence + state checks. We do these BEFORE pinning
            // the pending-request entry so a request against a wrong/
            // terminal intent never wastes a storage slot.
            let intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::UnknownPolicy)?;
            // Already-expired is idempotent (matches legacy contract). The
            // legacy `expire_policy_mirror` returned Ok on already-Expired;
            // we preserve that semantic so well-behaved keepers re-posting
            // on a race don't trip a hard error.
            if matches!(intent.status, IntentStatus::Expired) {
                return Ok(());
            }
            // Settled intents cannot also expire — the audit narrative
            // requires the settle-or-expire dichotomy to be enforced at
            // the pallet boundary.
            ensure!(
                !matches!(intent.status, IntentStatus::Settled),
                Error::<T>::IntentNotEligibleForExpiry
            );
            // Resolve the canonical policy id for THIS intent. The witness
            // is cross-checked against the requester's claim so a colluding
            // requester can't recycle one Cardano Expire tx onto the wrong
            // Materios intent (the EXPP digest commits to this resolved
            // id at attest time).
            let resolved_policy_id = Self::resolve_intent_policy_id(&intent)?;
            ensure!(
                attestation_evidence.policy_id_witness == resolved_policy_id,
                Error::<T>::ExpiryEvidenceMismatch
            );

            if let Some(previous) = PolicyExpireRequests::<T>::get(intent_id) {
                ensure!(
                    Self::request_expired(previous.submitted_block),
                    Error::<T>::ExpiryRequestAlreadyExists
                );
            }

            let now = <frame_system::Pallet<T>>::block_number();
            let record = ExpiryRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                requester: who.clone(),
                evidence: attestation_evidence,
                submitted_block: now,
            };
            PolicyExpireRequests::<T>::insert(intent_id, record);

            Self::deposit_event(Event::ExpiryRequested {
                intent_id,
                requester: who,
                cardano_tx_hash,
                policy_id_witness: attestation_evidence.policy_id_witness,
            });
            Ok(())
        }

        /// Task #267 (mis-sec P0): Phase 2 of the new attested expire
        /// pipeline. The committee submits M-of-N signatures over the
        /// canonical EXPP payload, which the pallet rebuilds from the
        /// stored `PolicyExpireRequests` entry + the on-chain intent's
        /// resolved policy id + the pinned `MainchainGenesisHash`. The
        /// requester cannot influence the digest after
        /// `request_expire_policy` landed — it's wholly determined by
        /// chain state.
        ///
        /// Per-call invariants:
        /// - A `PolicyExpireRequests` entry must exist for this intent_id
        ///   (`ExpiryRequestMissing`).
        /// - The pending entry must be fresh
        ///   (`now - submitted_block <= Config::SettlementRequestTtl`,
        ///   otherwise `ExpiryRequestExpired`).
        /// - Intent must still be in storage (`UnknownPolicy`) and not
        ///   settled (`IntentNotEligibleForExpiry`). Already-Expired is
        ///   idempotent — the pending request is consumed and Ok returns,
        ///   matching the legacy contract.
        /// - M-of-N sig bundle verifies via
        ///   `Self::ensure_threshold_signatures` against the rebuilt EXPP
        ///   digest (caller-binding, distinct-signer, member-only).
        ///
        /// On success, the intent flips to `Expired`, drops from the
        /// `PendingBatches` index, the pending expire-request is removed,
        /// and refund-credit semantics fire identically to the TTL sweep
        /// (for `BuyPolicy` intents the unspent premium returns to the
        /// submitter; the legacy `expire_policy_mirror` did NOT refund
        /// here because the keeper's "policy expired on Cardano" claim
        /// pre-dated the refund-on-expiry contract — closing that gap is
        /// out of scope for THIS PR but the storage move is identical).
        /// `IntentExpired{reason=PolicyExpiredOnCardano}` is the canonical
        /// event for indexers.
        #[pallet::call_index(18)]
        #[pallet::weight((Weight::from_parts(55_000_000, 0)
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn attest_expire_policy(
            origin: OriginFor<T>,
            intent_id: IntentId,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(Weight::from_parts(55_000_000, 0), |checked| {
                let who = ensure_signed(origin)?;
                ensure!(
                    T::CommitteeMembership::is_member(&who),
                    Error::<T>::NotCommitteeMember
                );
                ensure!(
                    signatures.len() <= T::MaxCommittee::get() as usize,
                    Error::<T>::TooManySignatures
                );

                // Hydrate the pending request — every attestor signs over a
                // payload derived from these stored bytes plus chain state.
                let request = PolicyExpireRequests::<T>::get(intent_id)
                    .ok_or(Error::<T>::ExpiryRequestMissing)?;

                // TTL gate. Expired requests can't be attested; the keeper
                // must post fresh evidence (a stale observation could be
                // stale because the Cardano tx got reorged or the attestor
                // pool was offline too long).
                let now = <frame_system::Pallet<T>>::block_number();
                let now_u64: u64 = now.into();
                let submitted_u64: u64 = request.submitted_block.into();
                let age = now_u64.saturating_sub(submitted_u64);
                let ttl_u64: u64 = T::SettlementRequestTtl::get().into();
                ensure!(age <= ttl_u64, Error::<T>::ExpiryRequestExpired);

                // Intent hydration. Still needed even though
                // request_expire_policy already cross-checked — a settle
                // could race a parallel attest and terminalize the intent
                // before this call lands.
                let mut intent = Intents::<T>::get(intent_id).ok_or(Error::<T>::UnknownPolicy)?;
                // Already-Expired is idempotent — consume the pending request
                // and return Ok so a sibling caller that posted late doesn't
                // see a confusing error.
                if matches!(intent.status, IntentStatus::Expired) {
                    PolicyExpireRequests::<T>::remove(intent_id);
                    return Ok(());
                }
                ensure!(
                    !matches!(intent.status, IntentStatus::Settled),
                    Error::<T>::IntentNotEligibleForExpiry
                );

                // Re-resolve the canonical policy id from the on-chain intent.
                // We already cross-checked this against the requester's
                // witness in request_expire_policy, but the digest must
                // commit to chain state, so we compute it again here.
                let resolved_policy_id = Self::resolve_intent_policy_id(&intent)?;

                // Build the canonical EXPP payload + run the M-of-N gate.
                let chain_id = Self::materios_chain_id_bytes();
                let mc_genesis = T::MainchainGenesisHash::get();
                let payload = expire_policy_attested_payload(
                    &chain_id,
                    &intent_id,
                    &resolved_policy_id,
                    &request.evidence.cardano_tx_hash,
                    request.evidence.observed_at_depth,
                    request.evidence.observed_slot,
                    &mc_genesis,
                );
                Self::verify_threshold_signatures::<T::SigVerifier>(
                    &payload,
                    &who,
                    &signatures,
                    checked,
                )?;

                // All checks pass — expire the intent. State transition +
                // index cleanup mirror the legacy `expire_policy_mirror`
                // exactly; the only delta is the trust gate now requires
                // M-of-N over falsifiable Cardano evidence.
                intent.status = IntentStatus::Expired;
                Intents::<T>::insert(intent_id, intent);
                Self::remove_from_pending_batches(intent_id);

                // Consume the pending request — canonical post-state is
                // "intent expired, no pending entry."
                PolicyExpireRequests::<T>::remove(intent_id);

                Self::deposit_event(Event::IntentExpired {
                    intent_id,
                    reason: ExpiryReason::PolicyExpiredOnCardano,
                });
                Ok(())
            })
        }

        // -------------------------------------------------------------
        // Task #84 (mis-sec P1) — bond + slash on settlement evidence
        //
        // `request_settle` and `request_batch_settle` reserve the bond with
        // the request. A watcher who proves the requester's evidence is
        // fraudulent via `slash_bad_settlement_evidence` earns
        // `SlashWatcherShareBps / 10_000` of the bond; the rest goes to the
        // treasury. After attestation plus `BondReleaseDelayBlocks`, or after
        // an unattested request expires, any caller releases the bond to its
        // requester. `post_settlement_bond` bonds requests stored before
        // request-time bonding.
        // -------------------------------------------------------------

        /// The requester of an unbonded request stored before request-time
        /// bonding reserves `amount` of `Config::Currency` against it. The
        /// reserve is slashable until the request is attested or expires.
        ///
        /// Per-call invariants:
        /// - Pending request must exist (`SettlementRequestMissing`) and be
        ///   within `SettlementRequestTtl` (`SettlementRequestExpired`), so
        ///   no bond lands after its slash window has closed.
        /// - Caller must match the request's `requester` field
        ///   (`NotRequester`).
        /// - `amount` must be positive and at least
        ///   `Config::MinSettlementBond` (`BondBelowMinimum`).
        /// - Request must not already be bonded
        ///   (`BondAlreadyReserved`).
        /// - Claim must not already be attested (`RequestAlreadyAttested`)
        ///   — bonds MUST be posted before `attest_settle` lands.
        ///
        /// On success: `Currency::reserve(who, amount)` succeeds,
        /// `ClaimSettlementRequests[claim_id].bond_amount` is rewritten
        /// to `amount`, and `SettlementBondPosted` is emitted.
        #[pallet::call_index(19)]
        #[pallet::weight((T::WeightInfo::post_settlement_bond(), DispatchClass::Operational, Pays::Yes))]
        pub fn post_settlement_bond(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            amount: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut record = ClaimSettlementRequests::<T>::get(claim_id)
                .ok_or(Error::<T>::SettlementRequestMissing)?;

            ensure!(
                !Self::request_expired(record.submitted_block),
                Error::<T>::SettlementRequestExpired
            );

            // Caller-binding: only the original requester can bond
            // their own request. A third party bonding someone else's
            // request would let them lock the requester into an
            // economic position they didn't choose.
            ensure!(record.requester == who, Error::<T>::NotRequester);
            // Single-shot: bonds cannot stack. The design memo §6 #9
            // contemplates a single bond amount per request — re-bonding
            // would either race with a watcher or double-reserve.
            ensure!(record.bond_amount == 0, Error::<T>::BondAlreadyReserved);
            // Bonds MUST land before attest_settle. Once the claim has
            // flipped to settled (and the pending request consumed),
            // the storage map no longer has the entry, so the
            // SettlementRequestMissing path above handles that case;
            // this guard catches the rarer case where the claim was
            // attested via a race-window batch path but the pending
            // request was *not* removed (defensive). It also matches
            // the design memo's contract: bond → request → attest.
            if let Some(claim) = Claims::<T>::get(claim_id) {
                ensure!(!claim.settled, Error::<T>::RequestAlreadyAttested);
            }

            Self::reserve_settlement_bond(claim_id, &who, amount)?;

            record.bond_amount = amount;
            ClaimSettlementRequests::<T>::insert(claim_id, record);

            Ok(())
        }

        /// Task #84 (mis-sec P1): the watcher posts a `FraudProof`
        /// against an outstanding `request_settle` entry. M-of-N
        /// committee signatures over the canonical FRV2 digest attest
        /// the watcher's claim is truthful; the reserved bond is split
        /// `SlashWatcherShareBps / 10_000` to the watcher and the rest
        /// to the treasury PalletId-derived account.
        ///
        /// Per-call invariants:
        /// - Caller must be a committee member (`NotCommitteeMember`),
        ///   checked before any signature verification.
        /// - Pending request must exist (`SettlementRequestMissing`) and be
        ///   within `SettlementRequestTtl` (`SettlementRequestExpired`).
        /// - Pending request must be bonded (`BondNotReserved`).
        /// - `fraud_proof` must be internally consistent with the
        ///   stored evidence (`FraudProofInvalid`) — e.g., a
        ///   `WrongAmount { actual_lovelace = X }` proof requires
        ///   `X != stored.amount_lovelace`.
        /// - `signatures` must clear the same M-of-N threshold
        ///   `attest_settle` uses (`FraudThresholdNotMet`).
        /// - `signatures` must verify against the canonical FRV2
        ///   pre-image (`InvalidSignature` — surfaced by
        ///   `ensure_threshold_signatures`).
        /// - Caller binding: the watcher's own pubkey MUST appear in
        ///   the sig bundle (`ensure_threshold_signatures` enforces).
        ///
        /// On success: the bond is repatriated via
        /// `Currency::repatriate_reserved` (watcher gets
        /// `bond * watcher_bps / 10_000`, treasury gets the rest),
        /// `SlashedSettlementRequests[claim_id, request_id]` is set, the
        /// `ClaimSettlementRequests` row is removed (so
        /// `attest_settle` errors with `SettlementRequestMissing`),
        /// and `SettlementBondSlashed` is emitted. Any other request for
        /// the claim can then be filed and attested.
        #[pallet::call_index(20)]
        #[pallet::weight((T::WeightInfo::slash_bad_settlement_evidence()
            .saturating_add(T::WeightInfo::threshold_signatures(signatures.len().min(T::MaxCommittee::get() as usize) as u32)),
            DispatchClass::Operational, Pays::No))]
        pub fn slash_bad_settlement_evidence(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            fraud_proof: FraudProof,
            signatures: Vec<(CommitteePubkey, CommitteeSig)>,
        ) -> DispatchResultWithPostInfo {
            Self::with_signature_weight(T::WeightInfo::slash_bad_settlement_evidence(), |checked| {
                let who = ensure_signed(origin)?;
                ensure!(
                    T::CommitteeMembership::is_member(&who),
                    Error::<T>::NotCommitteeMember
                );
                // Cap sigs len BEFORE any verify cycle — same DoS-gate
                // pattern as `attest_settle` (Task #75).
                ensure!(
                    signatures.len() <= T::MaxCommittee::get() as usize,
                    Error::<T>::TooManySignatures
                );

                // Threshold pre-check so the watcher gets the explicit
                // FraudThresholdNotMet rather than the generic
                // InsufficientSignatures error from ensure_threshold_signatures
                // — distinct UX for the slash path. We still let
                // ensure_threshold_signatures do the per-sig verify and the
                // caller-binding gate.
                let effective_threshold = {
                    let stored = MinSignerThreshold::<T>::get();
                    let base = if stored == 0 {
                        T::DefaultMinSignerThreshold::get()
                    } else {
                        stored
                    };
                    base.max(1)
                };
                ensure!(
                    signatures.len() as u32 >= effective_threshold,
                    Error::<T>::FraudThresholdNotMet
                );

                // Hydrate the pending request.
                let record = ClaimSettlementRequests::<T>::get(claim_id)
                    .ok_or(Error::<T>::SettlementRequestMissing)?;

                ensure!(
                    !Self::request_expired(record.submitted_block),
                    Error::<T>::SettlementRequestExpired
                );

                // Bond-presence gate.
                ensure!(record.bond_amount > 0, Error::<T>::BondNotReserved);

                // Internal-consistency check on the fraud proof. The
                // canonical contract: `WrongAmount` / `WrongBeneficiary`
                // must allege a value DIFFERENT from what the requester
                // committed to (otherwise there's no fraud being alleged).
                // `TxNotFound` is always internally consistent — the proof
                // is the absence of the asserted tx_hash on Cardano,
                // which the committee's M-of-N attests.
                match fraud_proof {
                    FraudProof::WrongAmount { actual_lovelace } => {
                        ensure!(
                            actual_lovelace != (record.evidence.amount_lovelace as u128),
                            Error::<T>::FraudProofInvalid
                        );
                    }
                    FraudProof::WrongBeneficiary {
                        actual_payment_hash,
                    } => {
                        ensure!(
                            actual_payment_hash != record.evidence.beneficiary_addr_hash,
                            Error::<T>::FraudProofInvalid
                        );
                    }
                    FraudProof::TxNotFound => { /* always internally consistent */ }
                }

                // Build the canonical FRV2 pre-image and run the M-of-N
                // gate (caller-binding, distinct-signer, member-only,
                // per-sig sr25519 verify) — same routine attest_settle
                // uses.
                let chain_id = Self::materios_chain_id_bytes();
                let payload = slash_bad_settlement_evidence_payload(
                    &chain_id,
                    &claim_id,
                    &record,
                    &fraud_proof,
                );
                Self::verify_threshold_signatures::<T::SigVerifier>(
                    &payload,
                    &who,
                    &signatures,
                    checked,
                )?;

                // Compute the watcher / treasury split. We clamp the bps
                // input into `[0, 10_000]` defensively — a misconfigured
                // runtime that returned 12_000 would otherwise pay the
                // watcher more than the bond. Clamp keeps the invariant
                // `watcher_share + treasury_share == bond_amount`.
                let raw_bps = T::SlashWatcherShareBps::get();
                let clamped_bps = raw_bps.min(10_000u32);
                // u128 math throughout — bond_amount is u128 by the type
                // contract on SettlementRequestRecord.
                let bond_u128 = record.bond_amount;
                let watcher_share_u128: u128 =
                    bond_u128.saturating_mul(clamped_bps as u128) / 10_000u128;
                let treasury_share_u128: u128 = bond_u128.saturating_sub(watcher_share_u128);

                let requester = record.requester.clone();
                let treasury_account: T::AccountId =
                    T::SettlementTreasuryPalletId::get().into_account_truncating();

                // Convert u128 shares → BalanceOf<T>. We try_into both so a
                // misconfigured runtime fails LOUDLY rather than silently
                // truncating.
                let watcher_balance: BalanceOf<T> = watcher_share_u128
                    .try_into()
                    .map_err(|_| Error::<T>::BondAmountConversionOverflow)?;
                let treasury_balance: BalanceOf<T> = treasury_share_u128
                    .try_into()
                    .map_err(|_| Error::<T>::BondAmountConversionOverflow)?;

                // Each share moves only out of the settlement reserve; a
                // shortfall there is reported, never taken from the
                // requester's other reserves.
                let repatriate = |beneficiary: &T::AccountId,
                                      share: BalanceOf<T>|
                 -> Result<u128, DispatchError> {
                    if share.is_zero() {
                        return Ok(0);
                    }
                    let unpaid = T::Currency::repatriate_reserved_named(
                        &SETTLEMENT_BOND_RESERVE_ID,
                        &requester,
                        beneficiary,
                        share,
                        BalanceStatus::Free,
                    )?;
                    Ok(share.saturating_sub(unpaid).saturated_into())
                };
                let watcher_paid = repatriate(&who, watcher_balance)?;
                let treasury_paid = repatriate(&treasury_account, treasury_balance)?;
                let missing_amount = bond_u128
                    .saturating_sub(watcher_paid)
                    .saturating_sub(treasury_paid);
                if missing_amount > 0 {
                    Self::deposit_event(Event::SettlementBondReserveDeficit {
                        claim_id,
                        requester: requester.clone(),
                        missing_amount,
                    });
                }

                // Tombstone + cleanup. Removing the pending request makes
                // attest_settle error with SettlementRequestMissing, which
                // is the canonical post-state per the design memo.
                SlashedSettlementRequests::<T>::insert(
                    claim_id,
                    settlement_request_id(&record),
                    (),
                );
                ClaimSettlementRequests::<T>::remove(claim_id);

                Self::deposit_event(Event::SettlementBondSlashed {
                    claim_id,
                    requester,
                    watcher: who,
                    watcher_share: watcher_paid,
                    treasury_share: treasury_paid,
                    fraud_proof,
                });
                Ok(())
            })
        }

        /// Permissionlessly return a bond to its requester after successful
        /// attestation plus the release delay, or after an unattested request
        /// expires. Slashing and attestation remain valid at the TTL boundary;
        /// expiry release begins on the next block.
        #[pallet::call_index(21)]
        #[pallet::weight((T::WeightInfo::release_settlement_bond(), DispatchClass::Operational, Pays::Yes))]
        pub fn release_settlement_bond(
            origin: OriginFor<T>,
            claim_id: ClaimId,
        ) -> DispatchResult {
            let _caller = ensure_signed(origin)?;
            let attested_at = match BondedClaimAttestedAt::<T>::get(claim_id) {
                Some(block) => block,
                None => {
                    let request = ClaimSettlementRequests::<T>::get(claim_id)
                        .ok_or(Error::<T>::BondNotReserved)?;
                    ensure!(request.bond_amount > 0, Error::<T>::BondNotReserved);
                    ensure!(
                        Self::request_expired(request.submitted_block),
                        Error::<T>::BondReleaseTooEarly
                    );
                    return Self::remove_expired_settlement_request(claim_id);
                }
            };

            // The pending `ClaimSettlementRequests` entry has been
            // consumed by `attest_settle`, so we keep a side-record of
            // (requester, bond_amount) in the `BondedClaimRequester`
            // map written at attest time. Look it up here.
            let (requester, bond_amount) =
                BondedClaimRequester::<T>::get(claim_id)
                    .ok_or(Error::<T>::BondNotReserved)?;

            // Release-delay gate.
            let now = <frame_system::Pallet<T>>::block_number();
            let now_u64: u64 = now.into();
            let attested_u64: u64 = attested_at.into();
            let elapsed = now_u64.saturating_sub(attested_u64);
            let delay_u64: u64 = T::BondReleaseDelayBlocks::get().into();
            ensure!(elapsed >= delay_u64, Error::<T>::BondReleaseTooEarly);

            Self::refund_settlement_bond(claim_id, requester, bond_amount)
        }
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    impl<T: Config> Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
        T::AccountId: Encode,
    {
        pub fn do_submit_intent(
            who: T::AccountId,
            kind: IntentKind,
        ) -> Result<IntentId, DispatchError> {
            // Pool utilization cap (Aegis v2 Q1) — only evaluated for BuyPolicy.
            if let IntentKind::BuyPolicy { premium_ada, .. } = &kind {
                // Debit credits FIRST so refund on expiry is well-defined.
                let c = Credits::<T>::get(&who);
                ensure!(c >= *premium_ada, Error::<T>::InsufficientCredit);
                let u = PoolUtilization::<T>::get();
                let nav = u.total_nav_ada.max(1); // avoid div/0 on empty pool
                let proposed = u.outstanding_coverage_ada.saturating_add(*premium_ada);
                let new_bps = ((proposed as u128).saturating_mul(10_000)
                    / nav as u128) as u32;
                ensure!(
                    new_bps <= u.cap_bps,
                    Error::<T>::PoolUtilizationExceeded
                );
                Credits::<T>::insert(&who, c - *premium_ada);
            }
            if let IntentKind::RefundCredit { amount_ada } = &kind {
                let c = Credits::<T>::get(&who);
                ensure!(c >= *amount_ada, Error::<T>::InsufficientCredit);
                Credits::<T>::insert(&who, c - *amount_ada);
            }

            let nonce = Nonces::<T>::get(&who);
            let now_u32: u32 = <frame_system::Pallet<T>>::block_number()
                .into()
                .try_into()
                .unwrap_or(u32::MAX);
            let ttl = IntentTTL::<T>::get();
            let ttl_block = now_u32.saturating_add(if ttl == 0 {
                T::DefaultIntentTTL::get()
            } else {
                ttl
            });

            let submitter_bytes = crate::account_to_bytes(&who);
            let intent_id = compute_intent_id(&submitter_bytes, nonce, &kind, now_u32);

            ensure!(
                !Intents::<T>::contains_key(intent_id),
                Error::<T>::DuplicateIntent
            );

            // Issue #6: maintain a bounded index alongside Intents so
            // get_pending_batches can avoid the O(N) Intents::iter() scan.
            // Check the capacity BEFORE any storage mutation so the TX is a
            // no-op on bound-exceeded.
            let mut pb = PendingBatches::<T>::get();
            pb.try_push(intent_id)
                .map_err(|_| Error::<T>::PendingBatchesFull)?;

            let intent = Intent {
                submitter: who.clone(),
                nonce,
                kind,
                submitted_block: now_u32,
                ttl_block,
                status: IntentStatus::Pending,
            };
            Intents::<T>::insert(intent_id, intent);
            Nonces::<T>::insert(&who, nonce.saturating_add(1));
            PendingBatches::<T>::put(pb);

            let mut queue = ExpiryQueue::<T>::get(ttl_block);
            let _ = queue.try_push(intent_id); // best-effort; if full, GC runs next block
            ExpiryQueue::<T>::insert(ttl_block, queue);

            Self::deposit_event(Event::IntentSubmitted {
                intent_id,
                submitter: who,
                nonce,
            });
            Ok(intent_id)
        }

        fn validate_fairness_proof(p: &BatchFairnessProof) -> DispatchResult {
            // pro_rata <= 10000
            ensure!(p.pro_rata_scale_bps <= 10_000, Error::<T>::InvalidFairnessProof);
            // parallel-vec invariant
            let n = p.sorted_intent_ids.len();
            ensure!(
                p.requested_amounts_ada.len() == n && p.awarded_amounts_ada.len() == n,
                Error::<T>::InvalidFairnessProof
            );
            // sorted_intent_ids strictly ascending
            for w in p.sorted_intent_ids.windows(2) {
                ensure!(
                    w[0].as_bytes() < w[1].as_bytes(),
                    Error::<T>::InvalidFairnessProof
                );
            }
            // per-entry awarded = requested * scale / 10000
            // sum awarded <= pool_balance_ada
            let mut sum_awarded: u128 = 0;
            for i in 0..n {
                let req = p.requested_amounts_ada[i] as u128;
                let award = p.awarded_amounts_ada[i] as u128;
                let expected = req.saturating_mul(p.pro_rata_scale_bps as u128) / 10_000u128;
                ensure!(award == expected, Error::<T>::InvalidFairnessProof);
                sum_awarded = sum_awarded.saturating_add(award);
            }
            ensure!(
                sum_awarded <= p.pool_balance_ada as u128,
                Error::<T>::InvalidFairnessProof
            );
            // batch_block_range must be inclusive + non-decreasing
            ensure!(
                p.batch_block_range.0 <= p.batch_block_range.1,
                Error::<T>::InvalidFairnessProof
            );
            Ok(())
        }

        /// Runtime-API helper: return up to `max_count` attested-but-not-
        /// vouchered intents with `submitted_block >= since_block`.
        ///
        /// Issue #6: this previously scanned the entire `Intents` map which
        /// was O(N_total) per keeper poll. We now iterate the
        /// `PendingBatches` index (bounded by `MaxPendingBatches`) and
        /// in-memory filter by status. Terminal transitions (settle, expire,
        /// voucher) remove their id from the index, so the iteration cost
        /// tracks real work, not historical churn.
        pub fn get_pending_batches(
            since_block: BlockNumber,
            max_count: u32,
        ) -> Vec<BatchPayload<T::AccountId>> {
            let mut out = Vec::new();
            let pb = PendingBatches::<T>::get();
            for intent_id in pb.iter() {
                let intent = match Intents::<T>::get(intent_id) {
                    Some(i) => i,
                    None => continue, // stale index entry, harmless
                };
                if intent.submitted_block < since_block {
                    continue;
                }
                if intent.status != IntentStatus::Attested {
                    continue;
                }
                let sigs = AttestationSigs::<T>::get(intent_id).unwrap_or_default();
                let sigs_static: BoundedVec<
                    (CommitteePubkey, CommitteeSig),
                    ConstU32<MAX_COMMITTEE>,
                > = BoundedVec::truncate_from(sigs.into_inner());
                out.push(BatchPayload {
                    intent,
                    intent_id: *intent_id,
                    attestation_sigs: sigs_static,
                });
                if out.len() as u32 >= max_count {
                    break;
                }
            }
            out
        }

        /// Issue #6: remove `intent_id` from the `PendingBatches` index. No-op
        /// if the id isn't present (idempotent on already-terminalized intents).
        pub(crate) fn remove_from_pending_batches(intent_id: IntentId) {
            PendingBatches::<T>::mutate(|pb| {
                if let Some(pos) = pb.iter().position(|id| id == &intent_id) {
                    pb.remove(pos);
                }
            });
        }

        /// Task #73: thin wrapper around `T::MateriosChainId::get()` returning
        /// the raw 32-byte H256 view used by every pre-image helper. Inlined
        /// at every call site so the chain-id pull happens once per extrinsic.
        pub fn materios_chain_id_bytes() -> [u8; 32] {
            T::MateriosChainId::get().0
        }

        /// Task #79: build the canonical Plutus V3 Data CBOR for a voucher's
        /// beneficiary address. Vouchers carry the raw CIP-0019 type-0 buffer
        /// (`0x01 || payment_hash(28) || stake_hash(28)`); the canonical
        /// digest binds the Aiken-equivalent CBOR shape, so we re-derive it
        /// here rather than trusting an attacker-provided pre-encoded blob.
        ///
        /// Address shapes other than type-0 (script-payment, pointer, etc.)
        /// are NOT supported in the v1 voucher schema and are surfaced as
        /// `InvalidBeneficiaryAddress`.
        pub fn beneficiary_cbor_for(
            addr: &BoundedVec<u8, ConstU32<MAX_CARDANO_ADDR>>,
        ) -> Result<[u8; 80], DispatchError> {
            let raw: &[u8] = addr.as_slice();
            let (payment_hash, stake_hash) =
                crate::voucher_canonicalize::split_type0_address_bytes(raw)
                    .map_err(|_| Error::<T>::InvalidBeneficiaryAddress)?;
            Ok(crate::voucher_canonicalize::build_type0_address_cbor(
                crate::voucher_canonicalize::Type0AddressHashes {
                    payment_hash: &payment_hash,
                    stake_hash: &stake_hash,
                },
            ))
        }

        /// Task #266 (mis-sec P0): re-derive the canonical voucher digest
        /// from an on-chain `Voucher` value, matching the form used by
        /// `request_voucher` / RVCH. The `attest_settle` payload commits to
        /// this digest so every honest attestor recomputes the same bytes
        /// without trusting any requester-supplied digest.
        pub fn compute_canonical_voucher_digest(
            voucher: &Voucher,
        ) -> Result<[u8; 32], DispatchError> {
            let chain_id = Self::materios_chain_id_bytes();
            let aegis_script_hash = T::AegisPolicyV1ScriptHash::get();
            let beneficiary_cbor =
                Self::beneficiary_cbor_for(&voucher.beneficiary_cardano_addr)?;
            Ok(
                crate::voucher_canonicalize::compute_voucher_digest_with_address(
                    crate::voucher_canonicalize::ChainIdentity {
                        materios_chain_id: &chain_id,
                        network_magic: T::NetworkMagic::get(),
                        aegis_policy_script_hash: &aegis_script_hash,
                        settlement_version: T::SettlementVersion::get(),
                    },
                    &voucher.claim_id,
                    &voucher.policy_id,
                    &beneficiary_cbor,
                    voucher.amount_ada,
                    &voucher.batch_fairness_proof_digest,
                    voucher.issued_block,
                    voucher.expiry_slot_cardano,
                ),
            )
        }

        /// Task #266 (mis-sec P0): cutover guard for the legacy
        /// `settle_claim` / `settle_batch_atomic` extrinsics. Before the
        /// runtime upgrade lands `StcaCutoverBlock`, both paths coexist so
        /// keepers can roll out gradually. Post-cutover, any legacy call
        /// hard-rejects with `Error::DeprecatedExtrinsic` so old keepers
        /// cannot ride the trust-vacuous path past the audit fix.
        ///
        /// A zero cutover is closed once storage version 1 is present,
        /// including fresh genesis. Older versions retain the migration's
        /// grace window; nonzero cutovers are inclusive.
        pub fn ensure_legacy_settle_path_open() -> DispatchResult {
            let cutover = StcaCutoverBlock::<T>::get();
            if cutover == BlockNumberFor::<T>::default() {
                ensure!(
                    SettlementStorageVersion::<T>::get() < 1,
                    Error::<T>::DeprecatedExtrinsic
                );
                return Ok(());
            }
            let now = <frame_system::Pallet<T>>::block_number();
            // After cutover, hard-reject.
            ensure!(now < cutover, Error::<T>::DeprecatedExtrinsic);
            Ok(())
        }

        /// Task #267 (mis-sec P0): cutover guard for the legacy
        /// `expire_policy_mirror` extrinsic. Mirrors
        /// `ensure_legacy_settle_path_open` exactly — once the spec-N+1
        /// migration schedules `PolicyExpireCutoverBlock`, the legacy
        /// path hard-rejects with `Error::DeprecatedExtrinsic`. Pre-
        /// cutover the legacy path is still open so keepers can roll out
        /// gradually onto the new EXPP request/attest pair.
        pub fn ensure_legacy_expire_path_open() -> DispatchResult {
            let cutover = PolicyExpireCutoverBlock::<T>::get();
            if cutover == BlockNumberFor::<T>::default() {
                ensure!(
                    SettlementStorageVersion::<T>::get() < 2,
                    Error::<T>::DeprecatedExtrinsic
                );
                return Ok(());
            }
            let now = <frame_system::Pallet<T>>::block_number();
            ensure!(now < cutover, Error::<T>::DeprecatedExtrinsic);
            Ok(())
        }

        /// Task #267 (mis-sec P0): resolve the canonical Cardano-side
        /// policy id for an on-chain intent. Used by both
        /// `request_expire_policy` (to cross-check the requester's
        /// witness) and `attest_expire_policy` (to feed the EXPP digest
        /// pre-image from chain state).
        ///
        /// Mapping:
        /// - `BuyPolicy { product_id, .. }` → `product_id`. The
        ///   product_id IS the policy id from the Aegis-side perspective
        ///   (the on-chain Aiken validator mints one Policy NFT per
        ///   product id at BuyPolicy time, so they share a 1:1 binding).
        /// - `RequestPayout { policy_id, .. }` → `policy_id`. The
        ///   payout intent already carries the explicit Cardano policy
        ///   id it's draining against.
        /// - `RefundCredit { .. }` → rejected with
        ///   `IntentNotEligibleForExpiry`. Refund-credit intents have no
        ///   Cardano-side policy and can never be Expire-redeemed.
        pub fn resolve_intent_policy_id(
            intent: &Intent<T::AccountId>,
        ) -> Result<PolicyId, DispatchError> {
            match &intent.kind {
                IntentKind::BuyPolicy { product_id, .. } => Ok(*product_id),
                IntentKind::RequestPayout { policy_id, .. } => Ok(*policy_id),
                IntentKind::RefundCredit { .. } => {
                    Err(Error::<T>::IntentNotEligibleForExpiry.into())
                }
                // Task #259 §8.2: PerpAction intents are perp-engine
                // settlement audit-trail events, not Aegis policies —
                // they have no Cardano-side policy to resolve, so the
                // expire/policy-resolution path is structurally
                // inapplicable. Mirror the RefundCredit branch's
                // semantics.
                IntentKind::PerpAction(_) => {
                    Err(Error::<T>::IntentNotEligibleForExpiry.into())
                }
            }
        }

        /// Issue #7: verify that `signatures` contains at least the effective
        /// `MinSignerThreshold` distinct, valid sr25519 signatures over
        /// `payload`, each produced by a current committee member. The caller
        /// (`who`) itself MUST appear as one of the signers — this binds the
        /// on-chain origin to the multisig bundle so a stale bundle can't be
        /// replayed by a non-signing member.
        pub fn ensure_threshold_signatures(
            payload: &[u8; 32],
            who: &T::AccountId,
            signatures: &[(CommitteePubkey, CommitteeSig)],
        ) -> DispatchResult {
            Self::verify_threshold_signatures::<T::SigVerifier>(payload, who, signatures, &mut 0)
        }

        pub(crate) fn verify_threshold_signatures<V: VerifyCommitteeSignature>(
            payload: &[u8; 32],
            who: &T::AccountId,
            signatures: &[(CommitteePubkey, CommitteeSig)],
            checked: &mut u32,
        ) -> DispatchResult {
            ensure!(
                signatures.len() <= T::MaxCommittee::get() as usize,
                Error::<T>::TooManySignatures
            );
            let effective_threshold = {
                let stored = MinSignerThreshold::<T>::get();
                let base = if stored == 0 {
                    T::DefaultMinSignerThreshold::get()
                } else {
                    stored
                };
                base.max(1)
            };

            // Short-circuit: must have at least `threshold` entries.
            ensure!(
                signatures.len() as u32 >= effective_threshold,
                Error::<T>::InsufficientSignatures
            );

            // Origin-binding: the caller's own pubkey must be one of the signers.
            let caller_pubkey = T::CommitteeMembership::pubkey_of(who);

            let mut seen: alloc::vec::Vec<CommitteePubkey> =
                alloc::vec::Vec::with_capacity(signatures.len());
            ensure!(
                signatures.iter().any(|(key, _)| key == &caller_pubkey),
                Error::<T>::InsufficientSignatures
            );
            // Every entry passes the duplicate and membership checks before
            // any signature is verified. `checked` counts scanned entries and
            // each is charged a full signature, which covers its scan and its
            // verification whichever check fails.
            for (pubkey, _) in signatures.iter() {
                *checked = checked.saturating_add(1);
                ensure!(!seen.contains(pubkey), Error::<T>::DuplicateSigner);
                let account = T::CommitteeMembership::account_of_pubkey(pubkey)
                    .ok_or(Error::<T>::SignerNotCommitteeMember)?;
                ensure!(
                    T::CommitteeMembership::is_member(&account),
                    Error::<T>::SignerNotCommitteeMember
                );
                seen.push(*pubkey);
            }
            for (pubkey, sig) in signatures.iter() {
                ensure!(V::verify(pubkey, sig, payload), Error::<T>::InvalidSignature);
            }
            Ok(())
        }

        fn with_signature_weight(
            base: Weight,
            dispatch: impl FnOnce(&mut u32) -> DispatchResult,
        ) -> DispatchResultWithPostInfo {
            use frame_support::dispatch::WithPostDispatchInfo;
            let mut checked = 0;
            let result = dispatch(&mut checked);
            let actual = base.saturating_add(T::WeightInfo::threshold_signatures(checked));
            result
                .map(|()| Some(actual).into())
                .map_err(|error| error.with_weight(actual))
        }

        #[cfg(feature = "try-runtime")]
        fn settlement_storage_digest() -> [u8; 32] {
            use frame_support::traits::PalletInfoAccess;
            let prefix = Self::name_hash();
            let mut digest = [0u8; 32];
            let mut key = prefix.to_vec();
            while let Some(next) =
                sp_io::storage::next_key(&key).filter(|next| next.starts_with(&prefix))
            {
                let value = sp_io::storage::get(&next).map(|value| value.to_vec());
                digest = sp_io::hashing::blake2_256(&(digest, &next, value).encode());
                key = next;
            }
            digest
        }

        fn request_expired(submitted: BlockNumberFor<T>) -> bool {
            let now: u64 = frame_system::Pallet::<T>::block_number().into();
            let submitted: u64 = submitted.into();
            let ttl: u64 = T::SettlementRequestTtl::get().into();
            now.saturating_sub(submitted) > ttl
        }

        fn remove_expired_settlement_request(claim_id: ClaimId) -> DispatchResult {
            if let Some(request) = ClaimSettlementRequests::<T>::get(claim_id) {
                ensure!(
                    Self::request_expired(request.submitted_block),
                    Error::<T>::SettlementRequestAlreadyExists
                );
                Self::discard_settlement_request(claim_id, request)?;
            }
            Ok(())
        }

        /// Removes an unattested request and refunds its bond.
        fn discard_settlement_request(
            claim_id: ClaimId,
            request: SettlementRequestRecord<T::AccountId, BlockNumberFor<T>>,
        ) -> DispatchResult {
            if request.bond_amount > 0 {
                Self::refund_settlement_bond(claim_id, request.requester, request.bond_amount)?;
            }
            ClaimSettlementRequests::<T>::remove(claim_id);
            Ok(())
        }

        /// Checks evidence for a claim the way every request and supersede
        /// does, returning the claim and its voucher.
        fn checked_settlement_target(
            claim_id: ClaimId,
            evidence: &SettlementEvidence,
        ) -> Result<(Claim, Voucher), DispatchError> {
            ensure!(
                evidence.mainchain_genesis_hash == T::MainchainGenesisHash::get(),
                Error::<T>::WrongMainchainGenesis
            );
            ensure!(
                evidence.observed_at_depth >= T::MinFinalityDepth::get(),
                Error::<T>::FinalityDepthBelowMinimum
            );
            ensure!(
                evidence.observed_at_depth <= MAX_OBSERVED_DEPTH,
                Error::<T>::FinalityDepthAboveMaximum
            );
            let claim = Claims::<T>::get(claim_id).ok_or(Error::<T>::ClaimNotFound)?;
            ensure!(!claim.settled, Error::<T>::AlreadySettled);
            let voucher = Vouchers::<T>::get(claim_id).ok_or(Error::<T>::VoucherMissing)?;
            ensure!(
                evidence.amount_lovelace == voucher.amount_ada,
                Error::<T>::SettlementEvidenceMismatch
            );
            let (payment_hash, _stake_hash) =
                crate::voucher_canonicalize::split_type0_address_bytes(
                    voucher.beneficiary_cardano_addr.as_slice(),
                )
                .map_err(|_| Error::<T>::InvalidBeneficiaryAddress)?;
            ensure!(
                evidence.beneficiary_addr_hash == payment_hash,
                Error::<T>::SettlementEvidenceMismatch
            );
            Ok((claim, voucher))
        }

        /// Marks an attested claim settled, retires its intent and releases
        /// its pool coverage.
        fn settle_attested_claim(
            claim_id: ClaimId,
            mut claim: Claim,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
        ) {
            claim.settled = true;
            claim.settled_direct = settled_direct;
            claim.cardano_tx_hash = cardano_tx_hash;
            let intent_id = claim.intent_id;
            let amount = claim.amount_ada;
            Claims::<T>::insert(claim_id, claim);
            if let Some(mut intent) = Intents::<T>::get(intent_id) {
                intent.status = IntentStatus::Settled;
                Intents::<T>::insert(intent_id, intent);
            }
            Self::remove_from_pending_batches(intent_id);
            PoolUtilization::<T>::mutate(|u| {
                u.outstanding_coverage_ada = u.outstanding_coverage_ada.saturating_sub(amount);
                u.total_nav_ada = u.total_nav_ada.saturating_sub(amount);
            });
            Self::deposit_event(Event::ClaimSettled {
                claim_id,
                cardano_tx_hash,
                settled_direct,
            });
        }

        /// Replaces an expired request, refuses a request instance that was
        /// already slashed, and reserves the new request's bond.
        fn store_settlement_request(
            claim_id: ClaimId,
            record: SettlementRequestRecord<T::AccountId, BlockNumberFor<T>>,
        ) -> DispatchResult {
            Self::remove_expired_settlement_request(claim_id)?;
            ensure!(
                !SlashedSettlementRequests::<T>::contains_key(
                    claim_id,
                    settlement_request_id(&record)
                ),
                Error::<T>::BondSlashedNoRelease
            );
            Self::reserve_settlement_bond(claim_id, &record.requester, record.bond_amount)?;
            ClaimSettlementRequests::<T>::insert(claim_id, record);
            Ok(())
        }

        fn reserve_settlement_bond(
            claim_id: ClaimId,
            requester: &T::AccountId,
            amount: u128,
        ) -> DispatchResult {
            ensure!(
                amount > 0 && amount >= T::MinSettlementBond::get(),
                Error::<T>::BondBelowMinimum
            );
            let balance: BalanceOf<T> = amount
                .try_into()
                .map_err(|_| Error::<T>::BondAmountConversionOverflow)?;
            T::Currency::reserve_named(&SETTLEMENT_BOND_RESERVE_ID, requester, balance)?;
            Self::deposit_event(Event::SettlementBondPosted {
                claim_id,
                requester: requester.clone(),
                amount,
            });
            Ok(())
        }

        fn refund_settlement_bond(
            claim_id: ClaimId,
            requester: T::AccountId,
            bond_amount: u128,
        ) -> DispatchResult {
            let balance: BalanceOf<T> = bond_amount
                .try_into()
                .map_err(|_| Error::<T>::BondAmountConversionOverflow)?;
            let missing_amount: u128 =
                T::Currency::unreserve_named(&SETTLEMENT_BOND_RESERVE_ID, &requester, balance)
                    .saturated_into();
            if missing_amount > 0 {
                Self::deposit_event(Event::SettlementBondReserveDeficit {
                    claim_id,
                    requester: requester.clone(),
                    missing_amount,
                });
            }
            BondedClaimAttestedAt::<T>::remove(claim_id);
            BondedClaimRequester::<T>::remove(claim_id);
            Self::deposit_event(Event::SettlementBondReleased {
                claim_id,
                requester,
                amount: bond_amount.saturating_sub(missing_amount),
            });
            Ok(())
        }

        /// Runtime-API: full voucher for a claim id.
        pub fn get_voucher(claim_id: ClaimId) -> Option<Voucher> {
            Vouchers::<T>::get(claim_id)
        }

        /// Test helper: number of pending intents (any status). Not in public API.
        #[cfg(test)]
        pub fn intent_count() -> u32 {
            Intents::<T>::iter().count() as u32
        }
    }
}

// Re-export for downstream / Aiken-parity SDK.
pub use crate::types::{
    compute_committee_set_digest, compute_fairness_proof_digest, compute_intent_id,
    domain_hash, RequestVoucherEntry, SettleBatchEntry, SubmitIntentEntry,
};
// #79: the SCALE-form voucher digest is gone. The canonical helper is now
// `voucher_canonicalize::compute_voucher_digest_with_address` which binds the
// chain-identity fields (#73) and the Aiken-mirrored Plutus V3 Data CBOR.
pub use crate::voucher_canonicalize::{
    compute_voucher_digest_with_address, ChainIdentity,
};
