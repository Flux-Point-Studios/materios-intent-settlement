//! Shared type definitions for `pallet-oracle` (MON Phase 1, task #268).
//!
//! The canonical hash preimage in [`submit_price_payload`] is authoritative
//! per the design memo at `/home/deci/work/mon-phase1-aegis-extend-design.md`
//! §1. Aegis publishers and downstream verifiers must reproduce these exact
//! bytes (domain tag + chain_id + pair_id + price + decimals + slot) and the
//! exact `blake2_256` over them.

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, BoundedVec};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

pub use parity_scale_codec as codec;

// ---------------------------------------------------------------------------
// Primitive aliases
// ---------------------------------------------------------------------------

/// 32-byte canonical pair identifier — `sha256(pair_string_utf8)`.
///
/// Examples:
/// - `sha256("ADA/USD") = 0x50cd6650c96bf3c016e7ce6acd4659cb6fc648e091813433f17ed75842833993`
/// - `sha256("BTC/USD")`
/// - `sha256("ETH/USD")`
///
/// Pair strings are fixed forever per pair. A pair-string change requires a
/// fresh `pair_id` and is treated as a different feed by every consumer —
/// this is intentional and prevents silent re-meaning of a deployed pair.
pub type PairId = [u8; 32];

/// 32-byte sr25519 attestor pubkey (raw bytes, not SS58).
pub type AttestorPubkey = [u8; 32];

/// 64-byte sr25519 signature over the canonical PRIC payload digest.
pub type AttestorSig = [u8; 64];

/// Materios slot number observed by the attestor at the time of the price
/// reading. Used both for replay defence (PRIC preimage binds the slot) and
/// freshness (`PriceFeed.last_update_slot`).
pub type SlotNumber = u64;

// ---------------------------------------------------------------------------
// Bounded constants
// ---------------------------------------------------------------------------

/// Upper bound on attestors registered per pair. Phase 1 ships with 1-5
/// attestors per pair (the 5 Aegis publishers); the bound is sized for the
/// `project_validator_growth_plan.md` 16-validator backbone.
pub const MAX_ATTESTORS_PER_PAIR: u32 = 16;

/// Upper bound on the `PendingAttestations[(pair_id, slot)]` bundle. Same
/// as `MAX_ATTESTORS_PER_PAIR` — one slot can never have more attestor
/// submissions than there are registered attestors.
pub const MAX_PENDING_PER_SLOT: u32 = 16;

// ---------------------------------------------------------------------------
// Domain tag (the cross-team parity anchor)
// ---------------------------------------------------------------------------

/// Domain tag for the canonical PRIC payload signed by Aegis publishers and
/// any future MON attestor. Verified absent from the eleven intent-settlement
/// tags (CRDP / STCL / RVCH / STBA / ABIN / RVBN / SBIN / STCA / BSTA / EXPP
/// / INTA) and the two domain-internal digest tags (CMTT / BFPR / VCHR), so a
/// PRIC sig cannot replay onto any other pallet preimage.
pub const TAG_PRIC: &[u8; 4] = b"PRIC";

// ---------------------------------------------------------------------------
// PriceFeed — the canonical aggregated per-pair record
// ---------------------------------------------------------------------------

/// Aggregation method recorded alongside a `PriceFeed`. v1 ships `Median`
/// only (or single-value passthrough when `MinAttestorThreshold == 1`); v2
/// adds `TrimmedMedian2020` per `materios-oracle-design.md §4`.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub enum AggregationMethod {
    /// Plain median (or the single submitter's value when M=1).
    Median = 0,
    /// 20/20 trimmed median — v2.
    TrimmedMedian2020 = 1,
}

/// Final per-pair aggregated price record. Updated atomically when
/// `submit_price` crosses `MinAttestorThreshold` for a `(pair_id,
/// slot_observed)` bundle.
#[derive(
    Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub struct PriceFeed<BlockNumber> {
    /// Aggregated price as a raw `u64` integer. Real value =
    /// `price / 10^decimals`.
    pub last_price: u64,
    /// Decimal places. Real value = `last_price / 10^last_decimals`. Bounded
    /// 0..=18.
    pub last_decimals: u8,
    /// Materios slot reported by the attestors (NOT the block in which the
    /// extrinsic landed). Monotone: `submit_price` rejects an aggregation
    /// whose `slot_observed <= last_update_slot`.
    pub last_update_slot: SlotNumber,
    /// Materios block number when this `PriceFeed` row was last written.
    /// Used for storage-rent / GC accounting in v2.
    pub last_update_block: BlockNumber,
    /// Aggregation method used to produce `last_price`. Bound by
    /// `Config::MaxAttestors`.
    pub aggregation: AggregationMethod,
    /// Pubkeys that contributed to this aggregation. Bound by
    /// `Config::MaxAttestors`. Recorded so downstream consumers
    /// (perp-engine #259, mm-rebate #257) can attribute attestor sets per
    /// price update — useful for both audit and v2 slashing forensics.
    pub attestor_set: BoundedVec<AttestorPubkey, ConstU32<MAX_ATTESTORS_PER_PAIR>>,
}

// ---------------------------------------------------------------------------
// PriceObservation — one attestor's submission, pending aggregation
// ---------------------------------------------------------------------------

/// A single attestor's price observation, buffered in
/// `PendingAttestations[(pair_id, slot_observed)]` until the bundle crosses
/// threshold. The pallet does not store the original `decimals` here because
/// every observation for the same `(pair_id, slot_observed)` is required to
/// share the same `decimals` value — `submit_price` rejects a submission
/// whose `decimals` differs from the first one in the bundle (so the
/// aggregator doesn't have to renormalise mid-aggregation).
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub struct PriceObservation {
    pub pubkey: AttestorPubkey,
    pub price: u64,
    pub sig: AttestorSig,
}

// ---------------------------------------------------------------------------
// Canonical PRIC payload — the cross-team parity anchor
// ---------------------------------------------------------------------------

/// Canonical preimage digest signed by an attestor for `submit_price`.
///
/// Preimage byte layout:
///
/// ```text
/// digest = blake2_256(
///     b"PRIC"                  // 4-byte domain tag
///     || chain_id      (32B)   // Materios chain identity (preprod vs mainnet)
///     || pair_id       (32B)   // sha256(canonical pair string utf8)
///     || price         (LE u64)
///     || decimals      (1B)    // 0..=18
///     || slot_observed (LE u64)
/// )
/// ```
///
/// Each input pins a replay-vector:
/// - `b"PRIC"` separates from every intent-settlement pallet tag (CRDP/STCL/
///   RVCH/STBA/ABIN/RVBN/SBIN/STCA/BSTA/EXPP/INTA) plus the three intent-
///   settlement internal digest tags (CMTT/BFPR/VCHR). Pallet-oracle owns
///   this tag exclusively.
/// - `chain_id` blocks cross-chain replay (preprod sig on mainnet runtime).
/// - `pair_id` blocks cross-pair replay (ADA/USD sig accepted as BTC/USD).
/// - `price` is the value being signed; tamper-evident.
/// - `decimals` blocks cross-decimals replay (6-dec sig replays at 18-dec
///   feed).
/// - `slot_observed` blocks cross-slot replay (yesterday's sig replays
///   today) and serves as the monotone gate on PriceFeed updates.
///
/// Per `feedback_mofn_hash_determinism.md`: only chain-derived state appears
/// in the preimage. No operator-local fields (wall clock, observation
/// timestamp). Time-of-observation maps to `slot_observed`, which every
/// honest attestor observes the same way.
pub fn submit_price_payload(
    chain_id: &[u8; 32],
    pair_id: &PairId,
    price: u64,
    decimals: u8,
    slot_observed: SlotNumber,
) -> [u8; 32] {
    // Capacity: 4 (tag) + 32 (chain_id) + 32 (pair_id) + 8 (price) + 1
    // (decimals) + 8 (slot) = 85 bytes.
    let mut body = sp_std::vec::Vec::with_capacity(4 + 32 + 32 + 8 + 1 + 8);
    body.extend_from_slice(TAG_PRIC);
    body.extend_from_slice(chain_id);
    body.extend_from_slice(pair_id);
    body.extend_from_slice(&price.to_le_bytes());
    body.push(decimals);
    body.extend_from_slice(&slot_observed.to_le_bytes());
    sp_core::hashing::blake2_256(&body)
}

/// Helper: produce the canonical `PairId` for a pair string. Aegis publishers
/// (Python) and downstream Aiken validators reproduce this with their own
/// `sha256` implementations; this fn exists for Rust-side test fixtures and
/// runtime-API consumers that hold the raw pair string.
///
/// Examples:
/// - `pair_id_for_string("ADA/USD")` →
///   `0x50cd6650c96bf3c016e7ce6acd4659cb6fc648e091813433f17ed75842833993`
pub fn pair_id_for_string(pair: &[u8]) -> PairId {
    sp_io::hashing::sha2_256(pair)
}
