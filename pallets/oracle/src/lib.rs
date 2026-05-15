//! # `pallet-oracle` — Materios Oracle Network (MON) Phase 1 scaffolding
//!
//! Task #268. Design memo:
//! `/home/deci/work/mon-phase1-aegis-extend-design.md`.
//!
//! ## Scope of this skeleton
//!
//! What ships as **real impl** (this PR):
//! - The canonical PRIC payload helper [`types::submit_price_payload`] —
//!   byte-exact, cross-team parity anchor for Aegis publishers (Python),
//!   downstream Aiken validators (PlutusV3 byte slices), and substrate
//!   verifiers.
//! - The `PairId` / `PriceObservation` / `PriceFeed` / `AggregationMethod`
//!   type surface in [`types`].
//! - The pallet's `Config` / `Event` / `Error` / `Storage` shape so the
//!   compiler enforces it for the impl PR that follows.
//! - 5 unit tests in [`tests`] covering payload byte-exactness, the
//!   pair-id sha256 fixture, threshold storage layout, stale-slot
//!   rejection, and duplicate-pubkey rejection.
//!
//! What ships as **stub** (placeholders for impl in a later PR):
//! - `submit_price` — validates the public surface (signer is committee
//!   member, `signatures.len() >= MinAttestorThreshold` once impl lands)
//!   but currently returns `Ok(())` without state mutation. Threshold-
//!   crossing logic, sig verification, monotonicity gate, aggregation,
//!   and event emission all land in the impl PR.
//! - `register_attestor` — sudo-only stub, returns `Ok(())`. Impl PR adds
//!   `Attestors[pair_id]` insertion + idempotency.
//!
//! ## Pattern alignment
//!
//! Mirrors `pallet-intent-settlement`'s domain-tagged-preimage pattern
//! (chain_id-prefixed, blake2_256, plain byte stream not SCALE) so a future
//! shared `ensure_threshold_signatures` helper can be lifted cleanly across
//! both pallets without duplicating the sig-verify contract.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use types::{
    pair_id_for_string, submit_price_payload, AggregationMethod, AttestorPubkey,
    AttestorSig, PairId, PriceFeed, PriceObservation, SlotNumber, MAX_ATTESTORS_PER_PAIR,
    MAX_PENDING_PER_SLOT, TAG_PRIC,
};

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{pallet_prelude::*, BoundedVec};
    use frame_system::pallet_prelude::*;

    // ---------------------------------------------------------------------
    // Config
    // ---------------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// 32-byte Materios chain identity (genesis hash). Pinned into every
        /// PRIC preimage so a sig signed on preprod is structurally invalid
        /// on mainnet/testnet/post-reset. Mirrors the chain-id binding
        /// landed in pallet-intent-settlement via #73.
        #[pallet::constant]
        type MateriosChainId: Get<[u8; 32]>;

        /// Minimum attestor count required to aggregate a `PriceFeed` update.
        /// v1 default is 1 (single Aegis publisher per pair). Sudo bumps via
        /// `set_min_attestor_threshold` (impl PR) once Witness Network /
        /// Node-3 / Hetzner attestor pool grows.
        #[pallet::constant]
        type MinAttestorThreshold: Get<u32>;

        /// Maximum number of attestors registerable per pair. Canonical
        /// default 16 (`types::MAX_ATTESTORS_PER_PAIR`).
        #[pallet::constant]
        type MaxAttestors: Get<u32>;

        /// Maximum age in slots for a `submit_price` submission. Submissions
        /// reporting `slot_observed < current_chain_slot - MaxStaleSlots`
        /// are rejected with `Error::StaleSubmission`. Default 1200 (~2h at
        /// 6s slot target).
        #[pallet::constant]
        type MaxStaleSlots: Get<u64>;

        /// Maximum future-slot drift accepted. Submissions reporting
        /// `slot_observed > current_chain_slot + MaxFutureSlots` are
        /// rejected to block trivial front-running. Default 50 slots.
        #[pallet::constant]
        type MaxFutureSlots: Get<u64>;

        /// Predicate trait for "is this account a registered MON attestor".
        /// In v1 production this is wired to a per-pair `Attestors` storage
        /// lookup; in tests we substitute a `MockAttestorRegistry`.
        type AttestorRegistry: IsAttestorFor<Self::AccountId>;
    }

    /// Per-pair attestor membership predicate. Mirrors the
    /// `IsCommitteeMember` trait from `pallet-intent-settlement::pallet` —
    /// kept as a separate trait here to keep the two pallets independently
    /// composable in test runtimes (a runtime can wire one mock for each).
    pub trait IsAttestorFor<AccountId> {
        fn is_attestor(pair_id: &PairId, who: &AccountId) -> bool;
        fn pubkey_of(who: &AccountId) -> AttestorPubkey;
        fn threshold_for(pair_id: &PairId) -> u32;
    }

    // ---------------------------------------------------------------------
    // Pallet declaration
    // ---------------------------------------------------------------------

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    /// One canonical aggregated price per pair. Written when a
    /// `submit_price` call crosses `MinAttestorThreshold`. Downstream
    /// pallets (perp-engine #259, mm-rebate #257) read via
    /// `Pallet::<T>::get_price(pair_id)`.
    #[pallet::storage]
    pub type Prices<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        PairId,
        PriceFeed<BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Per-pair attestor pubkey roster. Sudo-managed in v1 via
    /// `register_attestor` (impl PR adds insertion). Lex-sorted for
    /// deterministic round-robin aggregation in v2 (per
    /// `materios-oracle-design.md §5`).
    #[pallet::storage]
    pub type Attestors<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        PairId,
        BoundedVec<AttestorPubkey, <T as Config>::MaxAttestors>,
        ValueQuery,
    >;

    /// `(pair_id, slot_observed) -> bundle of attestor observations`. Cleared
    /// on threshold-cross by the call that flips `Prices[pair_id]`. Stale
    /// rows are GC'd in `on_initialize` (impl PR) when their
    /// `slot_observed` is older than `MaxStaleSlots`.
    #[pallet::storage]
    pub type PendingAttestations<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        PairId,
        Blake2_128Concat,
        SlotNumber,
        BoundedVec<PriceObservation, <T as Config>::MaxAttestors>,
        ValueQuery,
    >;

    /// Idempotency: blocks a single attestor from submitting twice for the
    /// same `(pair_id, slot_observed)`. Key = `(pair_id, slot_observed,
    /// attestor_pubkey)`. Cleared alongside `PendingAttestations` on
    /// threshold-cross.
    #[pallet::storage]
    pub type AttestorSubmitted<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (PairId, SlotNumber, AttestorPubkey),
        (),
        OptionQuery,
    >;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    // The event enum is defined here so the storage/runtime layout is
    // pinned for the impl PR; the `generate_deposit` helper is omitted
    // until impl PR (re-add `#[pallet::generate_deposit(pub(super) fn
    // deposit_event)]` once `submit_price` / `register_attestor` emit
    // events). Skipping it keeps the v1 stub build warning-free.
    #[pallet::event]
    pub enum Event<T: Config> {
        /// Aggregated `PriceFeed` was written. Emitted once per pair per
        /// threshold-crossing slot. `attestor_count` is the number of
        /// observations that contributed to the aggregation.
        PriceUpdated {
            pair_id: PairId,
            price: u64,
            decimals: u8,
            observed_at_slot: SlotNumber,
            attestor_count: u32,
            aggregation: AggregationMethod,
        },
        /// A single attestor's observation was accepted into the pending
        /// bundle for `(pair_id, slot_observed)`. `pending_count` reflects
        /// the post-insert bundle size; once it reaches
        /// `MinAttestorThreshold` the next `submit_price` (or this one)
        /// will trigger a `PriceUpdated`.
        PriceAttestationSubmitted {
            pair_id: PairId,
            slot_observed: SlotNumber,
            attestor: AttestorPubkey,
            pending_count: u32,
        },
        /// Sudo registered a new attestor for a pair. v2 will replace this
        /// with a bonded permissionless registration call.
        AttestorRegistered {
            pair_id: PairId,
            pubkey: AttestorPubkey,
        },
    }

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// The pending bundle has fewer than `MinAttestorThreshold`
        /// observations. Surfaced when `submit_price` impl evaluates the
        /// threshold gate; for v1 stub this is a marker that the runtime
        /// must wire `MinAttestorThreshold`.
        BelowThreshold,
        /// The reported `slot_observed` is older than
        /// `current_chain_slot - MaxStaleSlots`, or older than the most
        /// recent `Prices[pair_id].last_update_slot` (the monotonicity
        /// gate). Either way the submission is rejected.
        StaleSubmission,
        /// The reported `slot_observed` is more than `MaxFutureSlots`
        /// ahead of the current chain slot. Blocks trivial front-running.
        FutureSubmission,
        /// `sr25519_verify(sig, payload, pubkey) == false` for one of the
        /// signatures in the call. The impl PR wires the verifier via
        /// `sp_io::crypto::sr25519_verify`. v1 stub carries the error so
        /// downstream consumers can pattern-match early.
        InvalidSignature,
        /// `pubkey` is not a registered attestor for `pair_id`. Phase 1
        /// resolution is sudo `register_attestor`; Phase 2 = bonded
        /// permissionless.
        NotAttestor,
        /// Caller submitted the same `pubkey` twice in one call (defends
        /// against the "1-of-2 by replaying my own sig" attack).
        DuplicatePubkey,
        /// `pair_id` is not registered (no `Attestors[pair_id]` entry).
        /// Emitted by `submit_price` when the pair was never `register_attestor`'d.
        UnknownPair,
        /// `decimals > 18`. Per design memo §1, the canonical decimals
        /// range is 0..=18 (matches `sp-arithmetic::FixedU128`'s
        /// resolution). Caller must scale before submission.
        DecimalsOutOfRange,
        /// One observation in a `(pair_id, slot)` bundle reports a
        /// `decimals` value different from the first observation in the
        /// same bundle. Renormalising mid-aggregation is forbidden in v1.
        DecimalsBundleMismatch,
        /// `PendingAttestations[(pair_id, slot)]` is already at
        /// `MaxAttestors` capacity. Should not happen in steady state; if
        /// it does, the attestor pool size + threshold are mis-tuned.
        BundleFull,
        /// `register_attestor` called with a pubkey already registered for
        /// this pair. Idempotency requires this to be a hard reject so
        /// duplicate-registration attempts surface as failed extrinsics.
        AttestorAlreadyRegistered,
        /// `register_attestor` called when `Attestors[pair_id]` is already
        /// at `MaxAttestors` capacity.
        AttestorRegistryFull,
    }

    // ---------------------------------------------------------------------
    // Calls
    // ---------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Phase 1 stub. Future impl will:
        ///
        /// 1. Validate `decimals <= 18`.
        /// 2. Validate `pubkey ∈ Attestors[pair_id]` via
        ///    `T::AttestorRegistry::is_attestor`.
        /// 3. Build the canonical PRIC payload via
        ///    [`types::submit_price_payload`] and verify the sig with
        ///    `sp_io::crypto::sr25519_verify`.
        /// 4. Reject if `AttestorSubmitted[(pair_id, slot_observed,
        ///    pubkey)]` is already set (duplicate).
        /// 5. Reject if `slot_observed < current_slot - MaxStaleSlots` or
        ///    `slot_observed > current_slot + MaxFutureSlots`.
        /// 6. Reject if `Prices[pair_id]` exists with `last_update_slot >=
        ///    slot_observed` (monotonicity).
        /// 7. Push `(pubkey, price, sig)` into `PendingAttestations[(pair_id,
        ///    slot_observed)]` and set `AttestorSubmitted[…]`.
        /// 8. If bundle reached `MinAttestorThreshold`, compute median (v1)
        ///    or trimmed median (v2), write `Prices[pair_id]`, clear
        ///    `PendingAttestations[(pair_id, slot_observed)]` and
        ///    `AttestorSubmitted[…]` rows for this slot, emit
        ///    `PriceUpdated`. Otherwise emit `PriceAttestationSubmitted`.
        ///
        /// **Current behaviour:** signature parameters are accepted, no
        /// state mutation, returns `Ok(())`. Build target: skeleton
        /// compiles, runtime can wire it as a noop pallet, impl PR fills
        /// the body atomically.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn submit_price(
            origin: OriginFor<T>,
            _pair_id: PairId,
            _price: u64,
            _decimals: u8,
            _slot_observed: SlotNumber,
            _pubkey: AttestorPubkey,
            _sig: AttestorSig,
        ) -> DispatchResult {
            // v1 surface: caller is a signed origin (attestor's substrate
            // account, distinct from `pubkey` which is the sr25519 raw
            // key — these MUST agree under `T::AttestorRegistry::pubkey_of`,
            // checked in the impl PR).
            let _who = ensure_signed(origin)?;
            // Impl PR replaces this stub. See doc above for the contract
            // the impl must satisfy.
            Ok(())
        }

        /// Phase 1 stub. Sudo-only in v1 — Phase 2 swaps for bonded
        /// permissionless. Future impl will:
        ///
        /// 1. `ensure_root(origin)`.
        /// 2. Reject `Attestors[pair_id].contains(&pubkey)` →
        ///    `Error::AttestorAlreadyRegistered`.
        /// 3. Push `pubkey` into `Attestors[pair_id]`; bail if full →
        ///    `Error::AttestorRegistryFull`.
        /// 4. Emit `AttestorRegistered`.
        ///
        /// **Current behaviour:** accepts a root origin, no state mutation,
        /// returns `Ok(())`. Impl PR fills the body.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn register_attestor(
            origin: OriginFor<T>,
            _pair_id: PairId,
            _pubkey: AttestorPubkey,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Ok(())
        }
    }

    // ---------------------------------------------------------------------
    // Runtime-API surface (consumed by perp-engine #259, mm-rebate #257)
    // ---------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        /// Read API for downstream pallets and off-chain RPC. Returns
        /// `(price, decimals, last_update_slot)` or `None` if the pair has
        /// no aggregated `PriceFeed` yet.
        pub fn get_price(pair_id: PairId) -> Option<(u64, u8, SlotNumber)> {
            Prices::<T>::get(pair_id)
                .map(|f| (f.last_price, f.last_decimals, f.last_update_slot))
        }

        /// Read API: returns true iff the latest aggregated update for
        /// `pair_id` is no older than `max_age_slots` relative to
        /// `current_slot`. Downstream consumers MUST gate every read on
        /// this — a stale `PriceFeed` is the largest single source of
        /// settlement risk in v1 (no Materios-rail uptime SLA yet).
        pub fn is_price_fresh(
            pair_id: PairId,
            current_slot: SlotNumber,
            max_age_slots: u64,
        ) -> bool {
            match Prices::<T>::get(pair_id) {
                Some(f) => {
                    current_slot.saturating_sub(f.last_update_slot) <= max_age_slots
                }
                None => false,
            }
        }
    }
}
