//! # `pallet-oracle` — Materios Oracle Network (MON) Phase 1
//!
//! Task #268. Design memo:
//! `/home/deci/work/mon-phase1-aegis-extend-design.md`.
//!
//! ## What ships in this impl PR
//!
//! - **`submit_price`** — per-attestor price submission. Validates:
//!   1. caller's substrate account → pubkey binding via
//!      `T::AttestorRegistry::pubkey_of`,
//!   2. pubkey ∈ `Attestors[pair_id]`,
//!   3. `decimals <= 18`,
//!   4. sr25519 sig over the canonical PRIC preimage
//!      (`types::submit_price_payload`) via `sp_io::crypto::sr25519_verify`,
//!   5. idempotency: `AttestorSubmitted[(pair, slot, pubkey)]` not set,
//!   6. freshness: `slot_observed >= current_slot - MaxStaleSlots`,
//!   7. anti-front-run: `slot_observed <= current_slot + MaxFutureSlots`,
//!   8. monotonicity: `slot_observed > Prices[pair_id].last_update_slot`,
//!   9. decimals coherence in the pending bundle.
//!
//!   On accept: push `(pubkey, price, sig)` into
//!   `PendingAttestations[(pair_id, slot)]`. If `len() >=
//!   MinAttestorThreshold` for this slot, compute plain median (v1),
//!   write `Prices[pair_id]`, clear the pending bundle + per-attestor
//!   idempotency rows, emit `PriceUpdated`. Otherwise emit
//!   `PriceAttestationSubmitted`.
//!
//! - **`register_attestor`** — sudo-only. Appends `pubkey` to
//!   `Attestors[pair_id]`. Rejects duplicates with
//!   `AttestorAlreadyRegistered` and a full roster with
//!   `AttestorRegistryFull`. Emits `AttestorRegistered`.
//!
//! ## Pattern alignment
//!
//! Mirrors `pallet-intent-settlement`'s domain-tagged-preimage pattern
//! (chain_id-prefixed, blake2_256, plain byte stream not SCALE) so a future
//! shared `ensure_threshold_signatures` helper can be lifted cleanly across
//! both pallets without duplicating the sig-verify contract.
//!
//! ## Aggregation policy
//!
//! v1 ships **plain median** per design memo §3 (or single-value
//! passthrough at M=1). Trimmed median is explicitly v2 and requires
//! M ≥ 5 to be useful — out-of-scope for Phase 1 where the Aegis fleet
//! ships at M=1 → M=3.

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

    /// Decimals witness pinned on the first observation of a
    /// `(pair_id, slot)` bundle. Subsequent observations for the same slot
    /// must match this value or the call fails with
    /// `Error::DecimalsBundleMismatch`. Cleared alongside
    /// `PendingAttestations` on threshold-cross.
    ///
    /// Stored separately (not embedded in `PriceObservation`) so that the
    /// existing on-disk shape of `PriceObservation { pubkey, price, sig }`
    /// in the scaffold's `types.rs` is preserved byte-for-byte — the
    /// design memo §1 storage table doesn't include decimals in the
    /// observation. The witness map is the minimal extension to enforce
    /// the cross-attestor decimals coherence rule the design memo
    /// requires.
    #[pallet::storage]
    pub type BundleDecimals<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (PairId, SlotNumber),
        u8,
        OptionQuery,
    >;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
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
        /// The signed origin's substrate account does not bind (via
        /// `T::AttestorRegistry::pubkey_of`) to the `pubkey` argument in
        /// `submit_price`. Defends against an attestor's substrate account
        /// being hijacked to submit prices under a DIFFERENT attestor's
        /// pubkey + sig.
        OriginPubkeyMismatch,
        /// This attestor already submitted for `(pair_id, slot_observed)`.
        /// Equivocation evidence is collected v2; for v1 the duplicate is
        /// simply rejected.
        AlreadySubmitted,
    }

    // ---------------------------------------------------------------------
    // Calls
    // ---------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Per-attestor price submission. See module doc for the full
        /// validation contract.
        ///
        /// Validation order (any failure rolls back without storage writes):
        /// 1. `ensure_signed(origin)` returns the caller's substrate account.
        /// 2. `T::AttestorRegistry::pubkey_of(who) == pubkey` —
        ///    `Error::OriginPubkeyMismatch` otherwise.
        /// 3. `decimals <= 18` — `Error::DecimalsOutOfRange` otherwise.
        /// 4. `Attestors[pair_id].contains(&pubkey)` —
        ///    `Error::NotAttestor` otherwise. `Attestors[pair_id]` empty →
        ///    `Error::UnknownPair`.
        /// 5. `sp_io::crypto::sr25519_verify(sig, PRIC_digest, pubkey)` —
        ///    `Error::InvalidSignature` otherwise.
        /// 6. `AttestorSubmitted[(pair_id, slot_observed, pubkey)]` not set
        ///    — `Error::AlreadySubmitted` otherwise.
        /// 7. Freshness: current_block.saturating_sub(slot_observed) <=
        ///    `MaxStaleSlots` — `Error::StaleSubmission` otherwise. We use
        ///    block-number as the chain-slot proxy until #277 wires
        ///    `pallet-aura` slot lookup.
        /// 8. Anti-front-run: slot_observed.saturating_sub(current_block) <=
        ///    `MaxFutureSlots` — `Error::FutureSubmission` otherwise.
        /// 9. Monotonicity: `slot_observed > Prices[pair_id].last_update_slot`
        ///    — `Error::StaleSubmission` otherwise.
        /// 10. Decimals coherence in the pending bundle: every observation
        ///     for `(pair_id, slot)` must share the same `decimals`.
        ///     `Error::DecimalsBundleMismatch` otherwise. We persist
        ///     `decimals` on the slot's first observation via
        ///     `BundleDecimals[(pair_id, slot)]`.
        ///
        /// On accept: push into `PendingAttestations[(pair_id, slot)]`,
        /// mark `AttestorSubmitted[…]`. If
        /// `PendingAttestations[(pair_id, slot)].len() >=
        /// MinAttestorThreshold`, run aggregation (plain median, v1),
        /// write `Prices[pair_id]`, clear pending rows for this slot,
        /// emit `PriceUpdated`. Otherwise emit
        /// `PriceAttestationSubmitted` with the post-insert bundle size.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn submit_price(
            origin: OriginFor<T>,
            pair_id: PairId,
            price: u64,
            decimals: u8,
            slot_observed: SlotNumber,
            pubkey: AttestorPubkey,
            sig: AttestorSig,
        ) -> DispatchResult {
            // `Saturating` semantics come from u64::saturating_sub /
            // saturating_add inherent methods on the integer types
            // themselves — no trait import needed. Per constraint.
            let who = ensure_signed(origin)?;

            // (1) origin → pubkey binding
            ensure!(
                T::AttestorRegistry::pubkey_of(&who) == pubkey,
                Error::<T>::OriginPubkeyMismatch
            );

            // (2) decimals range
            ensure!(decimals <= 18, Error::<T>::DecimalsOutOfRange);

            // (3) pubkey registered for pair
            let roster = Attestors::<T>::get(pair_id);
            ensure!(!roster.is_empty(), Error::<T>::UnknownPair);
            ensure!(roster.contains(&pubkey), Error::<T>::NotAttestor);

            // (4) sr25519 sig verify over the canonical PRIC payload
            let chain_id = T::MateriosChainId::get();
            let digest = types::submit_price_payload(
                &chain_id, &pair_id, price, decimals, slot_observed,
            );
            let pk = sp_core::sr25519::Public::from_raw(pubkey);
            let sg = sp_core::sr25519::Signature::from_raw(sig);
            ensure!(
                sp_io::crypto::sr25519_verify(&sg, &digest, &pk),
                Error::<T>::InvalidSignature
            );

            // (5) idempotency: per-attestor, per-(pair, slot)
            ensure!(
                !AttestorSubmitted::<T>::contains_key((pair_id, slot_observed, pubkey)),
                Error::<T>::AlreadySubmitted
            );

            // (6+7) freshness + anti-front-run. Use the block number as the
            // chain-slot proxy for v1; #277 plumbs real `pallet-aura` slot.
            // `BlockNumberFor<T>` is some integer-shaped type; cast via
            // `saturated_into<u64>()`.
            let current_block: SlotNumber = {
                use frame_support::sp_runtime::traits::SaturatedConversion;
                let n: BlockNumberFor<T> = frame_system::Pallet::<T>::block_number();
                n.saturated_into::<u64>()
            };
            ensure!(
                current_block.saturating_sub(slot_observed) <= T::MaxStaleSlots::get(),
                Error::<T>::StaleSubmission
            );
            ensure!(
                slot_observed.saturating_sub(current_block) <= T::MaxFutureSlots::get(),
                Error::<T>::FutureSubmission
            );

            // (8) monotonicity vs last aggregated update
            if let Some(feed) = Prices::<T>::get(pair_id) {
                ensure!(
                    slot_observed > feed.last_update_slot,
                    Error::<T>::StaleSubmission
                );
            }

            // (9) decimals coherence in the slot's bundle. If a witness is
            // recorded (i.e. at least one prior observation landed), the
            // new submission must match. The witness is set on first
            // observation and cleared on threshold-cross, so it's the
            // single source of truth.
            let bundle_was_empty =
                BundleDecimals::<T>::get((pair_id, slot_observed)).is_none();
            if let Some(recorded) = BundleDecimals::<T>::get((pair_id, slot_observed)) {
                ensure!(decimals == recorded, Error::<T>::DecimalsBundleMismatch);
            }

            // -----------------------------------------------------------------
            // All validation passed — mutate state.
            // -----------------------------------------------------------------

            // Push the observation. `try_mutate` so the BoundedVec push
            // returns Err if at `MaxAttestors` capacity.
            PendingAttestations::<T>::try_mutate(
                pair_id,
                slot_observed,
                |bundle| -> DispatchResult {
                    bundle
                        .try_push(PriceObservation { pubkey, price, sig })
                        .map_err(|_| Error::<T>::BundleFull)?;
                    Ok(())
                },
            )?;

            AttestorSubmitted::<T>::insert((pair_id, slot_observed, pubkey), ());

            // Persist decimals on first observation for this (pair, slot).
            if bundle_was_empty {
                BundleDecimals::<T>::insert((pair_id, slot_observed), decimals);
            }

            let bundle_after = PendingAttestations::<T>::get(pair_id, slot_observed);
            let pending_count = bundle_after.len() as u32;
            let threshold = T::MinAttestorThreshold::get();

            if pending_count >= threshold {
                // Aggregate and flip Prices[pair_id].
                let (agg_price, attestor_set) = aggregate_median::<T>(&bundle_after);

                // Bound attestor_set under MAX_ATTESTORS_PER_PAIR. `roster`
                // is BoundedVec<_, T::MaxAttestors>; MAX_ATTESTORS_PER_PAIR
                // is the canonical const that bounds the persisted
                // `attestor_set` field. The runtime MUST configure
                // `MaxAttestors == MAX_ATTESTORS_PER_PAIR`; if it doesn't,
                // we still cap here for safety.
                let mut bounded_set: BoundedVec<
                    AttestorPubkey,
                    ConstU32<MAX_ATTESTORS_PER_PAIR>,
                > = BoundedVec::new();
                for pk in attestor_set.iter() {
                    // Truncation-safe: if MaxAttestors > MAX_ATTESTORS_PER_PAIR,
                    // we silently cap. This is a runtime-config invariant
                    // not a hot path.
                    let _ = bounded_set.try_push(*pk);
                }

                let feed = PriceFeed {
                    last_price: agg_price,
                    last_decimals: decimals,
                    last_update_slot: slot_observed,
                    last_update_block: frame_system::Pallet::<T>::block_number(),
                    aggregation: AggregationMethod::Median,
                    attestor_set: bounded_set,
                };
                Prices::<T>::insert(pair_id, feed);

                // Clear per-attestor idempotency rows for this slot.
                for obs in bundle_after.iter() {
                    AttestorSubmitted::<T>::remove((pair_id, slot_observed, obs.pubkey));
                }
                // Clear the bundle itself + decimals witness.
                PendingAttestations::<T>::remove(pair_id, slot_observed);
                BundleDecimals::<T>::remove((pair_id, slot_observed));

                Self::deposit_event(Event::PriceUpdated {
                    pair_id,
                    price: agg_price,
                    decimals,
                    observed_at_slot: slot_observed,
                    attestor_count: pending_count,
                    aggregation: AggregationMethod::Median,
                });
            } else {
                Self::deposit_event(Event::PriceAttestationSubmitted {
                    pair_id,
                    slot_observed,
                    attestor: pubkey,
                    pending_count,
                });
            }

            Ok(())
        }

        /// Sudo-registers an attestor for a pair. v1 only; Phase 2+ swaps
        /// for bonded permissionless registration.
        ///
        /// Validation:
        /// 1. `ensure_root(origin)`.
        /// 2. `Attestors[pair_id].contains(&pubkey)` →
        ///    `Error::AttestorAlreadyRegistered`.
        /// 3. `try_push` into `Attestors[pair_id]`; full → `Error::AttestorRegistryFull`.
        /// 4. Emit `AttestorRegistered { pair_id, pubkey }`.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn register_attestor(
            origin: OriginFor<T>,
            pair_id: PairId,
            pubkey: AttestorPubkey,
        ) -> DispatchResult {
            ensure_root(origin)?;

            Attestors::<T>::try_mutate(pair_id, |roster| -> DispatchResult {
                ensure!(
                    !roster.contains(&pubkey),
                    Error::<T>::AttestorAlreadyRegistered
                );
                roster
                    .try_push(pubkey)
                    .map_err(|_| Error::<T>::AttestorRegistryFull)?;
                Ok(())
            })?;

            Self::deposit_event(Event::AttestorRegistered { pair_id, pubkey });
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

    // ---------------------------------------------------------------------
    // Aggregation (v1: plain median per design memo §3)
    // ---------------------------------------------------------------------

    /// Plain median of `bundle.iter().map(|o| o.price)`. v1 aggregation
    /// per design memo §3 — trimmed median is explicitly v2 (requires
    /// M ≥ 5 to be useful; Phase 1 ships at M=1 → M=3).
    ///
    /// Returns `(median_price, attestor_pubkey_set)`. The set is the same
    /// length and order as the input bundle; downstream stores it in
    /// `PriceFeed.attestor_set` for audit + v2 slashing forensics.
    ///
    /// At M=1 (single Aegis publisher), the lone observation's price
    /// passes through unchanged. At M=2 the median is the mean of the
    /// two — but per design memo `MinAttestorThreshold` defaults to 1
    /// and bumps to 3 only after the pool grows, so M=2 is a transient
    /// state we don't optimise for.
    fn aggregate_median<T: Config>(
        bundle: &BoundedVec<PriceObservation, <T as Config>::MaxAttestors>,
    ) -> (u64, alloc::vec::Vec<AttestorPubkey>) {
        let mut prices: alloc::vec::Vec<u64> = bundle.iter().map(|o| o.price).collect();
        prices.sort_unstable();
        let n = prices.len();
        let median = if n == 0 {
            0u64
        } else if n % 2 == 1 {
            prices[n / 2]
        } else {
            // Even count: mean of the two middle values, saturating-add
            // then halve so we never panic on overflow.
            let lo = prices[n / 2 - 1];
            let hi = prices[n / 2];
            ((lo as u128 + hi as u128) / 2) as u64
        };
        let pubkeys: alloc::vec::Vec<AttestorPubkey> =
            bundle.iter().map(|o| o.pubkey).collect();
        (median, pubkeys)
    }
}

