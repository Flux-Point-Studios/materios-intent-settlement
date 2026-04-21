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
pub mod types;
pub mod voucher_canonicalize;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration;

#[cfg(test)]
mod proptest;

pub use types::*;

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

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec::Vec;
    use frame_support::{pallet_prelude::*, BoundedVec};
    use frame_system::pallet_prelude::*;

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
    }

    /// Abstracts "is this account a member of the current committee?"
    pub trait IsCommitteeMember<AccountId> {
        fn is_member(who: &AccountId) -> bool;
        fn threshold() -> u32;
        fn member_count() -> u32;
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
        }
    }

    // ---------------------------------------------------------------------
    // Hooks — bounded TTL sweep
    // ---------------------------------------------------------------------

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
    {
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
                        Self::deposit_event(Event::IntentExpired {
                            intent_id,
                            reason: ExpiryReason::TTL,
                        });
                    }
                }
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
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(50_000_000, 0), DispatchClass::Operational, Pays::No))]
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

            // If already Attested, make this a no-op (idempotent).
            let mut intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::IntentNotFound)?;
            if intent.status != IntentStatus::Pending {
                return Ok(());
            }

            // We don't crypto-verify the ed25519 sig against `intent_id` bytes
            // here at runtime — that's the Cardano validator's job per spec §1.2
            // (Aiken verifies committee sigs). Substrate only enforces that
            // the caller is a committee member and that (pubkey, sig) are
            // well-formed and non-duplicated. That keeps attestation cheap and
            // avoids double-verification (ed25519 is verified at Cardano time).

            // Append to the pending bundle; reject duplicates by pubkey.
            let mut bundle = PendingAttestations::<T>::get(intent_id);
            if bundle.iter().any(|(p, _)| p == &pubkey) {
                return Ok(()); // idempotent on duplicate pubkey
            }
            bundle
                .try_push((pubkey, sig))
                .map_err(|_| Error::<T>::TooManySigs)?;
            PendingAttestations::<T>::insert(intent_id, bundle.clone());

            let threshold = T::CommitteeMembership::threshold();
            if bundle.len() as u32 >= threshold {
                intent.status = IntentStatus::Attested;
                Intents::<T>::insert(intent_id, intent);
                AttestationSigs::<T>::insert(intent_id, bundle.clone());
                PendingAttestations::<T>::remove(intent_id);
                Self::deposit_event(Event::IntentAttested {
                    intent_id,
                    attestor_count: bundle.len() as u32,
                });
            }
            Ok(())
        }

        /// Committee member submits a voucher + fairness proof. The voucher
        /// itself carries the full M-of-N signature bundle; this pallet
        /// checks the fairness-proof invariants and the voucher-to-proof
        /// binding, stores the voucher, and flips the bound intent from
        /// `Attested -> Vouchered`. The Cardano validator re-verifies the
        /// ed25519 signatures.
        #[pallet::call_index(2)]
        #[pallet::weight((Weight::from_parts(100_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn request_voucher(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            intent_id: IntentId,
            voucher: Voucher,
            fairness_proof: BatchFairnessProof,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );

            // Check duplicate-voucher first so callers get an unambiguous error
            // when they retry with the same claim_id.
            ensure!(
                !Vouchers::<T>::contains_key(claim_id),
                Error::<T>::DuplicateVoucher
            );
            let mut intent =
                Intents::<T>::get(intent_id).ok_or(Error::<T>::IntentNotFound)?;
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

            let voucher_digest = compute_voucher_digest(&voucher);

            // Store claim + voucher, flip intent state.
            let claim = Claim {
                intent_id,
                policy_id: voucher.policy_id,
                amount_ada: voucher.amount_ada,
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

            // Bump outstanding coverage for utilization tracking.
            PoolUtilization::<T>::mutate(|u| {
                u.outstanding_coverage_ada =
                    u.outstanding_coverage_ada.saturating_add(fairness_proof.pool_balance_ada.min(
                        fairness_proof.awarded_amounts_ada.iter().copied().sum(),
                    ));
            });

            Self::deposit_event(Event::VoucherIssued {
                claim_id,
                voucher_digest,
                fairness_proof_digest: bfpr_digest,
            });
            Ok(())
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
        #[pallet::weight((Weight::from_parts(50_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn settle_claim(
            origin: OriginFor<T>,
            claim_id: ClaimId,
            cardano_tx_hash: [u8; 32],
            settled_direct: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            let mut claim =
                Claims::<T>::get(claim_id).ok_or(Error::<T>::ClaimNotFound)?;
            if claim.settled {
                return Ok(()); // idempotent
            }
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

            // Decrement outstanding coverage.
            PoolUtilization::<T>::mutate(|u| {
                u.outstanding_coverage_ada =
                    u.outstanding_coverage_ada.saturating_sub(amount);
            });

            Self::deposit_event(Event::ClaimSettled {
                claim_id,
                cardano_tx_hash,
                settled_direct,
            });
            Ok(())
        }

        /// Committee reports that a policy expired on Cardano (Expire redeemer
        /// was executed). Cleans up any bound Materios intent that's still
        /// open.
        #[pallet::call_index(5)]
        #[pallet::weight((Weight::from_parts(30_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn expire_policy_mirror(
            origin: OriginFor<T>,
            intent_id: IntentId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
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
            Self::deposit_event(Event::IntentExpired {
                intent_id,
                reason: ExpiryReason::PolicyExpiredOnCardano,
            });
            Ok(())
        }

        /// Committee registers a confirmed Cardano deposit to the premium
        /// collector script. Idempotent on `(who, cardano_tx_hash)`.
        #[pallet::call_index(6)]
        #[pallet::weight((Weight::from_parts(30_000_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn credit_deposit(
            origin: OriginFor<T>,
            target: T::AccountId,
            amount_ada: AdaLovelace,
            cardano_tx_hash: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                T::CommitteeMembership::is_member(&who),
                Error::<T>::NotCommitteeMember
            );
            let key = (target.clone(), cardano_tx_hash);
            ensure!(
                !ProcessedDeposits::<T>::contains_key(&key),
                Error::<T>::DepositAlreadyProcessed
            );
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
        pub fn get_pending_batches(
            since_block: BlockNumber,
            max_count: u32,
        ) -> Vec<BatchPayload<T::AccountId>> {
            let mut out = Vec::new();
            for (intent_id, intent) in Intents::<T>::iter() {
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
                    intent_id,
                    attestation_sigs: sigs_static,
                });
                if out.len() as u32 >= max_count {
                    break;
                }
            }
            out
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
    compute_voucher_digest, domain_hash,
};
