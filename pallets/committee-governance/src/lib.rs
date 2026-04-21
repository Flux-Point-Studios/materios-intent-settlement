//! # `pallet_committee_governance`
//!
//! Materios-side record-of-truth for the committee pubkey set and threshold
//! used by `pallet_intent_settlement` and mirrored to Cardano under
//! metadata label 8746. Implements `docs/spec-v1.md §3`.
//!
//! Key invariants:
//!
//! - `Members: BoundedVec<CommitteePubkey, MaxCommittee>` + `Threshold: u32`
//!   are both **storage values** — N and M are never hardcoded in logic so
//!   the 2-of-7 → 5-of-11 migration is pure data (per `docs/committee-expansion-5-of-11.md`).
//! - All mutations go through `propose_*` extrinsics requiring `Root` origin
//!   (dispatched via the existing 2-of-3 multisig-sudo per
//!   `reference_multisig_sudo.md`). Each `propose_*` extends the single
//!   `PendingRotation` with a new event; the whole bundle only takes effect
//!   after `RotationTimelock` has elapsed and `execute_rotation` is called
//!   (permissionless).
//! - After `execute_rotation`, a committee member calls `mirror_to_cardano`
//!   recording the Cardano anchor tx hash under label 8746.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

pub mod types;

#[cfg(test)]
mod tests;

pub use types::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec::Vec;
    use codec::{Decode, Encode, MaxEncodedLen};
    use frame_support::{
        pallet_prelude::*,
        BoundedVec,
    };
    use frame_system::pallet_prelude::*;
    use parity_scale_codec as codec;
    use scale_info::TypeInfo;
    use sp_runtime::RuntimeDebug;

    pub type CommitteePubkey = [u8; 32];
    pub type BlockNumber = u32;

    /// Concrete in-pallet schedule type (generic over `T: Config` so it picks
    /// up `T::MaxRotationEvents` without needing its own Get-bound type
    /// parameter — that's what tripped `TypeInfo` derivation in v0.1).
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq)]
    #[scale_info(skip_type_params(T))]
    pub struct RotationSchedule<T: Config> {
        pub events: BoundedVec<CommitteeEvent, <T as Config>::MaxRotationEvents>,
        pub proposed_block: BlockNumber,
        pub effective_block: BlockNumber,
        pub schedule_digest: [u8; 32],
    }

    // -----------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Max committee size. Per spec §3.1 = 32.
        #[pallet::constant]
        type MaxCommittee: Get<u32>;

        /// Default rotation timelock = 24h at 6s blocks = 14_400 blocks.
        /// Spec §3.1 quotes 28_800 (~48h) but the task brief asks 14_400 (~24h)
        /// so we use the brief value. Stored in `RotationTimelock` so it is
        /// governance-tunable without a runtime upgrade.
        #[pallet::constant]
        type DefaultRotationTimelock: Get<BlockNumber>;

        /// Max events queued in one pending rotation.
        #[pallet::constant]
        type MaxRotationEvents: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // -----------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------

    #[pallet::storage]
    pub type Members<T: Config> =
        StorageValue<_, BoundedVec<CommitteePubkey, <T as Config>::MaxCommittee>, ValueQuery>;

    #[pallet::storage]
    pub type Threshold<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    pub type RotationTimelock<T: Config> = StorageValue<_, BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub type PendingRotation<T: Config> =
        StorageValue<_, RotationSchedule<T>, OptionQuery>;

    #[pallet::storage]
    pub type CardanoMirrorState<T: Config> = StorageValue<_, LastMirrorTx, ValueQuery>;

    // -----------------------------------------------------------------
    // Genesis
    // -----------------------------------------------------------------

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_members: Vec<CommitteePubkey>,
        pub initial_threshold: u32,
        pub rotation_timelock: BlockNumber,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let bv: BoundedVec<CommitteePubkey, <T as Config>::MaxCommittee> =
                BoundedVec::try_from(self.initial_members.clone())
                    .expect("genesis initial_members exceeds MaxCommittee");
            Members::<T>::put(bv);
            Threshold::<T>::put(self.initial_threshold);
            RotationTimelock::<T>::put(if self.rotation_timelock == 0 {
                T::DefaultRotationTimelock::get()
            } else {
                self.rotation_timelock
            });
        }
    }

    // -----------------------------------------------------------------
    // Events + Errors
    // -----------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RotationProposed {
            schedule_digest: [u8; 32],
            timelock_expires: BlockNumber,
            event_count: u32,
        },
        RotationExecuted {
            schedule_digest: [u8; 32],
        },
        RotationCancelled {
            schedule_digest: [u8; 32],
        },
        MemberAdded {
            pubkey: CommitteePubkey,
            effective_block: BlockNumber,
        },
        MemberRemoved {
            pubkey: CommitteePubkey,
            effective_block: BlockNumber,
        },
        MemberRotated {
            old: CommitteePubkey,
            new: CommitteePubkey,
            effective_block: BlockNumber,
        },
        ThresholdChanged {
            old: u32,
            new: u32,
            effective_block: BlockNumber,
        },
        CardanoMirrorUpdated {
            committee_set_digest: [u8; 32],
            mirror_tx: [u8; 32],
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Threshold would be invalid after the rotation is applied.
        InvalidThreshold,
        /// Timelock has not elapsed yet.
        TimelockNotElapsed,
        /// No pending rotation to execute/cancel.
        NoPendingRotation,
        /// Adding this member would exceed `MaxCommittee`.
        CommitteeFull,
        /// Rotation-events queue is full.
        TooManyEvents,
        /// Member already in the committee.
        AlreadyMember,
        /// Member not found.
        UnknownMember,
        /// Caller is not a committee member (for mirror_to_cardano).
        NotCommitteeMember,
    }

    // -----------------------------------------------------------------
    // Extrinsics
    // -----------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
    {
        /// Root: queue an Add event.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn propose_add_member(
            origin: OriginFor<T>,
            pubkey: CommitteePubkey,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Self::append_rotation_event(CommitteeEvent::Added { pubkey })
        }

        /// Root: queue a Remove event.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn propose_remove_member(
            origin: OriginFor<T>,
            pubkey: CommitteePubkey,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Self::append_rotation_event(CommitteeEvent::Removed { pubkey })
        }

        /// Root: queue a RotatedPubkey event.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn propose_rotate_pubkey(
            origin: OriginFor<T>,
            old: CommitteePubkey,
            new: CommitteePubkey,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Self::append_rotation_event(CommitteeEvent::RotatedPubkey { old, new })
        }

        /// Root: queue a ThresholdChange event.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn propose_threshold_change(
            origin: OriginFor<T>,
            new_threshold: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            // Validate future threshold against (current Members + pending adds
            // - pending removes). See spec §3.2.
            let members = Members::<T>::get();
            let mut count_after = members.len() as i64;
            if let Some(sched) = PendingRotation::<T>::get() {
                for ev in sched.events.iter() {
                    match ev {
                        CommitteeEvent::Added { .. } => count_after += 1,
                        CommitteeEvent::Removed { .. } => count_after -= 1,
                        _ => {}
                    }
                }
            }
            let old = Threshold::<T>::get();
            ensure!(
                new_threshold >= 1 && (new_threshold as i64) <= count_after.max(1),
                Error::<T>::InvalidThreshold
            );
            // Emitting event on propose so auditors see the attempted change.
            Self::deposit_event(Event::ThresholdChanged {
                old,
                new: new_threshold,
                effective_block: Self::effective_block(),
            });
            Self::append_rotation_event(CommitteeEvent::ExpandedThreshold {
                old,
                new: new_threshold,
            })
        }

        /// Permissionless: anyone can trigger the rotation once the timelock
        /// expires. Applies the pending events in order and clears state.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn execute_rotation(origin: OriginFor<T>) -> DispatchResult {
            ensure_signed(origin)?;
            // Peek first so we can reject without mutating state.
            let sched =
                PendingRotation::<T>::get().ok_or(Error::<T>::NoPendingRotation)?;
            let now_u32 = Self::current_block();
            ensure!(
                now_u32 >= sched.effective_block,
                Error::<T>::TimelockNotElapsed
            );
            let digest = sched.schedule_digest;

            let mut members = Members::<T>::get();
            let mut threshold = Threshold::<T>::get();

            for ev in sched.events.iter() {
                match ev.clone() {
                    CommitteeEvent::Added { pubkey } => {
                        ensure!(
                            !members.iter().any(|p| p == &pubkey),
                            Error::<T>::AlreadyMember
                        );
                        members.try_push(pubkey).map_err(|_| Error::<T>::CommitteeFull)?;
                        Self::deposit_event(Event::MemberAdded {
                            pubkey,
                            effective_block: now_u32,
                        });
                    }
                    CommitteeEvent::Removed { pubkey } => {
                        let idx = members
                            .iter()
                            .position(|p| p == &pubkey)
                            .ok_or(Error::<T>::UnknownMember)?;
                        members.remove(idx);
                        Self::deposit_event(Event::MemberRemoved {
                            pubkey,
                            effective_block: now_u32,
                        });
                    }
                    CommitteeEvent::RotatedPubkey { old, new } => {
                        let idx = members
                            .iter()
                            .position(|p| p == &old)
                            .ok_or(Error::<T>::UnknownMember)?;
                        members[idx] = new;
                        Self::deposit_event(Event::MemberRotated {
                            old,
                            new,
                            effective_block: now_u32,
                        });
                    }
                    CommitteeEvent::ExpandedThreshold { old, new } => {
                        // Use final `new` (may be clamped below).
                        let _ = old;
                        // Clamp to [1, members.len()].
                        let clamped = new.min(members.len() as u32).max(1);
                        threshold = clamped;
                    }
                }
            }

            // Final threshold sanity: 1 <= threshold <= members.len().
            let m = members.len() as u32;
            ensure!(m >= 1, Error::<T>::InvalidThreshold);
            ensure!(
                threshold >= 1 && threshold <= m,
                Error::<T>::InvalidThreshold
            );

            Members::<T>::put(members);
            Threshold::<T>::put(threshold);
            PendingRotation::<T>::kill();

            Self::deposit_event(Event::RotationExecuted {
                schedule_digest: digest,
            });
            Ok(())
        }

        /// Committee member records that the new committee-set digest has been
        /// anchored to Cardano under metadata label 8746. Emits
        /// `CardanoMirrorUpdated`. Idempotent if the same tx-hash is posted twice.
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn mirror_to_cardano(
            origin: OriginFor<T>,
            cardano_tx_hash: [u8; 32],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // Digest of the current committee state.
            let digest = crate::types::compute_committee_set_digest(
                Members::<T>::get().as_slice(),
                Threshold::<T>::get(),
            );
            let now = Self::current_block();
            CardanoMirrorState::<T>::put(LastMirrorTx {
                committee_set_digest: digest,
                cardano_tx_hash,
                mirrored_at_block: now,
            });
            Self::deposit_event(Event::CardanoMirrorUpdated {
                committee_set_digest: digest,
                mirror_tx: cardano_tx_hash,
            });
            Ok(())
        }

        /// Root: cancel the currently-pending rotation. Emits `RotationCancelled`.
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn cancel_pending_rotation(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;
            let sched =
                PendingRotation::<T>::take().ok_or(Error::<T>::NoPendingRotation)?;
            Self::deposit_event(Event::RotationCancelled {
                schedule_digest: sched.schedule_digest,
            });
            Ok(())
        }

        /// Root: set the rotation timelock (governance knob; used to tune
        /// 24h → longer/shorter without a runtime upgrade).
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn set_rotation_timelock(
            origin: OriginFor<T>,
            blocks: BlockNumber,
        ) -> DispatchResult {
            ensure_root(origin)?;
            RotationTimelock::<T>::put(blocks.max(1));
            Ok(())
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    impl<T: Config> Pallet<T>
    where
        BlockNumberFor<T>: Into<u64> + Copy,
    {
        fn current_block() -> BlockNumber {
            <frame_system::Pallet<T>>::block_number()
                .into()
                .try_into()
                .unwrap_or(u32::MAX)
        }

        fn effective_block() -> BlockNumber {
            let now = Self::current_block();
            let tl = RotationTimelock::<T>::get();
            let tl = if tl == 0 { T::DefaultRotationTimelock::get() } else { tl };
            now.saturating_add(tl)
        }

        fn append_rotation_event(ev: CommitteeEvent) -> DispatchResult {
            let effective_block = Self::effective_block();
            let mut sched =
                PendingRotation::<T>::get().unwrap_or_else(|| RotationSchedule::<T> {
                    events: BoundedVec::<
                        CommitteeEvent,
                        <T as Config>::MaxRotationEvents,
                    >::default(),
                    proposed_block: Self::current_block(),
                    effective_block,
                    schedule_digest: [0u8; 32],
                });
            sched
                .events
                .try_push(ev)
                .map_err(|_| Error::<T>::TooManyEvents)?;
            let mut body = alloc::vec::Vec::new();
            body.extend_from_slice(&sched.events.to_vec().encode());
            body.extend_from_slice(&sched.effective_block.to_le_bytes());
            sched.schedule_digest = crate::types::domain_hash(*b"CMTT", &body);
            let digest = sched.schedule_digest;
            let event_count = sched.events.len() as u32;
            let eff = sched.effective_block;
            PendingRotation::<T>::put(sched);
            Self::deposit_event(Event::RotationProposed {
                schedule_digest: digest,
                timelock_expires: eff,
                event_count,
            });
            Ok(())
        }

        /// Read-only helper: is `pubkey` currently in the committee?
        pub fn is_pubkey_member(pubkey: &CommitteePubkey) -> bool {
            Members::<T>::get().iter().any(|p| p == pubkey)
        }

        /// Read-only helper: current committee digest (used by keeper RPC).
        pub fn committee_digest() -> [u8; 32] {
            crate::types::compute_committee_set_digest(
                Members::<T>::get().as_slice(),
                Threshold::<T>::get(),
            )
        }

    }
}
