//! Unit + integration tests for `pallet_committee_governance`.
//!
//! Covers spec §3.7 acceptance:
//! - Full rotation lifecycle (propose → timelock → execute → mirror).
//! - Threshold-bounds (reject 0 and N+1).
//! - Permissionless `execute_rotation`.
//! - Cancellation.
//! - 2-of-7 → 5-of-11 expansion is pure data, not code.

#![cfg(test)]

use crate as pallet_committee_governance;
use crate::types::*;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstU32, Hooks},
    BoundedVec,
};
use sp_runtime::{traits::IdentityLookup, BuildStorage};

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        CommitteeGov: pallet_committee_governance,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
}

parameter_types! {
    pub const MaxCommittee: u32 = 32;
    pub const DefaultRotationTimelock: u32 = 14_400;
    pub const MaxRotationEvents: u32 = 16;
}

impl pallet_committee_governance::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommittee = MaxCommittee;
    type DefaultRotationTimelock = DefaultRotationTimelock;
    type MaxRotationEvents = MaxRotationEvents;
}

fn new_ext_with_seven() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    // Seed 7 members + threshold 2.
    pallet_committee_governance::pallet::GenesisConfig::<Test> {
        initial_members: (1u8..=7).map(|i| [i; 32]).collect(),
        initial_threshold: 2,
        rotation_timelock: 14_400,
        _phantom: core::marker::PhantomData,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
    });
    ext
}

fn new_ext_empty() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        pallet_committee_governance::pallet::RotationTimelock::<Test>::put(10u32);
    });
    ext
}

// ---------------------------------------------------------------------------
// propose_* require Root
// ---------------------------------------------------------------------------

#[test]
fn propose_add_requires_root() {
    new_ext_empty().execute_with(|| {
        assert_noop!(
            CommitteeGov::propose_add_member(RuntimeOrigin::signed(1), [1u8; 32]),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [1u8; 32]
        ));
    });
}

#[test]
fn propose_remove_requires_root() {
    new_ext_with_seven().execute_with(|| {
        assert_noop!(
            CommitteeGov::propose_remove_member(
                RuntimeOrigin::signed(1),
                [1u8; 32]
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn propose_rotate_pubkey_requires_root() {
    new_ext_with_seven().execute_with(|| {
        assert_noop!(
            CommitteeGov::propose_rotate_pubkey(
                RuntimeOrigin::signed(1),
                [1u8; 32],
                [9u8; 32]
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(CommitteeGov::propose_rotate_pubkey(
            RuntimeOrigin::root(),
            [1u8; 32],
            [9u8; 32]
        ));
    });
}

#[test]
fn propose_threshold_change_validates_bounds() {
    new_ext_with_seven().execute_with(|| {
        // 0 is invalid
        assert_noop!(
            CommitteeGov::propose_threshold_change(RuntimeOrigin::root(), 0),
            pallet_committee_governance::pallet::Error::<Test>::InvalidThreshold
        );
        // N+1 = 8 is invalid (no pending adds)
        assert_noop!(
            CommitteeGov::propose_threshold_change(RuntimeOrigin::root(), 8),
            pallet_committee_governance::pallet::Error::<Test>::InvalidThreshold
        );
        // 5 is fine (≤ 7)
        assert_ok!(CommitteeGov::propose_threshold_change(
            RuntimeOrigin::root(),
            5
        ));
    });
}

// ---------------------------------------------------------------------------
// Full lifecycle: propose → timelock → execute → mirror
// ---------------------------------------------------------------------------

#[test]
fn full_rotation_lifecycle_2of7_to_5of11() {
    new_ext_with_seven().execute_with(|| {
        // Queue 4 adds + threshold change.
        for i in 8u8..=11 {
            assert_ok!(CommitteeGov::propose_add_member(
                RuntimeOrigin::root(),
                [i; 32]
            ));
        }
        assert_ok!(CommitteeGov::propose_threshold_change(
            RuntimeOrigin::root(),
            5
        ));

        // Before timelock — execute should fail.
        System::set_block_number(2);
        assert_noop!(
            CommitteeGov::execute_rotation(RuntimeOrigin::signed(99)),
            pallet_committee_governance::pallet::Error::<Test>::TimelockNotElapsed
        );

        // Fast-forward past the timelock.
        System::set_block_number(1 + 14_400 + 1);
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(99)));

        let members =
            pallet_committee_governance::pallet::Members::<Test>::get();
        assert_eq!(members.len(), 11);
        assert_eq!(
            pallet_committee_governance::pallet::Threshold::<Test>::get(),
            5
        );

        // Mirror to Cardano.
        assert_ok!(CommitteeGov::mirror_to_cardano(
            RuntimeOrigin::signed(99),
            [0x42u8; 32]
        ));
        let state =
            pallet_committee_governance::pallet::CardanoMirrorState::<Test>::get();
        assert_eq!(state.cardano_tx_hash, [0x42u8; 32]);

        // Digest matches the pallet's own compute.
        let expected = crate::types::compute_committee_set_digest(members.as_slice(), 5);
        assert_eq!(state.committee_set_digest, expected);
    });
}

#[test]
fn execute_rotation_is_permissionless() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [99u8; 32]
        ));
        System::set_block_number(1 + 14_400 + 1);
        // Any signed origin, including non-members, can execute.
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(0xEEEE)));
    });
}

#[test]
fn cancel_pending_rotation_by_root() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [99u8; 32]
        ));
        // Signed cancel fails.
        assert_noop!(
            CommitteeGov::cancel_pending_rotation(RuntimeOrigin::signed(1)),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(CommitteeGov::cancel_pending_rotation(RuntimeOrigin::root()));
        // Pending cleared.
        assert_eq!(
            pallet_committee_governance::pallet::PendingRotation::<Test>::get(),
            None
        );
        // And cancel again is NoPendingRotation.
        assert_noop!(
            CommitteeGov::cancel_pending_rotation(RuntimeOrigin::root()),
            pallet_committee_governance::pallet::Error::<Test>::NoPendingRotation
        );
    });
}

#[test]
fn add_duplicate_member_rejects_at_execute() {
    new_ext_with_seven().execute_with(|| {
        // Propose adding [1;32] which is already a member.
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [1u8; 32]
        ));
        System::set_block_number(1 + 14_400 + 1);
        assert_noop!(
            CommitteeGov::execute_rotation(RuntimeOrigin::signed(1)),
            pallet_committee_governance::pallet::Error::<Test>::AlreadyMember
        );
    });
}

#[test]
fn remove_unknown_member_rejects_at_execute() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_remove_member(
            RuntimeOrigin::root(),
            [99u8; 32]
        ));
        System::set_block_number(1 + 14_400 + 1);
        assert_noop!(
            CommitteeGov::execute_rotation(RuntimeOrigin::signed(1)),
            pallet_committee_governance::pallet::Error::<Test>::UnknownMember
        );
    });
}

#[test]
fn rotate_pubkey_happy() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_rotate_pubkey(
            RuntimeOrigin::root(),
            [1u8; 32],
            [0x55u8; 32]
        ));
        System::set_block_number(1 + 14_400 + 1);
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(1)));
        let members =
            pallet_committee_governance::pallet::Members::<Test>::get();
        assert!(members.iter().any(|p| p == &[0x55u8; 32]));
        assert!(!members.iter().any(|p| p == &[1u8; 32]));
    });
}

#[test]
fn committee_full_rejected() {
    // Seed near-full committee and try to add beyond MaxCommittee.
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_committee_governance::pallet::GenesisConfig::<Test> {
        initial_members: (0u8..32).map(|i| [i + 1; 32]).collect(),
        initial_threshold: 2,
        rotation_timelock: 2,
        _phantom: core::marker::PhantomData,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [200u8; 32]
        ));
        System::set_block_number(100);
        assert_noop!(
            CommitteeGov::execute_rotation(RuntimeOrigin::signed(1)),
            pallet_committee_governance::pallet::Error::<Test>::CommitteeFull
        );
    });
}

#[test]
fn no_pending_rotation_error() {
    new_ext_empty().execute_with(|| {
        System::set_block_number(100);
        assert_noop!(
            CommitteeGov::execute_rotation(RuntimeOrigin::signed(1)),
            pallet_committee_governance::pallet::Error::<Test>::NoPendingRotation
        );
    });
}

#[test]
fn set_rotation_timelock_root_only() {
    new_ext_empty().execute_with(|| {
        assert_noop!(
            CommitteeGov::set_rotation_timelock(RuntimeOrigin::signed(1), 100),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(CommitteeGov::set_rotation_timelock(
            RuntimeOrigin::root(),
            100
        ));
        assert_eq!(
            pallet_committee_governance::pallet::RotationTimelock::<Test>::get(),
            100
        );
    });
}

// ---------------------------------------------------------------------------
// Initial-authorization test: seed via propose_add × 7 + threshold → 2
// ---------------------------------------------------------------------------

#[test]
fn remove_member_happy_path() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_remove_member(
            RuntimeOrigin::root(),
            [3u8; 32]
        ));
        System::set_block_number(1 + 14_400 + 1);
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(1)));
        let members = pallet_committee_governance::pallet::Members::<Test>::get();
        assert_eq!(members.len(), 6);
        assert!(!members.iter().any(|p| p == &[3u8; 32]));
    });
}

#[test]
fn multi_event_rotation_apply_in_order() {
    // Queue: Add 8, Add 9, Remove 1, Threshold→4. All executed in one call.
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [8u8; 32]
        ));
        assert_ok!(CommitteeGov::propose_add_member(
            RuntimeOrigin::root(),
            [9u8; 32]
        ));
        assert_ok!(CommitteeGov::propose_remove_member(
            RuntimeOrigin::root(),
            [1u8; 32]
        ));
        assert_ok!(CommitteeGov::propose_threshold_change(
            RuntimeOrigin::root(),
            4
        ));
        System::set_block_number(1 + 14_400 + 1);
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(42)));
        let members = pallet_committee_governance::pallet::Members::<Test>::get();
        assert_eq!(members.len(), 8); // 7 - 1 + 2
        assert_eq!(
            pallet_committee_governance::pallet::Threshold::<Test>::get(),
            4
        );
        assert!(!members.iter().any(|p| p == &[1u8; 32]));
        assert!(members.iter().any(|p| p == &[8u8; 32]));
        assert!(members.iter().any(|p| p == &[9u8; 32]));
    });
}

#[test]
fn too_many_events_rejected() {
    new_ext_empty().execute_with(|| {
        // MaxRotationEvents = 16; add 16 adds then try to add a 17th.
        for i in 1u8..=16 {
            assert_ok!(CommitteeGov::propose_add_member(
                RuntimeOrigin::root(),
                [i; 32]
            ));
        }
        assert_noop!(
            CommitteeGov::propose_add_member(RuntimeOrigin::root(), [17u8; 32]),
            pallet_committee_governance::pallet::Error::<Test>::TooManyEvents
        );
    });
}

#[test]
fn mirror_to_cardano_records_digest_and_hash() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::mirror_to_cardano(
            RuntimeOrigin::signed(42),
            [0x77u8; 32]
        ));
        let st =
            pallet_committee_governance::pallet::CardanoMirrorState::<Test>::get();
        assert_eq!(st.cardano_tx_hash, [0x77u8; 32]);
        let members = pallet_committee_governance::pallet::Members::<Test>::get();
        let expected = crate::types::compute_committee_set_digest(
            members.as_slice(),
            2,
        );
        assert_eq!(st.committee_set_digest, expected);
    });
}

#[test]
fn is_pubkey_member_and_committee_digest_helpers() {
    new_ext_with_seven().execute_with(|| {
        assert!(
            pallet_committee_governance::pallet::Pallet::<Test>::is_pubkey_member(
                &[1u8; 32]
            )
        );
        assert!(
            !pallet_committee_governance::pallet::Pallet::<Test>::is_pubkey_member(
                &[99u8; 32]
            )
        );
        let d =
            pallet_committee_governance::pallet::Pallet::<Test>::committee_digest();
        // Same digest computed manually
        let expected = crate::types::compute_committee_set_digest(
            pallet_committee_governance::pallet::Members::<Test>::get().as_slice(),
            2,
        );
        assert_eq!(d, expected);
    });
}

#[test]
fn set_rotation_timelock_zero_clamped_to_one() {
    new_ext_empty().execute_with(|| {
        assert_ok!(CommitteeGov::set_rotation_timelock(
            RuntimeOrigin::root(),
            0
        ));
        assert_eq!(
            pallet_committee_governance::pallet::RotationTimelock::<Test>::get(),
            1
        );
    });
}

#[test]
fn genesis_with_zero_timelock_uses_default() {
    // When the genesis config supplies rotation_timelock = 0, the build
    // function must fall back to DefaultRotationTimelock.
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_committee_governance::pallet::GenesisConfig::<Test> {
        initial_members: vec![[1u8; 32]],
        initial_threshold: 1,
        rotation_timelock: 0,
        _phantom: core::marker::PhantomData,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        assert_eq!(
            pallet_committee_governance::pallet::RotationTimelock::<Test>::get(),
            14_400
        );
    });
}

#[test]
fn threshold_applied_on_execute() {
    new_ext_with_seven().execute_with(|| {
        assert_ok!(CommitteeGov::propose_threshold_change(
            RuntimeOrigin::root(),
            5
        ));
        System::set_block_number(1 + 14_400 + 1);
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(0)));
        assert_eq!(
            pallet_committee_governance::pallet::Threshold::<Test>::get(),
            5
        );
    });
}

#[test]
fn initial_seed_via_propose_batch() {
    new_ext_empty().execute_with(|| {
        pallet_committee_governance::pallet::RotationTimelock::<Test>::put(2u32);
        for i in 1u8..=7 {
            assert_ok!(CommitteeGov::propose_add_member(
                RuntimeOrigin::root(),
                [i; 32]
            ));
        }
        assert_ok!(CommitteeGov::propose_threshold_change(
            RuntimeOrigin::root(),
            2
        ));
        System::set_block_number(100);
        assert_ok!(CommitteeGov::execute_rotation(RuntimeOrigin::signed(0)));
        assert_eq!(
            pallet_committee_governance::pallet::Members::<Test>::get().len(),
            7
        );
        assert_eq!(
            pallet_committee_governance::pallet::Threshold::<Test>::get(),
            2
        );
    });
}
