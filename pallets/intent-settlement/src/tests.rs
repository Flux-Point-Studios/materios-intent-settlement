//! Unit tests for `pallet_intent_settlement` — happy + sad paths for every
//! extrinsic, plus TTL sweep, idempotency, and fairness-proof invariant tests.

#![cfg(test)]

use crate as pallet_intent_settlement;
use crate::pallet::IsCommitteeMember;
use crate::types::*;
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstU32, Hooks},
    BoundedVec,
};
use parity_scale_codec as codec;
use sp_core::H256;
use sp_runtime::{
    traits::IdentityLookup,
    BuildStorage,
};

// ---------------------------------------------------------------------------
// Mock runtime
// ---------------------------------------------------------------------------

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        IntentSettlement: pallet_intent_settlement,
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
    pub const MaxExpirePerBlock: u32 = 256;
    pub const DefaultIntentTTL: u32 = 600;
    pub const DefaultClaimTTL: u32 = 28_800;
}

/// Mock committee: fixed threshold 2, members {1, 2, 3}.
pub struct MockCommittee;
impl IsCommitteeMember<u64> for MockCommittee {
    fn is_member(who: &u64) -> bool {
        matches!(*who, 1 | 2 | 3)
    }
    fn threshold() -> u32 {
        2
    }
    fn member_count() -> u32 {
        3
    }
}

impl pallet_intent_settlement::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommittee = MaxCommittee;
    type MaxExpirePerBlock = MaxExpirePerBlock;
    type DefaultIntentTTL = DefaultIntentTTL;
    type DefaultClaimTTL = DefaultClaimTTL;
    type CommitteeMembership = MockCommittee;
}

pub const ALICE: u64 = 100;
pub const BOB: u64 = 101;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        pallet_intent_settlement::pallet::IntentTTL::<Test>::put(600u32);
        pallet_intent_settlement::pallet::ClaimTTL::<Test>::put(28_800u32);
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::put(
            PoolUtilizationParams {
                target_bps: 5_000,
                cap_bps: 7_500,
                total_nav_ada: 10_000_000, // 10 ADA
                outstanding_coverage_ada: 0,
            },
        );
    });
    ext
}

fn bp(id: u8, strike: u64, premium: u64) -> IntentKind {
    IntentKind::BuyPolicy {
        product_id: H256::from([id; 32]),
        strike,
        term_slots: 86_400,
        premium_ada: premium,
        beneficiary_cardano_addr: BoundedVec::try_from(vec![0xA1u8; 57]).unwrap(),
    }
}

fn intent_id_for(account: u64, nonce: u64, kind: &IntentKind, blk: u32) -> IntentId {
    let mut buf = [0u8; 32];
    let enc = account.encode();
    buf[..enc.len()].copy_from_slice(&enc);
    compute_intent_id(&buf, nonce, kind, blk)
}

// ---------------------------------------------------------------------------
// submit_intent — happy + sad
// ---------------------------------------------------------------------------

#[test]
fn submit_intent_happy_path_buy_policy_debits_credit_and_stores_intent() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 1_000_000u64);
        let kind = bp(0xAB, 500_000, 500_000);
        let expected_id = intent_id_for(ALICE, 0, &kind, 1);

        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(expected_id).unwrap();
        assert_eq!(intent.submitter, ALICE);
        assert_eq!(intent.nonce, 0);
        assert_eq!(intent.status, IntentStatus::Pending);
        assert_eq!(intent.submitted_block, 1);
        assert_eq!(intent.ttl_block, 1 + 600);

        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            500_000u64
        );
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            1
        );
    });
}

#[test]
fn submit_intent_rejects_buy_policy_without_credit() {
    new_test_ext().execute_with(|| {
        // Alice has no credit
        let kind = bp(0xCD, 1, 1_000_000);
        assert_noop!(
            IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), kind),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientCredit
        );
    });
}

#[test]
fn submit_intent_rejects_pool_utilization_exceeded() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, u64::MAX);
        // cap = 7500 bps of 10 ADA NAV = 7.5 ADA max outstanding. Try 9 ADA.
        let kind = bp(0xEF, 1, 9_000_000);
        assert_noop!(
            IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), kind),
            pallet_intent_settlement::pallet::Error::<Test>::PoolUtilizationExceeded
        );
    });
}

#[test]
fn submit_intent_request_payout_doesnt_touch_credit() {
    new_test_ext().execute_with(|| {
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([7u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 32]).unwrap(),
        };
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(BOB),
            kind
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(BOB),
            0
        );
    });
}

#[test]
fn submit_intent_auto_increments_nonce() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 10_000_000u64);
        for n in 0u64..3 {
            let kind = bp((n as u8).wrapping_add(1), 1, 100_000);
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                kind
            ));
            assert_eq!(
                pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
                n + 1
            );
        }
    });
}

// ---------------------------------------------------------------------------
// attest_intent — happy, threshold-crossing, idempotency, non-member
// ---------------------------------------------------------------------------

fn submit_and_get_id(account: u64) -> IntentId {
    let kind = IntentKind::RequestPayout {
        policy_id: H256::from([11u8; 32]),
        oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
    };
    let expected = intent_id_for(account, 0, &kind, 1);
    assert_ok!(IntentSettlement::submit_intent(
        RuntimeOrigin::signed(account),
        kind
    ));
    expected
}

#[test]
fn attest_intent_first_signer_keeps_pending() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            [1u8; 32],
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);
    });
}

#[test]
fn attest_intent_crosses_threshold_attests() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            [1u8; 32],
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            [2u8; 32],
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
        let sigs =
            pallet_intent_settlement::pallet::AttestationSigs::<Test>::get(iid).unwrap();
        assert_eq!(sigs.len(), 2);
    });
}

#[test]
fn attest_intent_rejects_non_member() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_noop!(
            IntentSettlement::attest_intent(
                RuntimeOrigin::signed(ALICE), // ALICE=100, not in {1,2,3}
                iid,
                [1u8; 32],
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn attest_intent_duplicate_pubkey_is_noop() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            [5u8; 32],
            [0u8; 64]
        ));
        // same pubkey via member 2 — second call is a noop, intent stays Pending
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            [5u8; 32],
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);
        let b =
            pallet_intent_settlement::pallet::PendingAttestations::<Test>::get(iid);
        assert_eq!(b.len(), 1);
    });
}

#[test]
fn attest_intent_after_attested_is_idempotent() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            [1u8; 32],
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            [2u8; 32],
            [0u8; 64]
        ));
        // Third signer arrives late — pallet must treat as no-op.
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(3),
            iid,
            [3u8; 32],
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
    });
}

// ---------------------------------------------------------------------------
// request_voucher — happy, invariant violations, state mismatch
// ---------------------------------------------------------------------------

fn attested_intent() -> IntentId {
    let iid = submit_and_get_id(ALICE);
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(1),
        iid,
        [1u8; 32],
        [0u8; 64]
    ));
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(2),
        iid,
        [2u8; 32],
        [0u8; 64]
    ));
    iid
}

fn good_fairness_proof(iid: IntentId, amount: u64) -> BatchFairnessProof {
    BatchFairnessProof {
        batch_block_range: (1, 1),
        sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
        requested_amounts_ada: BoundedVec::try_from(vec![amount]).unwrap(),
        pool_balance_ada: amount.saturating_mul(10),
        pro_rata_scale_bps: 10_000,
        awarded_amounts_ada: BoundedVec::try_from(vec![amount]).unwrap(),
    }
}

fn good_voucher(
    claim_id: ClaimId,
    bfpr: &BatchFairnessProof,
    amount: u64,
) -> Voucher {
    Voucher {
        claim_id,
        policy_id: H256::from([9u8; 32]),
        beneficiary_cardano_addr: BoundedVec::try_from(vec![0xB1u8; 57]).unwrap(),
        amount_ada: amount,
        batch_fairness_proof_digest: compute_fairness_proof_digest(bfpr),
        issued_block: 2,
        expiry_slot_cardano: 100_000,
        committee_sigs: BoundedVec::try_from(vec![
            ([1u8; 32], [0u8; 64]),
            ([2u8; 32], [0u8; 64]),
        ])
        .unwrap(),
    }
}

#[test]
fn request_voucher_happy_path() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);

        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher.clone(),
            bfpr.clone()
        ));

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
        assert!(
            pallet_intent_settlement::pallet::Vouchers::<Test>::contains_key(claim_id)
        );
        assert!(
            pallet_intent_settlement::pallet::Claims::<Test>::contains_key(claim_id)
        );
    });
}

#[test]
fn request_voucher_rejects_pending_intent() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE); // still Pending
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentStatusMismatch
        );
    });
}

#[test]
fn request_voucher_rejects_bad_pro_rata_scale() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([7u8; 32]);
        let mut bfpr = good_fairness_proof(iid, 1_000);
        bfpr.pro_rata_scale_bps = 10_001; // >100%
        // awarded now violates invariant even without the scale check
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_awarded_mismatch() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([9u8; 32]);
        let mut bfpr = good_fairness_proof(iid, 1_000);
        // award too high vs requested*scale/10000
        bfpr.awarded_amounts_ada = BoundedVec::try_from(vec![1_500u64]).unwrap();
        let voucher = good_voucher(claim_id, &bfpr, 1_500);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_awarded_exceeds_pool() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([11u8; 32]);
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![1_000_000u64]).unwrap(),
            pool_balance_ada: 100_000, // only 0.1 ADA in pool
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![1_000_000u64]).unwrap(),
        };
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_digest_mismatch() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([13u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let mut voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        voucher.batch_fairness_proof_digest = [0xFFu8; 32]; // wrong digest
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::FairnessDigestMismatch
        );
    });
}

#[test]
fn request_voucher_rejects_duplicate_claim() {
    // First voucher succeeds. Second attempt on the same claim_id against a
    // *different* attested intent must be rejected with DuplicateVoucher
    // (rather than IntentStatusMismatch) — the duplicate-check fires before
    // the state-transition check.
    new_test_ext().execute_with(|| {
        let iid1 = attested_intent();
        let claim_id = H256::from([99u8; 32]);
        let bfpr1 = good_fairness_proof(iid1, 1_000_000);
        let voucher1 = good_voucher(claim_id, &bfpr1, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid1,
            voucher1,
            bfpr1
        ));

        // Second attested intent, same claim_id.
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([22u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![1u8; 8]).unwrap(),
        };
        let iid2 = intent_id_for(BOB, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(BOB),
            kind
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid2,
            [1u8; 32],
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid2,
            [2u8; 32],
            [0u8; 64]
        ));
        let bfpr2 = good_fairness_proof(iid2, 500_000);
        let voucher2 = good_voucher(claim_id, &bfpr2, 500_000);

        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid2,
                voucher2,
                bfpr2
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateVoucher
        );
    });
}

// ---------------------------------------------------------------------------
// settle_claim / expire_policy_mirror / credit_deposit / request_credit_refund
// ---------------------------------------------------------------------------

#[test]
fn settle_claim_happy_path_flips_state_idempotently() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr
        ));
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xFFu8; 32],
            false
        ));
        let claim =
            pallet_intent_settlement::pallet::Claims::<Test>::get(claim_id).unwrap();
        assert!(claim.settled);
        assert_eq!(claim.cardano_tx_hash, [0xFFu8; 32]);
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Settled);

        // Calling again is idempotent.
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xEEu8; 32],
            true
        ));
        let claim2 =
            pallet_intent_settlement::pallet::Claims::<Test>::get(claim_id).unwrap();
        // tx_hash NOT overwritten (idempotent = first-write-wins)
        assert_eq!(claim2.cardano_tx_hash, [0xFFu8; 32]);
        assert!(!claim2.settled_direct);
    });
}

#[test]
fn settle_claim_unknown_id_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(1),
                H256::from([0u8; 32]),
                [0u8; 32],
                false
            ),
            pallet_intent_settlement::pallet::Error::<Test>::ClaimNotFound
        );
    });
}

#[test]
fn settle_claim_rejects_non_member() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(ALICE),
                H256::from([0u8; 32]),
                [0u8; 32],
                false
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn expire_policy_mirror_flips_to_expired() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Expired);
    });
}

#[test]
fn expire_policy_mirror_unknown_policy_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::expire_policy_mirror(
                RuntimeOrigin::signed(1),
                H256::from([0u8; 32])
            ),
            pallet_intent_settlement::pallet::Error::<Test>::UnknownPolicy
        );
    });
}

#[test]
fn credit_deposit_happy_and_idempotent() {
    new_test_ext().execute_with(|| {
        let tx = [0xABu8; 32];
        assert_ok!(IntentSettlement::credit_deposit(
            RuntimeOrigin::signed(1),
            ALICE,
            1_500_000,
            tx
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            1_500_000
        );
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                1_500_000,
                tx
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DepositAlreadyProcessed
        );
    });
}

#[test]
fn credit_deposit_rejects_non_member() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(ALICE),
                ALICE,
                1_000,
                [0u8; 32]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn request_credit_refund_debits_immediately() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 5_000_000u64);
        assert_ok!(IntentSettlement::request_credit_refund(
            RuntimeOrigin::signed(ALICE),
            2_000_000
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            3_000_000
        );
    });
}

#[test]
fn request_credit_refund_rejects_insufficient_credit() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::request_credit_refund(RuntimeOrigin::signed(ALICE), 1),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientCredit
        );
    });
}

// ---------------------------------------------------------------------------
// TTL sweep + pool_utilization governance
// ---------------------------------------------------------------------------

#[test]
fn ttl_sweep_expires_pending_and_refunds_credit() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::Credits::<Test>::insert(ALICE, 1_000_000u64);
        let kind = bp(0x01, 1, 1_000_000);
        let iid = intent_id_for(ALICE, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            0
        );

        // Jump to TTL block and run on_initialize.
        System::set_block_number(1 + 600);
        <IntentSettlement as Hooks<u64>>::on_initialize(1 + 600);

        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Expired);
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            1_000_000
        );
    });
}

#[test]
fn genesis_with_zero_ttl_uses_default() {
    // If genesis provides intent_ttl = 0, build() should fall back to DefaultIntentTTL.
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_intent_settlement::pallet::GenesisConfig::<Test> {
        intent_ttl: 0,
        claim_ttl: 0,
        pool_utilization: PoolUtilizationParams::default(),
        _phantom: core::marker::PhantomData,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        assert_eq!(
            pallet_intent_settlement::pallet::IntentTTL::<Test>::get(),
            600
        );
        assert_eq!(
            pallet_intent_settlement::pallet::ClaimTTL::<Test>::get(),
            28_800
        );
    });
}

#[test]
fn submit_intent_with_ttl_storage_zero_uses_default() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::IntentTTL::<Test>::put(0u32);
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([0x42; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
        };
        let iid = intent_id_for(ALICE, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(ALICE),
            kind
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Test>::get(iid).unwrap();
        // Default TTL = 600
        assert_eq!(intent.ttl_block, 1 + 600);
    });
}

#[test]
fn set_pool_utilization_requires_root() {
    new_test_ext().execute_with(|| {
        let p = PoolUtilizationParams::default();
        assert_noop!(
            IntentSettlement::set_pool_utilization(RuntimeOrigin::signed(1), p),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(IntentSettlement::set_pool_utilization(
            RuntimeOrigin::root(),
            p
        ));
    });
}

// ---------------------------------------------------------------------------
// Runtime API helper (get_pending_batches / get_voucher)
// ---------------------------------------------------------------------------

#[test]
fn runtime_api_get_pending_batches_returns_attested_only() {
    new_test_ext().execute_with(|| {
        let iid1 = attested_intent(); // 1 attested
        let _iid2 = submit_and_get_id(BOB); // 1 pending
        let out =
            pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(0, 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].intent_id, iid1);
    });
}

#[test]
fn runtime_api_get_pending_batches_since_block_filter_and_max_count() {
    new_test_ext().execute_with(|| {
        let iid1 = attested_intent(); // submitted at block 1, attested
        // Bump the block number so the second attested intent has a newer block.
        System::set_block_number(5);
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([55u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
        };
        let iid2 = intent_id_for(BOB, 0, &kind, 5);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(BOB),
            kind
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid2,
            [4u8; 32],
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid2,
            [5u8; 32],
            [0u8; 64]
        ));

        // since_block = 3 filters out iid1 (block 1), keeps iid2 (block 5).
        let filtered =
            pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(3, 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].intent_id, iid2);

        // max_count = 1 returns one entry even though 2 qualify.
        let capped =
            pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(0, 1);
        assert_eq!(capped.len(), 1);

        // ensure iid1 still exists so we exercise the "returns attested only" branch at scale
        assert!(
            pallet_intent_settlement::pallet::Intents::<Test>::contains_key(iid1)
        );
    });
}

#[test]
fn runtime_api_get_voucher_roundtrip() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([77u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher.clone(),
            bfpr
        ));
        let got = pallet_intent_settlement::pallet::Pallet::<Test>::get_voucher(
            claim_id,
        )
        .unwrap();
        assert_eq!(got.amount_ada, voucher.amount_ada);
    });
}

// ---------------------------------------------------------------------------
// Additional coverage: error paths on nonexistent intents, max-sig overflow,
// expire-policy idempotency, genesis defaults.
// ---------------------------------------------------------------------------

#[test]
fn attest_intent_on_nonexistent_intent_errors() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::attest_intent(
                RuntimeOrigin::signed(1),
                H256::from([0xAA; 32]),
                [1u8; 32],
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentNotFound
        );
    });
}

#[test]
fn request_voucher_on_nonexistent_intent_errors() {
    new_test_ext().execute_with(|| {
        let iid = H256::from([0u8; 32]); // no such intent
        let bfpr = good_fairness_proof(iid, 100);
        let voucher = good_voucher(H256::from([8u8; 32]), &bfpr, 100);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([8u8; 32]),
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::IntentNotFound
        );
    });
}

#[test]
fn expire_policy_mirror_idempotent_on_expired() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid
        ));
        // Second call — same intent in Expired state; must be a no-op Ok.
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid
        ));
    });
}

#[test]
fn expire_policy_mirror_rejects_non_member() {
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_noop!(
            IntentSettlement::expire_policy_mirror(
                RuntimeOrigin::signed(ALICE), // not a committee member
                iid
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn request_voucher_rejects_non_member() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(H256::from([1u8; 32]), &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(ALICE), // not a committee member
                H256::from([1u8; 32]),
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn request_voucher_rejects_parallel_vec_mismatch() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![1_000u64, 2_000u64])
                .unwrap(), // extra entry
            pool_balance_ada: 10_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![1_000u64]).unwrap(),
        };
        let voucher = good_voucher(H256::from([1u8; 32]), &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([1u8; 32]),
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_unsorted_intent_ids() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            // Reversed / duplicate ordering.
            sorted_intent_ids: BoundedVec::try_from(vec![
                H256::from([2u8; 32]),
                H256::from([1u8; 32]),
            ])
            .unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![100u64, 100]).unwrap(),
            pool_balance_ada: 10_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![100u64, 100]).unwrap(),
        };
        let voucher = good_voucher(H256::from([1u8; 32]), &bfpr, 100);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([1u8; 32]),
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn request_voucher_rejects_bad_block_range() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let bfpr = BatchFairnessProof {
            batch_block_range: (10, 5), // inverted
            sorted_intent_ids: BoundedVec::try_from(vec![iid]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![1_000u64]).unwrap(),
            pool_balance_ada: 10_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![1_000u64]).unwrap(),
        };
        let voucher = good_voucher(H256::from([3u8; 32]), &bfpr, 1_000);
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                H256::from([3u8; 32]),
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidFairnessProof
        );
    });
}

#[test]
fn full_settle_decrements_outstanding_coverage() {
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::from([42u8; 32]);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid,
            voucher,
            bfpr
        ));
        let before =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert!(before.outstanding_coverage_ada > 0);
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xAA; 32],
            false
        ));
        let after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert!(after.outstanding_coverage_ada < before.outstanding_coverage_ada);
    });
}

// ---------------------------------------------------------------------------
// Test vectors against docs/test-vectors.json
// ---------------------------------------------------------------------------

#[test]
fn test_vectors_match_json() {
    // Validates intent_id + voucher_digest + bfpr_digest + committee_set_digest
    // against fixed vectors so Team B's Aiken side can cross-compare.
    let vectors =
        include_str!("../../../docs/test-vectors.json");
    let v: serde_json::Value = serde_json::from_str(vectors).unwrap();

    // intent_id vector (moved under `teamA_realistic_vectors` namespace in
    // docs/test-vectors.json v1.1 when the three-way voucher_digest_with_address
    // anchor landed — see commit f189092).
    let iv = &v["teamA_realistic_vectors"]["intent_id"];
    let submitter: [u8; 32] = hex::decode(iv["submitter_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nonce: u64 = iv["nonce"].as_u64().unwrap();
    let blk: u32 = iv["submitted_block"].as_u64().unwrap() as u32;
    let premium: u64 = iv["kind"]["premium_ada"].as_u64().unwrap();
    let strike: u64 = iv["kind"]["strike"].as_u64().unwrap();
    let term: u32 = iv["kind"]["term_slots"].as_u64().unwrap() as u32;
    let product: [u8; 32] =
        hex::decode(iv["kind"]["product_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let addr: Vec<u8> = hex::decode(iv["kind"]["addr_hex"].as_str().unwrap()).unwrap();
    let kind = IntentKind::BuyPolicy {
        product_id: H256::from(product),
        strike,
        term_slots: term,
        premium_ada: premium,
        beneficiary_cardano_addr: BoundedVec::try_from(addr).unwrap(),
    };
    let got = compute_intent_id(&submitter, nonce, &kind, blk);
    let expected: [u8; 32] = hex::decode(iv["expected_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(got.as_bytes(), &expected, "intent_id vector mismatch");

    // committee_set_digest vector (same relocation as above).
    let cv = &v["teamA_realistic_vectors"]["committee_set_digest"];
    let mut pubkeys = Vec::new();
    for entry in cv["pubkeys_hex"].as_array().unwrap() {
        let b: [u8; 32] = hex::decode(entry.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        pubkeys.push(b);
    }
    let threshold: u32 = cv["threshold"].as_u64().unwrap() as u32;
    let got2 = compute_committee_set_digest(&pubkeys, threshold);
    let expected2: [u8; 32] = hex::decode(cv["expected_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(got2, expected2, "committee_set_digest mismatch");
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let s = s.trim_start_matches("0x");
        if s.len() % 2 != 0 {
            return Err(());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks(2) {
            let hi = char_to_nib(chunk[0])?;
            let lo = char_to_nib(chunk[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }
    fn char_to_nib(c: u8) -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    }
}
