//! Unit tests for `pallet_intent_settlement` — happy + sad paths for every
//! extrinsic, plus TTL sweep, idempotency, and fairness-proof invariant tests.

#![cfg(test)]

use crate as pallet_intent_settlement;
use crate::pallet::{IsCommitteeMember, VerifyCommitteeSignature};
use crate::types::*;
use crate::{credit_deposit_payload, settle_claim_payload};
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::Hooks,
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
    /// Issue #6: test runtime bound on PendingBatches index.
    pub const MaxPendingBatches: u32 = 16;
    /// Issue #7: preprod default.
    pub const DefaultMinSignerThreshold: u32 = 2;
}

/// Issue #4 helper: our tests use `u64` AccountIds. Derive a synthetic
/// `CommitteePubkey` by left-padding the u64's little-endian bytes into the
/// 32-byte slot (matches the left-pad semantics of `account_to_bytes`).
pub fn mock_pubkey_of(who: &u64) -> CommitteePubkey {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&who.to_le_bytes());
    out
}

pub fn mock_account_of_pubkey(pubkey: &CommitteePubkey) -> Option<u64> {
    // Reverse the left-pad: first 8 bytes = LE u64.
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&pubkey[..8]);
    let candidate = u64::from_le_bytes(lo);
    if matches!(candidate, 1 | 2 | 3) && pubkey[8..].iter().all(|b| *b == 0) {
        Some(candidate)
    } else {
        None
    }
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
    fn pubkey_of(who: &u64) -> CommitteePubkey {
        mock_pubkey_of(who)
    }
    fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<u64> {
        mock_account_of_pubkey(pubkey)
    }
}

/// Issue #7: deterministic stub verifier used by the test runtime. Tests
/// exercise the M-of-N + distinct-signer logic (the expensive bit) without
/// having to produce real sr25519 signatures over each canonical payload —
/// a signature is "valid" iff its first byte == pubkey's first byte (the
/// easiest-to-read marker that still lets `test_invalid_signature_rejected`
/// exercise the rejection path).
pub struct MockSigVerifier;
impl VerifyCommitteeSignature for MockSigVerifier {
    fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, _msg: &[u8]) -> bool {
        sig[0] == pubkey[0]
    }
}

/// Construct a valid `(pubkey, sig)` pair for a given committee member and
/// payload. The sig is just `[pubkey[0]; 64]` which the `MockSigVerifier`
/// accepts; real sr25519 verification exercises the same code path in prod.
pub fn mock_sig_for(member: u64) -> (CommitteePubkey, CommitteeSig) {
    let pk = mock_pubkey_of(&member);
    let mut sig = [0u8; 64];
    sig[0] = pk[0];
    (pk, sig)
}

/// Build a 2-of-3 signature envelope for `settle_claim` from members 1 and 2.
pub fn mock_settle_sigs() -> Vec<(CommitteePubkey, CommitteeSig)> {
    vec![mock_sig_for(1), mock_sig_for(2)]
}

/// Build a 2-of-3 signature envelope for `credit_deposit` from members 1 and 2.
pub fn mock_credit_sigs() -> Vec<(CommitteePubkey, CommitteeSig)> {
    vec![mock_sig_for(1), mock_sig_for(2)]
}

impl pallet_intent_settlement::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommittee = MaxCommittee;
    type MaxExpirePerBlock = MaxExpirePerBlock;
    type DefaultIntentTTL = DefaultIntentTTL;
    type DefaultClaimTTL = DefaultClaimTTL;
    type CommitteeMembership = MockCommittee;
    type MaxPendingBatches = MaxPendingBatches;
    type DefaultMinSignerThreshold = DefaultMinSignerThreshold;
    type SigVerifier = MockSigVerifier;
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
        // Issue #7: seed the M-of-N floor (tests default to the preprod 2-of-N).
        pallet_intent_settlement::pallet::MinSignerThreshold::<Test>::put(2u32);
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
            mock_pubkey_of(&1),
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
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            mock_pubkey_of(&2),
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
                mock_pubkey_of(&ALICE),
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::NotCommitteeMember
        );
    });
}

#[test]
fn attest_intent_duplicate_pubkey_is_noop() {
    // Two members can no longer share a pubkey (Issue #4 binds pubkey to
    // caller identity), so this test now exercises the dedup guard via the
    // *same* member retrying: the bundle already has member 1's pubkey, the
    // second call is ignored.
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        // Same member 1 retries — dedup by pubkey makes this a no-op.
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
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
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));
        // Third signer arrives late — pallet must treat as no-op.
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(3),
            iid,
            mock_pubkey_of(&3),
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
        mock_pubkey_of(&1),
        [0u8; 64]
    ));
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(2),
        iid,
        mock_pubkey_of(&2),
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
            (mock_pubkey_of(&1), [0u8; 64]),
            (mock_pubkey_of(&2), [0u8; 64]),
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
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid2,
            mock_pubkey_of(&2),
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
            false,
            mock_settle_sigs()
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
            true,
            mock_settle_sigs()
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
                false,
                mock_settle_sigs()
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
                false,
                mock_settle_sigs()
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
            tx,
            mock_credit_sigs()
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
                tx,
                mock_credit_sigs()
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
                [0u8; 32],
                mock_credit_sigs()
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
        min_signer_threshold: 0,
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
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid2,
            mock_pubkey_of(&2),
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
                mock_pubkey_of(&1),
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
            false,
            mock_settle_sigs()
        ));
        let after =
            pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert!(after.outstanding_coverage_ada < before.outstanding_coverage_ada);
    });
}

// ---------------------------------------------------------------------------
// Issue #4 — attest_intent caller/pubkey binding
// ---------------------------------------------------------------------------

#[test]
fn test_attest_intent_rejects_caller_pubkey_mismatch() {
    // Alice (account 1) tries to attest "from" Bob's (account 2) pubkey — in
    // the pre-fix code this was a silent accept, letting one caller push
    // N committee votes. After Issue #4 it is rejected with
    // `CallerPubkeyMismatch` before any storage mutation.
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_noop!(
            IntentSettlement::attest_intent(
                RuntimeOrigin::signed(1),           // caller = member 1
                iid,
                mock_pubkey_of(&2),                 // pubkey derived from 2
                [0u8; 64]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::CallerPubkeyMismatch
        );
        // PendingAttestations must be empty — rejection is pre-mutation.
        let b = pallet_intent_settlement::pallet::PendingAttestations::<Test>::get(iid);
        assert_eq!(b.len(), 0);
    });
}

#[test]
fn test_attest_intent_accepts_matching_pubkey() {
    // Positive counterpart: same-origin + derived-pubkey is still accepted.
    new_test_ext().execute_with(|| {
        let iid = submit_and_get_id(ALICE);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
    });
}

// ---------------------------------------------------------------------------
// Issue #5 — outstanding_coverage accounting symmetry + overflow guard
// ---------------------------------------------------------------------------

#[test]
fn test_outstanding_coverage_symmetric_accounting() {
    // Reproduces the drift scenario from the issue brief: submit many intents,
    // voucher+settle ONE, expire the rest. The pre-fix batch-sum semantics
    // inflated `outstanding_coverage_ada` to sum(awarded), so settle-1 left
    // (N-1)x residue. After Issue #5 the counter is symmetric and settling
    // the only vouchered intent returns it to zero.
    new_test_ext().execute_with(|| {
        let per_intent = 50u64;
        let n = 5u64;

        // Submit N RequestPayout intents (no credit needed, no pool cap impact).
        let mut iids = Vec::with_capacity(n as usize);
        for i in 0..n {
            let kind = IntentKind::RequestPayout {
                policy_id: H256::from([i as u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![i as u8; 8]).unwrap(),
            };
            let iid = intent_id_for(ALICE, i, &kind, 1);
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                kind
            ));
            iids.push(iid);
        }

        // Attest + voucher+settle only iids[0]. The rest TTL-expire.
        let iid0 = iids[0];
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid0,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid0,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));

        let claim_id = H256::from([0xCC; 32]);
        // Note: fairness_proof sums across ALL sorted intents in the batch,
        // so we pass n * per_intent as the batch total; the SINGLE voucher's
        // amount_ada is just `per_intent`. Pre-fix code added n*per_intent
        // into outstanding_coverage; post-fix adds per_intent.
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: {
                let mut v = iids.clone();
                v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                BoundedVec::try_from(v).unwrap()
            },
            requested_amounts_ada: BoundedVec::try_from(vec![per_intent; n as usize])
                .unwrap(),
            pool_balance_ada: per_intent * n * 10,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![per_intent; n as usize])
                .unwrap(),
        };
        let voucher = good_voucher(claim_id, &bfpr, per_intent);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid0,
            voucher,
            bfpr
        ));
        let mid = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_eq!(
            mid.outstanding_coverage_ada, per_intent,
            "post-fix: only the single claim's amount is counted, not the full batch sum"
        );

        // Settle the one claim. Counter returns to 0.
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(1),
            claim_id,
            [0xDE; 32],
            false,
            mock_settle_sigs()
        ));
        let final_ = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_eq!(
            final_.outstanding_coverage_ada, 0,
            "symmetric: request_voucher(+amount) and settle_claim(-amount) balance exactly"
        );
    });
}

#[test]
fn test_outstanding_coverage_overflow_rejected() {
    // Seed outstanding_coverage near u64::MAX; a voucher whose amount_ada
    // would push it past u64::MAX must be rejected with CoverageOverflow,
    // not silently wrap.
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::pallet::PoolUtilization::<Test>::mutate(|u| {
            u.outstanding_coverage_ada = u64::MAX - 10;
        });

        let iid = attested_intent();
        let claim_id = H256::from([0xAA; 32]);
        // voucher.amount_ada = 1_000 > remaining headroom (10) → overflow.
        let bfpr = good_fairness_proof(iid, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        let before = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr
            ),
            pallet_intent_settlement::pallet::Error::<Test>::CoverageOverflow
        );
        let after = pallet_intent_settlement::pallet::PoolUtilization::<Test>::get();
        assert_eq!(
            before.outstanding_coverage_ada, after.outstanding_coverage_ada,
            "no storage mutation on overflow reject"
        );
        // Claim must not exist either.
        assert!(
            !pallet_intent_settlement::pallet::Claims::<Test>::contains_key(claim_id)
        );
    });
}

// ---------------------------------------------------------------------------
// Issue #6 — PendingBatches index maintenance
// ---------------------------------------------------------------------------

#[test]
fn test_pending_batches_index_is_maintained() {
    // Submit 3 intents, voucher one, expire one, the remaining must be the
    // only one in the `PendingBatches` index AND the only one returned by
    // get_pending_batches (after being attested). The prior implementation
    // iterated Intents::iter() which grew with every submit historically;
    // this check proves the index tracks real work, not churn.
    new_test_ext().execute_with(|| {
        // Submit 3.
        let k1 = IntentKind::RequestPayout {
            policy_id: H256::from([1u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let k2 = IntentKind::RequestPayout {
            policy_id: H256::from([2u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let k3 = IntentKind::RequestPayout {
            policy_id: H256::from([3u8; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0u8; 8]).unwrap(),
        };
        let iid1 = intent_id_for(ALICE, 0, &k1, 1);
        let iid2 = intent_id_for(ALICE, 1, &k2, 1);
        let iid3 = intent_id_for(ALICE, 2, &k3, 1);
        assert_ok!(IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), k1));
        assert_ok!(IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), k2));
        assert_ok!(IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), k3));

        // Index now contains all 3.
        let pb = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb.len(), 3);
        assert!(pb.contains(&iid1));
        assert!(pb.contains(&iid2));
        assert!(pb.contains(&iid3));

        // Expire iid2 via expire_policy_mirror.
        assert_ok!(IntentSettlement::expire_policy_mirror(
            RuntimeOrigin::signed(1),
            iid2
        ));
        let pb_after_expire =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_after_expire.len(), 2);
        assert!(!pb_after_expire.contains(&iid2));

        // Attest + voucher iid1 → transitions out of PendingBatches (Vouchered
        // is beyond the keeper's Attested window).
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid1,
            mock_pubkey_of(&1),
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(2),
            iid1,
            mock_pubkey_of(&2),
            [0u8; 64]
        ));
        let claim_id = H256::from([0xAA; 32]);
        let bfpr = good_fairness_proof(iid1, 1_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000);
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            claim_id,
            iid1,
            voucher,
            bfpr
        ));
        let pb_final =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_final.len(), 1);
        assert_eq!(pb_final[0], iid3);
    });
}

#[test]
fn test_get_pending_batches_iterates_index_not_intents_map() {
    // Plant a stale Intents entry WITHOUT an index record (simulating what
    // a bad pre-migration state might look like) and confirm that
    // get_pending_batches returns 0 — proving the fn reads the index.
    new_test_ext().execute_with(|| {
        let rogue_id = H256::from([0xEE; 32]);
        let rogue_intent = Intent::<u64> {
            submitter: ALICE,
            nonce: 0,
            kind: IntentKind::RequestPayout {
                policy_id: H256::from([0x77; 32]),
                oracle_evidence: BoundedVec::try_from(vec![0u8; 4]).unwrap(),
            },
            submitted_block: 1,
            ttl_block: 1 + 600,
            status: IntentStatus::Attested,
        };
        pallet_intent_settlement::pallet::Intents::<Test>::insert(
            rogue_id,
            rogue_intent,
        );
        // Index is still empty — no submit_intent was called.
        let out = pallet_intent_settlement::pallet::Pallet::<Test>::get_pending_batches(
            0, 10,
        );
        assert_eq!(
            out.len(), 0,
            "get_pending_batches must read the PendingBatches index, NOT Intents::iter()"
        );
    });
}

#[test]
fn test_pending_batches_bounded() {
    // MaxPendingBatches in the test runtime is 16; submit 16 successfully
    // then the 17th must hit PendingBatchesFull with no state mutation.
    new_test_ext().execute_with(|| {
        for i in 0..16u64 {
            let kind = IntentKind::RequestPayout {
                policy_id: H256::from([(i + 1) as u8; 32]),
                oracle_evidence: BoundedVec::try_from(vec![i as u8; 8]).unwrap(),
            };
            assert_ok!(IntentSettlement::submit_intent(
                RuntimeOrigin::signed(ALICE),
                kind
            ));
        }
        let pb_full = pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_full.len(), 16);

        // 17th rejected.
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([0xFE; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0xFE; 8]).unwrap(),
        };
        assert_noop!(
            IntentSettlement::submit_intent(RuntimeOrigin::signed(ALICE), kind),
            pallet_intent_settlement::pallet::Error::<Test>::PendingBatchesFull
        );
        // Index unchanged — still 16.
        let pb_after =
            pallet_intent_settlement::pallet::PendingBatches::<Test>::get();
        assert_eq!(pb_after.len(), 16);
        // Nonces unchanged past 16 (i.e. the rejected call did not bump it).
        assert_eq!(
            pallet_intent_settlement::pallet::Nonces::<Test>::get(ALICE),
            16
        );
    });
}

// ---------------------------------------------------------------------------
// Issue #7 — M-of-N signature gate on credit_deposit + settle_claim
// ---------------------------------------------------------------------------

#[test]
fn test_credit_deposit_rejects_below_threshold() {
    // With MinSignerThreshold = 2 (preprod default), one signature must
    // fail with InsufficientSignatures.
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                1_000_000,
                [0xAB; 32],
                vec![mock_sig_for(1)] // only 1 signer
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
        // Credits unchanged.
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            0
        );
    });
}

#[test]
fn test_credit_deposit_accepts_threshold() {
    // Two valid signatures from distinct members on the canonical payload.
    new_test_ext().execute_with(|| {
        assert_ok!(IntentSettlement::credit_deposit(
            RuntimeOrigin::signed(1),
            ALICE,
            2_000_000,
            [0xCD; 32],
            vec![mock_sig_for(1), mock_sig_for(2)]
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::Credits::<Test>::get(ALICE),
            2_000_000
        );
    });
}

#[test]
fn test_settle_claim_rejects_below_threshold() {
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
        // Only one signer: rejected.
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(1),
                claim_id,
                [0xFF; 32],
                false,
                vec![mock_sig_for(1)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
        // Claim state NOT mutated.
        let claim = pallet_intent_settlement::pallet::Claims::<Test>::get(claim_id)
            .unwrap();
        assert!(!claim.settled);
    });
}

#[test]
fn test_multisig_duplicate_signers_rejected() {
    // Member 1's sig twice — must be rejected as DuplicateSigner so that
    // "2-of-2 by one caller pasting the same sig" can't pass the bar.
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100_000,
                [0x11; 32],
                vec![mock_sig_for(1), mock_sig_for(1)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::DuplicateSigner
        );
    });
}

#[test]
fn test_multisig_caller_must_be_one_of_the_signers() {
    // Member 3 calls the extrinsic but the signature bundle is from 1+2
    // only — even though it's a valid 2-of-3 by signer-count, the origin-
    // binding check rejects it so stale bundles can't be replayed.
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(3),
                ALICE,
                100_000,
                [0x22; 32],
                vec![mock_sig_for(1), mock_sig_for(2)]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InsufficientSignatures
        );
    });
}

#[test]
fn test_multisig_non_committee_signer_rejected() {
    // Craft a signature envelope with a pubkey that isn't in the committee.
    new_test_ext().execute_with(|| {
        let rogue = ([0xFFu8; 32], [0xFFu8; 64]);
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100_000,
                [0x33; 32],
                vec![mock_sig_for(1), rogue]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::SignerNotCommitteeMember
        );
    });
}

#[test]
fn test_multisig_invalid_signature_rejected() {
    // A signature that fails MockSigVerifier::verify (wrong marker byte) is
    // rejected with InvalidSignature.
    new_test_ext().execute_with(|| {
        let bad = (mock_pubkey_of(&2), [0u8; 64]); // marker mismatch
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100_000,
                [0x44; 32],
                vec![mock_sig_for(1), bad]
            ),
            pallet_intent_settlement::pallet::Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn test_set_min_signer_threshold_root_only() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            IntentSettlement::set_min_signer_threshold(RuntimeOrigin::signed(1), 3),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(IntentSettlement::set_min_signer_threshold(
            RuntimeOrigin::root(),
            3
        ));
        assert_eq!(
            pallet_intent_settlement::pallet::MinSignerThreshold::<Test>::get(),
            3
        );
    });
}

// Sanity: the canonical payload hashers are deterministic + domain-separated.
#[test]
fn test_multisig_payload_hashers_domain_separated() {
    let a = credit_deposit_payload(&[7u8; 32], 1_000, &[1u8; 32]);
    let b = credit_deposit_payload(&[7u8; 32], 1_000, &[1u8; 32]);
    let c = settle_claim_payload(&H256::from([7u8; 32]), &[1u8; 32], false);
    assert_eq!(a, b);
    assert_ne!(a, c);
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
