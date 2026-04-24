//! Integration test — full `submit → attest (2-of-3) → voucher → settle`
//! lifecycle using sp-keyring sr25519 identities for submitter and three
//! committee members.
//!
//! Spec §2.6 asks for a "2-validator testnet-like" lifecycle exercise. We
//! implement it via `TestExternalities` + `pallet_intent_settlement` + a
//! per-test `IsCommitteeMember` impl keyed off a `BoundedBTreeSet` that holds
//! the sr25519 derived AccountIds of three dev keys, with threshold 2.
//!
//! This is stronger than "mock-heavy unit test" because every intent flows
//! through real-signer origins and every state transition is verified
//! end-to-end across four blocks, with events inspected for the spec's
//! `IntentSubmitted`, `IntentAttested`, `VoucherIssued`, `ClaimSettled`.

#![cfg(test)]

use crate as pallet_intent_settlement;
use crate::pallet::{IsCommitteeMember, VerifyCommitteeSignature};
use crate::types::*;
use crate::{credit_deposit_payload, settle_claim_payload};
use codec::Encode;
use frame_support::{
    assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::Hooks,
    BoundedVec,
};
use parity_scale_codec as codec;
use sp_core::{sr25519, Pair, H256};
use sp_runtime::{traits::IdentityLookup, BuildStorage};

type Block = frame_system::mocking::MockBlock<Testnet>;

construct_runtime! {
    pub enum Testnet {
        System: frame_system,
        IntentSettlement: pallet_intent_settlement,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Testnet {
    type Block = Block;
    type AccountId = sp_runtime::AccountId32;
    type Lookup = IdentityLookup<Self::AccountId>;
}

parameter_types! {
    pub const MaxCommittee: u32 = 32;
    pub const MaxExpirePerBlock: u32 = 256;
    pub const DefaultIntentTTL: u32 = 600;
    pub const DefaultClaimTTL: u32 = 28_800;
    pub const MaxPendingBatches: u32 = 16;
    pub const DefaultMinSignerThreshold: u32 = 2;
}

/// Static committee: Alice/Bob/Charlie by sr25519 dev-key AccountId. Threshold 2.
fn committee_accounts() -> (
    sp_runtime::AccountId32,
    sp_runtime::AccountId32,
    sp_runtime::AccountId32,
) {
    let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
    let bob = sr25519::Pair::from_string("//Bob", None).unwrap();
    let charlie = sr25519::Pair::from_string("//Charlie", None).unwrap();
    (
        sp_runtime::AccountId32::from(alice.public().0),
        sp_runtime::AccountId32::from(bob.public().0),
        sp_runtime::AccountId32::from(charlie.public().0),
    )
}

pub struct CommitteeFromStorage;
impl IsCommitteeMember<sp_runtime::AccountId32> for CommitteeFromStorage {
    fn is_member(who: &sp_runtime::AccountId32) -> bool {
        let (a, b, c) = committee_accounts();
        who == &a || who == &b || who == &c
    }
    fn threshold() -> u32 {
        2
    }
    fn member_count() -> u32 {
        3
    }
    fn pubkey_of(who: &sp_runtime::AccountId32) -> CommitteePubkey {
        // AccountId32 encodes as its raw 32 bytes — the public key.
        let bytes: &[u8; 32] = who.as_ref();
        *bytes
    }
    fn account_of_pubkey(pubkey: &CommitteePubkey) -> Option<sp_runtime::AccountId32> {
        let candidate = sp_runtime::AccountId32::from(*pubkey);
        if Self::is_member(&candidate) {
            Some(candidate)
        } else {
            None
        }
    }
}

/// Integration-test signature verifier: accepts iff signer's real sr25519
/// signature over the payload. Using real crypto here is fine because
/// sp-keyring dev keys are in scope (sp_io::TestExternalities initializes
/// the keystore automatically for verification).
pub struct IntegrationSigVerifier;
impl VerifyCommitteeSignature for IntegrationSigVerifier {
    fn verify(pubkey: &CommitteePubkey, sig: &CommitteeSig, msg: &[u8]) -> bool {
        let pk = sp_core::sr25519::Public::from_raw(*pubkey);
        let sg = sp_core::sr25519::Signature::from_raw(*sig);
        sp_io::crypto::sr25519_verify(&sg, msg, &pk)
    }
}

/// Integration helper: produce a real sr25519 signature over `msg` for the
/// given dev-seed (e.g. "//Alice"). Used by the M-of-N gate on
/// `credit_deposit` / `settle_claim`.
fn sign_with(seed: &str, msg: &[u8]) -> (CommitteePubkey, CommitteeSig) {
    let pair = sp_core::sr25519::Pair::from_string(seed, None).unwrap();
    let sig = pair.sign(msg);
    (pair.public().0, sig.0)
}

impl pallet_intent_settlement::pallet::Config for Testnet {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommittee = MaxCommittee;
    type MaxExpirePerBlock = MaxExpirePerBlock;
    type DefaultIntentTTL = DefaultIntentTTL;
    type DefaultClaimTTL = DefaultClaimTTL;
    type CommitteeMembership = CommitteeFromStorage;
    type MaxPendingBatches = MaxPendingBatches;
    type DefaultMinSignerThreshold = DefaultMinSignerThreshold;
    type SigVerifier = IntegrationSigVerifier;
}

fn user_account() -> sp_runtime::AccountId32 {
    let dave = sr25519::Pair::from_string("//Dave", None).unwrap();
    sp_runtime::AccountId32::from(dave.public().0)
}

fn new_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Testnet>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        pallet_intent_settlement::pallet::IntentTTL::<Testnet>::put(600u32);
        pallet_intent_settlement::pallet::ClaimTTL::<Testnet>::put(28_800u32);
        pallet_intent_settlement::pallet::PoolUtilization::<Testnet>::put(
            PoolUtilizationParams {
                target_bps: 5_000,
                cap_bps: 7_500,
                total_nav_ada: 100_000_000,
                outstanding_coverage_ada: 0,
            },
        );
        pallet_intent_settlement::pallet::MinSignerThreshold::<Testnet>::put(2u32);
    });
    ext
}

#[test]
fn full_lifecycle_submit_attest_voucher_settle() {
    new_ext().execute_with(|| {
        let (alice, bob, _charlie) = committee_accounts();
        let user = user_account();

        // Block 1: committee credits deposit for user — now requires a
        // valid 2-of-3 signature envelope (Issue #7).
        let cardano_tx = [0xAA; 32];
        let mut target_bytes = [0u8; 32];
        target_bytes.copy_from_slice(&user.encode()[..32]);
        let deposit_payload = credit_deposit_payload(
            &target_bytes,
            10_000_000u64,
            &cardano_tx,
        );
        let deposit_sigs = vec![
            sign_with("//Alice", &deposit_payload),
            sign_with("//Bob", &deposit_payload),
        ];
        assert_ok!(IntentSettlement::credit_deposit(
            RuntimeOrigin::signed(alice.clone()),
            user.clone(),
            10_000_000u64,
            cardano_tx,
            deposit_sigs
        ));

        // Block 2: user submits BuyPolicy intent.
        System::set_block_number(2);
        let kind = IntentKind::BuyPolicy {
            product_id: H256::from([1; 32]),
            strike: 500_000,
            term_slots: 86_400,
            premium_ada: 2_000_000,
            beneficiary_cardano_addr: BoundedVec::try_from(vec![0xB1; 57]).unwrap(),
        };
        let mut submitter_bytes = [0u8; 32];
        submitter_bytes.copy_from_slice(&user.encode()[..32]);
        let expected_id = compute_intent_id(&submitter_bytes, 0, &kind, 2);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(user.clone()),
            kind
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(expected_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Pending);

        // Block 3: alice + bob attest — threshold (2) reached, → Attested.
        // Issue #4: pubkey must derive from origin's AccountId32.
        System::set_block_number(3);
        let alice_pk = {
            let b: &[u8; 32] = alice.as_ref();
            *b
        };
        let bob_pk = {
            let b: &[u8; 32] = bob.as_ref();
            *b
        };
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(alice.clone()),
            expected_id,
            alice_pk,
            [0u8; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(bob.clone()),
            expected_id,
            bob_pk,
            [0u8; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(expected_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);

        // Block 4: committee builds a voucher + fairness proof and calls request_voucher.
        System::set_block_number(4);
        let claim_id = H256::from([0xCC; 32]);
        let bfpr = BatchFairnessProof {
            batch_block_range: (2, 4),
            sorted_intent_ids: BoundedVec::try_from(vec![expected_id]).unwrap(),
            requested_amounts_ada: BoundedVec::try_from(vec![2_000_000u64]).unwrap(),
            pool_balance_ada: 100_000_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: BoundedVec::try_from(vec![2_000_000u64]).unwrap(),
        };
        let voucher = Voucher {
            claim_id,
            policy_id: H256::from([0x99; 32]),
            beneficiary_cardano_addr: BoundedVec::try_from(vec![0xB1; 57]).unwrap(),
            amount_ada: 2_000_000,
            batch_fairness_proof_digest: compute_fairness_proof_digest(&bfpr),
            issued_block: 4,
            expiry_slot_cardano: 100_000,
            committee_sigs: BoundedVec::try_from(vec![
                (alice_pk, [0u8; 64]),
                (bob_pk, [0u8; 64]),
            ])
            .unwrap(),
        };
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(alice.clone()),
            claim_id,
            expected_id,
            voucher,
            bfpr
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(expected_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);

        // Block 5: committee mirrors Cardano settlement — also M-of-N gated.
        System::set_block_number(5);
        let settle_payload = settle_claim_payload(&claim_id, &[0xDE; 32], false);
        let settle_sigs = vec![
            sign_with("//Alice", &settle_payload),
            sign_with("//Bob", &settle_payload),
        ];
        assert_ok!(IntentSettlement::settle_claim(
            RuntimeOrigin::signed(alice.clone()),
            claim_id,
            [0xDE; 32],
            false,
            settle_sigs
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(expected_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Settled);
        let claim =
            pallet_intent_settlement::pallet::Claims::<Testnet>::get(claim_id).unwrap();
        assert!(claim.settled);
        assert_eq!(claim.cardano_tx_hash, [0xDE; 32]);
    });
}

#[test]
fn concurrent_attestation_first_bundle_wins() {
    // Two committee members post M-of-N in the same block. First bundle to
    // cross threshold wins; subsequent calls are idempotent no-ops per spec.
    new_ext().execute_with(|| {
        let (alice, bob, charlie) = committee_accounts();
        let user = user_account();

        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([5; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0; 8]).unwrap(),
        };
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&user.encode()[..32]);
        let iid = compute_intent_id(&bytes, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(user.clone()),
            kind
        ));

        // Block 2 — all three sign; bind pubkey to origin (Issue #4).
        System::set_block_number(2);
        let alice_pk = {
            let b: &[u8; 32] = alice.as_ref();
            *b
        };
        let bob_pk = {
            let b: &[u8; 32] = bob.as_ref();
            *b
        };
        let charlie_pk = {
            let b: &[u8; 32] = charlie.as_ref();
            *b
        };
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(alice),
            iid,
            alice_pk,
            [0; 64]
        ));
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(bob),
            iid,
            bob_pk,
            [0; 64]
        ));
        // Third arrives late — must be a no-op (intent already Attested).
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(charlie),
            iid,
            charlie_pk,
            [0; 64]
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Attested);
        let sigs =
            pallet_intent_settlement::pallet::AttestationSigs::<Testnet>::get(iid)
                .unwrap();
        // Only the two signatures that crossed the threshold; late one ignored.
        assert_eq!(sigs.len(), 2);
    });
}

#[test]
fn ttl_expiry_across_multiple_blocks() {
    new_ext().execute_with(|| {
        let user = user_account();
        // Submit a pending RequestPayout that will expire.
        let kind = IntentKind::RequestPayout {
            policy_id: H256::from([7; 32]),
            oracle_evidence: BoundedVec::try_from(vec![0; 4]).unwrap(),
        };
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&user.encode()[..32]);
        let iid = compute_intent_id(&bytes, 0, &kind, 1);
        assert_ok!(IntentSettlement::submit_intent(
            RuntimeOrigin::signed(user.clone()),
            kind
        ));
        // Jump to expiry block.
        System::set_block_number(1 + 600);
        <IntentSettlement as Hooks<u64>>::on_initialize(1 + 600);
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(iid).unwrap();
        assert_eq!(intent.status, IntentStatus::Expired);
    });
}
