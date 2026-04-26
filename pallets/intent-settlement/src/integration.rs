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
use crate::{credit_deposit_payload, request_voucher_payload, settle_claim_payload};
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
    /// Task #177: max settle_batch_atomic size in the integration runtime.
    pub const MaxSettleBatch: u32 = 256;
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
    type MaxSettleBatch = MaxSettleBatch;
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
        // Task #174: M-of-N committee sigs over the canonical
        // request_voucher pre-image (b"RVCH" || claim_id || intent_id ||
        // voucher_digest || bfpr_digest).
        let voucher_digest = crate::types::compute_voucher_digest(&voucher);
        let bfpr_digest = crate::types::compute_fairness_proof_digest(&bfpr);
        let voucher_payload = request_voucher_payload(
            &claim_id,
            &expected_id,
            &voucher_digest,
            &bfpr_digest,
        );
        let voucher_sigs = vec![
            sign_with("//Alice", &voucher_payload),
            sign_with("//Bob", &voucher_payload),
        ];
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(alice.clone()),
            claim_id,
            expected_id,
            voucher,
            bfpr,
            voucher_sigs
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

// ---------------------------------------------------------------------------
// Task #174 — `request_voucher` integration tests with real sr25519 sigs.
//
// These exercise the new M-of-N gate against the Testnet runtime
// (`AccountId32` + real sr25519, no MockSigVerifier shortcuts). The unit
// tests in `tests.rs` use a deterministic stub for the sig verifier; here
// we sign the canonical pre-image with sp_core::Pair and let the real
// sp_io::crypto::sr25519_verify path run inside the pallet.
//
// Each test maps to one of the brief's 10-item list (T1–T10). T1 (4-arg
// decode error) is a wire-format property exercised at the chain-RPC layer
// and isn't representable in a Rust integration suite where the symbol
// only exists in its 5-arg form on this branch.
// ---------------------------------------------------------------------------

/// Build an Attested intent + voucher + bfpr + canonical request_voucher
/// pre-image. Reused by every Task #174 integration test below.
fn rv_setup_attested(
    user: &sp_runtime::AccountId32,
) -> (
    IntentId,
    ClaimId,
    BatchFairnessProof,
    Voucher,
    [u8; 32], // request_voucher payload digest
) {
    let (alice, bob, _charlie) = committee_accounts();
    // 1. user submits BuyPolicy.
    let kind = IntentKind::BuyPolicy {
        product_id: H256::from([1; 32]),
        strike: 500_000,
        term_slots: 86_400,
        premium_ada: 2_000_000,
        beneficiary_cardano_addr: BoundedVec::try_from(vec![0xB1; 57]).unwrap(),
    };
    let mut submitter_bytes = [0u8; 32];
    submitter_bytes.copy_from_slice(&user.encode()[..32]);
    let intent_id =
        compute_intent_id(&submitter_bytes, 0, &kind, System::block_number() as u32);

    // 2. credit user enough to cover premium (M-of-N over CRDP).
    let cardano_tx = [0xAA; 32];
    let mut target_bytes = [0u8; 32];
    target_bytes.copy_from_slice(&user.encode()[..32]);
    let crdp = credit_deposit_payload(&target_bytes, 10_000_000u64, &cardano_tx);
    let crdp_sigs = vec![sign_with("//Alice", &crdp), sign_with("//Bob", &crdp)];
    assert_ok!(IntentSettlement::credit_deposit(
        RuntimeOrigin::signed(alice.clone()),
        user.clone(),
        10_000_000u64,
        cardano_tx,
        crdp_sigs
    ));

    // 3. submit_intent.
    assert_ok!(IntentSettlement::submit_intent(
        RuntimeOrigin::signed(user.clone()),
        kind
    ));

    // 4. attest 2-of-3.
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
        intent_id,
        alice_pk,
        [0u8; 64]
    ));
    assert_ok!(IntentSettlement::attest_intent(
        RuntimeOrigin::signed(bob.clone()),
        intent_id,
        bob_pk,
        [0u8; 64]
    ));

    // 5. build voucher + bfpr + canonical request_voucher pre-image.
    let claim_id = H256::from([0xCC; 32]);
    let bfpr = BatchFairnessProof {
        batch_block_range: (1, System::block_number() as u32),
        sorted_intent_ids: BoundedVec::try_from(vec![intent_id]).unwrap(),
        requested_amounts_ada: BoundedVec::try_from(vec![2_000_000u64]).unwrap(),
        pool_balance_ada: 100_000_000,
        pro_rata_scale_bps: 10_000,
        awarded_amounts_ada: BoundedVec::try_from(vec![2_000_000u64]).unwrap(),
    };
    let bfpr_digest = compute_fairness_proof_digest(&bfpr);
    let voucher = Voucher {
        claim_id,
        policy_id: H256::from([0x99; 32]),
        beneficiary_cardano_addr: BoundedVec::try_from(vec![0xB1; 57]).unwrap(),
        amount_ada: 2_000_000,
        batch_fairness_proof_digest: bfpr_digest,
        issued_block: System::block_number() as u32,
        expiry_slot_cardano: 100_000,
        committee_sigs: BoundedVec::try_from(vec![
            (alice_pk, [0u8; 64]),
            (bob_pk, [0u8; 64]),
        ])
        .unwrap(),
    };
    let voucher_digest = compute_voucher_digest(&voucher);
    let payload = request_voucher_payload(
        &claim_id,
        &intent_id,
        &voucher_digest,
        &bfpr_digest,
    );
    (intent_id, claim_id, bfpr, voucher, payload)
}

#[test]
fn task174_request_voucher_t2_happy_path_real_sr25519() {
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        let sigs = vec![sign_with("//Alice", &payload), sign_with("//Bob", &payload)];
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(alice),
            claim_id,
            intent_id,
            voucher,
            bfpr,
            sigs
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(intent_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
    });
}

#[test]
fn task174_request_voucher_t3_below_threshold_rejected() {
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        // Only 1 sig (caller-only) when MinSignerThreshold=2.
        let sigs = vec![sign_with("//Alice", &payload)];
        frame_support::assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(alice),
                claim_id,
                intent_id,
                voucher,
                bfpr,
                sigs
            ),
            pallet_intent_settlement::pallet::Error::<Testnet>::InsufficientSignatures
        );
    });
}

#[test]
fn task174_request_voucher_t4_above_threshold_accepted() {
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        let sigs = vec![
            sign_with("//Alice", &payload),
            sign_with("//Bob", &payload),
            sign_with("//Charlie", &payload),
        ];
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(alice),
            claim_id,
            intent_id,
            voucher,
            bfpr,
            sigs
        ));
        let intent =
            pallet_intent_settlement::pallet::Intents::<Testnet>::get(intent_id)
                .unwrap();
        assert_eq!(intent.status, IntentStatus::Vouchered);
    });
}

#[test]
fn task174_request_voucher_t5_bad_sig_over_wrong_preimage_rejected() {
    // Member 2's sig is over a DIFFERENT pre-image (settle_claim's STCL),
    // so sr25519_verify on the request_voucher RVCH digest will fail.
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        let wrong_payload = settle_claim_payload(&claim_id, &[0u8; 32], false);
        let sigs = vec![
            sign_with("//Alice", &payload),
            sign_with("//Bob", &wrong_payload), // wrong digest under the right pubkey
        ];
        frame_support::assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(alice),
                claim_id,
                intent_id,
                voucher,
                bfpr,
                sigs
            ),
            pallet_intent_settlement::pallet::Error::<Testnet>::InvalidSignature
        );
    });
}

#[test]
fn task174_request_voucher_t6_non_committee_signer_rejected() {
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        // //Dave is not in committee_accounts() — only Alice/Bob/Charlie are.
        let dave_sig = sign_with("//Dave", &payload);
        let sigs = vec![sign_with("//Alice", &payload), dave_sig];
        frame_support::assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(alice),
                claim_id,
                intent_id,
                voucher,
                bfpr,
                sigs
            ),
            pallet_intent_settlement::pallet::Error::<Testnet>::SignerNotCommitteeMember
        );
    });
}

#[test]
fn task174_request_voucher_t7_duplicate_signer_rejected() {
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        // Alice signs twice — distinct sig instances (sr25519 sigs are
        // randomized) but the pubkey is the same, so DuplicateSigner fires.
        let sigs = vec![
            sign_with("//Alice", &payload),
            sign_with("//Alice", &payload),
        ];
        frame_support::assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(alice),
                claim_id,
                intent_id,
                voucher,
                bfpr,
                sigs
            ),
            pallet_intent_settlement::pallet::Error::<Testnet>::DuplicateSigner
        );
    });
}

#[test]
fn task174_request_voucher_t8_caller_not_in_bundle_rejected_epoch_proxy() {
    // Brief T8 maps to "sigs from old epoch's committee but the runtime is
    // now in a new epoch → reject". Our pallet doesn't carry an explicit
    // committee_epoch in the pre-image (per feedback_mofn_hash_determinism
    // we only use chain-derived state), so the equivalent guard is:
    // ensure_threshold_signatures requires the *origin* to be in the sig
    // bundle. After a committee rotation, a stale bundle posted by a
    // current member who wasn't on the prior committee fails this check.
    // We exercise that here: Charlie calls request_voucher with a bundle
    // signed by Alice + Bob only.
    new_ext().execute_with(|| {
        let user = user_account();
        let (_alice, _bob, charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, payload) = rv_setup_attested(&user);
        let sigs = vec![sign_with("//Alice", &payload), sign_with("//Bob", &payload)];
        frame_support::assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(charlie),
                claim_id,
                intent_id,
                voucher,
                bfpr,
                sigs
            ),
            pallet_intent_settlement::pallet::Error::<Testnet>::InsufficientSignatures
        );
    });
}

#[test]
fn task174_request_voucher_t9_preimage_determinism_across_operators() {
    // Two "operators" independently compute the request_voucher pre-image
    // from the same on-chain state and produce two sigs. The pallet
    // accepts the bundle iff both digests match — which is the regression
    // target for `feedback_mofn_hash_determinism.md` (no operator-local
    // wall-clock or attestation_level in the pre-image).
    new_ext().execute_with(|| {
        let user = user_account();
        let (alice, _bob, _charlie) = committee_accounts();
        let (intent_id, claim_id, bfpr, voucher, _payload) =
            rv_setup_attested(&user);

        // Operator 1 (Alice): recomputes pre-image from scratch.
        let voucher_digest_1 = compute_voucher_digest(&voucher);
        let bfpr_digest_1 = compute_fairness_proof_digest(&bfpr);
        let payload_1 = request_voucher_payload(
            &claim_id,
            &intent_id,
            &voucher_digest_1,
            &bfpr_digest_1,
        );
        let alice_sig = sign_with("//Alice", &payload_1);

        // Operator 2 (Bob): same recompute, must produce byte-identical digest.
        let voucher_digest_2 = compute_voucher_digest(&voucher);
        let bfpr_digest_2 = compute_fairness_proof_digest(&bfpr);
        let payload_2 = request_voucher_payload(
            &claim_id,
            &intent_id,
            &voucher_digest_2,
            &bfpr_digest_2,
        );
        assert_eq!(
            payload_1, payload_2,
            "two operators MUST derive byte-identical pre-image (mofn-hash-determinism rule)"
        );
        let bob_sig = sign_with("//Bob", &payload_2);

        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(alice),
            claim_id,
            intent_id,
            voucher,
            bfpr,
            vec![alice_sig, bob_sig]
        ));
    });
}
