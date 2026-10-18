//! FRAME benchmarks for settlement mutation and threshold verification.
//! The signature benchmark explicitly uses real sr25519 verification.
//! Reproduction and sample bounds: docs/settlement-genesis-safety.md.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::pallet::{BalanceOf, Call, Config, IsCommitteeMember};
use frame_benchmarking::v2::*;
use frame_support::traits::{Currency, Get, NamedReservableCurrency};
use frame_system::pallet_prelude::BlockNumberFor;
use frame_system::RawOrigin;
use sp_runtime::traits::{AccountIdConversion, Saturating};
use sp_std::vec::Vec;

const MAX_BATCH_BENCH: u32 = 256;
const SIGNER_KEY_TYPE: sp_core::crypto::KeyTypeId = sp_core::crypto::KeyTypeId(*b"sett");

/// Sets `who`'s free balance to `amount` plus the existential deposit and
/// returns `amount` as a Currency balance.
fn fund_bond<T: Config>(who: &T::AccountId, amount: u128) -> BalanceOf<T> {
    let amount: BalanceOf<T> = amount
        .try_into()
        .ok()
        .expect("benchmark bond fits Currency balance");
    let _ = T::Currency::make_free_balance_be(
        who,
        amount.saturating_add(T::Currency::minimum_balance()),
    );
    amount
}

const BENCH_PRODUCT: PolicyId = PolicyId::repeat_byte(0x88);

/// A distinct 32-byte id: `index` big-endian, then `tag`.
fn bench_id(tag: &[u8; 4], index: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&index.to_be_bytes());
    id[4..8].copy_from_slice(tag);
    id
}

/// A BuyPolicy with the longest beneficiary address: the costliest kind to
/// submit, the only one that checks pool use, and refundable on expiry.
fn buy_policy(index: u32) -> IntentKind {
    IntentKind::BuyPolicy {
        product_id: BENCH_PRODUCT,
        strike: index.into(),
        term_slots: 86_400,
        premium_ada: 1_000,
        beneficiary_cardano_addr: frame_support::BoundedVec::try_from(
            sp_std::vec![0xB1u8; MAX_CARDANO_ADDR as usize],
        )
        .expect("MAX_CARDANO_ADDR bytes"),
    }
}

fn seed_intent<T: Config>(intent_id: IntentId, status: IntentStatus) {
    crate::pallet::Intents::<T>::insert(
        intent_id,
        Intent {
            submitter: whitelisted_caller(),
            nonce: 0,
            kind: buy_policy(0),
            submitted_block: 1,
            ttl_block: 1_000_000,
            status,
        },
    );
}

/// Fills `PendingBatches` to capacity less `room`, with `last` at the end:
/// the longest scan their removal can take.
fn fill_pending_batches<T: Config>(last: &[IntentId], room: u32) {
    let capacity = <T as Config>::MaxPendingBatches::get();
    let fillers = capacity
        .saturating_sub(room)
        .saturating_sub(last.len() as u32);
    let mut pending: Vec<IntentId> = (0..fillers)
        .map(|index| IntentId::from(bench_id(b"PEND", index)))
        .collect();
    pending.extend_from_slice(last);
    crate::pallet::PendingBatches::<T>::put(
        frame_support::BoundedVec::try_from(pending).expect("at most MaxPendingBatches entries"),
    );
}

/// Asserts the measured call left `PendingBatches` exactly `room` short of
/// capacity, so every push or removal it timed actually happened.
fn assert_pending_room<T: Config>(room: u32) {
    let len = crate::pallet::PendingBatches::<T>::get().len() as u32;
    assert_eq!(
        len,
        <T as Config>::MaxPendingBatches::get().saturating_sub(room)
    );
}

fn assert_status<T: Config>(intent_id: IntentId, status: IntentStatus) {
    assert_eq!(
        crate::pallet::Intents::<T>::get(intent_id)
            .expect("intent")
            .status,
        status
    );
}

fn assert_settled<T: Config>(claim_id: ClaimId) {
    assert!(
        crate::pallet::Claims::<T>::get(claim_id)
            .expect("claim")
            .settled
    );
    assert_status::<T>(intent_of::<T>(claim_id), IntentStatus::Settled);
}

/// Funds `caller` for `n` BuyPolicy premiums and leaves room for exactly `n`
/// submissions in `PendingBatches` and in the expiry slot they land in.
fn prepare_submission<T: Config>(caller: &T::AccountId, n: u32)
where
    BlockNumberFor<T>: Into<u64> + Copy,
{
    use crate::pallet::{Credits, ExpiryQueue, IntentTTL, PoolUtilization};
    Credits::<T>::insert(caller, 1_000u64.saturating_mul(n.into()));
    PoolUtilization::<T>::put(PoolUtilizationParams {
        target_bps: 10_000,
        cap_bps: 10_000,
        total_nav_ada: u64::MAX / 20_000,
        outstanding_coverage_ada: 0,
    });
    fill_pending_batches::<T>(&[], n);
    let now: u32 = <frame_system::Pallet<T>>::block_number()
        .into()
        .try_into()
        .unwrap_or(u32::MAX);
    let ttl = match IntentTTL::<T>::get() {
        0 => T::DefaultIntentTTL::get(),
        ttl => ttl,
    };
    let queued: Vec<IntentId> = (0..MAX_EXPIRE_PER_BLOCK.saturating_sub(n))
        .map(|index| IntentId::from(bench_id(b"QUEU", index)))
        .collect();
    ExpiryQueue::<T>::insert(
        now.saturating_add(ttl),
        frame_support::BoundedVec::try_from(queued).expect("below MAX_EXPIRE_PER_BLOCK"),
    );
}

/// A fairness proof at `MAX_BATCH` entries, the largest to validate and hash.
fn full_fairness_proof() -> BatchFairnessProof {
    let ids: Vec<IntentId> = (0..MAX_BATCH)
        .map(|index| IntentId::from(bench_id(b"BFPR", index)))
        .collect();
    let amounts = sp_std::vec![1_000u64; MAX_BATCH as usize];
    BatchFairnessProof {
        batch_block_range: (1, 1),
        sorted_intent_ids: frame_support::BoundedVec::try_from(ids).expect("MAX_BATCH ids"),
        requested_amounts_ada: frame_support::BoundedVec::try_from(amounts.clone())
            .expect("MAX_BATCH"),
        pool_balance_ada: 1_000u64.saturating_mul(MAX_BATCH.into()),
        pro_rata_scale_bps: 10_000,
        awarded_amounts_ada: frame_support::BoundedVec::try_from(amounts).expect("MAX_BATCH"),
    }
}

/// A voucher with a type-0 address and a full committee signature list.
fn voucher_for(claim_id: ClaimId, proof_digest: [u8; 32]) -> Voucher {
    let mut addr = sp_std::vec![0xB1u8; 57];
    addr[0] = 0x01;
    Voucher {
        claim_id,
        policy_id: BENCH_PRODUCT,
        beneficiary_cardano_addr: frame_support::BoundedVec::try_from(addr)
            .expect("57-byte address"),
        amount_ada: 1_000,
        batch_fairness_proof_digest: proof_digest,
        issued_block: 1,
        expiry_slot_cardano: 100_000,
        committee_sigs: frame_support::BoundedVec::try_from(
            sp_std::vec![([0u8; 32], [0u8; 64]); MAX_COMMITTEE as usize],
        )
        .expect("MAX_COMMITTEE signatures"),
    }
}

/// Seeds an unsettled claim, its voucher and its vouchered intent,
/// returning the claim id and evidence that passes every request check.
fn seed_settleable_claim<T: Config>(tag: &[u8; 4], index: u32) -> (ClaimId, SettlementEvidence)
where
    T::AccountId: parity_scale_codec::Encode,
{
    use crate::pallet::{Claims, PoolUtilization, Vouchers};
    let claim_id = ClaimId::from(bench_id(tag, index));
    let intent_id = IntentId::from(bench_id(tag, index));
    let voucher = voucher_for(
        claim_id,
        compute_fairness_proof_digest(&full_fairness_proof()),
    );
    let (payment_hash, _) =
        crate::voucher_canonicalize::split_type0_address_bytes(&voucher.beneficiary_cardano_addr)
            .expect("type-0 address");
    Vouchers::<T>::insert(claim_id, voucher);
    Claims::<T>::insert(
        claim_id,
        Claim {
            intent_id,
            policy_id: BENCH_PRODUCT,
            amount_ada: 1_000,
            issued_block: 1,
            expiry_slot_cardano: 100_000,
            settled: false,
            settled_direct: false,
            cardano_tx_hash: [0u8; 32],
        },
    );
    seed_intent::<T>(intent_id, IntentStatus::Vouchered);
    PoolUtilization::<T>::mutate(|u| {
        u.total_nav_ada = u.total_nav_ada.saturating_add(2_000);
        u.outstanding_coverage_ada = u.outstanding_coverage_ada.saturating_add(1_000);
    });
    let evidence = SettlementEvidence {
        cardano_tx_hash: [0xFFu8; 32],
        observed_at_depth: T::MinFinalityDepth::get(),
        observed_slot: 12_345_678,
        beneficiary_addr_hash: payment_hash,
        amount_lovelace: 1_000,
        mainchain_genesis_hash: T::MainchainGenesisHash::get(),
    };
    (claim_id, evidence)
}

fn intent_of<T: Config>(claim_id: ClaimId) -> IntentId {
    crate::pallet::Claims::<T>::get(claim_id)
        .expect("seeded claim")
        .intent_id
}

/// `evidence` with a slot no attestor will confirm: junk a request or
/// supersede must displace.
fn junk(evidence: SettlementEvidence) -> SettlementEvidence {
    SettlementEvidence {
        observed_slot: evidence.observed_slot.saturating_add(1),
        ..evidence
    }
}

/// Stores a request for `claim_id` carrying `evidence` from fresh account
/// `index`, submitted at block 0 with a reserved bond.
fn seed_bonded_request<T: Config>(claim_id: ClaimId, evidence: SettlementEvidence, index: u32) {
    let requester: T::AccountId = account("prior-requester", index, 0);
    let bond = T::MinSettlementBond::get().max(1);
    T::Currency::reserve_named(
        &SETTLEMENT_BOND_RESERVE_ID,
        &requester,
        fund_bond::<T>(&requester, bond),
    )
    .expect("funded bond");
    crate::pallet::ClaimSettlementRequests::<T>::insert(
        claim_id,
        SettlementRequestRecord::<T::AccountId, BlockNumberFor<T>> {
            requester,
            evidence,
            settled_direct: false,
            submitted_block: 0u32.into(),
            bond_amount: bond,
        },
    );
}

/// Moves the chain past the TTL of requests submitted at block 0.
fn expire_seeded_requests<T: Config>() {
    frame_system::Pallet::<T>::set_block_number(
        T::SettlementRequestTtl::get().saturating_add(1).into(),
    );
}

/// The STCA digest `attest_settle` and supersede verify for `evidence`.
fn stca_payload<T: Config>(claim_id: ClaimId, evidence: &SettlementEvidence) -> [u8; 32]
where
    T::AccountId: parity_scale_codec::Encode,
    BlockNumberFor<T>: Into<u64> + Copy,
{
    let voucher = crate::pallet::Vouchers::<T>::get(claim_id).expect("seeded voucher");
    settle_claim_attested_payload(
        &Pallet::<T>::materios_chain_id_bytes(),
        &claim_id,
        &Pallet::<T>::compute_canonical_voucher_digest(&voucher).expect("seeded voucher"),
        &evidence.cardano_tx_hash,
        false,
        &evidence.beneficiary_addr_hash,
        evidence.amount_lovelace,
        evidence.observed_at_depth,
        evidence.observed_slot,
        &evidence.mainchain_genesis_hash,
    )
}

/// A one-signature bundle from the benchmark committee key `public`.
fn signed(
    public: &sp_core::sr25519::Public,
    payload: &[u8; 32],
) -> Vec<(CommitteePubkey, CommitteeSig)> {
    let signature = sp_io::crypto::sr25519_sign(SIGNER_KEY_TYPE, public, payload)
        .expect("benchmark key was generated");
    sp_std::vec![(public.0, signature.0)]
}

/// Generates the calling committee member's sr25519 key so the
/// integration runtime can verify its signature.
fn committee_signer<T: Config>(seed: &[u8]) -> (T::AccountId, sp_core::sr25519::Public)
where
    T::AccountId: parity_scale_codec::Encode,
{
    use parity_scale_codec::Decode;
    let public = sp_io::crypto::sr25519_generate(SIGNER_KEY_TYPE, Some(seed.to_vec()));
    let caller = T::AccountId::decode(&mut &public.0[..])
        .expect("runtime account decodes a committee public key");
    T::BenchmarkHelper::whitelist_as_committee(&caller);
    crate::pallet::MinSignerThreshold::<T>::put(1);
    (caller, public)
}

/// Build a vouchered claim under a synthetic id for the given index. Uses
/// pallet-internal storage writes directly (we're not measuring the
/// upstream submit/attest/voucher pipeline here — just the settle batch).
fn seed_vouchered_claim<T: Config>(index: u32, amount: u64) -> ClaimId
where
    T::AccountId: parity_scale_codec::Encode,
{
    use crate::pallet::{Claims, Intents};

    // Synthetic claim_id derived from index — guaranteed unique inside the
    // benchmark batch.
    let mut id_bytes = [0u8; 32];
    id_bytes[..4].copy_from_slice(&index.to_be_bytes());
    id_bytes[4..8].copy_from_slice(b"BENC");
    let claim_id = ClaimId::from(id_bytes);
    let intent_id = IntentId::from(id_bytes); // distinct namespace fine for bench

    Claims::<T>::insert(
        claim_id,
        Claim {
            intent_id,
            policy_id: PolicyId::from([0u8; 32]),
            amount_ada: amount,
            issued_block: 1,
            expiry_slot_cardano: 100_000,
            settled: false,
            settled_direct: false,
            cardano_tx_hash: [0u8; 32],
        },
    );

    // Stub intent record so the settle path's status flip is realistic.
    // We rely on the runtime's AccountId being constructible from a seed via
    // `account` helper. Use a dummy submitter account (root-equivalent
    // through bench infra) — the value isn't read in settle_batch_atomic.
    let submitter: T::AccountId = whitelisted_caller();
    let _ = Intents::<T>::insert(
        intent_id,
        Intent {
            submitter,
            nonce: index as u64,
            kind: IntentKind::RequestPayout {
                policy_id: PolicyId::from([0u8; 32]),
                oracle_evidence: Default::default(),
            },
            submitted_block: 1,
            ttl_block: 1_000_000,
            status: IntentStatus::Vouchered,
        },
    );

    claim_id
}

#[benchmarks(
    where
        T::AccountId: parity_scale_codec::Encode,
        BlockNumberFor<T>: Into<u64> + Copy,
)]
mod benchmarks {
    use super::*;

    #[cfg(test)]
    fn execute_in_integration_runtime(benchmark: fn() -> Result<(), BenchmarkError>) {
        let mut ext = crate::integration::new_ext();
        ext.register_extension(sp_keystore::KeystoreExt::new(
            sp_keystore::testing::MemoryKeystore::new(),
        ));
        ext.execute_with(|| {
            frame_support::assert_ok!(benchmark());
        });
    }

    #[cfg(test)]
    #[test]
    fn genesis_safety_benchmark_threshold_signatures_executes() {
        execute_in_integration_runtime(
            Pallet::<crate::integration::Testnet>::test_benchmark_threshold_signatures,
        );
    }

    #[cfg(test)]
    #[test]
    fn genesis_safety_benchmark_bond_lifecycle_executes() {
        type Runtime = crate::integration::Testnet;
        for benchmark in [
            Pallet::<Runtime>::test_benchmark_request_settle,
            Pallet::<Runtime>::test_benchmark_request_batch_settle,
            Pallet::<Runtime>::test_benchmark_post_settlement_bond,
            Pallet::<Runtime>::test_benchmark_release_settlement_bond,
            Pallet::<Runtime>::test_benchmark_slash_bad_settlement_evidence,
            Pallet::<Runtime>::test_benchmark_supersede_settlement_request,
        ] {
            execute_in_integration_runtime(benchmark);
        }
    }

    #[cfg(test)]
    #[test]
    fn genesis_safety_benchmark_intent_and_settlement_paths_execute() {
        type Runtime = crate::integration::Testnet;
        for benchmark in [
            Pallet::<Runtime>::test_benchmark_submit_intent,
            Pallet::<Runtime>::test_benchmark_request_credit_refund,
            Pallet::<Runtime>::test_benchmark_submit_batch_intents,
            Pallet::<Runtime>::test_benchmark_attest_intent,
            Pallet::<Runtime>::test_benchmark_attest_batch_intents,
            Pallet::<Runtime>::test_benchmark_request_voucher,
            Pallet::<Runtime>::test_benchmark_request_batch_vouchers,
            Pallet::<Runtime>::test_benchmark_attest_settle,
            Pallet::<Runtime>::test_benchmark_attest_batch_settle,
            Pallet::<Runtime>::test_benchmark_attest_expire_policy,
            Pallet::<Runtime>::test_benchmark_expire_intents,
        ] {
            execute_in_integration_runtime(benchmark);
        }
    }

    /// Includes full-committee decoding and real crypto even when the host
    /// runtime uses BenchAllowAnyVerifier for its other benchmarks.
    #[benchmark]
    fn threshold_signatures(s: Linear<1, { T::MaxCommittee::get() }>) {
        use parity_scale_codec::Decode;
        let payload = [0x5Au8; 32];
        let mut signatures = Vec::new();
        for index in 0..T::MaxCommittee::get() {
            let seed = alloc::format!("//settlement-signature-benchmark/{index}");
            let public =
                sp_io::crypto::sr25519_generate(SIGNER_KEY_TYPE, Some(seed.as_bytes().to_vec()));
            let account = T::AccountId::decode(&mut &public.0[..])
                .expect("runtime account decodes a committee public key");
            T::BenchmarkHelper::whitelist_as_committee(&account);
            assert!(T::CommitteeMembership::is_member(&account));
            let signature = sp_io::crypto::sr25519_sign(SIGNER_KEY_TYPE, &public, &payload)
                .expect("benchmark key was generated");
            signatures.push((public.0, signature.0));
        }
        assert_eq!(
            T::CommitteeMembership::member_count(),
            T::MaxCommittee::get()
        );
        signatures.sort_unstable_by_key(|(key, _)| *key);
        signatures.reverse();
        signatures.truncate(s as usize);
        let caller = T::CommitteeMembership::account_of_pubkey(&signatures[s as usize - 1].0)
            .expect("benchmark signer belongs to committee");
        crate::pallet::MinSignerThreshold::<T>::put(1);
        let mut checked = 0;

        #[block]
        {
            Pallet::<T>::verify_threshold_signatures::<crate::Sr25519Verifier>(
                &payload,
                &caller,
                &signatures,
                &mut checked,
            )
            .expect("valid benchmark bundle");
        }

        assert_eq!(checked, s);
    }

    #[benchmark]
    fn settle_batch_atomic(n: Linear<1, MAX_BATCH_BENCH>) {
        crate::pallet::SettlementStorageVersion::<T>::put(0);
        crate::pallet::StcaCutoverBlock::<T>::kill();
        let mut entries: Vec<SettleBatchEntry> = Vec::with_capacity(n as usize);
        for i in 0..n {
            let cid = seed_vouchered_claim::<T>(i, 1_000);
            entries.push(SettleBatchEntry {
                claim_id: cid,
                cardano_tx_hash: [0u8; 32],
                settled_direct: i % 2 == 0,
            });
        }

        // Build a dummy committee bundle. Real signature verification is
        // pluggable via T::SigVerifier; downstream runtimes wire in
        // Sr25519Verifier and this benchmark's weight will reflect that
        // production cost.
        let caller: T::AccountId = whitelisted_caller();
        T::BenchmarkHelper::whitelist_as_committee(&caller);
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];

        let bv: frame_support::BoundedVec<SettleBatchEntry, T::MaxSettleBatch> =
            frame_support::BoundedVec::try_from(entries).expect("bench n <= MaxSettleBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // NOTE: `impl_benchmark_test_suite!` is intentionally OMITTED. Wiring it
    // here pins benchmarks into the pallet's own mock runtime, but our mock
    // uses `u64` AccountId (intentionally — see `tests::mock_pubkey_of`).
    // The benchmark closure computes a payload digest using the AccountId's
    // committee-pubkey derivation, which is fine for `whitelisted_caller`
    // (any 32-byte pubkey works) but doesn't round-trip in the mock's
    // `account_of_pubkey` (which only knows about members 1/2/3). The
    // production weight pass runs in the materios-runtime, which wires
    // `Sr25519Verifier` against real AccountId32 — that's where the
    // canonical weight values come from.

    /// Bench `submit_intent` with a BuyPolicy (credit debit and pool check),
    /// `PendingBatches` one short of capacity and the expiry slot one short
    /// of `MAX_EXPIRE_PER_BLOCK`.
    #[benchmark]
    fn submit_intent() {
        let caller: T::AccountId = whitelisted_caller();
        let kind = buy_policy(0);
        prepare_submission::<T>(&caller, 1);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), kind);

        assert_pending_room::<T>(0);
    }

    /// Bench `request_credit_refund` with `PendingBatches` one short of
    /// capacity and a nearly full expiry slot.
    #[benchmark]
    fn request_credit_refund() {
        let caller: T::AccountId = whitelisted_caller();
        prepare_submission::<T>(&caller, 1);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), 1_000);

        assert_pending_room::<T>(0);
    }

    /// Bench `submit_batch_intents` with `n` BuyPolicy entries filling
    /// `PendingBatches` to capacity and one nearly full expiry slot.
    #[benchmark]
    fn submit_batch_intents(
        n: Linear<1, { T::MaxSubmitBatch::get().min(T::MaxPendingBatches::get()) }>,
    ) {
        let caller: T::AccountId = whitelisted_caller();
        prepare_submission::<T>(&caller, n);
        let entries: frame_support::BoundedVec<SubmitIntentEntry, T::MaxSubmitBatch> = (0..n)
            .map(|index| SubmitIntentEntry {
                kind: buy_policy(index),
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("bench n <= MaxSubmitBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), entries);

        assert_pending_room::<T>(0);
    }

    /// Bench the `attest_intent` call that crosses the threshold with a full
    /// committee bundle: it reads `MaxCommittee - 1` pending attestations
    /// and writes the full bundle to `AttestationSigs`. Verification of the
    /// caller's signature is charged by `threshold_signatures(1)`.
    #[benchmark]
    fn attest_intent() {
        let intent_id = IntentId::from(bench_id(b"ATIN", 0));
        seed_intent::<T>(intent_id, IntentStatus::Pending);
        let (caller, public) = committee_signer::<T>(b"//settlement-attest-intent-benchmark");
        let others: Vec<(CommitteePubkey, CommitteeSig)> = (1..T::MaxCommittee::get())
            .map(|index| (bench_id(b"PEER", index), [0u8; 64]))
            .collect();
        crate::pallet::PendingAttestations::<T>::insert(
            intent_id,
            frame_support::BoundedVec::try_from(others).expect("MaxCommittee - 1 entries"),
        );
        let payload = attest_intent_payload(&Pallet::<T>::materios_chain_id_bytes(), &intent_id);
        let signature = sp_io::crypto::sr25519_sign(SIGNER_KEY_TYPE, &public, &payload)
            .expect("benchmark key was generated");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), intent_id, public.0, signature.0);

        assert_status::<T>(intent_id, IntentStatus::Attested);
    }

    /// Bench `attest_batch_intents` across `n` pending intents, each written
    /// back with its stored bundle.
    #[benchmark]
    fn attest_batch_intents(n: Linear<1, { T::MaxAttestBatch::get() }>) {
        let intent_ids: Vec<IntentId> = (0..n)
            .map(|index| {
                let intent_id = IntentId::from(bench_id(b"BABI", index));
                seed_intent::<T>(intent_id, IntentStatus::Pending);
                intent_id
            })
            .collect();
        let (caller, public) = committee_signer::<T>(b"//settlement-batch-intents-benchmark");
        let payload =
            attest_batch_intents_payload(&Pallet::<T>::materios_chain_id_bytes(), &intent_ids);
        let attested = intent_ids.clone();
        let intent_ids: frame_support::BoundedVec<IntentId, T::MaxAttestBatch> =
            intent_ids.try_into().expect("bench n <= MaxAttestBatch");

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            intent_ids,
            signed(&public, &payload),
        );

        for intent_id in attested {
            assert_status::<T>(intent_id, IntentStatus::Attested);
        }
    }

    /// Bench `request_voucher` with a full-size fairness proof and the
    /// intent last in a full `PendingBatches`.
    #[benchmark]
    fn request_voucher() {
        let intent_id = IntentId::from(bench_id(b"RQVC", 0));
        let claim_id = ClaimId::from(bench_id(b"RQVC", 1));
        seed_intent::<T>(intent_id, IntentStatus::Attested);
        fill_pending_batches::<T>(&[intent_id], 0);
        let proof = full_fairness_proof();
        let voucher = voucher_for(claim_id, compute_fairness_proof_digest(&proof));
        let (caller, public) = committee_signer::<T>(b"//settlement-voucher-benchmark");
        let payload = request_voucher_payload(
            &Pallet::<T>::materios_chain_id_bytes(),
            &claim_id,
            &intent_id,
            &Pallet::<T>::compute_canonical_voucher_digest(&voucher).expect("valid voucher"),
            &compute_fairness_proof_digest(&proof),
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_id,
            intent_id,
            voucher,
            proof,
            signed(&public, &payload),
        );

        assert_status::<T>(intent_id, IntentStatus::Vouchered);
    }

    /// Bench `request_batch_vouchers` across `n` entries with full-size
    /// fairness proofs, their intents last in a full `PendingBatches`.
    #[benchmark]
    fn request_batch_vouchers(
        n: Linear<1, { T::MaxVoucherBatch::get().min(T::MaxPendingBatches::get()) }>,
    ) {
        let proof = full_fairness_proof();
        let proof_digest = compute_fairness_proof_digest(&proof);
        let mut entries = Vec::with_capacity(n as usize);
        let mut signed_entries = Vec::with_capacity(n as usize);
        for index in 0..n {
            let intent_id = IntentId::from(bench_id(b"BRBV", index));
            let claim_id = ClaimId::from(bench_id(b"BRBC", index));
            seed_intent::<T>(intent_id, IntentStatus::Attested);
            let voucher = voucher_for(claim_id, proof_digest);
            signed_entries.push((
                claim_id,
                intent_id,
                Pallet::<T>::compute_canonical_voucher_digest(&voucher).expect("valid voucher"),
                proof_digest,
            ));
            entries.push(RequestVoucherEntry {
                claim_id,
                intent_id,
                voucher,
                fairness_proof: proof.clone(),
            });
        }
        let intent_ids: Vec<IntentId> = entries.iter().map(|entry| entry.intent_id).collect();
        fill_pending_batches::<T>(&intent_ids, 0);
        let (caller, public) = committee_signer::<T>(b"//settlement-batch-voucher-benchmark");
        let payload = request_batch_vouchers_payload(
            &Pallet::<T>::materios_chain_id_bytes(),
            &signed_entries,
        );
        let entries: frame_support::BoundedVec<RequestVoucherEntry, T::MaxVoucherBatch> =
            entries.try_into().expect("bench n <= MaxVoucherBatch");

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            entries,
            signed(&public, &payload),
        );

        for intent_id in intent_ids {
            assert_status::<T>(intent_id, IntentStatus::Vouchered);
        }
    }

    /// Bench `request_settle` replacing an expired request bonded by another
    /// account, so the refund and the new reserve are both measured.
    #[benchmark]
    fn request_settle() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"RQST", 0);
        seed_bonded_request::<T>(claim_id, junk(evidence), 0);
        expire_seeded_requests::<T>();
        let caller: T::AccountId = whitelisted_caller();
        let bond = T::MinSettlementBond::get().max(1);
        fund_bond::<T>(&caller, bond);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_id,
            evidence.cardano_tx_hash,
            false,
            evidence,
            bond,
        );
    }

    /// Bench `attest_settle` on a bonded request, which also writes the
    /// bond's side records, with the intent last in a full `PendingBatches`.
    #[benchmark]
    fn attest_settle() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"ATST", 0);
        seed_bonded_request::<T>(claim_id, evidence, 0);
        fill_pending_batches::<T>(&[intent_of::<T>(claim_id)], 0);
        let (caller, public) = committee_signer::<T>(b"//settlement-attest-benchmark");
        let payload = stca_payload::<T>(claim_id, &evidence);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_id,
            signed(&public, &payload),
        );

        assert_settled::<T>(claim_id);
        assert_pending_room::<T>(1);
    }

    /// Bench `request_batch_settle` across Linear<1, MAX_BATCH_BENCH>, each
    /// entry replacing an expired request bonded by a different account.
    #[benchmark]
    fn request_batch_settle(n: Linear<1, MAX_BATCH_BENCH>) {
        let entries: Vec<SettleAttestedBatchEntry> = (0..n)
            .map(|index| {
                let (claim_id, evidence) = seed_settleable_claim::<T>(b"RQBS", index);
                seed_bonded_request::<T>(claim_id, junk(evidence), index);
                SettleAttestedBatchEntry {
                    claim_id,
                    evidence,
                    settled_direct: false,
                }
            })
            .collect();
        expire_seeded_requests::<T>();
        let caller: T::AccountId = whitelisted_caller();
        let bond = T::MinSettlementBond::get().max(1);
        fund_bond::<T>(&caller, bond.saturating_mul(n.into()));
        let entries: frame_support::BoundedVec<SettleAttestedBatchEntry, T::MaxSettleBatch> =
            entries.try_into().expect("bench n <= MaxSettleBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), entries, bond);
    }

    /// Bench `attest_batch_settle` across `n` bonded requests, their intents
    /// last in a full `PendingBatches`.
    #[benchmark]
    fn attest_batch_settle(
        n: Linear<1, { T::MaxSettleBatch::get().min(T::MaxPendingBatches::get()) }>,
    ) {
        let mut claim_ids = Vec::with_capacity(n as usize);
        let mut signed_entries = Vec::with_capacity(n as usize);
        for index in 0..n {
            let (claim_id, evidence) = seed_settleable_claim::<T>(b"ATBS", index);
            seed_bonded_request::<T>(claim_id, evidence, index);
            let voucher = crate::pallet::Vouchers::<T>::get(claim_id).expect("seeded voucher");
            signed_entries.push(BatchAttestEntryBytes {
                claim_id,
                voucher_digest: Pallet::<T>::compute_canonical_voucher_digest(&voucher)
                    .expect("seeded voucher"),
                cardano_tx_hash: evidence.cardano_tx_hash,
                settled_direct: false,
                beneficiary_hash: evidence.beneficiary_addr_hash,
                amount_ada: evidence.amount_lovelace,
                depth: evidence.observed_at_depth,
                slot: evidence.observed_slot,
                mc_genesis: evidence.mainchain_genesis_hash,
            });
            claim_ids.push(claim_id);
        }
        let intent_ids: Vec<IntentId> = claim_ids
            .iter()
            .map(|claim_id| intent_of::<T>(*claim_id))
            .collect();
        fill_pending_batches::<T>(&intent_ids, 0);
        let (caller, public) = committee_signer::<T>(b"//settlement-batch-attest-benchmark");
        let payload =
            attest_batch_settle_payload(&Pallet::<T>::materios_chain_id_bytes(), &signed_entries);
        let settled = claim_ids.clone();
        let claim_ids: frame_support::BoundedVec<ClaimId, T::MaxSettleBatch> =
            claim_ids.try_into().expect("bench n <= MaxSettleBatch");

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_ids,
            signed(&public, &payload),
        );

        for claim_id in settled {
            assert_settled::<T>(claim_id);
        }
        assert_pending_room::<T>(n);
    }

    /// Bench `request_expire_policy` — phase 1 of the attested expire path.
    /// Seeds an attested BuyPolicy intent so the policy_id_witness check
    /// has a deterministic match against the on-chain product_id.
    #[benchmark]
    fn request_expire_policy() {
        use crate::pallet::Intents;
        let caller: T::AccountId = whitelisted_caller();

        let mut iid_bytes = [0u8; 32];
        iid_bytes[..4].copy_from_slice(b"REXP");
        let intent_id = IntentId::from(iid_bytes);
        let product_id = PolicyId::from([0x77u8; 32]);

        // Type-0 address (header 0x01 + 28-byte payment + 28-byte stake)
        // — required by the canonical voucher digest in BuyPolicy intents.
        let mut addr = sp_std::vec::Vec::with_capacity(57);
        addr.push(0x01u8);
        for _ in 0..28 {
            addr.push(0xB1u8);
        }
        for _ in 0..28 {
            addr.push(0xB1u8);
        }
        let kind = IntentKind::BuyPolicy {
            product_id,
            strike: 1,
            term_slots: 86_400,
            premium_ada: 1_000,
            beneficiary_cardano_addr: frame_support::BoundedVec::try_from(addr)
                .expect("57B fits ConstU32<MAX_CARDANO_ADDR>"),
        };
        Intents::<T>::insert(
            intent_id,
            Intent {
                submitter: caller.clone(),
                nonce: 0u64,
                kind,
                submitted_block: 1,
                ttl_block: 1_000_000,
                status: IntentStatus::Attested,
            },
        );

        let mc_g = T::MainchainGenesisHash::get();
        let depth = T::MinFinalityDepth::get();
        let evidence = ExpiryEvidence {
            cardano_tx_hash: [0xCFu8; 32],
            observed_at_depth: depth,
            observed_slot: 12_345_678,
            mainchain_genesis_hash: mc_g,
            policy_id_witness: product_id,
        };

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            intent_id,
            evidence.cardano_tx_hash,
            evidence,
        );
    }

    /// Bench `attest_expire_policy` with the intent last in a full
    /// `PendingBatches`.
    #[benchmark]
    fn attest_expire_policy() {
        let intent_id = IntentId::from(bench_id(b"ATXP", 0));
        seed_intent::<T>(intent_id, IntentStatus::Attested);
        fill_pending_batches::<T>(&[intent_id], 0);
        let (caller, public) = committee_signer::<T>(b"//settlement-expire-benchmark");
        let evidence = ExpiryEvidence {
            cardano_tx_hash: [0xCFu8; 32],
            observed_at_depth: T::MinFinalityDepth::get(),
            observed_slot: 12_345_678,
            mainchain_genesis_hash: T::MainchainGenesisHash::get(),
            policy_id_witness: BENCH_PRODUCT,
        };
        crate::pallet::PolicyExpireRequests::<T>::insert(
            intent_id,
            ExpiryRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                requester: caller.clone(),
                evidence,
                submitted_block: <frame_system::Pallet<T>>::block_number(),
            },
        );
        let payload = expire_policy_attested_payload(
            &Pallet::<T>::materios_chain_id_bytes(),
            &intent_id,
            &BENCH_PRODUCT,
            &evidence.cardano_tx_hash,
            evidence.observed_at_depth,
            evidence.observed_slot,
            &evidence.mainchain_genesis_hash,
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            intent_id,
            signed(&public, &payload),
        );

        assert_status::<T>(intent_id, IntentStatus::Expired);
        assert_pending_room::<T>(1);
    }

    /// Bench the `on_initialize` expiry sweep over `n` pending BuyPolicy
    /// intents, each refunding its premium and leaving a full
    /// `PendingBatches` from the end.
    #[benchmark]
    fn expire_intents(n: Linear<1, { MAX_EXPIRE_PER_BLOCK.min(T::MaxPendingBatches::get()) }>) {
        let expiry_block: u32 = 10;
        let intent_ids: Vec<IntentId> = (0..n)
            .map(|index| {
                let intent_id = IntentId::from(bench_id(b"EXPI", index));
                seed_intent::<T>(intent_id, IntentStatus::Pending);
                intent_id
            })
            .collect();
        fill_pending_batches::<T>(&intent_ids, 0);
        crate::pallet::ExpiryQueue::<T>::insert(
            expiry_block,
            frame_support::BoundedVec::try_from(intent_ids.clone())
                .expect("n <= MAX_EXPIRE_PER_BLOCK"),
        );

        #[block]
        {
            <Pallet<T> as frame_support::traits::Hooks<BlockNumberFor<T>>>::on_initialize(
                expiry_block.into(),
            );
        }

        assert!(crate::pallet::ExpiryQueue::<T>::get(expiry_block).is_empty());
        for intent_id in intent_ids {
            assert_status::<T>(intent_id, IntentStatus::Expired);
        }
        assert_pending_room::<T>(n);
    }

    // ---- Bond lifecycle benches ------------------------------------------
    //
    // Each bench measures its call's most expensive branch with a real
    // reserved bond. Threshold verification is charged separately by
    // `threshold_signatures`, so the committee calls carry one signature.
    // ---------------------------------------------------------------------

    /// Bench `post_settlement_bond` on an unbonded request stored before
    /// request-time bonding.
    #[benchmark]
    fn post_settlement_bond() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"PBND", 0);
        let caller: T::AccountId = whitelisted_caller();
        crate::pallet::ClaimSettlementRequests::<T>::insert(
            claim_id,
            SettlementRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                requester: caller.clone(),
                evidence,
                settled_direct: false,
                submitted_block: <frame_system::Pallet<T>>::block_number(),
                bond_amount: 0u128,
            },
        );
        let bond = T::MinSettlementBond::get().max(1);
        fund_bond::<T>(&caller, bond);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), claim_id, bond);
    }

    /// Bench `release_settlement_bond` on an expired, unattested request:
    /// it reads and removes the request row on top of the refund and the
    /// side-record removals the attested branch also performs.
    #[benchmark]
    fn release_settlement_bond() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"REBN", 0);
        seed_bonded_request::<T>(claim_id, junk(evidence), 0);
        expire_seeded_requests::<T>();
        let caller: T::AccountId = whitelisted_caller();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), claim_id);
    }

    /// Bench `slash_bad_settlement_evidence` against a reserved bond of at
    /// least 2, so a split such as Materios' 50% pays both the watcher and
    /// the treasury.
    #[benchmark]
    fn slash_bad_settlement_evidence() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"SLBE", 0);
        let (caller, public) = committee_signer::<T>(b"//settlement-slash-benchmark");
        let treasury: T::AccountId = T::SettlementTreasuryPalletId::get().into_account_truncating();
        for receiver in [&caller, &treasury] {
            let _ = T::Currency::make_free_balance_be(receiver, T::Currency::minimum_balance());
        }
        let requester: T::AccountId = account("requester", 0, 0);
        let bond = T::MinSettlementBond::get().max(2);
        T::Currency::reserve_named(
            &SETTLEMENT_BOND_RESERVE_ID,
            &requester,
            fund_bond::<T>(&requester, bond),
        )
        .expect("funded bond");
        let record = SettlementRequestRecord::<T::AccountId, BlockNumberFor<T>> {
            requester,
            evidence,
            settled_direct: false,
            submitted_block: <frame_system::Pallet<T>>::block_number(),
            bond_amount: bond,
        };
        let proof = crate::types::FraudProof::WrongAmount {
            actual_lovelace: (evidence.amount_lovelace as u128).saturating_add(1),
        };
        let payload = slash_bad_settlement_evidence_payload(
            &Pallet::<T>::materios_chain_id_bytes(),
            &claim_id,
            &record,
            &proof,
        );
        let signature = sp_io::crypto::sr25519_sign(SIGNER_KEY_TYPE, &public, &payload)
            .expect("benchmark key was generated");
        crate::pallet::ClaimSettlementRequests::<T>::insert(claim_id, record);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_id,
            proof,
            sp_std::vec![(public.0, signature.0)],
        );
    }

    /// Bench `supersede_settlement_request` displacing a bonded request, so
    /// the refund and the settle transitions are both measured, with the
    /// intent last in a full `PendingBatches`.
    #[benchmark]
    fn supersede_settlement_request() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"SPSD", 0);
        seed_bonded_request::<T>(claim_id, junk(evidence), 0);
        fill_pending_batches::<T>(&[intent_of::<T>(claim_id)], 0);
        let (caller, public) = committee_signer::<T>(b"//settlement-supersede-benchmark");
        let payload = stca_payload::<T>(claim_id, &evidence);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_id,
            false,
            evidence,
            signed(&public, &payload),
        );
    }
}
