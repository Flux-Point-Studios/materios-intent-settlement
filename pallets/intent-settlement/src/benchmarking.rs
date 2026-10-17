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

/// Seeds an unsettled claim and its voucher, returning the claim id and
/// evidence that passes every request check.
fn seed_settleable_claim<T: Config>(tag: &[u8; 4], index: u32) -> (ClaimId, SettlementEvidence)
where
    T::AccountId: parity_scale_codec::Encode,
{
    use crate::pallet::{Claims, PoolUtilization, Vouchers};
    let mut id_bytes = [0u8; 32];
    id_bytes[..4].copy_from_slice(&index.to_be_bytes());
    id_bytes[4..8].copy_from_slice(tag);
    let claim_id = ClaimId::from(id_bytes);
    let intent_id = IntentId::from(id_bytes);
    let amount: u64 = 1_000;
    let payment_hash = [0xB1u8; 28];
    let mut addr = Vec::with_capacity(57);
    addr.push(0x01u8);
    addr.extend_from_slice(&payment_hash);
    addr.extend_from_slice(&[0xB1u8; 28]);
    let bfpr = BatchFairnessProof {
        batch_block_range: (1, 1),
        sorted_intent_ids: frame_support::BoundedVec::try_from(sp_std::vec![intent_id]).unwrap(),
        requested_amounts_ada: frame_support::BoundedVec::try_from(sp_std::vec![amount]).unwrap(),
        pool_balance_ada: 1_000_000_000,
        pro_rata_scale_bps: 10_000,
        awarded_amounts_ada: frame_support::BoundedVec::try_from(sp_std::vec![amount]).unwrap(),
    };
    Vouchers::<T>::insert(
        claim_id,
        Voucher {
            claim_id,
            policy_id: PolicyId::from([0u8; 32]),
            beneficiary_cardano_addr: frame_support::BoundedVec::try_from(addr).unwrap(),
            amount_ada: amount,
            batch_fairness_proof_digest: compute_fairness_proof_digest(&bfpr),
            issued_block: 1,
            expiry_slot_cardano: 100_000,
            committee_sigs: Default::default(),
        },
    );
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
    PoolUtilization::<T>::mutate(|u| {
        u.total_nav_ada = u.total_nav_ada.saturating_add(amount.saturating_mul(2));
        u.outstanding_coverage_ada = u.outstanding_coverage_ada.saturating_add(amount);
    });
    let evidence = SettlementEvidence {
        cardano_tx_hash: [0xFFu8; 32],
        observed_at_depth: T::MinFinalityDepth::get(),
        observed_slot: 12_345_678,
        beneficiary_addr_hash: payment_hash,
        amount_lovelace: amount,
        mainchain_genesis_hash: T::MainchainGenesisHash::get(),
    };
    (claim_id, evidence)
}

/// Stores a request for `claim_id` from a fresh account `index`, submitted
/// at block 0 with a reserved bond, and moves the chain past its TTL. The
/// request's slot differs from `evidence`, so it is unattestable junk that
/// a request or supersede must refund.
fn seed_expired_bonded_request<T: Config>(
    claim_id: ClaimId,
    evidence: SettlementEvidence,
    index: u32,
) {
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
            evidence: SettlementEvidence {
                observed_slot: evidence.observed_slot.saturating_add(1),
                ..evidence
            },
            settled_direct: false,
            submitted_block: 0u32.into(),
            bond_amount: bond,
        },
    );
    frame_system::Pallet::<T>::set_block_number(
        T::SettlementRequestTtl::get().saturating_add(1).into(),
    );
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
            frame_support::BoundedVec::try_from(entries)
                .expect("bench n <= MaxSettleBatch");

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

    // ---- Task #211 — attest_batch_intents bench -------------------------

    /// Bench `attest_batch_intents` across `Linear<1, MAX_BATCH>` so the
    /// runtime weight generator produces a sublinear curve matching the
    /// spec-207 cost model:
    ///   N=1   ~55M ref_time   N=64  ~250M ref_time
    ///   N=8   ~75M ref_time   N=256 ~800M ref_time
    /// Versus 256x3 = 768 single `attest_intent` calls at ~50M each =
    /// ~38B ref_time, the batch path is ~50x cheaper at the per-block-budget
    /// level. The bigger structural win is M-of-N collapse: pre-spec-207 a
    /// 3-of-3 committee posted M*N = 768 separate sig-verifies; post-spec-207
    /// it's ONE.
    #[benchmark]
    fn attest_batch_intents(n: Linear<1, MAX_BATCH_BENCH>) {
        use crate::pallet::Intents;
        let mut intent_ids: sp_std::vec::Vec<IntentId> =
            sp_std::vec::Vec::with_capacity(n as usize);
        let submitter: T::AccountId = whitelisted_caller();
        for i in 0..n {
            let mut id_bytes = [0u8; 32];
            id_bytes[..4].copy_from_slice(&i.to_be_bytes());
            id_bytes[4..8].copy_from_slice(b"BABI");
            let iid = IntentId::from(id_bytes);
            Intents::<T>::insert(
                iid,
                Intent {
                    submitter: submitter.clone(),
                    nonce: i as u64,
                    kind: IntentKind::RequestPayout {
                        policy_id: PolicyId::from([0u8; 32]),
                        oracle_evidence: Default::default(),
                    },
                    submitted_block: 1,
                    ttl_block: 1_000_000,
                    status: IntentStatus::Pending,
                },
            );
            intent_ids.push(iid);
        }

        let caller: T::AccountId = whitelisted_caller();
        T::BenchmarkHelper::whitelist_as_committee(&caller);
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];

        let bv: frame_support::BoundedVec<IntentId, T::MaxAttestBatch> =
            frame_support::BoundedVec::try_from(intent_ids)
                .expect("bench n <= MaxAttestBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // ---- Task #212 — request_batch_vouchers bench -----------------------

    /// Bench `request_batch_vouchers` across `Linear<1, MAX_BATCH>` so the
    /// runtime weight generator produces a sublinear curve matching the
    /// spec-207 cost model:
    ///   N=1   ~60M ref_time   N=64  ~700M ref_time
    ///   N=8   ~130M ref_time  N=256 ~2.6B ref_time
    /// Versus 256 single `request_voucher` calls at ~100M each = ~25.6B
    /// ref_time, the batch path is ~10x cheaper at the per-block-budget
    /// level.
    #[benchmark]
    fn request_batch_vouchers(n: Linear<1, MAX_BATCH_BENCH>) {
        use crate::pallet::Intents;
        let submitter: T::AccountId = whitelisted_caller();
        let mut entries: sp_std::vec::Vec<RequestVoucherEntry> =
            sp_std::vec::Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut id_bytes = [0u8; 32];
            id_bytes[..4].copy_from_slice(&i.to_be_bytes());
            id_bytes[4..8].copy_from_slice(b"BRBV");
            let intent_id = IntentId::from(id_bytes);
            let mut cid_bytes = id_bytes;
            cid_bytes[8..12].copy_from_slice(b"CLAM");
            let claim_id = ClaimId::from(cid_bytes);
            Intents::<T>::insert(
                intent_id,
                Intent {
                    submitter: submitter.clone(),
                    nonce: i as u64,
                    kind: IntentKind::RequestPayout {
                        policy_id: PolicyId::from([0u8; 32]),
                        oracle_evidence: Default::default(),
                    },
                    submitted_block: 1,
                    ttl_block: 1_000_000,
                    status: IntentStatus::Attested,
                },
            );
            let bfpr = BatchFairnessProof {
                batch_block_range: (1, 1),
                sorted_intent_ids: frame_support::BoundedVec::try_from(
                    sp_std::vec![intent_id],
                ).unwrap(),
                requested_amounts_ada: frame_support::BoundedVec::try_from(
                    sp_std::vec![1_000u64],
                ).unwrap(),
                pool_balance_ada: 1_000_000_000,
                pro_rata_scale_bps: 10_000,
                awarded_amounts_ada: frame_support::BoundedVec::try_from(
                    sp_std::vec![1_000u64],
                ).unwrap(),
            };
            let bfpr_d = compute_fairness_proof_digest(&bfpr);
            // #79: voucher digest now requires a CIP-0019 type-0 address
            // shape so the canonical CBOR-bound digest can be derived.
            let mut addr = sp_std::vec::Vec::with_capacity(57);
            addr.push(0x01u8);
            for _ in 0..28 {
                addr.push(0xB1u8);
            }
            for _ in 0..28 {
                addr.push(0xB1u8);
            }
            let voucher = Voucher {
                claim_id,
                policy_id: PolicyId::from([0u8; 32]),
                beneficiary_cardano_addr: frame_support::BoundedVec::try_from(addr)
                    .expect("57B fits ConstU32<MAX_CARDANO_ADDR>"),
                amount_ada: 1_000,
                batch_fairness_proof_digest: bfpr_d,
                issued_block: 1,
                expiry_slot_cardano: 100_000,
                committee_sigs: Default::default(),
            };
            entries.push(RequestVoucherEntry {
                claim_id,
                intent_id,
                voucher,
                fairness_proof: bfpr,
            });
        }

        let caller: T::AccountId = whitelisted_caller();
        T::BenchmarkHelper::whitelist_as_committee(&caller);
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];
        let bv: frame_support::BoundedVec<RequestVoucherEntry, T::MaxVoucherBatch> =
            frame_support::BoundedVec::try_from(entries)
                .expect("bench n <= MaxVoucherBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // ---- Task #266 (mis-sec P0) — request_settle + attest_settle benches
    //
    // The new attested-settle path replaces the legacy `settle_claim` /
    // `settle_batch_atomic`. Per design-memo §6 #6 the STCA pre-image is
    // 209 bytes vs the legacy STCL's 97 bytes, which crosses from 2 blake2
    // blocks to 4 — one extra blake2 round per signer (~300 ns at M=3,
    // committee=64). Re-bench captures the new weight constants.
    //
    // Bench-cli command (run via downstream materios-runtime):
    //   frame-omni-bencher v1 benchmark pallet \
    //     --runtime <materios_runtime.compact.compressed.wasm> \
    //     --pallet pallet_intent_settlement \
    //     --extrinsic request_settle,attest_settle,
    //                 request_batch_settle,attest_batch_settle \
    //     --steps 10 --repeat 5 --genesis-builder runtime
    //
    // Expected slope (the bench uses BenchAllowAnyVerifier so sig-verify is
    // excluded; production runtimes add a fixed Sr25519Verifier cost on top):
    //   request_settle  ~30M ref_time  (voucher hydration + storage write)
    //   attest_settle   ~55M ref_time  (voucher hydration + storage writes)
    //   request_batch_settle (n) ~25M + n*7M ref_time
    //   attest_batch_settle (n)  ~50M + n*14M ref_time
    // ---------------------------------------------------------------------

    /// Bench `request_settle` replacing an expired request bonded by another
    /// account, so the refund and the new reserve are both measured.
    #[benchmark]
    fn request_settle() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"RQST", 0);
        seed_expired_bonded_request::<T>(claim_id, evidence, 0);
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

    /// Bench `attest_settle` — single-claim phase 2 of the attested path.
    /// Pre-seeds the pending request + voucher + claim so the bench only
    /// measures the sig-verify + storage-mutation cost of the attest call
    /// itself.
    #[benchmark]
    fn attest_settle() {
        use crate::pallet::{
            ClaimSettlementRequests, Claims, PoolUtilization, Vouchers,
        };
        let mut id_bytes = [0u8; 32];
        id_bytes[..4].copy_from_slice(b"ATST");
        let claim_id = ClaimId::from(id_bytes);
        let intent_id = IntentId::from(id_bytes);
        let amount: u64 = 1_000;
        let payment_hash = [0xB1u8; 28];
        let mut addr = sp_std::vec::Vec::with_capacity(57);
        addr.push(0x01u8);
        addr.extend_from_slice(&payment_hash);
        addr.extend_from_slice(&[0xB1u8; 28]);
        let addr_bv = frame_support::BoundedVec::<u8, sp_core::ConstU32<MAX_CARDANO_ADDR>>::try_from(
            addr,
        )
        .unwrap();
        let bfpr = BatchFairnessProof {
            batch_block_range: (1, 1),
            sorted_intent_ids: frame_support::BoundedVec::try_from(
                sp_std::vec![intent_id],
            )
            .unwrap(),
            requested_amounts_ada: frame_support::BoundedVec::try_from(
                sp_std::vec![amount],
            )
            .unwrap(),
            pool_balance_ada: 1_000_000_000,
            pro_rata_scale_bps: 10_000,
            awarded_amounts_ada: frame_support::BoundedVec::try_from(
                sp_std::vec![amount],
            )
            .unwrap(),
        };
        let bfpr_d = compute_fairness_proof_digest(&bfpr);
        let voucher = Voucher {
            claim_id,
            policy_id: PolicyId::from([0u8; 32]),
            beneficiary_cardano_addr: addr_bv,
            amount_ada: amount,
            batch_fairness_proof_digest: bfpr_d,
            issued_block: 1,
            expiry_slot_cardano: 100_000,
            committee_sigs: Default::default(),
        };
        Vouchers::<T>::insert(claim_id, voucher);
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
        PoolUtilization::<T>::mutate(|u| {
            u.total_nav_ada = u.total_nav_ada.saturating_add(amount.saturating_mul(2));
            u.outstanding_coverage_ada =
                u.outstanding_coverage_ada.saturating_add(amount);
        });

        let caller: T::AccountId = whitelisted_caller();
        T::BenchmarkHelper::whitelist_as_committee(&caller);
        let mc_g = T::MainchainGenesisHash::get();
        let evidence = SettlementEvidence {
            cardano_tx_hash: [0xFFu8; 32],
            observed_at_depth: T::MinFinalityDepth::get(),
            observed_slot: 12_345_678,
            beneficiary_addr_hash: payment_hash,
            amount_lovelace: amount,
            mainchain_genesis_hash: mc_g,
        };
        ClaimSettlementRequests::<T>::insert(
            claim_id,
            SettlementRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                requester: caller.clone(),
                evidence,
                settled_direct: false,
                submitted_block: <frame_system::Pallet<T>>::block_number(),
                bond_amount: 0u128,
            },
        );

        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), claim_id, signatures);
    }

    /// Bench `request_batch_settle` across Linear<1, MAX_BATCH_BENCH>, each
    /// entry replacing an expired request bonded by a different account.
    #[benchmark]
    fn request_batch_settle(n: Linear<1, MAX_BATCH_BENCH>) {
        let entries: Vec<SettleAttestedBatchEntry> = (0..n)
            .map(|index| {
                let (claim_id, evidence) = seed_settleable_claim::<T>(b"RQBS", index);
                seed_expired_bonded_request::<T>(claim_id, evidence, index);
                SettleAttestedBatchEntry {
                    claim_id,
                    evidence,
                    settled_direct: false,
                }
            })
            .collect();
        let caller: T::AccountId = whitelisted_caller();
        let bond = T::MinSettlementBond::get().max(1);
        fund_bond::<T>(&caller, bond.saturating_mul(n.into()));
        let entries: frame_support::BoundedVec<SettleAttestedBatchEntry, T::MaxSettleBatch> =
            entries.try_into().expect("bench n <= MaxSettleBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), entries, bond);
    }

    /// Bench `attest_batch_settle` across Linear<1, MAX_BATCH_BENCH>. The
    /// single BSTA sig-verify amortises across N entries; per-entry cost is
    /// voucher hydration + storage writes.
    #[benchmark]
    fn attest_batch_settle(n: Linear<1, MAX_BATCH_BENCH>) {
        use crate::pallet::{
            ClaimSettlementRequests, Claims, PoolUtilization, Vouchers,
        };
        let caller: T::AccountId = whitelisted_caller();
        T::BenchmarkHelper::whitelist_as_committee(&caller);
        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let mc_g = T::MainchainGenesisHash::get();
        let payment_hash = [0xB1u8; 28];
        let mut claim_ids: sp_std::vec::Vec<ClaimId> =
            sp_std::vec::Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut id_bytes = [0u8; 32];
            id_bytes[..4].copy_from_slice(&i.to_be_bytes());
            id_bytes[4..8].copy_from_slice(b"ATBS");
            let claim_id = ClaimId::from(id_bytes);
            let intent_id = IntentId::from(id_bytes);
            let amount: u64 = 1_000;
            let mut addr = sp_std::vec::Vec::with_capacity(57);
            addr.push(0x01u8);
            addr.extend_from_slice(&payment_hash);
            addr.extend_from_slice(&[0xB1u8; 28]);
            let addr_bv = frame_support::BoundedVec::<u8, sp_core::ConstU32<MAX_CARDANO_ADDR>>::try_from(
                addr,
            )
            .unwrap();
            let bfpr = BatchFairnessProof {
                batch_block_range: (1, 1),
                sorted_intent_ids: frame_support::BoundedVec::try_from(
                    sp_std::vec![intent_id],
                )
                .unwrap(),
                requested_amounts_ada: frame_support::BoundedVec::try_from(
                    sp_std::vec![amount],
                )
                .unwrap(),
                pool_balance_ada: 1_000_000_000,
                pro_rata_scale_bps: 10_000,
                awarded_amounts_ada: frame_support::BoundedVec::try_from(
                    sp_std::vec![amount],
                )
                .unwrap(),
            };
            let bfpr_d = compute_fairness_proof_digest(&bfpr);
            let voucher = Voucher {
                claim_id,
                policy_id: PolicyId::from([0u8; 32]),
                beneficiary_cardano_addr: addr_bv,
                amount_ada: amount,
                batch_fairness_proof_digest: bfpr_d,
                issued_block: 1,
                expiry_slot_cardano: 100_000,
                committee_sigs: Default::default(),
            };
            Vouchers::<T>::insert(claim_id, voucher);
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
            let evidence = SettlementEvidence {
                cardano_tx_hash: [0xFFu8; 32],
                observed_at_depth: T::MinFinalityDepth::get(),
                observed_slot: 12_345_678,
                beneficiary_addr_hash: payment_hash,
                amount_lovelace: amount,
                mainchain_genesis_hash: mc_g,
            };
            ClaimSettlementRequests::<T>::insert(
                claim_id,
                SettlementRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                    requester: caller.clone(),
                    evidence,
                    settled_direct: false,
                    submitted_block: <frame_system::Pallet<T>>::block_number(),
                    bond_amount: 0u128,
                },
            );
            claim_ids.push(claim_id);
        }
        PoolUtilization::<T>::mutate(|u| {
            u.total_nav_ada = u
                .total_nav_ada
                .saturating_add(1_000u64.saturating_mul(n as u64 * 2));
            u.outstanding_coverage_ada = u
                .outstanding_coverage_ada
                .saturating_add(1_000u64.saturating_mul(n as u64));
        });
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];
        let bv: frame_support::BoundedVec<ClaimId, T::MaxSettleBatch> =
            frame_support::BoundedVec::try_from(claim_ids).unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv, signatures);
    }

    // ---- Task #267 (mis-sec P0) — request_expire_policy + attest_expire_policy benches
    //
    // The new attested-expire path replaces the legacy `expire_policy_mirror`.
    // Per design memo §6 #7 the EXPP pre-image is 172 bytes vs the legacy
    // unsigned `expire_policy_mirror` (no sig pre-image at all). One blake2
    // block round-trip per sig, mirroring the spec-220 cost overhead.
    //
    // Bench-cli command (run via downstream materios-runtime):
    //   frame-omni-bencher v1 benchmark pallet \
    //     --runtime <materios_runtime.compact.compressed.wasm> \
    //     --pallet pallet_intent_settlement \
    //     --extrinsic request_expire_policy,attest_expire_policy \
    //     --steps 10 --repeat 5 --genesis-builder runtime
    //
    // Expected slope (the bench uses BenchAllowAnyVerifier so sig-verify is
    // excluded; production runtimes add a fixed Sr25519Verifier cost on top):
    //   request_expire_policy  ~25M ref_time  (intent hydration + storage write)
    //   attest_expire_policy   ~50M ref_time  (intent hydration + storage writes
    //                                          + M-of-N verify)
    // ---------------------------------------------------------------------

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

    /// Bench `attest_expire_policy` — phase 2 of the attested expire path.
    /// Pre-seeds the pending expire request + attested intent so the bench
    /// measures only the sig-verify + storage-mutation cost of the attest
    /// call itself.
    #[benchmark]
    fn attest_expire_policy() {
        use crate::pallet::{Intents, PolicyExpireRequests};
        let caller: T::AccountId = whitelisted_caller();
        T::BenchmarkHelper::whitelist_as_committee(&caller);

        let mut iid_bytes = [0u8; 32];
        iid_bytes[..4].copy_from_slice(b"ATXP");
        let intent_id = IntentId::from(iid_bytes);
        let product_id = PolicyId::from([0x88u8; 32]);

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
        let evidence = ExpiryEvidence {
            cardano_tx_hash: [0xCFu8; 32],
            observed_at_depth: T::MinFinalityDepth::get(),
            observed_slot: 12_345_678,
            mainchain_genesis_hash: mc_g,
            policy_id_witness: product_id,
        };
        PolicyExpireRequests::<T>::insert(
            intent_id,
            ExpiryRequestRecord::<T::AccountId, BlockNumberFor<T>> {
                requester: caller.clone(),
                evidence,
                submitted_block: <frame_system::Pallet<T>>::block_number(),
            },
        );

        let caller_pubkey = T::CommitteeMembership::pubkey_of(&caller);
        let signatures: sp_std::vec::Vec<(CommitteePubkey, CommitteeSig)> =
            sp_std::vec![(caller_pubkey, [0u8; 64])];

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), intent_id, signatures);
    }

    // ---- Task #210 — submit_batch_intents bench -------------------------

    /// Bench `submit_batch_intents` across `Linear<1, MAX_BATCH>` so the
    /// runtime weight generator produces a sublinear curve matching the
    /// spec-207 cost model:
    ///   N=1   ~55M ref_time
    ///   N=8   ~70M ref_time
    ///   N=64  ~150M ref_time
    ///   N=256 ~400M ref_time
    /// Versus 256 single `submit_intent` calls at ~500M each = 128B
    /// ref_time, the batch path is ~320x cheaper at the per-block-budget
    /// level. The economic win is even larger because the user pays one
    /// fee instead of N.
    #[benchmark]
    fn submit_batch_intents(n: Linear<1, MAX_BATCH_BENCH>) {
        let caller: T::AccountId = whitelisted_caller();
        let mut entries: sp_std::vec::Vec<SubmitIntentEntry> =
            sp_std::vec::Vec::with_capacity(n as usize);
        for i in 0..n {
            entries.push(SubmitIntentEntry {
                kind: IntentKind::RequestPayout {
                    policy_id: PolicyId::from({
                        let mut b = [0u8; 32];
                        b[..4].copy_from_slice(&i.to_be_bytes());
                        b
                    }),
                    oracle_evidence: Default::default(),
                },
            });
        }
        let bv: frame_support::BoundedVec<SubmitIntentEntry, T::MaxSubmitBatch> =
            frame_support::BoundedVec::try_from(entries)
                .expect("bench n <= MaxSubmitBatch");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), bv);
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
        seed_expired_bonded_request::<T>(claim_id, evidence, 0);
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
        _(RawOrigin::Signed(caller), claim_id, proof, sp_std::vec![(public.0, signature.0)]);
    }

    /// Bench `supersede_settlement_request` displacing a bonded request, so
    /// the refund and the settle transitions are both measured. The claim's
    /// intent sits last in a full `PendingBatches`, the longest scan its
    /// removal can take.
    #[benchmark]
    fn supersede_settlement_request() {
        let (claim_id, evidence) = seed_settleable_claim::<T>(b"SPSD", 0);
        seed_expired_bonded_request::<T>(claim_id, evidence, 0);
        let intent_id = crate::pallet::Claims::<T>::get(claim_id)
            .expect("seeded claim")
            .intent_id;
        crate::pallet::Intents::<T>::insert(
            intent_id,
            Intent {
                submitter: whitelisted_caller(),
                nonce: 0,
                kind: IntentKind::RequestPayout {
                    policy_id: PolicyId::from([0u8; 32]),
                    oracle_evidence: Default::default(),
                },
                submitted_block: 1,
                ttl_block: 1_000_000,
                status: IntentStatus::Vouchered,
            },
        );
        let capacity = <T as Config>::MaxPendingBatches::get();
        let mut pending: Vec<IntentId> = (1..capacity)
            .map(|index| {
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&index.to_be_bytes());
                id[4..8].copy_from_slice(b"PEND");
                IntentId::from(id)
            })
            .collect();
        pending.push(intent_id);
        crate::pallet::PendingBatches::<T>::put(
            frame_support::BoundedVec::try_from(pending).expect("capacity entries"),
        );
        let (caller, public) = committee_signer::<T>(b"//settlement-supersede-benchmark");
        let voucher = crate::pallet::Vouchers::<T>::get(claim_id).expect("seeded voucher");
        let payload = settle_claim_attested_payload(
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
        );
        let signature = sp_io::crypto::sr25519_sign(SIGNER_KEY_TYPE, &public, &payload)
            .expect("benchmark key was generated");

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            claim_id,
            false,
            evidence,
            sp_std::vec![(public.0, signature.0)],
        );
    }
}
