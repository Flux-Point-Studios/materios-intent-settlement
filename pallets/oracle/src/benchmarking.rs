//! Frame-benchmarking stubs for `pallet-oracle` Phase 1.
//!
//! Per task #268 scope these are skeletons only — the impl PR replaces the
//! dispatch bodies with real state mutation and these benches must measure
//! that work. For the scaffolding PR the benches exist so the
//! `runtime-benchmarks` feature gate compiles end-to-end.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

#[benchmarks]
mod benches {
    use super::*;

    /// Benchmarks the (stub) `submit_price` extrinsic. Impl PR rewrites
    /// this to measure sig-verify + pending-bundle insert + threshold-
    /// crossing aggregation, parametrised over bundle-size `n ∈
    /// [1, MaxAttestors]`.
    #[benchmark]
    fn submit_price() {
        let caller: T::AccountId = whitelisted_caller();
        let pair_id: types::PairId = [0u8; 32];
        let pubkey: types::AttestorPubkey = [0u8; 32];
        let sig: types::AttestorSig = [0u8; 64];

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            pair_id,
            42u64,
            6u8,
            1_000u64,
            pubkey,
            sig,
        );
    }

    /// Benchmarks the (stub) `register_attestor` extrinsic. Impl PR
    /// rewrites this to measure the `Attestors[pair_id]` push + idempotency
    /// check.
    #[benchmark]
    fn register_attestor() {
        let pair_id: types::PairId = [0u8; 32];
        let pubkey: types::AttestorPubkey = [0u8; 32];

        #[extrinsic_call]
        _(RawOrigin::Root, pair_id, pubkey);
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::tests::new_test_ext(),
        crate::tests::Test
    );
}
