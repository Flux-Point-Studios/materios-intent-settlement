//! Frame-benchmarking for `pallet-oracle` MON Phase 1 (task #268).
//!
//! Two benches:
//!
//! - `submit_price` — measures the threshold-crossing aggregation path.
//!   Pre-fills `PendingAttestations[(BENCH_PAIR_ID, slot)]` to
//!   `threshold - 1` synthetic observations (capped at
//!   `MaxAttestors - 1`) so the measured call lands at index
//!   `threshold - 1` and triggers aggregation (median sort over `n+1`
//!   elements + clear of `n+1` `AttestorSubmitted` rows + clear of
//!   `PendingAttestations` + `BundleDecimals` row + Prices write + event).
//!
//! - `register_attestor` — measures the sudo-only roster append. Single
//!   storage write + event; no parametrisation (Vec push is O(1) at the
//!   current bound).
//!
//! ## Sig-verify cost (production weight pass)
//!
//! The bench runs under `T::SigVerifier = BenchAllowAnyVerifier` (the
//! WASM runtime-benchmarks build's no-std environment can't sign with
//! `sp_core::sr25519::Pair::sign` — `full_crypto` is std-gated). The
//! production verifier `Sr25519Verifier` performs one
//! `sp_io::crypto::sr25519_verify` call (~50M ref_time). The runtime
//! `weights.rs` re-adds that fixed cost on top of the bench output —
//! same pattern as `pallet-intent-settlement` (see the
//! `BenchAllowAnyVerifier` doc-comment in this pallet's lib.rs for the
//! wire-up contract).

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

/// Pinned bench fixture — the canonical `ADA/USD` pair_id (sha256 of
/// the UTF-8 string `"ADA/USD"`). Matches `tests::ADA_USD_PAIR_ID` so a
/// bench rerun diff against test-harness values is straightforward.
const BENCH_PAIR_ID: types::PairId = [
    0x50, 0xcd, 0x66, 0x50, 0xc9, 0x6b, 0xf3, 0xc0,
    0x16, 0xe7, 0xce, 0x6a, 0xcd, 0x46, 0x59, 0xcb,
    0x6f, 0xc6, 0x48, 0xe0, 0x91, 0x81, 0x34, 0x33,
    0xf1, 0x7e, 0xd7, 0x58, 0x42, 0x83, 0x39, 0x93,
];

/// Deterministic bench attestor pubkey. The runtime's
/// `PalletOracleAttestorRegistry::pubkey_of` is the identity map over
/// `AccountId32` bytes (see `partnerchain-oracle-wire/runtime/src/lib.rs`
/// L1484), so any 32-byte value paired with the matching `AccountId32`
/// passes the origin-pubkey binding check. The byte pattern is
/// arbitrary but distinct from `[0u8; 32]` so any future bench that
/// also seeds synthetic observations doesn't accidentally collide.
const BENCH_ATTESTOR_PUBKEY: types::AttestorPubkey = [
    0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1,
    0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1,
    0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1,
    0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1,
];

#[benchmarks(
    where T: frame_system::Config<AccountId = sp_runtime::AccountId32>,
)]
mod benches {
    use super::*;
    use frame_support::traits::Get;

    /// Worst-case `submit_price` path: the call that triggers aggregation
    /// (bundle reaches `MinAttestorThreshold` post-insert).
    ///
    /// Setup:
    /// - Register the bench attestor for `BENCH_PAIR_ID`.
    /// - Pre-fill `PendingAttestations[(BENCH_PAIR_ID, slot)]` to
    ///   `threshold - 1` synthetic observations (we cap at
    ///   `MaxAttestors - 1` to leave a slot for the bench call).
    /// - Seed `BundleDecimals` so the decimals-coherence check passes.
    ///
    /// Measured call: the threshold-crossing `submit_price` which
    /// performs sig-verify (bench-bypassed via `BenchAllowAnyVerifier` —
    /// the production verifier weight is re-added in the runtime
    /// weights.rs) + bundle push + median sort + Prices write + clears.
    #[benchmark]
    fn submit_price() {
        let pubkey: types::AttestorPubkey = BENCH_ATTESTOR_PUBKEY;

        // Register the bench attestor.
        pallet::Attestors::<T>::mutate(BENCH_PAIR_ID, |roster| {
            // Test/runtime bound; if MaxAttestors=0 the benchmark would
            // be impossible to drive — this is a configuration error,
            // not a runtime bug — so we hard-fail loudly.
            roster
                .try_push(pubkey)
                .expect("MaxAttestors > 0 in any sane runtime config");
        });

        let slot: types::SlotNumber = 1u64;
        let price: u64 = 42u64;
        let decimals: u8 = 6;

        // Pre-fill the pending bundle to (threshold - 1) so the bench
        // call triggers the aggregation path. If threshold is 1, no
        // pre-fill is required — this is the M=1 happy path (design
        // memo §5).
        let threshold: u32 = T::MinAttestorThreshold::get();
        let max_attestors: u32 = T::MaxAttestors::get();
        let prefill_count: u32 = threshold
            .saturating_sub(1)
            .min(max_attestors.saturating_sub(1));

        // Persist the decimals witness on the first synthetic
        // observation so the bench call passes the decimals-coherence
        // gate.
        if prefill_count > 0u32 {
            pallet::BundleDecimals::<T>::insert((BENCH_PAIR_ID, slot), decimals);
        }

        pallet::PendingAttestations::<T>::mutate(BENCH_PAIR_ID, slot, |bundle| {
            for i in 0u32..prefill_count {
                let mut synthetic_pk = [0u8; 32];
                synthetic_pk[..4].copy_from_slice(&i.to_le_bytes());
                // Make the synthetic pks distinct from `BENCH_ATTESTOR_PUBKEY`
                // (which is the all-0xb1 pattern) so the bundle has
                // `threshold` unique pubkeys post-insert and the
                // duplicate-pubkey gate does not fire.
                let synthetic_sig = [0u8; 64];
                bundle
                    .try_push(types::PriceObservation {
                        pubkey: synthetic_pk,
                        price: 41u64 + i as u64,
                        sig: synthetic_sig,
                    })
                    .expect("prefill_count < MaxAttestors by construction");
            }
        });

        // The runtime's `PalletOracleAttestorRegistry::pubkey_of` is the
        // identity map over AccountId32 bytes (runtime L1484), so the
        // origin's account ID = the attestor pubkey bytes. Constructing
        // the caller this way satisfies the origin → pubkey binding
        // gate (gate (1) in `submit_price`).
        let caller: T::AccountId = sp_runtime::AccountId32::new(pubkey).into();

        // Dummy signature — accepted by `BenchAllowAnyVerifier`. The
        // production verifier weight (~50M ref_time for one
        // `sr25519_verify`) is re-added in the runtime weights.rs.
        let sig: types::AttestorSig = [0u8; 64];

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            BENCH_PAIR_ID,
            price,
            decimals,
            slot,
            pubkey,
            sig,
        );

        // Post-call invariants: the threshold-crossing path was taken,
        // so `Prices[BENCH_PAIR_ID]` is now populated and the pending
        // bundle is empty. Asserting these here guards the benchmark
        // against silent regressions (e.g. a future refactor that
        // breaks the aggregation trigger condition — the bench would
        // measure the wrong code path).
        assert!(
            pallet::Prices::<T>::get(BENCH_PAIR_ID).is_some(),
            "bench MUST exercise the threshold-cross aggregation path"
        );
        let pending = pallet::PendingAttestations::<T>::get(BENCH_PAIR_ID, slot);
        assert!(
            pending.is_empty(),
            "pending bundle MUST be cleared on threshold-cross"
        );
    }

    /// Sudo-only roster append. O(1) storage write + event emission.
    #[benchmark]
    fn register_attestor() {
        // Fresh pubkey distinct from `BENCH_ATTESTOR_PUBKEY` so this
        // bench is independent of the `submit_price` bench's setup.
        let pubkey: types::AttestorPubkey = [0x42u8; 32];

        #[extrinsic_call]
        _(RawOrigin::Root, BENCH_PAIR_ID, pubkey);

        // Post-call invariant: the pubkey is now in the roster.
        let roster = pallet::Attestors::<T>::get(BENCH_PAIR_ID);
        assert!(
            roster.contains(&pubkey),
            "register_attestor MUST persist the pubkey into the roster"
        );
    }

    // NOTE: `impl_benchmark_test_suite!` is intentionally OMITTED. The
    // bench harness assumes `T::AccountId = AccountId32` (32-byte sr25519
    // pubkey identity) but the test mock uses `u64` AccountId (so the
    // pallet's unit tests can keep the lightweight u64-keyed mock). The
    // production weight pass runs in the materios-runtime, which wires
    // `AccountId32` end-to-end — that's where the canonical weight
    // values come from. Mirrors the pattern in
    // `pallet-intent-settlement::benchmarking` (line 127 comment block).
}
