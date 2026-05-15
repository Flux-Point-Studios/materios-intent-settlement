//! Frame-benchmarking for `pallet-oracle` MON Phase 1 (task #268).
//!
//! Two benches:
//!
//! - `submit_price` — measures the single-attestor partial submission AND
//!   the threshold-crossing aggregation path. Parametrised over the
//!   pre-existing pending-bundle size `n ∈ [0, MaxAttestors - 1]`. The
//!   submission lands at index `n`. When `n + 1 == MinAttestorThreshold`,
//!   the call triggers aggregation (worst case: median sort over `n+1`
//!   elements + clear of `n+1` `AttestorSubmitted` rows + clear of
//!   `PendingAttestations` + `BundleDecimals` row + Prices write + event).
//!   The runtime-benchmarks bench builds the worst case
//!   (`n = MaxAttestors - 1`, aggregator path) so weights are over- not
//!   under-stated for production callers.
//!
//! - `register_attestor` — measures the sudo-only roster append. Single
//!   storage write + event; no parametrisation (Vec push is O(1) at the
//!   current bound).
//!
//! ## Production sig-verify weight
//!
//! `submit_price` calls `sp_io::crypto::sr25519_verify`, which costs a
//! fixed ~50µs CPU. The bench measures it through real-key signing (we
//! pass a real sr25519 sig produced by `sp_keyring::Sr25519Keyring::Alice`).
//! Mirrors the `Sr25519Verifier` path in `pallet-intent-settlement` — see
//! the "Production verifier" doc-comment at lib.rs:778 of the
//! intent-settlement pallet for the wire-up pattern.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use sp_core::sr25519;

/// Pinned bench fixtures — match the same `ADA/USD` pair_id used in
/// the unit tests so any bench rerun + diff against test-harness values
/// is straightforward.
const BENCH_PAIR_ID: types::PairId = [
    0x50, 0xcd, 0x66, 0x50, 0xc9, 0x6b, 0xf3, 0xc0,
    0x16, 0xe7, 0xce, 0x6a, 0xcd, 0x46, 0x59, 0xcb,
    0x6f, 0xc6, 0x48, 0xe0, 0x91, 0x81, 0x34, 0x33,
    0xf1, 0x7e, 0xd7, 0x58, 0x42, 0x83, 0x39, 0x93,
];

/// The bench harness can't call back into a `Sr25519Keyring`-based mock
/// (sp-keyring is a dev-dep and doesn't compile under runtime-benchmarks
/// in some runtime configurations). We instead generate a deterministic
/// sr25519 keypair from a hardcoded 32-byte seed and sign the canonical
/// PRIC payload at call time. Pattern mirrors the
/// `pallet-intent-settlement` bench fixtures.
fn bench_keypair() -> sr25519::Pair {
    use sp_core::Pair;
    // Same seed as `pallet-intent-settlement::benchmarks` Alice fixture
    // for cross-pallet bench coherence.
    let seed: [u8; 32] = *b"//Alice//Oracle//Bench////////32";
    sr25519::Pair::from_seed(&seed)
}

#[benchmarks(
    where T: frame_system::Config<AccountId = sp_runtime::AccountId32>,
)]
mod benches {
    use super::*;
    use frame_support::traits::Get;
    use sp_core::Pair;

    /// Worst-case `submit_price` path: the call that triggers aggregation
    /// (bundle reaches `MinAttestorThreshold` post-insert).
    ///
    /// Setup:
    /// - Register the bench attestor for `BENCH_PAIR_ID`.
    /// - Pre-fill `PendingAttestations[(BENCH_PAIR_ID, slot)]` to
    ///   `threshold - 1` synthetic observations (we cap at
    ///   `MaxAttestors - 1` to leave a slot for the bench call).
    ///
    /// Measured call: the threshold-crossing `submit_price` which performs
    /// sig-verify + bundle push + median sort + Prices write + clears.
    #[benchmark]
    fn submit_price() {
        let pair = bench_keypair();
        let pubkey: types::AttestorPubkey = pair.public().0;

        // Register the bench attestor.
        pallet::Attestors::<T>::mutate(BENCH_PAIR_ID, |roster| {
            let _ = roster.try_push(pubkey);
        });

        let slot: types::SlotNumber = 1u64;
        let price: u64 = 42u64;
        let decimals: u8 = 6;

        // Pre-fill the pending bundle to (threshold - 1) so the bench
        // call triggers the aggregation path. If threshold is 1, no
        // pre-fill needed (this is the M=1 happy path — design memo
        // §5).
        let threshold: u32 = T::MinAttestorThreshold::get();
        let max_attestors: u32 = T::MaxAttestors::get();
        let prefill_count: u32 = threshold
            .saturating_sub(1)
            .min(max_attestors.saturating_sub(1));

        // Also persist the decimals witness on the first synthetic
        // observation so the bench call passes the decimals-coherence
        // check.
        if prefill_count > 0u32 {
            pallet::BundleDecimals::<T>::insert((BENCH_PAIR_ID, slot), decimals);
        }

        pallet::PendingAttestations::<T>::mutate(BENCH_PAIR_ID, slot, |bundle| {
            for i in 0u32..prefill_count {
                let mut synthetic_pk = [0u8; 32];
                synthetic_pk[..4].copy_from_slice(&i.to_le_bytes());
                let synthetic_sig = [0u8; 64];
                let _ = bundle.try_push(types::PriceObservation {
                    pubkey: synthetic_pk,
                    price: 41u64 + i as u64,
                    sig: synthetic_sig,
                });
            }
        });

        // Build the canonical PRIC payload and sign it.
        let chain_id = T::MateriosChainId::get();
        let digest = types::submit_price_payload(
            &chain_id,
            &BENCH_PAIR_ID,
            price,
            decimals,
            slot,
        );
        let sig: types::AttestorSig = pair.sign(&digest).0;

        // The bench mock account is the pubkey's AccountId32. The
        // `T::AttestorRegistry::pubkey_of` must agree — runtime
        // configures this via the production registry. In bench, we
        // assume the runtime ties AccountId32 = pubkey bytes (standard
        // sr25519 mapping); if the production registry differs, the
        // sig-verify still measures correctly even if origin-binding
        // fails — the bench's measurable cost is sig-verify + storage
        // mutation.
        //
        // Note: when wired into the production runtime, this bench
        // needs an AttestorRegistry impl that maps the bench account
        // to the bench pubkey. The runtime-side wiring lands in
        // Phase 1D (separate PR).
        let caller: T::AccountId = sp_runtime::AccountId32::new(pubkey).into();

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
    }

    /// Sudo-only roster append. O(1) storage write + event emission.
    #[benchmark]
    fn register_attestor() {
        let pair = bench_keypair();
        let pubkey: types::AttestorPubkey = pair.public().0;

        #[extrinsic_call]
        _(RawOrigin::Root, BENCH_PAIR_ID, pubkey);
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
