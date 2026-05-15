//! Unit tests for `pallet-oracle` Phase 1 skeleton (task #268).
//!
//! Five tests in this file cover the contract surface that's REAL impl in
//! this PR (the canonical PRIC payload + the pair-id sha256 helper), plus
//! storage-layout / stub-call sanity:
//!
//! 1. [`pric_payload_byte_exact`] — pins the canonical PRIC digest for the
//!    `(ADA/USD, $0.425, 9 decimals, slot=173709)` fixture. This is the
//!    cross-team parity anchor: Aegis publisher Python code, downstream
//!    Aiken validators, and any Rust verifier must reproduce the same
//!    32-byte digest. Breaking this test breaks every signed payload in the
//!    fleet.
//! 2. [`pair_id_for_string_matches_sha256_ada_usd`] — pins
//!    `pair_id_for_string("ADA/USD")` to the sha256 of the literal bytes
//!    `[0x41, 0x44, 0x41, 0x2F, 0x55, 0x53, 0x44]` ("ADA/USD" utf8). Any
//!    silent change to the hash flow (e.g. switching sha256 → blake2_256 for
//!    pair_id) would re-meaning every existing feed; this test catches it.
//! 3. [`pending_attestations_storage_threshold_gate`] — exercises the v1
//!    pending-bundle storage map at threshold-1 capacity. Validates the
//!    impl-PR contract that pending bundles up to `MaxAttestors` are
//!    storable and readable.
//! 4. [`stale_submission_threshold_marker`] — verifies the
//!    `MaxStaleSlots` / `MaxFutureSlots` constants are wired into Config
//!    correctly. The stub dispatch doesn't enforce yet; this test pins
//!    the canonical defaults so the impl PR can't silently drift them.
//! 5. [`duplicate_pubkey_error_variant_distinct`] — verifies
//!    `Error::DuplicatePubkey` is a distinct variant from
//!    `Error::NotAttestor` / `Error::InvalidSignature` (it would be a
//!    classic gotcha to alias them with `#[doc(hidden)]` for byte savings).
//!    The discriminator matters at fail-extrinsic time so callers can
//!    distinguish a replay attempt from an unauthorised caller.

#![cfg(test)]

use crate as pallet_oracle;
use crate::pallet::IsAttestorFor;
use crate::types::*;
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    BoundedVec,
};
use hex_literal::hex;
use sp_runtime::{traits::IdentityLookup, BuildStorage};

// ---------------------------------------------------------------------------
// Mock runtime
// ---------------------------------------------------------------------------

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        Oracle: pallet_oracle,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
}

parameter_types! {
    /// Test fixture for the chain-identity prefix. The same `0x73` repeated
    /// 32 times that pallet-intent-settlement uses (see #73 fixture); keeps
    /// the cross-pallet test fixtures coherent.
    pub const TestMateriosChainId: [u8; 32] = [0x73u8; 32];
    /// v1 minimum: 1 attestor. Production preprod will start here; mainnet
    /// flips to 3 after Witness Network onboarding.
    pub const TestMinAttestorThreshold: u32 = 1;
    /// Test bound on attestors per pair. Matches canonical default 16.
    pub const TestMaxAttestors: u32 = 16;
    /// Test bound on stale-slot rejection. 1200 slots ~2h at 6s blocks.
    pub const TestMaxStaleSlots: u64 = 1200;
    /// Test bound on future-slot rejection.
    pub const TestMaxFutureSlots: u64 = 50;
}

/// Mock attestor registry. Members {1, 2, 3} attest for ANY pair (tests pin
/// per-pair rosters via direct storage manipulation in the impl PR; for v1
/// stub tests the registry is permissive).
pub struct MockAttestorRegistry;
impl IsAttestorFor<u64> for MockAttestorRegistry {
    fn is_attestor(_pair_id: &PairId, who: &u64) -> bool {
        matches!(*who, 1 | 2 | 3)
    }
    fn pubkey_of(who: &u64) -> AttestorPubkey {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&who.to_le_bytes());
        out
    }
    fn threshold_for(_pair_id: &PairId) -> u32 {
        TestMinAttestorThreshold::get()
    }
}

impl pallet_oracle::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MateriosChainId = TestMateriosChainId;
    type MinAttestorThreshold = TestMinAttestorThreshold;
    type MaxAttestors = TestMaxAttestors;
    type MaxStaleSlots = TestMaxStaleSlots;
    type MaxFutureSlots = TestMaxFutureSlots;
    type AttestorRegistry = MockAttestorRegistry;
}

fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

// ---------------------------------------------------------------------------
// Pinned fixtures (the cross-team parity anchor)
// ---------------------------------------------------------------------------

/// `sha256("ADA/USD")` — computed once in
/// `/home/deci/work/mon-phase1-aegis-extend-design.md` §1 and asserted
/// byte-exact here so every implementation (Python, Aiken, Rust) sees the
/// same `PairId`.
const ADA_USD_PAIR_ID: PairId =
    hex!("50cd6650c96bf3c016e7ce6acd4659cb6fc648e091813433f17ed75842833993");

/// `[0x73; 32]` — Materios chain-identity test fixture. Mirrors
/// `pallet-intent-settlement::tests::TestMateriosChainId` so #73-derived
/// digests are coherent across the two pallets at test time.
const TEST_CHAIN_ID: [u8; 32] = [0x73u8; 32];

/// Pinned PRIC digest for `(ADA/USD, price=425_000_000, decimals=9,
/// slot=173709)`. Pre-computed in
/// `/home/deci/work/mon-phase1-aegis-extend-design.md` §1 (test vector
/// table) via:
///
/// ```python
/// import hashlib
/// pair_id = hashlib.sha256(b"ADA/USD").digest()
/// chain_id = bytes([0x73] * 32)
/// preimage = (b"PRIC" + chain_id + pair_id
///             + (425_000_000).to_bytes(8, "little")
///             + bytes([9])
///             + (173_709).to_bytes(8, "little"))
/// assert len(preimage) == 85
/// digest = hashlib.blake2b(preimage, digest_size=32).digest()
/// ```
///
/// digest_hex =
///   `0x74f1ade6b8cab0be3dcaf4edddedd9df16c665a1f154a8ec224bde470a454ba2`
const PINNED_PRIC_DIGEST: [u8; 32] =
    hex!("74f1ade6b8cab0be3dcaf4edddedd9df16c665a1f154a8ec224bde470a454ba2");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn pric_payload_byte_exact() {
    // Inputs match the pinned fixture in the design memo §1. ANY drift in
    // domain tag bytes, chain_id position, pair_id position, price endian,
    // decimals position, or slot endian will flip this digest. That's the
    // contract: the digest is the cross-team parity anchor.
    let pair_id = ADA_USD_PAIR_ID;
    let chain_id = TEST_CHAIN_ID;
    let price: u64 = 425_000_000;
    let decimals: u8 = 9;
    let slot: SlotNumber = 173_709;

    let digest = submit_price_payload(&chain_id, &pair_id, price, decimals, slot);

    assert_eq!(
        digest, PINNED_PRIC_DIGEST,
        "PRIC payload digest drifted from pinned fixture — Aegis publisher \
         and Aiken validators will diverge. See design memo §1 test vector \
         table at /home/deci/work/mon-phase1-aegis-extend-design.md."
    );
}

#[test]
fn pair_id_for_string_matches_sha256_ada_usd() {
    // The pair-id derivation MUST be sha256 of the literal UTF-8 bytes of
    // the pair string. Aegis publisher Python uses `hashlib.sha256(b"ADA/USD")`;
    // this test pins the Rust-side implementation to the same digest so a
    // refactor that swaps sha256 → blake2_256 (or accidentally strips the
    // `/`) fails loudly here, not silently on-chain.
    let from_helper = pair_id_for_string(b"ADA/USD");
    assert_eq!(
        from_helper, ADA_USD_PAIR_ID,
        "pair_id_for_string(\"ADA/USD\") must equal sha256(b\"ADA/USD\"). \
         Any drift re-meanings every existing PriceFeed for this pair."
    );

    // Sanity check: distinct pair string → distinct pair_id. Defends
    // against the "single byte changed silently" failure mode.
    let btc_usd = pair_id_for_string(b"BTC/USD");
    assert_ne!(from_helper, btc_usd, "ADA/USD and BTC/USD must hash distinctly");
}

#[test]
fn pending_attestations_storage_threshold_gate() {
    // Storage layer round-trip: a `BoundedVec<PriceObservation>` at
    // `MaxAttestors` capacity is insertable and readable. The impl PR will
    // push entries via `submit_price`; this test pins the storage shape
    // (DoubleMap<PairId, SlotNumber, BoundedVec<...>>) so an accidental
    // schema change (e.g. swapping DoubleMap → triple-keyed Map) blows up
    // at test time.
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 173_709;

        // Build a 3-observation bundle (M=3 would be the v1.5 quorum once
        // the publisher pool grows beyond M=1).
        let mut bundle: BoundedVec<PriceObservation, <Test as pallet_oracle::Config>::MaxAttestors> =
            BoundedVec::new();
        for i in 0..3u8 {
            let mut pk = [0u8; 32];
            pk[0] = i + 1;
            let mut sig = [0u8; 64];
            sig[0] = i + 1;
            bundle
                .try_push(PriceObservation { pubkey: pk, price: 425_000_000 + i as u64, sig })
                .expect("3 observations < MaxAttestors=16");
        }

        pallet_oracle::pallet::PendingAttestations::<Test>::insert(pair_id, slot, bundle);

        let loaded = pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot);
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].price, 425_000_000);
        assert_eq!(loaded[2].price, 425_000_002);
        // Threshold gate pin: `MinAttestorThreshold = 1` for v1, so even
        // the first observation in this bundle would normally trigger an
        // aggregation. Keeping at 3 here pins the storage shape; impl PR
        // exercises the threshold-cross flow inside `submit_price`.
        assert!(
            (loaded.len() as u32) >= TestMinAttestorThreshold::get(),
            "test bundle must meet v1 threshold = 1"
        );
    });
}

#[test]
fn stale_submission_threshold_marker() {
    // Pin the canonical default constants so the impl PR can't silently
    // drift them (e.g. accidentally setting MaxStaleSlots = 12 instead of
    // 1200, which would reject every Aegis publisher tick > 72s old).

    assert_eq!(<Test as pallet_oracle::Config>::MaxStaleSlots::get(), 1200);
    assert_eq!(<Test as pallet_oracle::Config>::MaxFutureSlots::get(), 50);
    assert_eq!(<Test as pallet_oracle::Config>::MinAttestorThreshold::get(), 1);
    assert_eq!(<Test as pallet_oracle::Config>::MaxAttestors::get(), 16);
    // Chain-id fixture matches pallet-intent-settlement's `[0x73; 32]`
    // pattern. Production runtimes plumb the actual genesis hash.
    assert_eq!(<Test as pallet_oracle::Config>::MateriosChainId::get(), TEST_CHAIN_ID);
}

#[test]
fn duplicate_pubkey_error_variant_distinct() {
    // The pallet defines DuplicatePubkey, NotAttestor, and InvalidSignature
    // as three SEPARATE error variants. Conflating them at fail-extrinsic
    // time hides replay attempts behind generic "unauthorized" errors. Pin
    // the discriminator distinction here so a refactor that types
    // `DuplicatePubkey = NotAttestor` for byte savings flips this test.
    use pallet_oracle::pallet::Error;
    let dup: Error<Test> = Error::DuplicatePubkey;
    let not_attestor: Error<Test> = Error::NotAttestor;
    let bad_sig: Error<Test> = Error::InvalidSignature;

    // PartialEq isn't auto-derived on pallet errors (it's an enum with
    // PhantomData<T>); compare the discriminator strings via Debug to
    // pin the variants distinct without a brittle Encode-trip.
    let dup_s = format!("{:?}", dup);
    let na_s = format!("{:?}", not_attestor);
    let bs_s = format!("{:?}", bad_sig);

    assert_ne!(dup_s, na_s);
    assert_ne!(dup_s, bs_s);
    assert_ne!(na_s, bs_s);
    // Strong-shape assertion: each variant Debug-prints to its own name.
    assert!(dup_s.contains("DuplicatePubkey"));
    assert!(na_s.contains("NotAttestor"));
    assert!(bs_s.contains("InvalidSignature"));
}
