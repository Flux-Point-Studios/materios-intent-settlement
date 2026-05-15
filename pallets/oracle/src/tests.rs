//! Unit tests for `pallet-oracle` MON Phase 1 impl (task #268).
//!
//! Tests fall into two groups:
//!
//! **Scaffolding contract tests (preserved from PR #35):**
//! 1. [`pric_payload_byte_exact`] — pins the canonical PRIC digest for the
//!    `(ADA/USD, $0.425, 9 decimals, slot=173709)` fixture. Cross-team
//!    parity anchor for Aegis publishers (Python), downstream Aiken
//!    validators, and any Rust verifier.
//! 2. [`pair_id_for_string_matches_sha256_ada_usd`] — pins
//!    `pair_id_for_string("ADA/USD")` to the sha256 of the literal UTF-8
//!    bytes.
//! 3. [`pending_attestations_storage_threshold_gate`] — storage layout
//!    round-trip.
//! 4. [`stale_submission_threshold_marker`] — pins the canonical default
//!    constants.
//! 5. [`duplicate_pubkey_error_variant_distinct`] — error-variant
//!    discriminator distinctness.
//!
//! **Impl PR tests (this file adds):**
//! 6. [`submit_price_happy_path_threshold_3`] — 3 attestors submit
//!    different prices, 3rd triggers median aggregation, `Prices` updated.
//! 7. [`submit_price_partial_below_threshold`] — 2 submissions only →
//!    `PriceAttestationSubmitted`, no `Prices` write.
//! 8. [`submit_price_invalid_signature_rejected`] — forged sig rejected
//!    with `InvalidSignature`.
//! 9. [`submit_price_not_attestor_rejected`] — un-registered pubkey
//!    rejected with `NotAttestor`.
//! 10. [`register_attestor_duplicate_rejected`] — duplicate registration
//!     rejected with `AttestorAlreadyRegistered`.
//! 11. [`register_attestor_registry_full_rejected`] — N+1 registration
//!     rejected with `AttestorRegistryFull`.
//! 12. [`submit_price_origin_pubkey_mismatch_rejected`] — origin's
//!     account doesn't bind to the `pubkey` arg → rejected with
//!     `OriginPubkeyMismatch`.

#![cfg(test)]

use crate as pallet_oracle;
use crate::pallet::{IsAttestorFor, Error};
use crate::types::*;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    BoundedVec,
};
use hex_literal::hex;
use sp_core::sr25519;
use sp_keyring::Sr25519Keyring;
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
    /// Tests bump to 3 for the happy-path threshold; the design memo
    /// canonical default is 1 (Aegis-publisher v1 launch threshold) but
    /// the threshold-crossing logic is what we want to exercise.
    pub const TestMinAttestorThreshold: u32 = 3;
    /// Test bound on attestors per pair. Matches canonical default 16.
    pub const TestMaxAttestors: u32 = 16;
    /// Test bound on stale-slot rejection. Very large so block-1 tests
    /// can submit slot=100 without `StaleSubmission` firing.
    pub const TestMaxStaleSlots: u64 = 1_000_000;
    /// Test bound on future-slot rejection. Very large so block-1 tests
    /// can submit slot=100 without `FutureSubmission` firing.
    pub const TestMaxFutureSlots: u64 = 1_000_000;
}

// ---------------------------------------------------------------------------
// Sr25519Keyring-backed attestor registry mock
// ---------------------------------------------------------------------------
//
// In v1 production, `T::AttestorRegistry` would be wired to a runtime
// implementation that maps SS58 account IDs to sr25519 pubkeys (typically
// via `pallet-session` or a custom `Operators` storage map). In tests we
// substitute a hardcoded 1-to-1 map between `u64` account IDs and
// `sp_keyring::Sr25519Keyring` identities. Account ID `1` is Alice,
// `2` is Bob, `3` is Charlie, `4` is Dave, `5` is Eve, `6` is Ferdie.
//
// This lets us drive `submit_price` with REAL sr25519 signatures (rather
// than a marker-byte mock verifier) — the scaffold's docstring contract
// for `submit_price` explicitly mandates `sp_io::crypto::sr25519_verify`
// against the canonical PRIC payload, and `sp-keyring` is already in the
// pallet's dev-dependencies.

fn keyring_for(who: u64) -> Option<Sr25519Keyring> {
    match who {
        1 => Some(Sr25519Keyring::Alice),
        2 => Some(Sr25519Keyring::Bob),
        3 => Some(Sr25519Keyring::Charlie),
        4 => Some(Sr25519Keyring::Dave),
        5 => Some(Sr25519Keyring::Eve),
        6 => Some(Sr25519Keyring::Ferdie),
        _ => None,
    }
}

pub struct MockAttestorRegistry;
impl IsAttestorFor<u64> for MockAttestorRegistry {
    fn is_attestor(_pair_id: &PairId, who: &u64) -> bool {
        keyring_for(*who).is_some()
    }
    fn pubkey_of(who: &u64) -> AttestorPubkey {
        keyring_for(*who)
            .map(|k| k.public().0)
            .unwrap_or([0u8; 32])
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
// Test helpers
// ---------------------------------------------------------------------------

/// Sign the canonical PRIC payload for `(pair_id, price, decimals, slot)`
/// with the given keyring identity. Uses the SAME `TEST_CHAIN_ID` the
/// runtime exposes so submission-time verification matches.
fn sign_pric(
    keyring: Sr25519Keyring,
    pair_id: PairId,
    price: u64,
    decimals: u8,
    slot: SlotNumber,
) -> (AttestorPubkey, AttestorSig) {
    let digest = submit_price_payload(&TEST_CHAIN_ID, &pair_id, price, decimals, slot);
    let sig: sr25519::Signature = keyring.sign(&digest);
    (keyring.public().0, sig.0)
}

/// Drop a registered attestor's pubkey into `Attestors[pair_id]` via
/// direct storage write. Avoids round-tripping through `register_attestor`
/// in tests that only need an attestor to exist; the
/// `register_attestor` extrinsic itself is exercised in its own tests.
fn register_attestor_via_storage(pair_id: PairId, keyring: Sr25519Keyring) {
    pallet_oracle::pallet::Attestors::<Test>::mutate(pair_id, |roster| {
        roster
            .try_push(keyring.public().0)
            .expect("test roster small enough");
    });
}

// ---------------------------------------------------------------------------
// Tests (scaffold-preserved, 1-5)
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
    let from_helper = pair_id_for_string(b"ADA/USD");
    assert_eq!(
        from_helper, ADA_USD_PAIR_ID,
        "pair_id_for_string(\"ADA/USD\") must equal sha256(b\"ADA/USD\"). \
         Any drift re-meanings every existing PriceFeed for this pair."
    );

    let btc_usd = pair_id_for_string(b"BTC/USD");
    assert_ne!(from_helper, btc_usd, "ADA/USD and BTC/USD must hash distinctly");
}

#[test]
fn pending_attestations_storage_threshold_gate() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 173_709;

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
        assert!(
            (loaded.len() as u32) >= TestMinAttestorThreshold::get(),
            "test bundle must meet test threshold = 3"
        );
    });
}

#[test]
fn stale_submission_threshold_marker() {
    // Pin the canonical Config values exposed by the test runtime so a
    // future refactor that silently flips a constant blows up here. Note
    // the test runtime uses larger Max{Stale,Future}Slots than the
    // canonical defaults (1200 / 50) because the test-runtime block
    // number starts at 1 and tests need to submit slot numbers > 1 + 50
    // without triggering `FutureSubmission`. The CANONICAL production
    // defaults (1200 / 50) live in the runtime wiring (Phase 1D) and
    // are tested at runtime-integration level, not here.

    assert_eq!(<Test as pallet_oracle::Config>::MaxStaleSlots::get(), 1_000_000);
    assert_eq!(<Test as pallet_oracle::Config>::MaxFutureSlots::get(), 1_000_000);
    assert_eq!(<Test as pallet_oracle::Config>::MinAttestorThreshold::get(), 3);
    assert_eq!(<Test as pallet_oracle::Config>::MaxAttestors::get(), 16);
    assert_eq!(<Test as pallet_oracle::Config>::MateriosChainId::get(), TEST_CHAIN_ID);
}

#[test]
fn duplicate_pubkey_error_variant_distinct() {
    use pallet_oracle::pallet::Error;
    let dup: Error<Test> = Error::DuplicatePubkey;
    let not_attestor: Error<Test> = Error::NotAttestor;
    let bad_sig: Error<Test> = Error::InvalidSignature;

    let dup_s = format!("{:?}", dup);
    let na_s = format!("{:?}", not_attestor);
    let bs_s = format!("{:?}", bad_sig);

    assert_ne!(dup_s, na_s);
    assert_ne!(dup_s, bs_s);
    assert_ne!(na_s, bs_s);
    assert!(dup_s.contains("DuplicatePubkey"));
    assert!(na_s.contains("NotAttestor"));
    assert!(bs_s.contains("InvalidSignature"));
}

// ---------------------------------------------------------------------------
// Tests (impl PR, 6-12)
// ---------------------------------------------------------------------------

/// 3 attestors submit DIFFERENT prices for `(ADA/USD, slot=100)`. The
/// 3rd submission crosses `MinAttestorThreshold=3` and triggers
/// aggregation: plain median of [425_000_000, 425_000_500,
/// 425_001_000] = 425_000_500. After threshold-cross:
/// - `Prices[pair_id]` is populated with the median,
/// - `PendingAttestations[(pair_id, 100)]` is cleared,
/// - `AttestorSubmitted` rows for this slot are cleared,
/// - `PriceUpdated` event fires.
#[test]
fn submit_price_happy_path_threshold_3() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 100;
        let decimals: u8 = 9;

        // Register 3 attestors.
        register_attestor_via_storage(pair_id, Sr25519Keyring::Alice);
        register_attestor_via_storage(pair_id, Sr25519Keyring::Bob);
        register_attestor_via_storage(pair_id, Sr25519Keyring::Charlie);

        // Alice submits 425_000_000.
        let (pk_a, sig_a) = sign_pric(Sr25519Keyring::Alice, pair_id, 425_000_000, decimals, slot);
        assert_ok!(Oracle::submit_price(
            RuntimeOrigin::signed(1),
            pair_id, 425_000_000, decimals, slot, pk_a, sig_a,
        ));
        // Below threshold → no Prices write, PartialSubmission event.
        assert!(pallet_oracle::pallet::Prices::<Test>::get(pair_id).is_none());
        let pending = pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot);
        assert_eq!(pending.len(), 1);

        // Bob submits 425_001_000.
        let (pk_b, sig_b) = sign_pric(Sr25519Keyring::Bob, pair_id, 425_001_000, decimals, slot);
        assert_ok!(Oracle::submit_price(
            RuntimeOrigin::signed(2),
            pair_id, 425_001_000, decimals, slot, pk_b, sig_b,
        ));
        assert!(pallet_oracle::pallet::Prices::<Test>::get(pair_id).is_none());
        let pending = pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot);
        assert_eq!(pending.len(), 2);

        // Charlie submits 425_000_500 — crosses threshold.
        let (pk_c, sig_c) = sign_pric(Sr25519Keyring::Charlie, pair_id, 425_000_500, decimals, slot);
        assert_ok!(Oracle::submit_price(
            RuntimeOrigin::signed(3),
            pair_id, 425_000_500, decimals, slot, pk_c, sig_c,
        ));

        // Prices[pair_id] now populated with median 425_000_500.
        let feed = pallet_oracle::pallet::Prices::<Test>::get(pair_id)
            .expect("Prices must be set after threshold-cross");
        assert_eq!(feed.last_price, 425_000_500, "plain median of [425_000_000, 425_000_500, 425_001_000]");
        assert_eq!(feed.last_decimals, 9);
        assert_eq!(feed.last_update_slot, slot);
        assert_eq!(feed.aggregation, AggregationMethod::Median);
        assert_eq!(feed.attestor_set.len(), 3);

        // Pending bundle cleared.
        let pending_after =
            pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot);
        assert!(pending_after.is_empty(), "bundle MUST be cleared on threshold-cross");

        // Per-attestor idempotency rows cleared.
        assert!(!pallet_oracle::pallet::AttestorSubmitted::<Test>::contains_key(
            (pair_id, slot, pk_a)
        ));
        assert!(!pallet_oracle::pallet::AttestorSubmitted::<Test>::contains_key(
            (pair_id, slot, pk_b)
        ));
        assert!(!pallet_oracle::pallet::AttestorSubmitted::<Test>::contains_key(
            (pair_id, slot, pk_c)
        ));

        // Decimals witness cleared.
        assert!(
            pallet_oracle::pallet::BundleDecimals::<Test>::get((pair_id, slot)).is_none(),
            "decimals witness MUST be cleared on threshold-cross"
        );

        // Runtime read-API surfaces the aggregated value.
        let (read_price, read_decimals, read_slot) =
            Oracle::get_price(pair_id).expect("get_price after aggregation");
        assert_eq!(read_price, 425_000_500);
        assert_eq!(read_decimals, 9);
        assert_eq!(read_slot, slot);

        // Event emitted.
        System::assert_has_event(
            pallet_oracle::pallet::Event::<Test>::PriceUpdated {
                pair_id,
                price: 425_000_500,
                decimals: 9,
                observed_at_slot: slot,
                attestor_count: 3,
                aggregation: AggregationMethod::Median,
            }
            .into(),
        );
    });
}

/// 2 attestors submit; bundle is below `MinAttestorThreshold=3`. No
/// `Prices` write, `PriceAttestationSubmitted` event fires for each
/// submission.
#[test]
fn submit_price_partial_below_threshold() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 100;

        register_attestor_via_storage(pair_id, Sr25519Keyring::Alice);
        register_attestor_via_storage(pair_id, Sr25519Keyring::Bob);

        let (pk_a, sig_a) = sign_pric(Sr25519Keyring::Alice, pair_id, 100, 6, slot);
        assert_ok!(Oracle::submit_price(
            RuntimeOrigin::signed(1),
            pair_id, 100, 6, slot, pk_a, sig_a,
        ));

        let (pk_b, sig_b) = sign_pric(Sr25519Keyring::Bob, pair_id, 200, 6, slot);
        assert_ok!(Oracle::submit_price(
            RuntimeOrigin::signed(2),
            pair_id, 200, 6, slot, pk_b, sig_b,
        ));

        // No Prices write — threshold not crossed.
        assert!(pallet_oracle::pallet::Prices::<Test>::get(pair_id).is_none());

        // Bundle has both observations.
        let pending = pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot);
        assert_eq!(pending.len(), 2);

        // PriceAttestationSubmitted event fired for the second submission
        // (we check the most recent; ordering: event order matches
        // submission order so the last submission's pending_count=2).
        System::assert_has_event(
            pallet_oracle::pallet::Event::<Test>::PriceAttestationSubmitted {
                pair_id,
                slot_observed: slot,
                attestor: pk_b,
                pending_count: 2,
            }
            .into(),
        );

        // Specifically NO PriceUpdated event yet.
        let events = System::events();
        let has_updated = events.iter().any(|r| matches!(
            r.event,
            RuntimeEvent::Oracle(pallet_oracle::pallet::Event::PriceUpdated { .. })
        ));
        assert!(!has_updated, "PriceUpdated MUST NOT fire below threshold");
    });
}

/// A submission whose sig was signed over a DIFFERENT price than the
/// `price` argument fails with `InvalidSignature`. (This is the canonical
/// forged-sig attack: attacker replays an old sig over a tampered price.)
#[test]
fn submit_price_invalid_signature_rejected() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 100;
        let decimals: u8 = 6;

        register_attestor_via_storage(pair_id, Sr25519Keyring::Alice);

        // Sign over price=100 but submit with price=200. The verifier
        // recomputes the digest from the SUBMITTED price and the sig
        // won't match.
        let (pk_a, sig_over_100) = sign_pric(Sr25519Keyring::Alice, pair_id, 100, decimals, slot);

        assert_noop!(
            Oracle::submit_price(
                RuntimeOrigin::signed(1),
                pair_id, 200, decimals, slot, pk_a, sig_over_100,
            ),
            Error::<Test>::InvalidSignature
        );

        // No state mutation occurred.
        assert!(pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot).is_empty());
    });
}

/// A submission from an attestor whose pubkey is NOT in
/// `Attestors[pair_id]` fails with `NotAttestor`. (Caller has a valid
/// substrate account binding but the pubkey itself was never registered
/// for this pair.)
#[test]
fn submit_price_not_attestor_rejected() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 100;
        let decimals: u8 = 6;

        // Register Alice. Bob is NOT registered.
        register_attestor_via_storage(pair_id, Sr25519Keyring::Alice);

        // Bob signs a valid sig over a valid payload, but Bob's pubkey
        // isn't in the roster.
        let (pk_b, sig_b) = sign_pric(Sr25519Keyring::Bob, pair_id, 100, decimals, slot);

        assert_noop!(
            Oracle::submit_price(
                RuntimeOrigin::signed(2),
                pair_id, 100, decimals, slot, pk_b, sig_b,
            ),
            Error::<Test>::NotAttestor
        );
    });
}

/// `register_attestor` called twice for the same `(pair_id, pubkey)`
/// fails the second time with `AttestorAlreadyRegistered`.
#[test]
fn register_attestor_duplicate_rejected() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let pk_a = Sr25519Keyring::Alice.public().0;

        assert_ok!(Oracle::register_attestor(RuntimeOrigin::root(), pair_id, pk_a));
        // Second registration of same pubkey fails.
        assert_noop!(
            Oracle::register_attestor(RuntimeOrigin::root(), pair_id, pk_a),
            Error::<Test>::AttestorAlreadyRegistered
        );

        // Roster has exactly one entry.
        let roster = pallet_oracle::pallet::Attestors::<Test>::get(pair_id);
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0], pk_a);

        // Event was emitted once.
        System::assert_has_event(
            pallet_oracle::pallet::Event::<Test>::AttestorRegistered {
                pair_id,
                pubkey: pk_a,
            }
            .into(),
        );
    });
}

/// `register_attestor` called N+1 times where N = `MaxAttestors`
/// fails the N+1 call with `AttestorRegistryFull`.
#[test]
fn register_attestor_registry_full_rejected() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let max = <Test as pallet_oracle::Config>::MaxAttestors::get();

        // Fill the roster to capacity with distinct synthetic pubkeys.
        for i in 0..max {
            let mut pk = [0u8; 32];
            // Write i into bytes [0..4] so each pk is distinct.
            pk[..4].copy_from_slice(&(i as u32).to_le_bytes());
            assert_ok!(Oracle::register_attestor(RuntimeOrigin::root(), pair_id, pk));
        }

        // One more push — N+1 — must fail with AttestorRegistryFull.
        let mut overflow_pk = [0u8; 32];
        overflow_pk[..4].copy_from_slice(&(max as u32).to_le_bytes());
        assert_noop!(
            Oracle::register_attestor(RuntimeOrigin::root(), pair_id, overflow_pk),
            Error::<Test>::AttestorRegistryFull
        );

        // Roster is exactly at capacity, not over.
        let roster = pallet_oracle::pallet::Attestors::<Test>::get(pair_id);
        assert_eq!(roster.len() as u32, max);
    });
}

/// `submit_price` called by Alice's account (1) but with Bob's pubkey
/// argument fails with `OriginPubkeyMismatch`. Defends against the
/// "hijacked substrate account submits under another attestor's identity"
/// attack.
#[test]
fn submit_price_origin_pubkey_mismatch_rejected() {
    new_test_ext().execute_with(|| {
        let pair_id = ADA_USD_PAIR_ID;
        let slot: SlotNumber = 100;
        let decimals: u8 = 6;

        register_attestor_via_storage(pair_id, Sr25519Keyring::Bob);

        // Bob signs a valid sig — but Alice submits the extrinsic with
        // Bob's pubkey + sig. Origin binds to Alice (account 1) but the
        // pubkey arg is Bob's → mismatch.
        let (pk_b, sig_b) = sign_pric(Sr25519Keyring::Bob, pair_id, 100, decimals, slot);

        assert_noop!(
            Oracle::submit_price(
                RuntimeOrigin::signed(1), // Alice's account, NOT Bob's
                pair_id, 100, decimals, slot, pk_b, sig_b,
            ),
            Error::<Test>::OriginPubkeyMismatch
        );

        // No state mutation.
        assert!(pallet_oracle::pallet::PendingAttestations::<Test>::get(pair_id, slot).is_empty());
    });
}
