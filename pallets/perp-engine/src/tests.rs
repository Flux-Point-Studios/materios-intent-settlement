//! Unit tests for `pallet-perp-engine` v0 (task #259).
//!
//! PR-A scaffold landed 5 surface-only tests; PR-B adds the impl-body
//! coverage. This file ships both: the original PR-A tests plus
//! ~18 new behaviour tests for `open_position`, `close_position`,
//! `deposit_margin`, `withdraw_margin`, and `adjust_leverage` per the
//! impl contract in design memo §3 + §6.1.
//!
//! ## Mock oracle
//!
//! The mock `PriceOracle` reads from `MockOraclePrices` /
//! `MockOracleFresh` thread-local-backed storage maps so each test can
//! configure prices independently per feed_id. Use the helpers
//! `set_oracle_price` / `set_oracle_fresh` at the top of each test
//! that depends on a specific oracle state.
//!
//! ## Markets
//!
//! Tests register markets via direct storage writes (`Markets::insert`).
//! `governance_set_market` impl is reserved for PR-D so we bypass it
//! here — same shape as `pallet-oracle`'s `tests.rs` does for
//! `register_attestor` pre-coverage.
//!
//! ## Counts
//!
//! - 5 PR-A tests (kept intact, with `call_surface_exposed` adjusted
//!   for the new impl bodies that need a market registered).
//! - 18 new PR-B behaviour tests covering opens, closes, deposits,
//!   withdrawals, leverage adjusts, and the math-overflow guard.

#![cfg(test)]

use crate as pallet_perp_engine;
use crate::math;
use crate::pallet::{Error, PriceOracle};
use crate::types::*;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::ConstU128,
    PalletId,
};
use sp_runtime::{traits::IdentityLookup, BuildStorage};
use std::cell::RefCell;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Mock runtime
// ---------------------------------------------------------------------------

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        PerpEngine: pallet_perp_engine,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<u128>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
    type Balance = u128;
    type ExistentialDeposit = ConstU128<1>;
}

parameter_types! {
    /// 32-byte chain-identity fixture. Mirrors `pallet-oracle::tests`
    /// (the `0x73` repeated 32 times) so cross-pallet test fixtures stay
    /// coherent.
    pub const TestMateriosChainId: [u8; 32] = [0x73u8; 32];
    /// Hard cap on leverage across all markets. Design memo §9.1
    /// canonical default = 2000 bps (= 20×).
    pub const TestMaxLeverageBps: u32 = 2_000;
    /// Floor on leverage. §9.1 canonical default = 100 bps (= 1×).
    pub const TestMinLeverageBps: u32 = 100;
    /// Max distinct markets. v0 ships 3 at launch (§9.2); 32 leaves
    /// growth headroom.
    pub const TestMaxMarkets: u32 = 32;
    /// Funding-sample bound per epoch. §4.5 / §7.3: one sample per
    /// block; 600 = 1h at 6s.
    pub const TestMaxFundingSamplesPerEpoch: u32 = 600;
    /// Min keeper bond, in u128 MOTRA units. §6.4 canonical 100 MATRA;
    /// the test runtime uses raw integers and a `u128` Balance.
    pub const TestKeeperBondMinimum: u128 = 100;
    /// Mark freshness limit in blocks. §9.1 canonical default = 50
    /// (~5 min).
    pub const TestFreshnessLimitBlocks: u32 = 50;
    /// Max mark basis (deviation from oracle). §9.1 canonical 200 bps
    /// = 2%.
    pub const TestMaxMarkBasisBps: u32 = 200;
    /// Bad-debt circuit-breaker threshold. §9.1 canonical $10_000 =
    /// 10^22 in 1e18 units.
    pub const TestBadDebtCircuitBreakerThresholdE18: u128 = 10_000_000_000_000_000_000_000u128;
    /// Bad-debt window. §9.1 canonical 14_400 (~24h).
    pub const TestBadDebtWindowBlocks: u32 = 14_400;
    /// PalletId for the pot account. Matches the pattern used elsewhere
    /// in the workspace ("mat/" prefix per `feedback_chain_reset_runbook`).
    pub const TestPerpPalletId: PalletId = PalletId(*b"mat/pep0");
    /// Withdraw dwell time in blocks (24h at 6s = 14_400). Tests
    /// drive `System::set_block_number(now + dwell + 1)` to clear it.
    pub const TestWithdrawDwellBlocks: u32 = 14_400;
}

/// MATRA/USD feed id for the test fixture. Production: the canonical
/// Aegis-published feed handle.
fn matra_usd_feed_id() -> OracleFeedId {
    OracleFeedId::try_from(b"MATRA/USD".to_vec())
        .expect("9 bytes < MAX_MARKET_ID_LEN=16")
}

parameter_types! {
    pub TestMatraUsdFeedId: OracleFeedId = matra_usd_feed_id();
}

thread_local! {
    /// Per-feed price (1e18-scaled).
    static MOCK_ORACLE_PRICES: RefCell<HashMap<Vec<u8>, u128>> =
        RefCell::new(HashMap::new());
    /// Per-feed freshness flag.
    static MOCK_ORACLE_FRESH: RefCell<HashMap<Vec<u8>, bool>> =
        RefCell::new(HashMap::new());
}

/// Mock price oracle backed by thread-local storage. Tests can pause
/// or repoint a feed via `set_oracle_price` / `set_oracle_fresh`.
/// Default: every feed returns `$1.00` 1e18-scaled and is fresh.
pub struct MockPriceOracle;
impl PriceOracle for MockPriceOracle {
    fn latest_price_e18(feed_id: &OracleFeedId) -> Option<u128> {
        let key = feed_id.to_vec();
        MOCK_ORACLE_PRICES.with(|m| m.borrow().get(&key).copied())
    }
    fn price_age_blocks(_feed_id: &OracleFeedId) -> u32 {
        0
    }
    fn is_fresh(feed_id: &OracleFeedId) -> bool {
        let key = feed_id.to_vec();
        MOCK_ORACLE_FRESH.with(|m| m.borrow().get(&key).copied().unwrap_or(false))
    }
}

/// Wipes the mock oracle and configures `feed_id → price_e18` + fresh.
pub fn set_oracle_price(feed_id: &OracleFeedId, price_e18: u128) {
    let key = feed_id.to_vec();
    MOCK_ORACLE_PRICES.with(|m| {
        m.borrow_mut().insert(key.clone(), price_e18);
    });
    MOCK_ORACLE_FRESH.with(|m| {
        m.borrow_mut().insert(key, true);
    });
}

/// Sets a feed's freshness flag. Pricing must already be set via
/// `set_oracle_price`; this only flips `is_fresh`.
pub fn set_oracle_fresh(feed_id: &OracleFeedId, fresh: bool) {
    let key = feed_id.to_vec();
    MOCK_ORACLE_FRESH.with(|m| {
        m.borrow_mut().insert(key, fresh);
    });
}

/// Removes the price entry — `latest_price_e18` returns `None`.
/// Reserved for PR-C liquidate tests that need to drop the oracle
/// mid-flight. Public so the future-PR tests can use it.
#[allow(dead_code)]
pub fn clear_oracle_price(feed_id: &OracleFeedId) {
    let key = feed_id.to_vec();
    MOCK_ORACLE_PRICES.with(|m| {
        m.borrow_mut().remove(&key);
    });
    MOCK_ORACLE_FRESH.with(|m| {
        m.borrow_mut().remove(&key);
    });
}

impl pallet_perp_engine::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type PriceOracle = MockPriceOracle;
    type PalletId = TestPerpPalletId;
    type MateriosChainId = TestMateriosChainId;
    type MaxLeverageBps = TestMaxLeverageBps;
    type MinLeverageBps = TestMinLeverageBps;
    type MaxMarkets = TestMaxMarkets;
    type MaxFundingSamplesPerEpoch = TestMaxFundingSamplesPerEpoch;
    type KeeperBondMinimum = TestKeeperBondMinimum;
    type FreshnessLimitBlocks = TestFreshnessLimitBlocks;
    type MaxMarkBasisBps = TestMaxMarkBasisBps;
    type BadDebtCircuitBreakerThresholdE18 = TestBadDebtCircuitBreakerThresholdE18;
    type BadDebtWindowBlocks = TestBadDebtWindowBlocks;
    type MatraUsdFeedId = TestMatraUsdFeedId;
    type WithdrawDwellBlocks = TestWithdrawDwellBlocks;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        // Reset mock-oracle storage between tests (thread-local
        // would otherwise persist).
        MOCK_ORACLE_PRICES.with(|m| m.borrow_mut().clear());
        MOCK_ORACLE_FRESH.with(|m| m.borrow_mut().clear());
        System::set_block_number(1);
        // Default MATRA/USD = $1.00. Most tests treat MOTRA == USD
        // 1:1 so the conversion arithmetic doesn't dominate test
        // assertions; one test below pegs it differently to prove
        // the conversion math.
        set_oracle_price(&matra_usd_feed_id(), 1_000_000_000_000_000_000u128);
        // Default ADA/USD = $1.00 — same logic.
        set_oracle_price(&ada_usd_feed_id(), 1_000_000_000_000_000_000u128);
    });
    ext
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn ada_perp_market_id() -> MarketId {
    MarketId::try_from(b"ADA-PERP/USD".to_vec())
        .expect("12 bytes < MAX_MARKET_ID_LEN=16")
}

fn ada_usd_feed_id() -> OracleFeedId {
    OracleFeedId::try_from(b"ADA/USD".to_vec())
        .expect("7 bytes < MAX_MARKET_ID_LEN=16")
}

/// Build a canonical v0 MarketConfig for ADA-PERP/USD matching the
/// design-memo §9.1 defaults + §9.2 initial market set. Used in tests
/// that need a well-formed config without exercising the
/// governance_set_market validation path.
fn default_ada_perp_market_config() -> MarketConfig {
    MarketConfig {
        id: ada_perp_market_id(),
        oracle_feed_id: ada_usd_feed_id(),
        initial_margin_bps: 1_000,             // 10% (§9.1)
        maintenance_margin_bps: 500,            // 5% (§9.1)
        max_leverage_bps: 1_000,                // 10× at launch (§9.1)
        max_funding_per_epoch_bps: 400,         // 4%/h cap (§9.1, §7.1)
        liquidation_fee_bps: 50,                // 0.5% (§9.1)
        maker_fee_bps: -2,                      // 2 bps rebate (§9.1)
        taker_fee_bps: 7,                       // 7 bps taker (§9.1)
        max_position_size_e8: 250_000_000_000,  // $250k notional cap (§9.1)
        min_position_size_e8: 1_000_000,        // $10 dust filter (§9.1)
        mark_ema_window_blocks: 25,             // ~150s (§9.1)
        funding_epoch_blocks: 600,              // ~1h (§9.1, §7.2)
        paused: false,
    }
}

/// Inserts a fresh ADA-PERP market into storage. Tests bypass
/// `governance_set_market` (reserved for PR-D) and write directly.
fn register_default_market() {
    pallet_perp_engine::pallet::Markets::<Test>::insert(
        &ada_perp_market_id(),
        default_ada_perp_market_config(),
    );
}

/// Inserts a market that's paused (for the paused-rejection test).
fn register_paused_market() {
    let mut cfg = default_ada_perp_market_config();
    cfg.paused = true;
    pallet_perp_engine::pallet::Markets::<Test>::insert(&ada_perp_market_id(), cfg);
}

/// Credit `who` with raw MOTRA on the Balances pallet so they can
/// `deposit_margin`. (Tests that mutate `MarginAccount.free_e18`
/// directly skip Balances and write through the margin map.)
fn credit_motra(who: u64, amount: u128) {
    pallet_balances::Pallet::<Test>::force_set_balance(
        RuntimeOrigin::root(),
        who,
        amount,
    )
    .expect("force_set_balance succeeds");
}

/// Helper: directly seed `MarginAccount.free_e18` without going through
/// `deposit_margin`. Used by tests that want to skip the MOTRA leg
/// for clarity.
///
/// `weighted_deposit_rate_e18` is seeded to 0 so `withdraw_margin`
/// falls back to the LIVE MATRA/USD rate at withdraw time (the legacy
/// pre-snapshot conversion behaviour, preserved for tests that
/// directly seed balances and don't care about deposit-rate
/// accounting). New tests that exercise the snapshot-rate clamp
/// should call `deposit_margin` through the real extrinsic path so
/// the rate gets pinned correctly.
fn seed_free_margin(who: u64, free_e18: u128) {
    pallet_perp_engine::pallet::MarginAccounts::<Test>::insert(
        who,
        MarginAccount {
            free_e18,
            last_deposit_block: 0,
            weighted_deposit_rate_e18: 0,
        },
    );
}

// ---------------------------------------------------------------------------
// PR-A surface tests (kept)
// ---------------------------------------------------------------------------

/// Smoke test — every public type from `types::*` constructs end-to-end
/// under the test runtime. If a type's encoding shape drifts (e.g. a
/// field is renamed or its position swapped), this test fails to
/// compile.
#[test]
fn it_compiles() {
    // MarketId: bounded UTF-8 byte string.
    let market_id = ada_perp_market_id();
    assert_eq!(&market_id[..], b"ADA-PERP/USD");

    // PerpDirection at the extrinsic boundary.
    let long = PerpDirection::Long;
    let short = PerpDirection::Short;
    assert_ne!(long, short);

    // MarketConfig with all design-memo §9.1 defaults.
    let cfg = default_ada_perp_market_config();
    assert_eq!(cfg.initial_margin_bps, 1_000);
    assert_eq!(cfg.maintenance_margin_bps, 500);
    assert!(
        cfg.maintenance_margin_bps < cfg.initial_margin_bps,
        "MM must be < IM per §3.8 governance validation"
    );

    // Position: signed size + 1e18-scaled price + signed cumulative
    // funding. Pin all fields exist + accept canonical magnitudes.
    let pos = Position {
        size_e8: 100_000_000i128, // 1.0 long
        entry_mark_e18: 425_000_000_000_000_000u128, // $0.425 ADA/USD at 1e18
        locked_margin_e18: 42_500_000_000_000_000u128, // 10% margin
        leverage_bps: 1_000,
        opened_block: 100,
        cumulative_funding_at_open_e18: 0i128,
    };
    assert_eq!(pos.size_e8, 100_000_000);

    // MarginAccount with 1e18-scaled free balance.
    let acct = MarginAccount {
        free_e18: 1_000_000_000_000_000_000u128, // 1.0 pMATRA-USD
        last_deposit_block: 50,
        weighted_deposit_rate_e18: 1_000_000_000_000_000_000u128, // 1.0 MATRA/USD snapshot
    };
    assert_eq!(acct.free_e18, 1_000_000_000_000_000_000u128);
    assert_eq!(acct.weighted_deposit_rate_e18, 1_000_000_000_000_000_000u128);
    // Default impl gives zero balance + zero block.
    assert_eq!(MarginAccount::default().free_e18, 0);
    assert_eq!(MarginAccount::default().last_deposit_block, 0);

    // MarkPriceCache with positive AND negative basis variants.
    let cache_pos = MarkPriceCache {
        mark_e18: 425_100_000_000_000_000u128,
        oracle_e18: 425_000_000_000_000_000u128,
        block: 100,
        mark_ema_basis_e18: 100_000_000_000_000i128,
    };
    let cache_neg = MarkPriceCache {
        mark_e18: 424_900_000_000_000_000u128,
        oracle_e18: 425_000_000_000_000_000u128,
        block: 100,
        mark_ema_basis_e18: -100_000_000_000_000i128,
    };
    assert!(cache_pos.mark_e18 > cache_neg.mark_e18);

    // PerpActionKind: 4 distinct variants for the IntentKind::PerpAction
    // extension that lands in PR-C.
    assert_ne!(PerpActionKind::Open, PerpActionKind::Close);
    assert_ne!(PerpActionKind::Close, PerpActionKind::Liquidation);
    assert_ne!(PerpActionKind::Liquidation, PerpActionKind::LeverageAdjust);
}

/// Genesis storage is empty for every map. This pins the schema
/// against an accidental `GenesisConfig` block in PR-B that
/// pre-populates state.
#[test]
fn genesis_state_empty() {
    new_test_ext().execute_with(|| {
        // No markets registered.
        assert!(pallet_perp_engine::pallet::Markets::<Test>::iter().next().is_none());

        // No positions.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::iter().next().is_none());

        // No margin accounts.
        assert!(pallet_perp_engine::pallet::MarginAccounts::<Test>::iter().next().is_none());

        // No mark-price cache rows.
        assert!(pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::iter().next().is_none());

        // Cumulative funding index is empty.
        assert!(pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::iter().next().is_none());

        // No premium-index samples.
        assert!(pallet_perp_engine::pallet::PremiumIndexSamples::<Test>::iter().next().is_none());

        // No funding-epoch settle-progress rows.
        assert!(pallet_perp_engine::pallet::LastSettledFundingEpoch::<Test>::iter().next().is_none());

        // No in-flight keeper-bond reservations.
        assert!(pallet_perp_engine::pallet::ReservedKeeperBonds::<Test>::iter().next().is_none());

        // No bad debt accrued.
        assert!(pallet_perp_engine::pallet::BadDebtAccumulated::<Test>::iter().next().is_none());
    });
}

/// Surface check: stubs for `liquidate` / `settle_funding` /
/// `governance_set_market` still return `Ok(())` (PR-B preserves them
/// per the user's instruction). The dispatcher origin gates are
/// still exercised.
///
/// `open_position`, `close_position`, `deposit_margin`, `withdraw_margin`,
/// `adjust_leverage` have full impls now and are tested below — this
/// test only verifies the three stub extrinsics are still callable.
#[test]
fn call_surface_exposed_stubs_only() {
    new_test_ext().execute_with(|| {
        let market_id = ada_perp_market_id();
        let signer = 1u64;

        // (5) liquidate — stub, returns Ok.
        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(signer),
            2u64,
            market_id.clone(),
            100u128,
        ));

        // (6) settle_funding — stub, returns Ok.
        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            market_id.clone(),
            1u32,
        ));

        // (8) governance_set_market — stub, root-gated.
        assert_ok!(PerpEngine::governance_set_market(
            RuntimeOrigin::root(),
            market_id,
            default_ada_perp_market_config(),
        ));
    });
}

/// Pin the canonical Config defaults so PR-B can't silently drift them.
/// Values come from design memo §9.1 (the risk-parameter table) — any
/// drift here without a matching §9.1 update flips this test.
#[test]
fn default_constants_pinned() {
    assert_eq!(
        <Test as pallet_perp_engine::Config>::MaxLeverageBps::get(),
        2_000,
        "design memo §9.1: MaxLeverage hard cap is 20× = 2000 bps"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::MinLeverageBps::get(),
        100,
        "design memo §3.7: MinLeverage = 1× = 100 bps"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::MaxMarkets::get(),
        32,
        "v0 launches with 3 markets (§9.2); 32 leaves growth headroom"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::MaxFundingSamplesPerEpoch::get(),
        600,
        "design memo §4.5: 1h funding epoch at 6s blocks = 600 samples"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        100u128,
        "design memo §6.4: KeeperBondMinimum floor = 100 MATRA"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::FreshnessLimitBlocks::get(),
        50,
        "design memo §9.1: FreshnessLimit = 50 blocks (~5 min)"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::MaxMarkBasisBps::get(),
        200,
        "design memo §5.2 + §9.1: mark basis capped at ±2% of oracle"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::MateriosChainId::get(),
        [0x73u8; 32],
        "chain-id fixture matches pallet-intent-settlement / pallet-oracle"
    );
    assert_eq!(
        <Test as pallet_perp_engine::Config>::WithdrawDwellBlocks::get(),
        14_400,
        "design memo §3.4 + §9.1: 24h dwell at 6s blocks"
    );
}

/// All 10 design-memo-required error variants Debug-print to distinct
/// names. Pins the on-fail UX: callers (SDKs, indexers, dashboards)
/// must be able to pattern-match every failure mode without ambiguity.
#[test]
fn error_variants_distinct() {
    let market_not_found: Error<Test> = Error::MarketNotFound;
    let market_paused: Error<Test> = Error::MarketPaused;
    let leverage: Error<Test> = Error::LeverageOutOfBounds;
    let insufficient: Error<Test> = Error::InsufficientMargin;
    let no_pos: Error<Test> = Error::PositionNotFound;
    let slippage: Error<Test> = Error::MaxSlippageExceeded;
    let bad_liq: Error<Test> = Error::BadLiquidationAttempt;
    let oracle_down: Error<Test> = Error::OracleUnavailable;
    let epoch_done: Error<Test> = Error::EpochAlreadySettled;
    let arith: Error<Test> = Error::ArithmeticOverflow;
    let dwell: Error<Test> = Error::WithdrawDwellNotElapsed;

    let variants = [
        format!("{:?}", market_not_found),
        format!("{:?}", market_paused),
        format!("{:?}", leverage),
        format!("{:?}", insufficient),
        format!("{:?}", no_pos),
        format!("{:?}", slippage),
        format!("{:?}", bad_liq),
        format!("{:?}", oracle_down),
        format!("{:?}", epoch_done),
        format!("{:?}", arith),
        format!("{:?}", dwell),
    ];

    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a, b,
                    "Error variants must Debug-print distinctly so callers can \
                     pattern-match: {} vs {}",
                    a, b
                );
            }
        }
    }

    assert!(variants[0].contains("MarketNotFound"));
    assert!(variants[1].contains("MarketPaused"));
    assert!(variants[2].contains("LeverageOutOfBounds"));
    assert!(variants[3].contains("InsufficientMargin"));
    assert!(variants[4].contains("PositionNotFound"));
    assert!(variants[5].contains("MaxSlippageExceeded"));
    assert!(variants[6].contains("BadLiquidationAttempt"));
    assert!(variants[7].contains("OracleUnavailable"));
    assert!(variants[8].contains("EpochAlreadySettled"));
    assert!(variants[9].contains("ArithmeticOverflow"));
    assert!(variants[10].contains("WithdrawDwellNotElapsed"));
}

// ---------------------------------------------------------------------------
// PR-B behaviour tests: open_position (5)
// ---------------------------------------------------------------------------

/// Happy path: a funded MarginAccount opens a 1× ADA-PERP at $1.00.
/// Notional = 1e18 (= $1), initial margin at 1× = $1, so seed
/// free_e18 = $1 and verify everything ends up in `locked_margin_e18`.
#[test]
fn open_position_happy_path() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        // Seed 1.0 pMATRA-USD free (so 1× open consumes exactly that).
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,   // 1.0 contract
            100u32,            // 1× leverage (100 bps)
            50u32,             // 0.5% slippage
            0u128,             // no margin top-up
        ));

        // Position is recorded with correct sign + locked margin.
        let pos = pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .expect("position exists");
        assert_eq!(pos.size_e8, 100_000_000); // long sign
        assert_eq!(pos.entry_mark_e18, 1_000_000_000_000_000_000u128);
        assert_eq!(pos.locked_margin_e18, 1_000_000_000_000_000_000u128);

        // Free balance is now zero — all locked.
        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 0);
    });
}

/// Insufficient margin: open requires more pMATRA-USD than the
/// MarginAccount holds. Reject before mutating state.
#[test]
fn open_position_rejects_insufficient_margin() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        // Only seed $0.50 free — but 1× open at $1 needs $1.
        seed_free_margin(signer, 500_000_000_000_000_000u128);

        assert_noop!(
            PerpEngine::open_position(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                PerpDirection::Long,
                100_000_000u128,
                100u32,
                50u32,
                0u128,
            ),
            Error::<Test>::InsufficientMargin
        );

        // No position written.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .is_none());
    });
}

/// Leverage above the market cap is rejected. ADA-PERP defaults to
/// 10× = 1000 bps; we try 15× = 1500 bps.
#[test]
fn open_position_rejects_leverage_above_max() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_noop!(
            PerpEngine::open_position(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                PerpDirection::Long,
                100_000_000u128,
                1_500u32,           // 15× — over market cap (10×)
                50u32,
                0u128,
            ),
            Error::<Test>::LeverageOutOfBounds
        );
    });
}

/// Paused market: opens reject with `MarketPaused`.
#[test]
fn open_position_rejects_paused_market() {
    new_test_ext().execute_with(|| {
        register_paused_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_noop!(
            PerpEngine::open_position(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                PerpDirection::Long,
                100_000_000u128,
                100u32,
                50u32,
                0u128,
            ),
            Error::<Test>::MarketPaused
        );
    });
}

/// Stale oracle: opens reject with `OracleUnavailable`.
#[test]
fn open_position_rejects_oracle_unavailable() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);
        // Mark the ADA/USD feed stale.
        set_oracle_fresh(&ada_usd_feed_id(), false);

        assert_noop!(
            PerpEngine::open_position(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                PerpDirection::Long,
                100_000_000u128,
                100u32,
                50u32,
                0u128,
            ),
            Error::<Test>::OracleUnavailable
        );
    });
}

// ---------------------------------------------------------------------------
// PR-B behaviour tests: close_position (5)
// ---------------------------------------------------------------------------

/// Long win: open at $1.00, close at $1.10 → +$0.10 PnL.
#[test]
fn close_position_full_realizes_pnl_long_win() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        // Open at $1.00.
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Bump oracle to $1.10.
        set_oracle_price(&ada_usd_feed_id(), 1_100_000_000_000_000_000u128);

        // Close all.
        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            0u128,
            50u32,
        ));

        // Position gone.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .is_none());

        // Free balance: returned $1 locked + $0.10 PnL = $1.10.
        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 1_100_000_000_000_000_000u128);
    });
}

/// Long loss: open at $1.00, close at $0.90 → -$0.10 PnL.
#[test]
fn close_position_full_realizes_pnl_long_loss() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        set_oracle_price(&ada_usd_feed_id(), 900_000_000_000_000_000u128);

        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            0u128,
            50u32,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // $1 locked released + (-$0.10) realised = $0.90.
        assert_eq!(acct.free_e18, 900_000_000_000_000_000u128);
    });
}

/// Short win: open SHORT at $1.00, close at $0.90 → +$0.10 PnL.
#[test]
fn close_position_full_realizes_pnl_short_win() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Short,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Confirm short sign in storage.
        let pos = pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .unwrap();
        assert!(pos.size_e8 < 0);

        // Mark drops 10% — short wins.
        set_oracle_price(&ada_usd_feed_id(), 900_000_000_000_000_000u128);

        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            0u128,
            50u32,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 1_100_000_000_000_000_000u128);
    });
}

/// Partial close keeps the residual position open with proportionally
/// reduced locked margin. 1.0 long, close 0.5 → 0.5 long remains.
#[test]
fn close_position_partial_keeps_position() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        // Open 1.0 long at $1, 1× leverage → $1 locked margin.
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Close 0.5 at the same mark — no PnL, half margin released.
        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            50_000_000u128, // 0.5
            50u32,
        ));

        let pos = pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .expect("residual long remains");
        assert_eq!(pos.size_e8, 50_000_000); // 0.5 long
        assert_eq!(pos.locked_margin_e18, 500_000_000_000_000_000u128); // $0.50 locked

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 500_000_000_000_000_000u128); // $0.50 free
    });
}

/// Funding delta is applied on close. Open at funding-index = 0,
/// bump `CumulativeFundingIndex` to a positive value, close → the
/// long position pays funding (margin reduced).
#[test]
fn close_position_applies_funding_delta() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 2_000_000_000_000_000_000u128);

        // Open 1.0 long at $1, 1× leverage → $1 locked.
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Bump CumulativeFundingIndex by +1e16 (= small funding rate).
        // funding_owed = 1.0 * 1e16 / 1e8 = 1e8 → in 1e18 scale that's...
        // wait, the compute_funding_delta returns idx*signed_size/1e8.
        // idx = 1e16, size = 1e8, so result = 1e16 * 1e8 / 1e8 = 1e16.
        // That's $0.01 in 1e18 scale.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            10_000_000_000_000_000i128,
        );

        // Close all at same mark.
        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            0u128,
            50u32,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // Start: $1 seeded + $1 locked = $2 (re-released at close
        // because $1 was locked + $1 stayed free). After close:
        // free becomes $1 (originally) + $1 (released) - $0.01
        // (funding paid by long) = $1.99 in 1e18 scale.
        assert_eq!(acct.free_e18, 1_990_000_000_000_000_000u128);
    });
}

// ---------------------------------------------------------------------------
// PR-B behaviour tests: deposit_margin (1)
// ---------------------------------------------------------------------------

/// Deposit transfers MOTRA → pot, increments `free_e18` at the live
/// MATRA/USD rate, and updates `last_deposit_block`.
#[test]
fn deposit_margin_increments_free() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        credit_motra(signer, 10_000u128);
        // MATRA/USD = $1 (the default), so deposit_motra * 1e18 = pMATRA-USD
        // 10_000 * 1e18 = 1e22.

        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 5_000u128 * 1_000_000_000_000_000_000u128);
        assert_eq!(acct.last_deposit_block, 1); // tests start at block 1

        // Pot account received the MOTRA.
        let pot = pallet_perp_engine::pallet::Pallet::<Test>::pot_account();
        let pot_balance = pallet_balances::Pallet::<Test>::free_balance(&pot);
        assert_eq!(pot_balance, 5_000u128);
    });
}

/// Sec-review round-2 Vuln 1 regression: when the weighted-avg
/// computation would overflow `u128` intermediate products (the
/// previous "conservative-fallback" path), U256 math must compute the
/// correct rate — NEVER lower than `min(old_rate, new_rate)`, which
/// would otherwise let the user redeem more MOTRA than they deposited.
///
/// Scenario: a small initial deposit at a LOW rate ($0.10/MATRA →
/// rate=1e17) seeds the snapshot. A subsequent very large deposit at
/// a HIGH rate ($10/MATRA → rate=1e19) triggers the intermediate
/// overflow on `credit_e18 × rate_e18 = motra × 1e38` for any motra
/// ≥ ~4 (since u128::MAX ≈ 3.4e38). Pre-fix code would have kept the
/// old $0.10 rate; post-fix U256 produces the correct value-weighted
/// average in `[1e17, 1e19]`.
#[test]
fn deposit_margin_weighted_avg_handles_u128_overflow() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;

        // First deposit: small amount at rate $0.10 (1e17). Seeds
        // weighted_deposit_rate_e18 = 1e17.
        set_oracle_price(
            &matra_usd_feed_id(),
            100_000_000_000_000_000u128, // $0.10
        );
        credit_motra(signer, 1u128);
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            1u128,
        ));
        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.weighted_deposit_rate_e18, 100_000_000_000_000_000u128);
        assert_eq!(acct.free_e18, 100_000_000_000_000_000u128);

        // Second deposit: at rate $10 (1e19). With motra=5 MOTRA,
        // credit_e18 = 5 × 1e19 = 5e19 and `credit_e18 × rate_e18 =
        // 5e19 × 1e19 = 5e38` — overflows u128. Pre-fix kept the
        // old $0.10 rate. Post-fix U256 produces the value-weighted
        // average.
        set_oracle_price(
            &matra_usd_feed_id(),
            10_000_000_000_000_000_000u128, // $10
        );
        credit_motra(signer, 5u128);
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5u128,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // weighted_avg = (1e17 × 1e17 + 5e19 × 1e19) / (1e17 + 5e19)
        //              = (1e34 + 5e38) / 5.001e19
        //              ≈ 5.0001e38 / 5.001e19
        //              ≈ 9.998e18 (very close to the $10 rate since
        //                          the second deposit dominates the
        //                          pmatra-USD weight by 500×).
        // Lower bound: snapshot must NOT have stuck at the old
        // 1e17 (the pre-fix bug) — assert strictly greater than
        // the lower bound of the two input rates.
        assert!(
            acct.weighted_deposit_rate_e18 > 100_000_000_000_000_000u128,
            "snapshot must update beyond old low rate (got {})",
            acct.weighted_deposit_rate_e18
        );
        // Upper bound: weighted-avg can't exceed max(old, new) = 1e19.
        assert!(
            acct.weighted_deposit_rate_e18 <= 10_000_000_000_000_000_000u128,
            "snapshot must be bounded by max input rate (got {})",
            acct.weighted_deposit_rate_e18
        );
        // Sanity: pmatra-USD weight makes the snapshot land near 1e19.
        // We allow ±5% tolerance.
        let expected = 9_998_000_000_000_000_000u128;
        let tolerance = expected / 20;
        assert!(
            acct.weighted_deposit_rate_e18.abs_diff(expected) <= tolerance,
            "weighted-avg should land near {} (±5%); got {}",
            expected,
            acct.weighted_deposit_rate_e18
        );
    });
}

/// Sec-review round-2 Vuln 2 regression: cross-cohort PnL transfer
/// must NOT drain the pot. Two users in different deposit-rate
/// cohorts trade, the winner withdraws everything, and the loser
/// withdraws everything — the pot must remain solvent (total MOTRA
/// paid out ≤ total MOTRA deposited).
///
/// Scenario: User A deposits 1000 MOTRA at MATRA=$0.50 (snapshot=5e17).
/// User B deposits 1000 MOTRA at MATRA=$1.00 (snapshot=1e18). Live
/// rate stays at $1.00 (which is when A's PnL is settled). A wins
/// some PnL, B loses the same. Both withdraw at their snapshot rates.
///
/// Pre-fix: A's snapshot was unchanged at 5e17, so A redeemed PnL at
/// 2× MOTRA — pot deficit of `|PnL| × (1/5e17 − 1/1e18) = |PnL|/1e18`
/// per pMATRA-USD unit. Post-fix: A's snapshot bumps toward live=1e18
/// on PnL credit, so A redeems PnL at the same rate B's loss reduces
/// at — net pot delta ≈ 0.
#[test]
fn close_position_cross_cohort_pnl_preserves_pot_solvency() {
    new_test_ext().execute_with(|| {
        let user_a = 1u64;
        let user_b = 2u64;
        register_default_market();
        credit_motra(user_a, 2_000u128);
        credit_motra(user_b, 2_000u128);

        // A deposits at MATRA = $0.50 (rate=5e17). Snapshot=5e17.
        set_oracle_price(
            &matra_usd_feed_id(),
            500_000_000_000_000_000u128,
        );
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(user_a),
            1_000u128,
        ));
        let a_after_dep = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&user_a);
        assert_eq!(a_after_dep.weighted_deposit_rate_e18, 500_000_000_000_000_000u128);

        // B deposits at MATRA = $1.00 (rate=1e18). Snapshot=1e18.
        set_oracle_price(
            &matra_usd_feed_id(),
            1_000_000_000_000_000_000u128,
        );
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(user_b),
            1_000u128,
        ));
        let b_after_dep = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&user_b);
        assert_eq!(b_after_dep.weighted_deposit_rate_e18, 1_000_000_000_000_000_000u128);

        let pot = pallet_perp_engine::pallet::Pallet::<Test>::pot_account();
        let pot_initial = pallet_balances::Pallet::<Test>::free_balance(&pot);
        assert_eq!(pot_initial, 2_000u128);

        // A opens long, B opens short. ADA/USD oracle at $1.00.
        set_oracle_price(
            &ada_usd_feed_id(),
            1_000_000_000_000_000_000u128,
        );
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(user_a),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            500u32,
            50u32,
            0u128,
        ));
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(user_b),
            ada_perp_market_id(),
            PerpDirection::Short,
            100_000_000u128,
            500u32,
            50u32,
            0u128,
        ));

        // ADA price rises to $1.10. A wins, B loses.
        set_oracle_price(
            &ada_usd_feed_id(),
            1_100_000_000_000_000_000u128,
        );
        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(user_a),
            ada_perp_market_id(),
            0u128,
            10_000u32,
        ));
        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(user_b),
            ada_perp_market_id(),
            0u128,
            10_000u32,
        ));

        // POST-FIX: A's snapshot must have bumped toward 1e18 because
        // PnL credit at live rate triggered the weighted-avg update.
        // (Pre-fix: would have stayed at 5e17, allowing 2× MOTRA out.)
        let a_after_close = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&user_a);
        assert!(
            a_after_close.weighted_deposit_rate_e18 > 500_000_000_000_000_000u128,
            "A's snapshot must bump toward live rate after PnL credit (got {})",
            a_after_close.weighted_deposit_rate_e18
        );

        // Advance past dwell.
        let dwell = <Test as pallet_perp_engine::Config>::WithdrawDwellBlocks::get();
        System::set_block_number((dwell as u64) + 2);

        // Both withdraw their full balances.
        let a_free = a_after_close.free_e18;
        let b_after_close = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&user_b);
        let b_free = b_after_close.free_e18;
        if a_free > 0 {
            assert_ok!(PerpEngine::withdraw_margin(
                RuntimeOrigin::signed(user_a),
                a_free,
            ));
        }
        if b_free > 0 {
            assert_ok!(PerpEngine::withdraw_margin(
                RuntimeOrigin::signed(user_b),
                b_free,
            ));
        }

        // INVARIANT: total MOTRA paid out ≤ total MOTRA deposited.
        let pot_final = pallet_balances::Pallet::<Test>::free_balance(&pot);
        let total_paid_out = pot_initial - pot_final;
        assert!(
            total_paid_out <= 2_000u128,
            "pot drained: paid out {} MOTRA but only 2000 MOTRA deposited",
            total_paid_out
        );
    });
}

// ---------------------------------------------------------------------------
// PR-B behaviour tests: withdraw_margin (3)
// ---------------------------------------------------------------------------

/// Deposit, advance past the dwell time, withdraw — happy path.
#[test]
fn withdraw_margin_happy_path_after_dwell() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        credit_motra(signer, 10_000u128);

        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));

        // Advance past the dwell time.
        let dwell = <Test as pallet_perp_engine::Config>::WithdrawDwellBlocks::get();
        System::set_block_number((dwell as u64) + 2);

        // Withdraw 1_000 pMATRA-USD (= 1e3 * 1e18 scale).
        let withdraw_e18 = 1_000u128 * 1_000_000_000_000_000_000u128;
        assert_ok!(PerpEngine::withdraw_margin(
            RuntimeOrigin::signed(signer),
            withdraw_e18,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 4_000u128 * 1_000_000_000_000_000_000u128);

        // MOTRA returned to user.
        let bal = pallet_balances::Pallet::<Test>::free_balance(&signer);
        assert_eq!(bal, 5_000u128 + 1_000u128);
    });
}

/// Withdraw within the dwell window — rejected.
#[test]
fn withdraw_margin_rejects_during_dwell() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        credit_motra(signer, 10_000u128);
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));

        // Same block — dwell not elapsed.
        let withdraw_e18 = 1_000u128 * 1_000_000_000_000_000_000u128;
        assert_noop!(
            PerpEngine::withdraw_margin(
                RuntimeOrigin::signed(signer),
                withdraw_e18,
            ),
            Error::<Test>::WithdrawDwellNotElapsed
        );
    });
}

/// Withdraw that would take the account below its sum-of-locked-margins
/// floor is rejected with `InsufficientMargin`.
#[test]
fn withdraw_margin_rejects_below_initial_margin() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        credit_motra(signer, 10_000u128);
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));

        // Advance past dwell.
        let dwell = <Test as pallet_perp_engine::Config>::WithdrawDwellBlocks::get();
        System::set_block_number((dwell as u64) + 2);

        // Open a position that locks $1 (1.0 contract at $1, 1×).
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Free margin after open: ($5000 - $1) * 1e18.
        // Locked margin: $1 * 1e18.
        // Withdraw must respect post_free >= total_locked = $1 * 1e18.
        // So max withdraw = ($5000 - $1 - $1) * 1e18 = $4998 * 1e18.
        // Try $4999 * 1e18 — should fail.
        let withdraw_e18 = 4_999u128 * 1_000_000_000_000_000_000u128;
        assert_noop!(
            PerpEngine::withdraw_margin(
                RuntimeOrigin::signed(signer),
                withdraw_e18,
            ),
            Error::<Test>::InsufficientMargin
        );
    });
}

// ---------------------------------------------------------------------------
// PR-B behaviour tests: adjust_leverage (3)
// ---------------------------------------------------------------------------

/// Levering UP (smaller margin lock) releases margin back to free.
/// Open at 1× (locks $1), bump to 2× → locked drops to $0.50,
/// free gains $0.50.
#[test]
fn adjust_leverage_levers_up_unlocks_margin() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,            // 1×
            50u32,
            0u128,
        ));

        // Lever up to 2× — locked = $1 / 2 = $0.50.
        assert_ok!(PerpEngine::adjust_leverage(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            200u32, // 2×
        ));

        let pos = pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .unwrap();
        assert_eq!(pos.leverage_bps, 200);
        assert_eq!(pos.locked_margin_e18, 500_000_000_000_000_000u128);

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 500_000_000_000_000_000u128);
    });
}

/// Levering DOWN (larger margin lock) requires free margin. Open
/// at 2×, try to lever down to 1× — needs $0.50 from free.
#[test]
fn adjust_leverage_levers_down_requires_free_margin() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        // Seed $0.50 only — enough for a 2× open ($0.50 locked) but
        // NOT enough to lever down to 1× (which needs another $0.50
        // in free).
        seed_free_margin(signer, 500_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            200u32, // 2×
            50u32,
            0u128,
        ));

        // After open: free = 0, locked = $0.50.
        // Levering down to 1× needs locked = $1 → delta = +$0.50.
        // Free has $0 → InsufficientMargin.
        assert_noop!(
            PerpEngine::adjust_leverage(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                100u32, // 1×
            ),
            Error::<Test>::InsufficientMargin
        );
    });
}

/// Sec-review #259-Vuln-3: `adjust_leverage` must reject calls on a
/// paused market. Mirrors `open_position`'s paused gate; only
/// `close_position` may bypass per memo §5.5.
#[test]
fn adjust_leverage_rejects_paused_market() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Pause the market.
        let mut cfg = default_ada_perp_market_config();
        cfg.paused = true;
        pallet_perp_engine::pallet::Markets::<Test>::insert(ada_perp_market_id(), cfg);

        assert_noop!(
            PerpEngine::adjust_leverage(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                500u32,
            ),
            Error::<Test>::MarketPaused
        );
    });
}

/// Sec-review #259-Vuln-2: `adjust_leverage` must reject calls when the
/// market's oracle feed is stale. A stale oracle returns the cached
/// price, so without this gate a user could lever up against a
/// favourable cached price and be immediately liquidation-eligible
/// when the oracle recovers — bad-debt residual to mat/trsy via §6.5.
/// Mirrors the `open_position` freshness gate.
#[test]
fn adjust_leverage_rejects_stale_oracle() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Mark the market oracle stale; MATRA/USD feed stays fresh so
        // the MOTRA-conversion path isn't what trips.
        set_oracle_fresh(&ada_usd_feed_id(), false);

        assert_noop!(
            PerpEngine::adjust_leverage(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                500u32,
            ),
            Error::<Test>::OracleUnavailable
        );
    });
}

/// Sec-review #259-Vuln-1: pot-solvency invariant. `withdraw_margin`
/// converts pMATRA-USD → MOTRA at the account's WEIGHTED-AVG DEPOSIT
/// rate (snapshotted at deposit time), NOT the live rate. This
/// prevents the deposit-at-peak / withdraw-at-trough sandwich arb
/// that would otherwise drain other depositors' MOTRA from the pot.
///
/// Scenario: deposit 5_000 MOTRA at MATRA/USD = $1, then MATRA
/// depreciates to $0.50. With the live-rate (PRE-FIX) behaviour the
/// withdrawer would redeem the same pMATRA-USD claim for DOUBLE the
/// MOTRA they put in. With the snapshot-rate (POST-FIX) behaviour
/// they get back exactly what they deposited.
#[test]
fn withdraw_margin_uses_snapshot_rate_not_live() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        credit_motra(signer, 10_000u128);

        // Deposit at rate $1.00.
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));

        // The deposit snapshot rate is now $1.00 = 1e18.
        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(
            acct.weighted_deposit_rate_e18, 1_000_000_000_000_000_000u128,
            "first deposit must seed the rate snapshot"
        );
        // Credit = 5_000 MOTRA × 1e18 = 5e21 pMATRA-USD.
        assert_eq!(acct.free_e18, 5_000u128 * 1_000_000_000_000_000_000u128);

        // Advance past the dwell.
        let dwell = <Test as pallet_perp_engine::Config>::WithdrawDwellBlocks::get();
        System::set_block_number((dwell as u64) + 2);

        // ADVERSARIAL move: MATRA drops to $0.50. If withdraw used
        // the LIVE rate the user would extract 2× their deposit.
        set_oracle_price(
            &matra_usd_feed_id(),
            500_000_000_000_000_000u128, // $0.50
        );

        // Withdraw the full 5e21 pMATRA-USD balance.
        let pot = pallet_perp_engine::pallet::Pallet::<Test>::pot_account();
        let pot_before = pallet_balances::Pallet::<Test>::free_balance(&pot);
        let user_before = pallet_balances::Pallet::<Test>::free_balance(&signer);

        assert_ok!(PerpEngine::withdraw_margin(
            RuntimeOrigin::signed(signer),
            5_000u128 * 1_000_000_000_000_000_000u128,
        ));

        let pot_after = pallet_balances::Pallet::<Test>::free_balance(&pot);
        let user_after = pallet_balances::Pallet::<Test>::free_balance(&signer);

        // Snapshot-rate semantics: user gets back exactly the 5_000
        // MOTRA they deposited. NOT 10_000 (which is what the
        // pre-fix live-rate redemption would have paid).
        let pot_paid = pot_before - pot_after;
        let user_received = user_after - user_before;
        assert_eq!(
            pot_paid, 5_000u128,
            "pot must NOT pay more MOTRA than the user deposited"
        );
        assert_eq!(
            user_received, 5_000u128,
            "user redeems at snapshot rate, not live rate"
        );

        // Free balance zeroed; rate reset to 0 for future re-deposits.
        let acct_after = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct_after.free_e18, 0);
        assert_eq!(
            acct_after.weighted_deposit_rate_e18, 0,
            "full-drain withdraw resets rate snapshot"
        );
    });
}

/// Adjusting above the market cap is rejected.
#[test]
fn adjust_leverage_rejects_above_max() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        seed_free_margin(signer, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // ADA-PERP default max_leverage = 1000 bps (10×); try 1500.
        assert_noop!(
            PerpEngine::adjust_leverage(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                1_500u32,
            ),
            Error::<Test>::LeverageOutOfBounds
        );
    });
}

// ---------------------------------------------------------------------------
// PR-B math tests: overflow guard
// ---------------------------------------------------------------------------

/// `compute_notional` surfaces `MathOverflow` rather than silently
/// saturating. The pallet maps this to `Error::ArithmeticOverflow`.
#[test]
fn math_compute_notional_overflow_protected() {
    // Direct math::compute_notional check first.
    let r = math::compute_notional(u128::MAX, 2);
    assert!(r.is_err());

    // And the pallet-side error mapping.
    new_test_ext().execute_with(|| {
        // Manufacture a market with size cap at u128::MAX to defeat
        // the size-bound gate and reach the math.
        let mut cfg = default_ada_perp_market_config();
        cfg.max_position_size_e8 = u128::MAX;
        cfg.min_position_size_e8 = 0;
        pallet_perp_engine::pallet::Markets::<Test>::insert(
            &ada_perp_market_id(),
            cfg,
        );
        // Repoint oracle to an extreme price so size * price overflows.
        set_oracle_price(&ada_usd_feed_id(), u128::MAX);

        let signer = 1u64;
        seed_free_margin(signer, u128::MAX);

        // Caller asks for size=u128::MAX → notional check overflows.
        assert_noop!(
            PerpEngine::open_position(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                PerpDirection::Long,
                u128::MAX,
                100u32,
                50u32,
                0u128,
            ),
            Error::<Test>::ArithmeticOverflow
        );
    });
}
