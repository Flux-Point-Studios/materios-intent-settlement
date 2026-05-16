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

        // No bad-debt window timestamps.
        assert!(pallet_perp_engine::pallet::BadDebtWindowStart::<Test>::iter().next().is_none());
    });
}

/// Surface check: `governance_set_market` is still a stub (deferred to
/// PR-D). `liquidate` and `settle_funding` are no longer stubs — their
/// coverage is in the dedicated test sections below. The dispatcher
/// origin gate is still exercised for `governance_set_market`.
#[test]
fn call_surface_exposed_stubs_only() {
    new_test_ext().execute_with(|| {
        let market_id = ada_perp_market_id();

        // governance_set_market — stub, root-gated.
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
    let not_liq: Error<Test> = Error::PositionNotLiquidatable;
    let bond_low: Error<Test> = Error::KeeperBondInsufficient;
    let breaker: Error<Test> = Error::BadDebtCircuitBreakerTripped;

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
        format!("{:?}", not_liq),
        format!("{:?}", bond_low),
        format!("{:?}", breaker),
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
    assert!(variants[11].contains("PositionNotLiquidatable"));
    assert!(variants[12].contains("KeeperBondInsufficient"));
    assert!(variants[13].contains("BadDebtCircuitBreakerTripped"));
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

// ---------------------------------------------------------------------------
// PR-C piece 1 — liquidate (task #259 §3.5) — 16 tests
// ---------------------------------------------------------------------------

/// Seed a `ReservedKeeperBonds` entry directly. Production wires this
/// via a future `reserve_keeper_bond` extrinsic (deferred); v0 tests
/// + the impl read the storage as a passive gate.
fn seed_keeper_bond(market_id: &MarketId, keeper: u64, bond: u128) {
    pallet_perp_engine::pallet::ReservedKeeperBonds::<Test>::insert(
        market_id,
        keeper,
        bond,
    );
}

/// Fund the pallet pot with raw MOTRA so liquidate's pot → keeper
/// transfer can clear. The deposit_margin path normally seeds the
/// pot; tests that seed positions directly need a manual top-up.
fn fund_pot(amount: u128) {
    let pot = pallet_perp_engine::pallet::Pallet::<Test>::pot_account();
    pallet_balances::Pallet::<Test>::force_set_balance(
        RuntimeOrigin::root(),
        pot,
        amount,
    )
    .expect("force_set_balance succeeds");
}

/// Open an underwater-ready setup: register the default ADA-PERP
/// market, deposit `motra` MOTRA via the real extrinsic (so the
/// snapshot rate is pinned), and open a 1.0 contract position at 10×
/// leverage (locked = 10% of notional → modest mark moves push the
/// position into MM territory). Returns nothing; tests use the
/// hardcoded victim=1, keeper=2.
///
/// Why 10× and not 1×: with 1× leverage the locked margin equals the
/// notional, so a price drop has to wipe ~95% of the position before
/// equity dips below the 5% MM floor — unrealistic test stimulus. 10×
/// puts the MM-trip ~5 percentage points away from entry, which
/// matches real-world perp parameters (memo §9.1 default leverage).
fn open_underwater_setup(direction: PerpDirection, motra: u128) {
    let victim = 1u64;
    register_default_market();
    credit_motra(victim, motra);
    assert_ok!(PerpEngine::deposit_margin(
        RuntimeOrigin::signed(victim),
        motra,
    ));
    assert_ok!(PerpEngine::open_position(
        RuntimeOrigin::signed(victim),
        ada_perp_market_id(),
        direction,
        100_000_000u128, // 1.0 contract
        1_000u32,         // 10× leverage → locked = 10% notional
        50u32,
        0u128,
    ));
}

/// Test 1: happy-path long. Long 1.0 contract opened at $1.00 (10×
/// → locked = $0.10, MM at new mark = 5% × notional). Mark drops to
/// $0.50; PnL = -$0.50; equity = $0.10 − $0.50 = -$0.40 << MM.
/// Liquidation succeeds, PositionLiquidated event fired.
#[test]
fn liquidate_happy_path_long_underwater() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        // Pot has 1 MOTRA from the deposit; pad it so the keeper-fee
        // MOTRA transfer is legible at integer scale.
        fund_pot(100u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Drop mark to $0.50.
        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);

        let keeper_motra_pre =
            pallet_balances::Pallet::<Test>::free_balance(&keeper);

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        // Position removed.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());

        // Keeper MOTRA can only go up (a successful liquidate pays
        // the fee out of the pot to the keeper's free balance).
        let keeper_motra_post =
            pallet_balances::Pallet::<Test>::free_balance(&keeper);
        assert!(keeper_motra_post >= keeper_motra_pre);

        // PositionLiquidated event recorded.
        let saw_liquidated = System::events().iter().any(|er| {
            matches!(
                er.event,
                RuntimeEvent::PerpEngine(
                    pallet_perp_engine::Event::PositionLiquidated { .. }
                )
            )
        });
        assert!(saw_liquidated, "PositionLiquidated must be emitted");
    });
}

/// Test 2: happy-path short. Mark rises; short is underwater;
/// liquidation succeeds.
#[test]
fn liquidate_happy_path_short_underwater() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Short, 1u128);
        fund_pot(100u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Mark rises to $1.50 — short loses heavily.
        set_oracle_price(&ada_usd_feed_id(), 1_500_000_000_000_000_000u128);

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());
    });
}

/// Test 3: healthy position → `PositionNotLiquidatable`. v0 does not
/// slash the bond; it stays reserved.
#[test]
fn liquidate_rejects_healthy_position() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        fund_pot(100u128);
        let min_bond =
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get();
        seed_keeper_bond(&ada_perp_market_id(), keeper, min_bond);

        // Mark stays at $1.00 → position is healthy.
        assert_noop!(
            PerpEngine::liquidate(
                RuntimeOrigin::signed(keeper),
                victim,
                ada_perp_market_id(),
            ),
            Error::<Test>::PositionNotLiquidatable
        );

        // Position still present.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_some());

        // Bond untouched (no slashing in v0).
        let bond_after =
            pallet_perp_engine::pallet::ReservedKeeperBonds::<Test>::get(
                &ada_perp_market_id(),
                &keeper,
            );
        assert_eq!(bond_after, min_bond);
    });
}

/// Test 4: no `ReservedKeeperBonds` entry → `KeeperBondInsufficient`.
#[test]
fn liquidate_rejects_no_keeper_bond() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        // No seed_keeper_bond — storage returns ValueQuery default 0.
        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);

        assert_noop!(
            PerpEngine::liquidate(
                RuntimeOrigin::signed(keeper),
                victim,
                ada_perp_market_id(),
            ),
            Error::<Test>::KeeperBondInsufficient
        );
    });
}

/// Test 5: bond below minimum → `KeeperBondInsufficient`.
#[test]
fn liquidate_rejects_underbonded_keeper() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        let min =
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get();
        seed_keeper_bond(&ada_perp_market_id(), keeper, min - 1);

        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);

        assert_noop!(
            PerpEngine::liquidate(
                RuntimeOrigin::signed(keeper),
                victim,
                ada_perp_market_id(),
            ),
            Error::<Test>::KeeperBondInsufficient
        );
    });
}

/// Test 6: missing position → `PositionNotFound`.
#[test]
fn liquidate_rejects_missing_position() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        register_default_market();
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        assert_noop!(
            PerpEngine::liquidate(
                RuntimeOrigin::signed(keeper),
                victim,
                ada_perp_market_id(),
            ),
            Error::<Test>::PositionNotFound
        );
    });
}

/// Test 7: stale oracle → `OracleUnavailable`. Critical safety gate:
/// liquidate-on-stale could fire on a not-actually-underwater position.
/// Mirror the `adjust_leverage_rejects_stale_oracle` pattern.
#[test]
fn liquidate_rejects_stale_oracle() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Drop mark to "clearly underwater" AND mark stale.
        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);
        set_oracle_fresh(&ada_usd_feed_id(), false);

        assert_noop!(
            PerpEngine::liquidate(
                RuntimeOrigin::signed(keeper),
                victim,
                ada_perp_market_id(),
            ),
            Error::<Test>::OracleUnavailable
        );
    });
}

/// Test 8: paused market does NOT block liquidation. Memo §5.5:
/// pausing a market must NOT trap user funds in open positions.
#[test]
fn liquidate_works_on_paused_market() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        fund_pot(100u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Drop mark, then pause the market.
        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);
        let mut cfg = default_ada_perp_market_config();
        cfg.paused = true;
        pallet_perp_engine::pallet::Markets::<Test>::insert(
            &ada_perp_market_id(),
            cfg,
        );

        // Liquidation still succeeds.
        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());
    });
}

/// Test 9: deep underwater → bad-debt accumulated. Force a huge
/// funding owed so equity-post-fee goes negative; assert
/// `BadDebtAccumulated[market]` is incremented by |equity|.
#[test]
fn liquidate_accumulates_bad_debt_when_equity_negative() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        fund_pot(100u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Force funding-owed beyond the locked margin.
        // funding_owed = 1e8 (size) * idx / 1e8 = idx (in 1e18 scale).
        // Set idx = 1.5e18 → funding_owed = $1.50, locked = $1 →
        // equity = 1 - 1.5 = -0.5; bad debt.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            1_500_000_000_000_000_000i128,
        );

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        let bd = pallet_perp_engine::pallet::BadDebtAccumulated::<Test>::get(
            &ada_perp_market_id(),
        );
        assert!(
            bd > 0,
            "deep-underwater liquidation must accumulate bad debt; got {}",
            bd
        );
        // Position gone.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());
        // Window timestamp was seeded.
        assert!(
            pallet_perp_engine::pallet::BadDebtWindowStart::<Test>::get(
                &ada_perp_market_id(),
            ) > 0
        );
    });
}

/// Test 10: bad debt over threshold in one tick → market auto-pauses
/// and `BadDebtCircuitBreakerTripped` event fires.
#[test]
fn liquidate_trips_circuit_breaker_at_threshold() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        register_default_market();
        let market_id = ada_perp_market_id();

        // Seed a massive position with tiny locked margin so the
        // resulting bad debt blows past the breaker threshold
        // (TestBadDebtCircuitBreakerThresholdE18 = 1e22).
        let pos = Position {
            size_e8: 10_000_000_000_000_000i128, // 1e16
            entry_mark_e18: 1_000_000_000_000_000_000u128,
            locked_margin_e18: 1_000_000_000_000_000_000u128, // $1
            leverage_bps: 100,
            opened_block: 1,
            cumulative_funding_at_open_e18: 0,
        };
        pallet_perp_engine::pallet::Positions::<Test>::insert(
            &market_id, &victim, pos,
        );
        // Victim has a snapshot rate so the fee transfer routes via
        // the snapshot path.
        pallet_perp_engine::pallet::MarginAccounts::<Test>::insert(
            &victim,
            MarginAccount {
                free_e18: 0,
                last_deposit_block: 0,
                weighted_deposit_rate_e18: 1_000_000_000_000_000_000u128,
            },
        );
        // Funding inflated → enormous funding_owed → enormous bad debt.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &market_id,
            1_000_000_000_000_000_000i128,
        );
        fund_pot(1_000_000u128);
        seed_keeper_bond(
            &market_id,
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            market_id.clone(),
        ));

        // Market is now paused.
        let m = pallet_perp_engine::pallet::Markets::<Test>::get(&market_id)
            .expect("market still registered after breaker trip");
        assert!(m.paused, "circuit breaker must auto-pause the market");

        // BadDebtCircuitBreakerTripped event co-emitted.
        let saw_breaker = System::events().iter().any(|er| {
            matches!(
                er.event,
                RuntimeEvent::PerpEngine(
                    pallet_perp_engine::Event::BadDebtCircuitBreakerTripped { .. }
                )
            )
        });
        assert!(
            saw_breaker,
            "BadDebtCircuitBreakerTripped must co-emit on threshold cross"
        );
    });
}

/// Test 11: fee capped at locked margin. Position has tiny locked
/// margin and large notional → raw fee > locked. Asserted via the
/// `liquidation_fee_e18` field on the emitted event.
#[test]
fn liquidate_fee_capped_at_locked_margin() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        register_default_market();
        let market_id = ada_perp_market_id();

        // notional = 1.0 * $1 = $1; raw_fee = 0.5% × $1 = $0.005.
        // Locked = $0.001 → fee must clamp to $0.001 = 1e15.
        let pos = Position {
            size_e8: 100_000_000i128,
            entry_mark_e18: 1_000_000_000_000_000_000u128,
            locked_margin_e18: 1_000_000_000_000_000u128, // $0.001
            leverage_bps: 100,
            opened_block: 1,
            cumulative_funding_at_open_e18: 0,
        };
        pallet_perp_engine::pallet::Positions::<Test>::insert(
            &market_id, &victim, pos,
        );
        pallet_perp_engine::pallet::MarginAccounts::<Test>::insert(
            &victim,
            MarginAccount {
                free_e18: 0,
                last_deposit_block: 0,
                weighted_deposit_rate_e18: 1_000_000_000_000_000_000u128,
            },
        );
        // Force liquidatable via funding.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &market_id,
            100_000_000_000_000_000i128, // 0.1
        );
        fund_pot(1_000u128);
        seed_keeper_bond(
            &market_id,
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            market_id.clone(),
        ));

        let fee = System::events().iter().find_map(|er| match &er.event {
            RuntimeEvent::PerpEngine(
                pallet_perp_engine::Event::PositionLiquidated {
                    liquidation_fee_e18,
                    ..
                },
            ) => Some(*liquidation_fee_e18),
            _ => None,
        });
        assert_eq!(
            fee,
            Some(1_000_000_000_000_000u128),
            "fee must be capped at locked_margin"
        );
    });
}

/// Test 12: PositionLiquidated event carries the expected fields.
#[test]
fn liquidate_event_emitted_with_correct_fields() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        fund_pot(1_000u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );
        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        let payload = System::events().iter().find_map(|er| match &er.event {
            RuntimeEvent::PerpEngine(
                pallet_perp_engine::Event::PositionLiquidated {
                    target,
                    keeper: k,
                    market_id,
                    size_e8_closed,
                    mark_e18_at_liquidation,
                    liquidation_fee_e18: _,
                    bad_debt_e18: _,
                },
            ) => Some((
                *target,
                *k,
                market_id.clone(),
                *size_e8_closed,
                *mark_e18_at_liquidation,
            )),
            _ => None,
        });
        let payload = payload.expect("PositionLiquidated emitted");
        assert_eq!(payload.0, victim);
        assert_eq!(payload.1, keeper);
        assert_eq!(payload.2, ada_perp_market_id());
        assert_eq!(payload.3, 100_000_000u128);
        assert_eq!(payload.4, 500_000_000_000_000_000u128);
    });
}

/// Test 13: atomicity. Force the inner MOTRA transfer to fail and
/// verify NO storage was mutated — position still present, no bad
/// debt accumulated, market not paused.
#[test]
fn liquidate_atomic_on_repatriate_failure() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        register_default_market();
        let market_id = ada_perp_market_id();
        // Build a sizable liquidatable position with a 1-wei snapshot
        // rate so the fee_motra calculation is huge — and then drain
        // the pot to 0 so the transfer fails.
        let pos = Position {
            size_e8: 1_000_000_000i128, // 10 contracts
            entry_mark_e18: 1_000_000_000_000_000_000u128,
            locked_margin_e18: 10_000_000_000_000_000_000u128, // $10
            leverage_bps: 100,
            opened_block: 1,
            cumulative_funding_at_open_e18: 0,
        };
        pallet_perp_engine::pallet::Positions::<Test>::insert(
            &market_id, &victim, pos,
        );
        pallet_perp_engine::pallet::MarginAccounts::<Test>::insert(
            &victim,
            MarginAccount {
                free_e18: 0,
                last_deposit_block: 0,
                weighted_deposit_rate_e18: 1u128, // 1 wei rate → fee_motra ~ fee_e18
            },
        );
        // Mark drops 50% → realised PnL = -$5 → liquidatable.
        set_oracle_price(&ada_usd_feed_id(), 500_000_000_000_000_000u128);
        fund_pot(0u128); // pot empty
        seed_keeper_bond(
            &market_id,
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        let res = PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            market_id.clone(),
        );
        assert!(res.is_err(), "transfer failure must propagate");

        // Position still present (atomic rollback).
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &market_id, &victim,
        )
        .is_some());
        // No bad debt.
        let bd = pallet_perp_engine::pallet::BadDebtAccumulated::<Test>::get(
            &market_id,
        );
        assert_eq!(bd, 0);
        // Market still not paused.
        let m = pallet_perp_engine::pallet::Markets::<Test>::get(&market_id)
            .unwrap();
        assert!(!m.paused);
    });
}

/// Test 14: positive-equity-but-underwater. Equity in (0, MM): fee
/// paid, residual margin returns to victim's free_e18, position gone,
/// no bad debt.
///
/// With 10× leverage and locked = $0.10 at entry mark $1.00:
/// Mark $0.94 → PnL = -$0.06, equity = $0.10 - $0.06 = $0.04.
/// MM = 5% × $0.94 = $0.047. equity ($0.04) < MM ($0.047): liquidatable.
/// equity > 0: positive-equity path → residual to victim.
#[test]
fn liquidate_releases_residual_margin_to_victim_on_positive_equity() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        fund_pot(1_000u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Drop mark to $0.94 → realised PnL = -$0.06 on a 1-contract
        // long. equity = locked $0.10 − $0.06 = $0.04. MM = 5% × $0.94
        // = $0.047 → equity < MM (liquidatable) AND equity > 0
        // (positive-equity residual path).
        set_oracle_price(&ada_usd_feed_id(), 940_000_000_000_000_000u128);

        let victim_free_pre =
            pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&victim)
                .free_e18;

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        // Position gone.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());

        // Victim got residual margin back (equity_post = $0.04 - fee
        // ≈ $0.04 - 0.5%×$0.94 = $0.04 - $0.0047 = $0.0353).
        let victim_free_post =
            pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&victim)
                .free_e18;
        assert!(
            victim_free_post > victim_free_pre,
            "positive-equity liquidation returns residual margin: \
             pre={}, post={}",
            victim_free_pre,
            victim_free_post,
        );

        // No bad debt (equity was positive).
        let bd = pallet_perp_engine::pallet::BadDebtAccumulated::<Test>::get(
            &ada_perp_market_id(),
        );
        assert_eq!(bd, 0);
    });
}

/// Test 15: funding delta is applied before the equity check. Mark
/// unchanged → would-be healthy on raw mark math, but accumulated
/// funding-owed pushes equity below MM. Liquidation succeeds.
#[test]
fn liquidate_funding_delta_applied_before_equity_check() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        open_underwater_setup(PerpDirection::Long, 1u128);
        fund_pot(1_000u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        // Mark stays $1.00 → realised PnL = 0. With 10× leverage,
        // locked = $0.10, MM = 5% × $1 = $0.05. Without funding,
        // equity ($0.10) > MM → healthy. idx = 0.06e18 →
        // funding_owed = 1e8 * 0.06e18 / 1e8 = 0.06e18 = $0.06.
        // equity = $0.10 − $0.06 = $0.04 < MM $0.05 → liquidatable.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            60_000_000_000_000_000i128,
        );

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());
    });
}

/// Sec-review regression: liquidate's positive-equity residual path
/// must bump `weighted_deposit_rate_e18` whenever realized PnL is
/// positive — the SAME cross-cohort pot-drain that close_position's
/// snapshot bump fixes (see
/// `feedback_u256_weighted_avg_volatile_collateral.md` Rule 3 +
/// `close_position_cross_cohort_pnl_preserves_pot_solvency`).
///
/// Pre-fix: an underwater long with positive PnL + heavy funding-owed
/// gets liquidated; the PnL gain rides into the victim's free_e18 at
/// the OLD (stale, lower) snapshot. The victim later withdraws at the
/// stale rate and drains MOTRA from other depositors' deposits at
/// `|pnl| × (1/old_snap − 1/live_rate)` per round.
///
/// This test sets:
///   - MATRA = $0.50 at deposit time → snapshot 5e17
///   - MATRA = $1.00 at liquidation time → live_rate 1e18
///   - ADA moves up so the long has +$0.05 realized PnL
///   - Funding-owed of $0.11 pushes equity under MM
///   - Liquidation leaves a positive residual that includes the
///     positive PnL credit.
///
/// Post-fix invariant: victim's snapshot bumps above 5e17 toward 1e18
/// (asymmetric clamp: only raises, never lowers).
#[test]
fn liquidate_residual_path_bumps_snapshot_on_positive_pnl_credit() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        register_default_market();
        credit_motra(victim, 2_000u128);

        // Deposit at MATRA = $0.50 → snapshot pinned to 5e17.
        set_oracle_price(
            &matra_usd_feed_id(),
            500_000_000_000_000_000u128,
        );
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(victim),
            1_000u128,
        ));
        let acct_after_dep =
            pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&victim);
        assert_eq!(
            acct_after_dep.weighted_deposit_rate_e18,
            500_000_000_000_000_000u128,
        );
        let snapshot_pre_liquidate = acct_after_dep.weighted_deposit_rate_e18;

        // ADA at $1.00, open long 1.0 contract at 10× → locked $0.10.
        set_oracle_price(
            &ada_usd_feed_id(),
            1_000_000_000_000_000_000u128,
        );
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(victim),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            1_000u32,
            50u32,
            0u128,
        ));

        // Bump MATRA live rate to $1.00 → live_rate 1e18. ADA up to
        // $1.05 → realized PnL = 1.0 × 0.05 = +$0.05 (1e18-scaled
        // = 5e16). Funding-owed of $0.11 (idx = 0.11e18) pushes
        // equity_pre = locked $0.10 + PnL $0.05 − funding $0.11
        // = $0.04, below MM = 5% × $1.05 = $0.0525.
        set_oracle_price(
            &matra_usd_feed_id(),
            1_000_000_000_000_000_000u128,
        );
        set_oracle_price(
            &ada_usd_feed_id(),
            1_050_000_000_000_000_000u128,
        );
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            110_000_000_000_000_000i128,
        );

        fund_pot(1_000u128);
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(keeper),
            victim,
            ada_perp_market_id(),
        ));

        // Position gone, residual delivered.
        assert!(pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &victim,
        )
        .is_none());

        // CRITICAL ASSERTION: snapshot bumped above the deposit-time
        // rate because positive PnL credit at live rate pulled the
        // weighted-avg up. Without the bump the victim could
        // withdraw the residual at MATRA=$0.50 cost basis even
        // though the new pMATRA-USD entered when MATRA=$1.00.
        let acct_post =
            pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&victim);
        assert!(
            acct_post.weighted_deposit_rate_e18 > snapshot_pre_liquidate,
            "snapshot MUST bump after positive-PnL liquidation residual \
             (deposit-time={}, post-liquidate={}). Sec-review HIGH: \
             without the bump, victim withdraws PnL gain at stale snapshot \
             and drains pot from other depositors.",
            snapshot_pre_liquidate,
            acct_post.weighted_deposit_rate_e18,
        );

        // Sanity: snapshot stays at-or-below live rate when PnL credit
        // is bounded by residual (asymmetric clamp prevents
        // overshoot above live for honest scenarios).
        assert!(
            acct_post.weighted_deposit_rate_e18 <= 10_000_000_000_000_000_000u128,
            "snapshot must remain bounded ({})",
            acct_post.weighted_deposit_rate_e18,
        );
    });
}

/// Test 16: non-existent market → `MarketNotFound`. Mirrors the
/// pattern from open_position. Bond gate is checked first (the keeper
/// has no bond against a market that doesn't exist), so we seed the
/// bond on the empty market_id slot to exercise the post-bond
/// market-existence path.
#[test]
fn liquidate_rejects_market_not_found() {
    new_test_ext().execute_with(|| {
        let victim = 1u64;
        let keeper = 2u64;
        // (do NOT register_default_market)
        seed_keeper_bond(
            &ada_perp_market_id(),
            keeper,
            <Test as pallet_perp_engine::Config>::KeeperBondMinimum::get(),
        );

        assert_noop!(
            PerpEngine::liquidate(
                RuntimeOrigin::signed(keeper),
                victim,
                ada_perp_market_id(),
            ),
            Error::<Test>::MarketNotFound
        );
    });
}

// ---------------------------------------------------------------------------
// PR-C piece 2 (#259 §3.6 + §5.2 + §8.2): settle_funding + on_initialize
// mark cache + IntentKind::PerpAction byte-pin
// ---------------------------------------------------------------------------

use frame_support::traits::Hooks;

/// Helper: open a long position at default $1.00 mark on the default
/// market and seed `free_e18` so the open succeeds. Reused by every
/// settle_funding behaviour test.
fn open_default_long(signer: u64, free_e18: u128, size_e8: u128) {
    register_default_market();
    seed_free_margin(signer, free_e18);
    assert_ok!(PerpEngine::open_position(
        RuntimeOrigin::signed(signer),
        ada_perp_market_id(),
        PerpDirection::Long,
        size_e8,
        100u32,
        50u32,
        0u128,
    ));
}

/// Helper: open a short position at default $1.00 mark on the default
/// market.
fn open_default_short(signer: u64, free_e18: u128, size_e8: u128) {
    register_default_market();
    seed_free_margin(signer, free_e18);
    assert_ok!(PerpEngine::open_position(
        RuntimeOrigin::signed(signer),
        ada_perp_market_id(),
        PerpDirection::Short,
        size_e8,
        100u32,
        50u32,
        0u128,
    ));
}

/// (§3.6 happy-path #1) Long position pays funding when index rose
/// during its open window — `free_e18` is debited.
#[test]
fn settle_funding_happy_long_paid() {
    new_test_ext().execute_with(|| {
        // Open 1.0 long at $1, 1× leverage → $1 locked. Seed $2 free
        // so the funding debit comes out of the residual $1 in free.
        let signer = 1u64;
        open_default_long(signer, 2_000_000_000_000_000_000u128, 100_000_000u128);

        // Bump CumulativeFundingIndex above the open snapshot. Index
        // delta of +1e16 → funding_owed = 1.0 * 1e16 / 1e8 = 1e16 in
        // 1e18-scaled pMATRA-USD ≈ $0.01.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            10_000_000_000_000_000i128,
        );

        let acct_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct_before.free_e18, 1_000_000_000_000_000_000u128);

        // Anyone can call (permissionless); use the holder for the test.
        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // Free was $1; funding debit was $0.01 → expect $0.99.
        assert_eq!(acct.free_e18, 990_000_000_000_000_000u128);

        // Position's snapshot is re-baselined so the next settle is a no-op.
        let pos = pallet_perp_engine::pallet::Positions::<Test>::get(
            &ada_perp_market_id(),
            &signer,
        )
        .unwrap();
        assert_eq!(pos.cumulative_funding_at_open_e18, 10_000_000_000_000_000i128);
    });
}

/// (§3.6 happy-path #2) Long position receives funding when index dropped
/// during its open window — `free_e18` is credited and the snapshot rate
/// bumps via weighted-avg.
#[test]
fn settle_funding_happy_long_received() {
    new_test_ext().execute_with(|| {
        // Open via deposit_margin so the snapshot rate is pinned to live
        // MATRA/USD (1e18). Then push CumulativeFundingIndex NEGATIVE so
        // the long position receives funding.
        let signer = 1u64;
        credit_motra(signer, 10_000u128);
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));
        register_default_market();
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Bump the snapshot deposit-rate floor by raising live MATRA/USD
        // before the settle so the weighted-avg actually moves up.
        set_oracle_price(
            &matra_usd_feed_id(),
            2_000_000_000_000_000_000u128, // $2.00 per MATRA
        );

        // Index delta of -1e16 → funding_received = 1.0 * 1e16 / 1e8 = 1e16.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            -10_000_000_000_000_000i128,
        );

        let acct_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        let snap_before = acct_before.weighted_deposit_rate_e18;

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // Credit was +$0.01.
        assert_eq!(acct.free_e18, acct_before.free_e18 + 10_000_000_000_000_000u128);
        // Snapshot bumped UP toward the live $2 rate.
        assert!(
            acct.weighted_deposit_rate_e18 > snap_before,
            "snapshot should bump toward live rate (was {}, now {})",
            snap_before,
            acct.weighted_deposit_rate_e18
        );
    });
}

/// (§3.6 happy-path #3) Short position pays funding when index dropped
/// during its open window — signed_size < 0 * idx_delta < 0 → debit.
#[test]
fn settle_funding_happy_short_paid() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        open_default_short(signer, 2_000_000_000_000_000_000u128, 100_000_000u128);

        // Index goes NEGATIVE → short pays.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            -10_000_000_000_000_000i128,
        );

        let acct_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct_before.free_e18, 1_000_000_000_000_000_000u128);

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // Short paid $0.01.
        assert_eq!(acct.free_e18, 990_000_000_000_000_000u128);
    });
}

/// (§3.6 happy-path #4) Short position receives funding when index rose
/// during its open window — signed_size < 0 * idx_delta > 0 → credit.
#[test]
fn settle_funding_happy_short_received() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        open_default_short(signer, 2_000_000_000_000_000_000u128, 100_000_000u128);

        // Index goes POSITIVE → short receives.
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            10_000_000_000_000_000i128,
        );

        let acct_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        // Short received $0.01.
        assert_eq!(
            acct.free_e18,
            acct_before.free_e18 + 10_000_000_000_000_000u128
        );
    });
}

/// (§3.6) Funding owed exceeds free balance — floor at 0 (bad-debt
/// absorption pattern from close_position). Per-epoch cap also kicks
/// in so the actual debit lands at `max_funding_per_epoch_bps × notional
/// / 10_000`; free still floors at 0.
#[test]
fn settle_funding_floor_at_zero() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        open_default_long(signer, 1_000_000_000_000_000_000u128, 100_000_000u128);

        let acct_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct_before.free_e18, 0);

        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            100_000_000_000_000_000_000i128,
        );

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let acct = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(acct.free_e18, 0);
    });
}

/// (§3.6) Calling settle_funding twice in a row is a no-op the second
/// time because the snapshot was re-baselined.
#[test]
fn settle_funding_rebaselines_snapshot() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        open_default_long(signer, 2_000_000_000_000_000_000u128, 100_000_000u128);

        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            10_000_000_000_000_000i128,
        );

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));
        let after_first = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(after_first.free_e18, 990_000_000_000_000_000u128);

        // Second call — snapshot now equals current index, so delta = 0.
        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));
        let after_second = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer);
        assert_eq!(after_second.free_e18, after_first.free_e18);
    });
}

/// (§3.6) settle_funding rejects on a paused market — same gate as
/// open / adjust_leverage. Only close_position bypasses (always-exit).
#[test]
fn settle_funding_rejects_paused_market() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        register_default_market();
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
            PerpEngine::settle_funding(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                signer,
            ),
            Error::<Test>::MarketPaused
        );
    });
}

/// (§3.6) settle_funding errors when the target has no open position.
#[test]
fn settle_funding_rejects_missing_position() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let signer = 1u64;
        let target = 99u64;

        assert_noop!(
            PerpEngine::settle_funding(
                RuntimeOrigin::signed(signer),
                ada_perp_market_id(),
                target,
            ),
            Error::<Test>::PositionNotFound
        );
    });
}

/// (§3.6 + feedback_u256_weighted_avg) On funding-received, snapshot
/// bumps via weighted-avg with the live MATRA/USD rate (asymmetric
/// clamp — only raises).
#[test]
fn settle_funding_snapshot_bump_on_received() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        credit_motra(signer, 10_000u128);

        // Deposit at MATRA/USD = $1 (snapshot = 1e18).
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));
        register_default_market();
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // MATRA appreciates to $2 — live rate climbs above the snapshot.
        set_oracle_price(
            &matra_usd_feed_id(),
            2_000_000_000_000_000_000u128,
        );

        // Long receives funding (index dropped).
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            -10_000_000_000_000_000i128,
        );

        let snap_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer)
            .weighted_deposit_rate_e18;

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let snap_after = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer)
            .weighted_deposit_rate_e18;
        assert!(
            snap_after > snap_before,
            "snapshot must raise on funding-received credit (before {}, after {})",
            snap_before,
            snap_after
        );
        assert!(
            snap_after <= 2_000_000_000_000_000_000u128,
            "snapshot must be bounded by max(old, live) — got {}",
            snap_after
        );
    });
}

/// (§3.6) On funding-PAID (debit), the snapshot rate is NOT mutated —
/// outbound funding doesn't bring fresh pMATRA-USD into the system.
#[test]
fn settle_funding_snapshot_unchanged_on_paid() {
    new_test_ext().execute_with(|| {
        let signer = 1u64;
        credit_motra(signer, 10_000u128);

        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            5_000u128,
        ));
        register_default_market();
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            PerpDirection::Long,
            100_000_000u128,
            100u32,
            50u32,
            0u128,
        ));

        // Move live rate so an erroneous bump would be visible. Snapshot
        // is at $1 = 1e18 — set live to $5 to make any "snapshot follows
        // live on debit" bug glaring.
        set_oracle_price(
            &matra_usd_feed_id(),
            5_000_000_000_000_000_000u128,
        );

        // Long pays funding (index rose).
        pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::insert(
            &ada_perp_market_id(),
            10_000_000_000_000_000i128,
        );

        let snap_before = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer)
            .weighted_deposit_rate_e18;

        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            ada_perp_market_id(),
            signer,
        ));

        let snap_after = pallet_perp_engine::pallet::MarginAccounts::<Test>::get(&signer)
            .weighted_deposit_rate_e18;
        assert_eq!(
            snap_after, snap_before,
            "outbound funding must not move the deposit-rate snapshot"
        );
    });
}

// ---------------------------------------------------------------------------
// on_initialize mark cache (≥8) — §5.2
// ---------------------------------------------------------------------------

/// (§5.2) on_initialize populates MarkPriceCacheMap when the oracle is
/// fresh. mark_e18 = oracle_e18 (no premium samples → EMA = 0).
#[test]
fn on_initialize_populates_mark_cache_for_fresh_oracle() {
    new_test_ext().execute_with(|| {
        register_default_market();
        set_oracle_price(
            &ada_usd_feed_id(),
            425_000_000_000_000_000u128,
        );

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(2);

        let cache = pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(
            &ada_perp_market_id(),
        );
        assert_eq!(cache.mark_e18, 425_000_000_000_000_000u128);
        assert_eq!(cache.oracle_e18, 425_000_000_000_000_000u128);
        assert_eq!(cache.mark_ema_basis_e18, 0);
        assert_eq!(cache.block, 2);
    });
}

/// (§5.2 + §5.5) on_initialize leaves the cache un-bumped when the
/// oracle is stale.
#[test]
fn on_initialize_marks_stale_for_unfresh_oracle() {
    new_test_ext().execute_with(|| {
        register_default_market();
        set_oracle_price(&ada_usd_feed_id(), 425_000_000_000_000_000u128);
        set_oracle_fresh(&ada_usd_feed_id(), false);

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(5);

        let cache = pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(
            &ada_perp_market_id(),
        );
        assert_eq!(cache.block, 0);
        assert_eq!(cache.mark_e18, 0);
    });
}

/// (§5.2 + §7.3) The hook pushes a sample into PremiumIndexSamples[market][0].
#[test]
fn on_initialize_pushes_premium_sample() {
    new_test_ext().execute_with(|| {
        register_default_market();
        set_oracle_price(&ada_usd_feed_id(), 425_000_000_000_000_000u128);

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(2);

        let samples = pallet_perp_engine::pallet::PremiumIndexSamples::<Test>::get(
            &ada_perp_market_id(),
            0u32,
        );
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0], 0i128);
    });
}

/// (§5.2) When the bounded vec is at capacity, the oldest sample is
/// dropped so the buffer stays bounded.
#[test]
fn on_initialize_drops_oldest_sample_at_capacity() {
    new_test_ext().execute_with(|| {
        register_default_market();
        set_oracle_price(&ada_usd_feed_id(), 425_000_000_000_000_000u128);

        let cap =
            <Test as pallet_perp_engine::Config>::MaxFundingSamplesPerEpoch::get() as u64;
        for n in 0..(cap + 5) {
            System::set_block_number(n + 1);
            let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(n + 1);
        }

        let samples = pallet_perp_engine::pallet::PremiumIndexSamples::<Test>::get(
            &ada_perp_market_id(),
            0u32,
        );
        assert_eq!(samples.len(), cap as usize);
    });
}

/// (§5.2) Extreme premium samples are clamped to ±MaxMarkBasisBps when
/// computing mark = oracle + clamp(EMA, ±X%).
#[test]
fn on_initialize_clamps_ema_to_max_basis_bps() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let oracle = 1_000_000_000_000_000_000u128;
        set_oracle_price(&ada_usd_feed_id(), oracle);

        let cap =
            <Test as pallet_perp_engine::Config>::MaxFundingSamplesPerEpoch::get() as usize;
        let mut huge: frame_support::BoundedVec<
            i128,
            <Test as pallet_perp_engine::Config>::MaxFundingSamplesPerEpoch,
        > = Default::default();
        let extreme = 1_000_000_000_000_000_000_000i128;
        for _ in 0..cap {
            huge.try_push(extreme).expect("bounded vec accepts cap items");
        }
        pallet_perp_engine::pallet::PremiumIndexSamples::<Test>::insert(
            &ada_perp_market_id(),
            0u32,
            huge,
        );

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(2);

        let cache = pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(
            &ada_perp_market_id(),
        );
        let max_basis_bps = <Test as pallet_perp_engine::Config>::MaxMarkBasisBps::get();
        let max_basis = (oracle / 10_000) * (max_basis_bps as u128);
        let expected_mark = oracle + max_basis;
        assert_eq!(cache.mark_e18, expected_mark);
    });
}

/// (§5.2) First block — no historical samples — mark equals oracle
/// exactly.
#[test]
fn on_initialize_zero_premium_when_no_samples() {
    new_test_ext().execute_with(|| {
        register_default_market();
        let oracle = 425_000_000_000_000_000u128;
        set_oracle_price(&ada_usd_feed_id(), oracle);

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(2);

        let cache = pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(
            &ada_perp_market_id(),
        );
        assert_eq!(cache.mark_e18, oracle);
        assert_eq!(cache.mark_ema_basis_e18, 0);
    });
}

/// (§5.2) Multiple markets — every active market gets its cache row
/// updated each block.
#[test]
fn on_initialize_iterates_all_markets() {
    new_test_ext().execute_with(|| {
        register_default_market();

        let btc_market = MarketId::try_from(b"BTC-PERP/USD".to_vec()).unwrap();
        let btc_feed = OracleFeedId::try_from(b"BTC/USD".to_vec()).unwrap();
        let mut btc_cfg = default_ada_perp_market_config();
        btc_cfg.id = btc_market.clone();
        btc_cfg.oracle_feed_id = btc_feed.clone();
        pallet_perp_engine::pallet::Markets::<Test>::insert(&btc_market, btc_cfg);

        set_oracle_price(&ada_usd_feed_id(), 425_000_000_000_000_000u128);
        set_oracle_price(&btc_feed, 60_000_000_000_000_000_000_000u128);

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(3);

        let ada_cache = pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(
            &ada_perp_market_id(),
        );
        let btc_cache =
            pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(&btc_market);
        assert_eq!(ada_cache.mark_e18, 425_000_000_000_000_000u128);
        assert_eq!(
            btc_cache.mark_e18,
            60_000_000_000_000_000_000_000u128
        );
    });
}

/// (§5.2 + §5.5) Paused markets are SKIPPED by on_initialize. Mark cache
/// freezes at its last fresh value, matching the §5.5 freshness contract.
/// Justification (also in PR body): freezing the cache on pause keeps
/// the §5.5 always-exit contract deterministic because `close_position`
/// reads the cached mark.
#[test]
fn on_initialize_skips_paused_markets() {
    new_test_ext().execute_with(|| {
        let mut cfg = default_ada_perp_market_config();
        cfg.paused = true;
        pallet_perp_engine::pallet::Markets::<Test>::insert(
            &ada_perp_market_id(),
            cfg,
        );
        set_oracle_price(&ada_usd_feed_id(), 425_000_000_000_000_000u128);

        let _w = <pallet_perp_engine::Pallet<Test> as Hooks<_>>::on_initialize(2);

        let cache = pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::get(
            &ada_perp_market_id(),
        );
        assert_eq!(cache.block, 0);
        assert_eq!(cache.mark_e18, 0);
    });
}

// ---------------------------------------------------------------------------
// IntentKind::PerpAction byte-pin (≥2) — §8.2
// ---------------------------------------------------------------------------

/// (§8.2) `IntentKind::PerpAction(PerpActionKind::*)` encodes via SCALE
/// with a byte-pinned layout. The first byte is the `IntentKind` variant
/// tag, the second is the `PerpActionKind` variant tag. Any drift in
/// either enum's declaration order would re-shuffle these tags and
/// silently misclassify intents. This test is the canary.
#[test]
fn intent_kind_perp_action_scale_encoding_byte_pinned() {
    use codec::Encode;
    use pallet_intent_settlement::types::IntentKind;
    use pallet_intent_settlement::types::PerpActionKind as IntentPerpActionKind;

    let perp_open = IntentKind::PerpAction(IntentPerpActionKind::Open);
    let bytes_open = perp_open.encode();
    assert_eq!(bytes_open[0], 0x03, "IntentKind::PerpAction tag must be 3");
    assert_eq!(bytes_open[1], 0x00, "PerpActionKind::Open tag must be 0");

    let perp_close = IntentKind::PerpAction(IntentPerpActionKind::Close);
    let bytes_close = perp_close.encode();
    assert_eq!(bytes_close[0], 0x03);
    assert_eq!(bytes_close[1], 0x01, "PerpActionKind::Close tag must be 1");

    let perp_liq = IntentKind::PerpAction(IntentPerpActionKind::Liquidation);
    let bytes_liq = perp_liq.encode();
    assert_eq!(bytes_liq[0], 0x03);
    assert_eq!(bytes_liq[1], 0x02, "PerpActionKind::Liquidation tag must be 2");

    let perp_adj = IntentKind::PerpAction(IntentPerpActionKind::LeverageAdjust);
    let bytes_adj = perp_adj.encode();
    assert_eq!(bytes_adj[0], 0x03);
    assert_eq!(
        bytes_adj[1], 0x03,
        "PerpActionKind::LeverageAdjust tag must be 3"
    );
}

/// (§8.2) Cross-pallet enum-discriminant guard. Both the local
/// `pallet-perp-engine::types::PerpActionKind` AND the mirror in
/// `pallet-intent-settlement::types::PerpActionKind` MUST encode to the
/// same single-byte discriminants. Pinning explicit byte sequences for
/// BOTH enums catches the silent drift.
#[test]
fn intent_kind_perp_action_variant_index_matches_source_order() {
    use codec::Encode;
    use pallet_intent_settlement::types::PerpActionKind as MirrorPerpActionKind;

    assert_eq!(PerpActionKind::Open.encode(), vec![0x00]);
    assert_eq!(PerpActionKind::Close.encode(), vec![0x01]);
    assert_eq!(PerpActionKind::Liquidation.encode(), vec![0x02]);
    assert_eq!(PerpActionKind::LeverageAdjust.encode(), vec![0x03]);

    assert_eq!(MirrorPerpActionKind::Open.encode(), vec![0x00]);
    assert_eq!(MirrorPerpActionKind::Close.encode(), vec![0x01]);
    assert_eq!(MirrorPerpActionKind::Liquidation.encode(), vec![0x02]);
    assert_eq!(MirrorPerpActionKind::LeverageAdjust.encode(), vec![0x03]);
}
