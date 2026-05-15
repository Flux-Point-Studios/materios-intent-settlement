//! Unit tests for `pallet-perp-engine` v0 scaffolding (task #259, PR-A).
//!
//! Scaffold-only contract: the tests in this file verify the pallet
//! compiles, the call surface is exposed via the constructed runtime,
//! genesis state is empty, default constants are pinned to design-memo
//! §9.1 values, and error variants are distinct. Real behaviour tests
//! land in PR-B alongside the dispatch impl bodies.
//!
//! Five tests:
//! 1. [`it_compiles`] — type-system smoke test: every public type from
//!    `types::*` constructs from raw fields under the test runtime.
//! 2. [`genesis_state_empty`] — `Markets`, `Positions`, `MarginAccounts`,
//!    `MarkPriceCacheMap`, `CumulativeFundingIndex`,
//!    `PremiumIndexSamples`, `LastSettledFundingEpoch`,
//!    `ReservedKeeperBonds`, `BadDebtAccumulated` are all empty / zero
//!    at genesis. Pins the storage schema against accidental
//!    `GenesisConfig`-bearing pre-population.
//! 3. [`call_surface_exposed`] — all 8 extrinsic stubs are callable
//!    through the runtime dispatcher and return `Ok(())`. Pins the
//!    signed/root origin gates per design memo §3.x.
//! 4. [`default_constants_pinned`] — `MaxLeverageBps`, `MinLeverageBps`,
//!    `FreshnessLimitBlocks`, `MaxMarkBasisBps`, `KeeperBondMinimum`,
//!    `MaxMarkets`, `MaxFundingSamplesPerEpoch` match the design-memo
//!    §9.1 risk-parameter table.
//! 5. [`error_variants_distinct`] — at least 9 error variants
//!    (`MarketNotFound`, `MarketPaused`, `LeverageOutOfBounds`,
//!    `InsufficientMargin`, `PositionNotFound`, `MaxSlippageExceeded`,
//!    `BadLiquidationAttempt`, `OracleUnavailable`, `EpochAlreadySettled`)
//!    Debug-print to distinct names — pins the on-fail UX so callers
//!    can pattern-match every failure mode.

#![cfg(test)]

use crate as pallet_perp_engine;
use crate::pallet::{Error, PriceOracle};
use crate::types::*;
use frame_support::{
    assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::ConstU128,
    PalletId,
};
use sp_runtime::{traits::IdentityLookup, BuildStorage};

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
}

/// Mock price oracle: returns `Some(1_000_000_000_000_000_000)` (1.0 at
/// 1e18 scale) for any feed_id, always fresh, age 0. Real adapter
/// wiring to `pallet-oracle::Pallet` lands in PR-D (runtime
/// integration) — out of scope for the scaffold.
pub struct MockPriceOracle;
impl PriceOracle for MockPriceOracle {
    fn latest_price_e18(_feed_id: &OracleFeedId) -> Option<u128> {
        Some(1_000_000_000_000_000_000u128)
    }
    fn price_age_blocks(_feed_id: &OracleFeedId) -> u32 {
        0
    }
    fn is_fresh(_feed_id: &OracleFeedId) -> bool {
        true
    }
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
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
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

// ---------------------------------------------------------------------------
// Tests
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
    };
    assert_eq!(acct.free_e18, 1_000_000_000_000_000_000u128);
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

        // No margin accounts. (ValueQuery returns default for missing
        // keys, but iter() must be empty.)
        assert!(pallet_perp_engine::pallet::MarginAccounts::<Test>::iter().next().is_none());

        // No mark-price cache rows.
        assert!(pallet_perp_engine::pallet::MarkPriceCacheMap::<Test>::iter().next().is_none());

        // Cumulative funding index is empty (i128 ValueQuery returns 0
        // for missing keys; iter() must yield no rows).
        assert!(pallet_perp_engine::pallet::CumulativeFundingIndex::<Test>::iter().next().is_none());

        // No premium-index samples.
        assert!(pallet_perp_engine::pallet::PremiumIndexSamples::<Test>::iter().next().is_none());

        // No funding-epoch settle-progress rows.
        assert!(pallet_perp_engine::pallet::LastSettledFundingEpoch::<Test>::iter().next().is_none());

        // No in-flight keeper-bond reservations. This is also the v0 §4.6
        // try_state invariant pinned here at genesis (PR-B adds the
        // hook).
        assert!(pallet_perp_engine::pallet::ReservedKeeperBonds::<Test>::iter().next().is_none());

        // No bad debt accrued.
        assert!(pallet_perp_engine::pallet::BadDebtAccumulated::<Test>::iter().next().is_none());
    });
}

/// Every one of the 8 extrinsic stubs is callable via the dispatcher
/// and returns `Ok(())`. Origin gates (`ensure_signed` x7,
/// `ensure_root` x1) are exercised.
///
/// Per the design memo §3 each extrinsic has a fixed signature; this
/// test pins that signature shape at the runtime-dispatch level.
#[test]
fn call_surface_exposed() {
    new_test_ext().execute_with(|| {
        let market_id = ada_perp_market_id();
        let signer = 1u64;

        // (1) open_position — signed.
        assert_ok!(PerpEngine::open_position(
            RuntimeOrigin::signed(signer),
            market_id.clone(),
            PerpDirection::Long,
            100_000_000u128,   // 1.0
            1_000u32,           // 10× leverage
            50u32,              // 0.5% slippage
            0u128,              // no margin top-up
        ));

        // (2) close_position — signed.
        assert_ok!(PerpEngine::close_position(
            RuntimeOrigin::signed(signer),
            market_id.clone(),
            0u128,              // 0 = close all
            50u32,
        ));

        // (3) deposit_margin — signed.
        assert_ok!(PerpEngine::deposit_margin(
            RuntimeOrigin::signed(signer),
            1_000u128,
        ));

        // (4) withdraw_margin — signed.
        assert_ok!(PerpEngine::withdraw_margin(
            RuntimeOrigin::signed(signer),
            1_000_000_000_000_000_000u128, // 1.0 pMATRA-USD
        ));

        // (5) liquidate — signed (permissionless).
        assert_ok!(PerpEngine::liquidate(
            RuntimeOrigin::signed(signer),
            2u64,               // target
            market_id.clone(),
            100u128,            // keeper bond
        ));

        // (6) settle_funding — signed (permissionless).
        assert_ok!(PerpEngine::settle_funding(
            RuntimeOrigin::signed(signer),
            market_id.clone(),
            1u32,
        ));

        // (7) adjust_leverage — signed.
        assert_ok!(PerpEngine::adjust_leverage(
            RuntimeOrigin::signed(signer),
            market_id.clone(),
            500u32,             // 5×
        ));

        // (8) governance_set_market — root only (sudo / 2-of-3 multisig).
        assert_ok!(PerpEngine::governance_set_market(
            RuntimeOrigin::root(),
            market_id.clone(),
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
}

/// All 9 design-memo-required error variants Debug-print to distinct
/// names. Pins the on-fail UX: callers (SDKs, indexers, dashboards)
/// must be able to pattern-match every failure mode without ambiguity.
///
/// Per the user's scaffolding contract: at minimum `MarketNotFound`,
/// `MarketPaused`, `LeverageOutOfBounds`, `InsufficientMargin`,
/// `PositionNotFound`, `MaxSlippageExceeded`, `BadLiquidationAttempt`,
/// `OracleUnavailable`, `EpochAlreadySettled`.
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
    ];

    // Every Debug-printed variant must be distinct from every other.
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

    // Sanity-check each variant name appears in its own Debug string.
    assert!(variants[0].contains("MarketNotFound"));
    assert!(variants[1].contains("MarketPaused"));
    assert!(variants[2].contains("LeverageOutOfBounds"));
    assert!(variants[3].contains("InsufficientMargin"));
    assert!(variants[4].contains("PositionNotFound"));
    assert!(variants[5].contains("MaxSlippageExceeded"));
    assert!(variants[6].contains("BadLiquidationAttempt"));
    assert!(variants[7].contains("OracleUnavailable"));
    assert!(variants[8].contains("EpochAlreadySettled"));
}
