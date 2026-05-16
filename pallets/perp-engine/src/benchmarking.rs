//! Frame-benchmarking stubs for `pallet-perp-engine` v0 scaffolding
//! (task #259, PR-A).
//!
//! Per the user's scaffolding contract these are empty bench declarations
//! only — PR-B replaces the dispatch bodies with real state mutation and
//! these benches must measure that work. For PR-A the benches exist so
//! the `runtime-benchmarks` feature gate compiles end-to-end.
//!
//! Each `#[benchmark]` here is a 1-line invocation against the stub
//! extrinsic; PR-B replaces the bodies with:
//!
//! - parametrised setup (e.g. `n ∈ [1, MaxFundingSamplesPerEpoch]` for
//!   `settle_funding`),
//! - real state pre-population (e.g. an open `Position` for the
//!   `liquidate` bench),
//! - assertion checks (per-extrinsic post-state invariants),
//! - `impl_benchmark_test_suite!` wiring (omitted here while the
//!   bench harness AccountId type would diverge from the u64 mock —
//!   see `pallet-oracle::benchmarking` comment block for the same
//!   pattern).

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::types::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

#[benchmarks]
mod benches {
    use super::*;

    fn bench_market_id() -> MarketId {
        MarketId::try_from(b"ADA-PERP/USD".to_vec()).expect("12 bytes fits MAX=16")
    }

    fn bench_oracle_feed() -> OracleFeedId {
        OracleFeedId::try_from(b"ADA/USD".to_vec()).expect("7 bytes fits MAX=16")
    }

    fn bench_market_config() -> MarketConfig {
        MarketConfig {
            id: bench_market_id(),
            oracle_feed_id: bench_oracle_feed(),
            initial_margin_bps: 1_000,
            maintenance_margin_bps: 500,
            max_leverage_bps: 1_000,
            max_funding_per_epoch_bps: 400,
            liquidation_fee_bps: 50,
            maker_fee_bps: -2,
            taker_fee_bps: 7,
            max_position_size_e8: 250_000_000_000,
            min_position_size_e8: 1_000_000,
            mark_ema_window_blocks: 25,
            funding_epoch_blocks: 600,
            paused: false,
        }
    }

    /// Benchmarks the stub `open_position` extrinsic. PR-B rewrites this
    /// to measure mark-cache read + margin lock + Position insert +
    /// PositionOpened event + IntentKind::PerpAction(Open) emit.
    #[benchmark]
    fn open_position() {
        let caller: T::AccountId = whitelisted_caller();
        let market_id = bench_market_id();

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            market_id,
            PerpDirection::Long,
            100_000_000u128,
            1_000u32,
            50u32,
            Default::default(),
        );
    }

    /// Benchmarks the stub `close_position` extrinsic. PR-B measures
    /// Position read + mark-cache read + PnL compute + funding-delta
    /// apply + locked-margin release + PositionClosed event.
    #[benchmark]
    fn close_position() {
        let caller: T::AccountId = whitelisted_caller();
        let market_id = bench_market_id();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), market_id, 0u128, 50u32);
    }

    /// Benchmarks the stub `deposit_margin` extrinsic. PR-B measures
    /// Currency::transfer + MarginAccount upsert + MarginDeposited event.
    #[benchmark]
    fn deposit_margin() {
        let caller: T::AccountId = whitelisted_caller();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), Default::default());
    }

    /// Benchmarks the stub `withdraw_margin` extrinsic. PR-B measures
    /// margin-equity check + dwell-time check + oracle-rate convert +
    /// Currency::transfer + MarginWithdrawn event.
    #[benchmark]
    fn withdraw_margin() {
        let caller: T::AccountId = whitelisted_caller();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), 1_000_000_000_000_000_000u128);
    }

    /// Benchmarks the `liquidate` extrinsic. PR-C piece 1 (#259 §3.5):
    /// keeper-bond gate read + Position read + mark vs MM compute +
    /// fee transfer + bad-debt accumulator + Position remove +
    /// PositionLiquidated event. Worst-case path measured here is the
    /// breaker-trip case (extra Markets write); v1 will parametrise
    /// (positive-equity vs bad-debt vs breaker-trip).
    #[benchmark]
    fn liquidate() {
        let caller: T::AccountId = whitelisted_caller();
        let target: T::AccountId = whitelisted_caller();
        let market_id = bench_market_id();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), target, market_id);
    }

    /// Benchmarks the `settle_funding` extrinsic. PR-C piece 2 (#259
    /// §3.6 + §7.4): pull-based per-(market, target) funding settle.
    /// Body measures funding-delta math + per-epoch clamp +
    /// MarginAccount update + (optional) U256 snapshot bump on
    /// funding-received + Position re-baseline + the
    /// `FundingSettledForPosition` event. Bench setup needs an open
    /// Position so the body exercises the full hot path — the
    /// PR-D bench skeleton fills in (market, position) seeding.
    #[benchmark]
    fn settle_funding() {
        let caller: T::AccountId = whitelisted_caller();
        let target: T::AccountId = whitelisted_caller();
        let market_id = bench_market_id();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), market_id, target);
    }

    /// Benchmarks the stub `adjust_leverage` extrinsic. PR-B measures
    /// Position read + locked-margin rebase + margin-equity recheck +
    /// LeverageAdjusted event.
    #[benchmark]
    fn adjust_leverage() {
        let caller: T::AccountId = whitelisted_caller();
        let market_id = bench_market_id();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), market_id, 500u32);
    }

    /// Benchmarks the stub `governance_set_market` extrinsic. PR-B
    /// measures config validation + try_state worsening-terms check +
    /// Markets upsert + MarketSet event.
    #[benchmark]
    fn governance_set_market() {
        let market_id = bench_market_id();
        let config = bench_market_config();

        #[extrinsic_call]
        _(RawOrigin::Root, market_id, config);
    }

    // NOTE: `impl_benchmark_test_suite!` intentionally omitted. The bench
    // harness assumes `T::AccountId = AccountId32` (sr25519 pubkey
    // identity in the production runtime); the test mock uses `u64`
    // AccountId for lightweight tests. Mirrors the comment block at
    // `pallet-oracle::benchmarking::benches` end-of-mod. Bench weights
    // come from runtime-side runs against `materios-runtime` after
    // PR-D wiring.
}
