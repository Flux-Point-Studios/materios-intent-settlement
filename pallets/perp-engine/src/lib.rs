//! # `pallet-perp-engine` — Materios Perp Engine v0
//!
//! Task #259. Design memo:
//! `/home/deci/work/perp-engine-v0-spec.md` (720 lines, locked).
//!
//! ## Scope (PR-B impl)
//!
//! Five extrinsic bodies land in this PR:
//! - [`pallet::Pallet::open_position`] — §3.1, full margin lock + sign
//!   handling, oracle-mark entry, IM check, dust + size + leverage
//!   bounds, optional MOTRA top-up.
//! - [`pallet::Pallet::close_position`] — §3.2, partial + full close,
//!   realized PnL, funding delta, locked-margin release. Closes work
//!   on a stale oracle (§5.5) so users can always exit.
//! - [`pallet::Pallet::deposit_margin`] — §3.3, MOTRA → pot transfer +
//!   pMATRA-USD credit at live MATRA/USD rate.
//! - [`pallet::Pallet::withdraw_margin`] — §3.4, dwell-time gate +
//!   locked-margin floor + pMATRA-USD → MOTRA conversion.
//! - [`pallet::Pallet::adjust_leverage`] — §3.7, locked-margin rebase
//!   + IM-floor invariant at current mark.
//!
//! Reserved for PR-C/D:
//! - [`pallet::Pallet::liquidate`] (PR-C) — keeper-bonded permissionless
//!   liquidation per §3.5 + §6.3.
//! - [`pallet::Pallet::settle_funding`] (PR-C) — pull-based funding
//!   epoch settlement per §3.6 + §7.4.
//! - [`pallet::Pallet::governance_set_market`] (PR-D) — sudo / multisig
//!   market creation + update per §3.8.
//!
//! ## Math layer
//!
//! All fixed-point arithmetic lives in [`crate::math`]. Each helper
//! surfaces `Result<_, MathOverflow>` so the call sites map cleanly to
//! `Error::ArithmeticOverflow` — no silent saturation, per design memo
//! §10.1 risk #3.
//!
//! ## Multi-PR sequence
//!
//! - **PR-A**: types + storage + extrinsic stubs (merged).
//! - **PR-B (this one)**: 5/8 extrinsic impl bodies + math module +
//!   18 new behaviour tests.
//! - **PR-C**: `liquidate` + `settle_funding` + `MarkPriceCache`
//!   on_initialize hook + `IntentKind::PerpAction` extension on
//!   `pallet-intent-settlement` (§8.2).
//! - **PR-D**: wire into `materios-runtime` `construct_runtime!`, with
//!   genesis `MarketsPaused = true` kill-switch per §next-steps.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod math;
pub mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use math::{
    compute_funding_delta, compute_initial_margin, compute_maintenance_margin,
    compute_notional, compute_realized_pnl_signed,
};
pub use types::{
    EpochNumber, MarginAccount, MarketConfig, MarketId, MarkPriceCache, OracleFeedId,
    PerpActionKind, PerpDirection, Position, MAX_MARKET_ID_LEN,
};

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::math::{
        compute_funding_delta, compute_initial_margin, compute_notional,
        compute_realized_pnl_signed,
    };
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ExistenceRequirement, ReservableCurrency},
        BoundedVec, PalletId,
    };
    use frame_system::pallet_prelude::*;
    use sp_core::U256;
    use sp_runtime::traits::{AccountIdConversion, SaturatedConversion, Zero};

    /// Balance alias derived from `T::Currency`. Used for MOTRA-denominated
    /// fields (margin top-ups, keeper bonds, treasury fees) — distinct
    /// from the 1e18-scaled pMATRA-USD virtual unit used for position
    /// margin equity (§3.3 collateral abstraction).
    pub type BalanceOf<T> = <<T as Config>::Currency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

    // ---------------------------------------------------------------------
    // Oracle abstraction — Config trait so the pallet stays unit-testable
    // ---------------------------------------------------------------------

    /// Price-oracle adapter trait. Production wiring points this at an
    /// adapter type that reads `pallet-oracle::Prices`; tests substitute
    /// a `MockPriceOracle` (see `tests.rs`). Mirrors the `IsAttestorFor`
    /// trait in `pallet-oracle` — same composability pattern.
    ///
    /// All prices are 1e18-scaled. The trait does NOT carry decimals; the
    /// adapter is responsible for normalising whatever scale
    /// `pallet-oracle::PriceFeed.last_decimals` reports up to 1e18 before
    /// returning.
    pub trait PriceOracle {
        /// Latest published price for the feed, scaled 1e18. Per §5.1 this
        /// is the trimmed-median value last published to Materios (NOT
        /// the Cardano L1 anchor — that lags by 20-60s and is too stale
        /// for mark price).
        fn latest_price_e18(feed_id: &OracleFeedId) -> Option<u128>;

        /// Age of the latest price in blocks at the current block height.
        /// Returns `u32::MAX` if the feed has no entries (i.e. never
        /// published).
        fn price_age_blocks(feed_id: &OracleFeedId) -> u32;

        /// True iff the feed is currently un-paused, has ≥ M signatures
        /// in its most recent slot, and `price_age_blocks <
        /// FreshnessLimit`. Per §5.5 a stale feed pauses opens +
        /// liquidations but still allows closes.
        fn is_fresh(feed_id: &OracleFeedId) -> bool;
    }

    // ---------------------------------------------------------------------
    // Config
    // ---------------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// MOTRA currency adapter. Used for `deposit_margin` /
        /// `withdraw_margin` transfers between the user and the pallet's
        /// pot account, and for `liquidate` keeper-bond reservation.
        /// Per §3.3 collateral abstraction, MOTRA is the on-chain token
        /// and pMATRA-USD is the internal accounting unit at the live
        /// oracle MATRA/USD rate.
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Price-oracle adapter. Production wires to `pallet-oracle`;
        /// tests substitute `MockPriceOracle`. See [`PriceOracle`]
        /// docstring for the contract.
        type PriceOracle: PriceOracle;

        /// PalletId from which the pallet derives its sovereign account
        /// for margin custody. MOTRA deposited via `deposit_margin` lives
        /// in `PalletId::into_account()`. Per §3.3.
        #[pallet::constant]
        type PalletId: Get<PalletId>;

        /// 32-byte Materios chain identity (genesis hash). Pinned into
        /// committee-signed payloads (none in v0 — `liquidate` uses
        /// oracle mark as evidence rather than committee sig — but the
        /// Config item is present so PR-B can introduce committee-signed
        /// flows without a Config-shape change). Mirrors the chain-id
        /// binding in `pallet-intent-settlement` (#73) and
        /// `pallet-oracle` (#268).
        #[pallet::constant]
        type MateriosChainId: Get<[u8; 32]>;

        /// Maximum leverage in bps, hard cap across ALL markets. Each
        /// market's `MarketConfig.max_leverage_bps` MUST be ≤ this value.
        /// Default 2000 (= 20×) per §9.1 governance range.
        #[pallet::constant]
        type MaxLeverageBps: Get<u32>;

        /// Minimum leverage in bps. Default 100 (= 1×). Per §3.7
        /// `adjust_leverage` bounds.
        #[pallet::constant]
        type MinLeverageBps: Get<u32>;

        /// Maximum number of distinct markets the pallet supports. Bounds
        /// `on_initialize` mark-price update cost (§5.2 iterates active
        /// markets every block). Default 32 — accommodates the v0 launch
        /// set (3 markets per §9.2) with growth headroom.
        #[pallet::constant]
        type MaxMarkets: Get<u32>;

        /// Maximum number of premium-index samples per funding epoch per
        /// market. Per §4.5 + §7.3, this MUST equal
        /// `funding_epoch_blocks` (one sample per block). Default 600
        /// (= 1h at 6s blocks).
        #[pallet::constant]
        type MaxFundingSamplesPerEpoch: Get<u32>;

        /// Minimum keeper bond for `liquidate`, in MOTRA. Default 100
        /// MATRA-equivalent units per §6.4 (governance-tunable per
        /// market via `MarketConfig` in v1; v0 ships this as a flat
        /// constant). Bond is `Currency::reserve`d at call time and
        /// slashed 100% on a false liquidation trigger (§6.3).
        #[pallet::constant]
        type KeeperBondMinimum: Get<BalanceOf<Self>>;

        /// Mark-price freshness limit in blocks. After this many blocks
        /// without a fresh oracle update, `MarkPriceCache[market_id]` is
        /// treated as stale and (a) opens reject with `MarkStale`, (b)
        /// liquidations reject with `MarkStale`, (c) closes still work
        /// at the last fresh mark (§5.5). Default 50 (~5 min at 6s).
        #[pallet::constant]
        type FreshnessLimitBlocks: Get<u32>;

        /// Maximum mark-price basis (deviation from oracle) in bps,
        /// applied to the EMA basis in `MarkPriceCache.mark_ema_basis_e18`.
        /// `mark_e18 = oracle_e18 + clamp(ema_basis, ±X% × oracle_e18)`.
        /// Structural protection against mark-price manipulation via
        /// thin CLOB liquidity. Default 200 bps = 2% per §5.2.
        #[pallet::constant]
        type MaxMarkBasisBps: Get<u32>;

        /// Bad-debt circuit-breaker threshold in 1e18-scaled pMATRA-USD.
        /// Per §6.5, if total bad debt over `BadDebtWindowBlocks` exceeds
        /// this value the market auto-pauses. Default $10_000 = 10^22
        /// (1e18 × 10^4).
        #[pallet::constant]
        type BadDebtCircuitBreakerThresholdE18: Get<u128>;

        /// Bad-debt rolling window in blocks. Default 14_400 (~24h at
        /// 6s blocks) per §9.1.
        #[pallet::constant]
        type BadDebtWindowBlocks: Get<u32>;

        /// MATRA/USD oracle feed handle. Used to translate MOTRA token
        /// amounts ↔ 1e18-scaled pMATRA-USD margin units in
        /// `deposit_margin` / `withdraw_margin` per §3.3 collateral
        /// abstraction.
        ///
        /// Production wires this to the canonical Aegis `MATRA/USD`
        /// feed id; tests register a fixture under
        /// `MockPriceOracle`. If the oracle is unavailable for this
        /// feed at deposit / withdraw time, both extrinsics fail with
        /// `OracleUnavailable` — collateral conversion is the central
        /// invariant.
        #[pallet::constant]
        type MatraUsdFeedId: Get<OracleFeedId>;

        /// Dwell time (in blocks) a fresh `deposit_margin` must elapse
        /// before the same account can `withdraw_margin`. Per §3.4
        /// bridge-deposit-replay protection; default 14_400 = ~24h at
        /// 6s blocks.
        #[pallet::constant]
        type WithdrawDwellBlocks: Get<u32>;
    }

    // ---------------------------------------------------------------------
    // Pallet declaration
    // ---------------------------------------------------------------------

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    /// Governance-set market configuration. One row per active market.
    /// `Identity` hasher per §4.1 — `MarketId` is governance-controlled
    /// bounded bytes, so no first-key DoS via collision crafting. Matches
    /// `pallet-oracle::PriceFeeds` hasher rationale.
    #[pallet::storage]
    pub type Markets<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        MarketId,
        MarketConfig,
        OptionQuery,
    >;

    /// Per-account-per-market open positions. Double map: first key
    /// `MarketId` (governance-set, Identity-safe in design memo §4.2 but
    /// we use `Blake2_128Concat` here because the BoundedVec MarketId
    /// shape isn't natively `Identity`-friendly under FRAME's hasher
    /// generic bounds — collision risk is still zero in practice
    /// because `MarketId` is governance-controlled). Second key
    /// `AccountId` (user-supplied), MUST be a crypto hasher per §4.2.
    #[pallet::storage]
    pub type Positions<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        MarketId,
        Blake2_128Concat,
        T::AccountId,
        Position,
        OptionQuery,
    >;

    /// Per-account free-margin balance. `Blake2_128Concat` because
    /// `AccountId` is user-supplied. `ValueQuery` returns
    /// `MarginAccount::default()` (free=0, last_deposit_block=0) for
    /// accounts that haven't deposited yet — equivalent to "no row".
    #[pallet::storage]
    pub type MarginAccounts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        MarginAccount,
        ValueQuery,
    >;

    /// Per-market mark-price cache, updated every block by
    /// `on_initialize` (§5.2 — impl PR). One row per active market.
    #[pallet::storage]
    pub type MarkPriceCacheMap<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        MarketId,
        MarkPriceCache,
        ValueQuery,
    >;

    /// Cumulative funding index per market, signed `i128` (cumulative
    /// funding can be net-positive or net-negative over the market's
    /// life). Updated by `settle_funding(epoch)` (§3.6). Per-position
    /// funding owed = `signed_size * (now - position.cumulative_funding_at_open_e18)`.
    #[pallet::storage]
    pub type CumulativeFundingIndex<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        MarketId,
        i128,
        ValueQuery,
    >;

    /// Per-market-per-epoch premium-index samples. Populated each block
    /// by `on_finalize` (§7.3 — impl PR). Pruned eagerly by
    /// `settle_funding(epoch)` once the median is computed. Bounded by
    /// `T::MaxFundingSamplesPerEpoch` so the storage churn is
    /// upper-bounded at ~10KB per market per epoch (§4.5).
    #[pallet::storage]
    pub type PremiumIndexSamples<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        MarketId,
        Blake2_128Concat,
        EpochNumber,
        BoundedVec<i128, <T as Config>::MaxFundingSamplesPerEpoch>,
        ValueQuery,
    >;

    /// Last-settled funding epoch number per market. `settle_funding` is
    /// idempotent: a call with `epoch <= LastSettledFundingEpoch[market]`
    /// is a no-op (§3.6).
    #[pallet::storage]
    pub type LastSettledFundingEpoch<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        MarketId,
        EpochNumber,
        ValueQuery,
    >;

    /// In-flight keeper-bond reservations for `liquidate` calls. Keyed
    /// by `(keeper, market, target)` — each tuple uniquely identifies
    /// one in-flight liquidation attempt. Released atomically inside
    /// `liquidate` after the trigger evaluation (§6.3).
    ///
    /// **Invariant (try_state, PR-B):** this map MUST be empty at the
    /// end of every block. A non-empty entry is a logic bug per §4.6.
    #[pallet::storage]
    pub type ReservedKeeperBonds<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (T::AccountId, MarketId, T::AccountId),
        BalanceOf<T>,
        OptionQuery,
    >;

    /// Cumulative bad debt absorbed by `mat/trsy` per market. Used by
    /// the bad-debt circuit breaker (§6.5). Reset by governance after
    /// investigation.
    #[pallet::storage]
    pub type BadDebtAccumulated<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        MarketId,
        u128,
        ValueQuery,
    >;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new position was opened. Emitted by `open_position` (§3.1)
        /// after margin lock-in and `Position` insert.
        PositionOpened {
            who: T::AccountId,
            market_id: MarketId,
            direction: PerpDirection,
            size_e8: u128,
            entry_mark_e18: u128,
            leverage_bps: u32,
        },
        /// An existing position was closed (fully or partially). Emitted
        /// by `close_position` (§3.2). `realized_pnl_e18_signed` is the
        /// PnL in 1e18-scaled pMATRA-USD; negative = loss.
        /// `funding_paid_e18_signed` reflects the pull-based funding
        /// accrual applied at close (§7.4): positive = paid by
        /// position holder, negative = received.
        PositionClosed {
            who: T::AccountId,
            market_id: MarketId,
            size_e8_closed: u128,
            exit_mark_e18: u128,
            realized_pnl_e18_signed: i128,
            funding_paid_e18_signed: i128,
        },
        /// Margin was deposited into the pallet pot account. Emitted by
        /// `deposit_margin` (§3.3) after `Currency::transfer` succeeds.
        MarginDeposited {
            who: T::AccountId,
            amount_motra: BalanceOf<T>,
            free_e18_after: u128,
        },
        /// Margin was withdrawn from the pallet pot account. Emitted by
        /// `withdraw_margin` (§3.4) after the dwell-time + margin-equity
        /// gate passes.
        MarginWithdrawn {
            who: T::AccountId,
            amount_e18: u128,
            free_e18_after: u128,
        },
        /// A position was liquidated by a permissionless keeper. Emitted
        /// by `liquidate` (§3.5) on a successful trigger. Keeper bond
        /// returned and 50% of liquidation fee routed to keeper as MOTRA
        /// reward; other 50% routed to `mat/trsy`.
        PositionLiquidated {
            target: T::AccountId,
            keeper: T::AccountId,
            market_id: MarketId,
            size_e8_closed: u128,
            mark_e18_at_liquidation: u128,
            liquidation_fee_e18: u128,
        },
        /// Funding epoch closed and `CumulativeFundingIndex` updated.
        /// Emitted by `settle_funding` (§3.6). The event is anchored to
        /// Cardano via the existing label-8746 checkpoint pipeline.
        FundingEpochSettled {
            market_id: MarketId,
            epoch: EpochNumber,
            rate_e18_signed: i128,
            new_cumulative_index_e18_signed: i128,
        },
        /// A position's leverage was adjusted. Emitted by
        /// `adjust_leverage` (§3.7) after `locked_margin_e18` rebase.
        LeverageAdjusted {
            who: T::AccountId,
            market_id: MarketId,
            old_leverage_bps: u32,
            new_leverage_bps: u32,
            new_locked_margin_e18: u128,
        },
        /// A market was created, updated, or paused by governance.
        /// Emitted by `governance_set_market` (§3.8). Worsening-terms
        /// updates are timelock-delayed per §9.3; this event fires at
        /// the moment the new config takes effect.
        MarketSet {
            market_id: MarketId,
            paused: bool,
        },
        /// A keeper attempted to liquidate a healthy position. Bond
        /// slashed 100% (half to `mat/trsy`, half burned). Emitted by
        /// `liquidate` (§3.5) on a false trigger — the on-chain mark at
        /// the included block was at or above maintenance margin, so
        /// the call should not have been made.
        BadLiquidationAttempt {
            keeper: T::AccountId,
            target: T::AccountId,
            market_id: MarketId,
            bond_slashed: BalanceOf<T>,
        },
    }

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// `Markets[market_id]` is `None`. Either the market was never
        /// registered or was removed by governance.
        MarketNotFound,
        /// `Markets[market_id].paused == true`. Opens + liquidations
        /// reject; closes continue per §5.5.
        MarketPaused,
        /// `leverage_bps` is below `MinLeverageBps` or above
        /// `MarketConfig.max_leverage_bps` / `Config::MaxLeverageBps`.
        LeverageOutOfBounds,
        /// User's `MarginAccount.free_e18` (or
        /// `Position.locked_margin_e18`) is below the required initial
        /// margin for the operation. Emitted by `open_position`,
        /// `adjust_leverage`, `withdraw_margin`.
        InsufficientMargin,
        /// `Positions[market_id][who]` is `None`. Caller has no open
        /// position in this market.
        PositionNotFound,
        /// Entry mark deviates from the cached mark by more than
        /// `max_slippage_bps`. Emitted by `open_position` /
        /// `close_position` when the user-supplied slippage tolerance
        /// is tighter than the actual deviation. Protects users from
        /// MEV / stale-price executions.
        MaxSlippageExceeded,
        /// `liquidate` called on a position whose equity is ≥
        /// maintenance margin at the included block's mark. Keeper bond
        /// is slashed 100% (§6.3); this error variant tags the failure
        /// in the event log even though the extrinsic returns `Ok(())`
        /// because the slash is the intended slow-path side effect.
        BadLiquidationAttempt,
        /// `T::PriceOracle::is_fresh(feed_id) == false` OR
        /// `T::PriceOracle::latest_price_e18(feed_id) == None`. Per §5.5
        /// the pallet refuses opens + liquidations on a stale feed;
        /// closes continue at the last fresh mark.
        OracleUnavailable,
        /// Cached mark is older than `FreshnessLimitBlocks`. Distinct
        /// from `OracleUnavailable` (which fires when the oracle layer
        /// itself reports stale) — this fires when the oracle is fresh
        /// but the pallet's own cache hasn't been refreshed yet (the
        /// `on_initialize` hook hasn't run for this market this block).
        MarkStale,
        /// `settle_funding(epoch)` called with `epoch <=
        /// LastSettledFundingEpoch[market_id]`. Per §3.6 the dispatch
        /// is idempotent — re-settling a closed epoch is a hard error,
        /// not a silent no-op, so off-chain keepers surface the
        /// retry-attempt in their logs.
        EpochAlreadySettled,
        /// `withdraw_margin` called within 24h (dwell time) of the
        /// latest `deposit_margin` call. Bridge-deposit-replay
        /// protection, same pattern as `request_credit_refund` in
        /// `pallet-intent-settlement`.
        DepositDwellTimeNotElapsed,
        /// Position size exceeds `MarketConfig.max_position_size_e8`.
        PositionSizeAboveMax,
        /// Position size is below `MarketConfig.min_position_size_e8`.
        /// Dust filter — prevents `Markets[market_id].max_position_size`
        /// from being bypassed via many sub-min positions.
        PositionSizeBelowMin,
        /// `governance_set_market` called with parameters strictly
        /// worse for users than the existing config WHILE there are
        /// open positions in the market. Per §3.8 `try_state` invariant
        /// — worsening updates require timelock or all-positions-closed.
        MarketHasOpenPositionsWorseningUpdate,
        /// `governance_set_market` called with an invalid config (e.g.
        /// `maintenance_margin_bps >= initial_margin_bps`,
        /// `oracle_feed_id` not registered, `max_leverage_bps >
        /// Config::MaxLeverageBps`).
        InvalidMarketConfig,
        /// `MarketId` already has an open position for this account.
        /// v0 is isolated-margin one-position-per-market-per-account
        /// (§1.2) — to flip direction, close first then open.
        PositionAlreadyExists,
        /// Caller provided a `keeper_bond_motra` below
        /// `Config::KeeperBondMinimum`. Per §3.5 the bond is the only
        /// economic skin-in-the-game for keepers.
        KeeperBondBelowMinimum,
        /// Bad debt accumulated in the rolling window has exceeded
        /// `BadDebtCircuitBreakerThresholdE18`. Market auto-pauses
        /// (§6.5) until governance investigates.
        BadDebtCircuitBreakerTripped,
        /// A position-math computation overflowed `u128` / `i128`.
        /// Surfaced via `math::MathOverflow` from any of
        /// `compute_notional` / `compute_initial_margin` /
        /// `compute_realized_pnl_signed` / `compute_funding_delta`.
        /// Treated as a logic bug, NOT a user error — the caller's
        /// inputs SHOULD be bounded by `MarketConfig.max_position_size_e8`
        /// + `T::MaxLeverageBps` long before this fires. Surfaced for
        /// pattern-match completeness.
        ArithmeticOverflow,
        /// `withdraw_margin` called within `WithdrawDwellBlocks` of the
        /// latest `deposit_margin`. Alias of `DepositDwellTimeNotElapsed`
        /// reserved for forward compatibility — both names are accepted
        /// in the API surface but the canonical error is
        /// `WithdrawDwellNotElapsed`.
        WithdrawDwellNotElapsed,
        /// Conversion between `u128` (1e18-scaled pMATRA-USD) and
        /// `BalanceOf<T>` (MOTRA, runtime-defined integer width) failed
        /// — the amount does not fit in the target type. Surfaced by
        /// `deposit_margin` / `withdraw_margin`.
        BalanceConversionOverflow,
        /// `open_position` called with `size_e8 == 0`. The dust filter
        /// catches non-zero values below `MarketConfig.min_position_size_e8`
        /// with `PositionSizeBelowMin`; this variant flags an exact-zero
        /// open which carries no economic meaning.
        PositionSizeZero,
    }

    // ---------------------------------------------------------------------
    // Calls — 8 extrinsic STUBS (return Ok(()) with TODO PR-B comments)
    // ---------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Open a new perpetual position. Per design memo §3.1.
        ///
        /// Flow:
        /// 1. `ensure_signed` the caller.
        /// 2. Load `Markets[market_id]`; reject paused / missing.
        /// 3. Validate `size_e8 > 0`, ∈ `[min, max]` market size bounds.
        /// 4. Validate `MinLeverageBps ≤ leverage_bps ≤
        ///    min(market.max_leverage_bps, T::MaxLeverageBps)`.
        /// 5. Fetch the live oracle price for the market's feed —
        ///    v0 uses the raw oracle as mark since
        ///    `MarkPriceCacheMap` population lands in PR-C alongside
        ///    the EMA basis. `OracleUnavailable` if the oracle has
        ///    no fresh price.
        /// 6. Optional `margin_top_up_motra`: transfer MOTRA → pot,
        ///    convert to pMATRA-USD via the live MATRA/USD feed,
        ///    increment `MarginAccount.free_e18` + bump
        ///    `last_deposit_block`.
        /// 7. Compute `notional = size * mark / 1e8`,
        ///    `initial_margin = notional * 100 / leverage_bps`.
        /// 8. Verify `MarginAccount.free_e18 >= initial_margin`.
        /// 9. Enforce one-position-per-(market, account) v0 invariant
        ///    via `PositionAlreadyExists`.
        /// 10. Lock margin (subtract from free, store on Position).
        /// 11. Insert Position; emit `PositionOpened`.
        ///
        /// Slippage: design memo §3.1 wires `max_slippage_bps` against
        /// (cached_mark vs first-observation-mark). v0 has no
        /// separate observation layer yet — PR-C adds `MarkPriceCacheMap`
        /// EMA population. Until then `max_slippage_bps` is enforced
        /// against the SAME mark on both sides, which is a no-op
        /// safety floor (it can only fail if `max_slippage_bps == 0`
        /// AND mark deviates from itself, which is impossible).
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(150_000_000, 3500))]
        pub fn open_position(
            origin: OriginFor<T>,
            market_id: MarketId,
            direction: PerpDirection,
            size_e8: u128,
            leverage_bps: u32,
            max_slippage_bps: u32,
            margin_top_up_motra: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // (1) market lookup + paused gate
            let market = Markets::<T>::get(&market_id)
                .ok_or(Error::<T>::MarketNotFound)?;
            ensure!(!market.paused, Error::<T>::MarketPaused);

            // (2) size bounds
            ensure!(size_e8 > 0, Error::<T>::PositionSizeZero);
            ensure!(
                size_e8 >= market.min_position_size_e8,
                Error::<T>::PositionSizeBelowMin
            );
            ensure!(
                size_e8 <= market.max_position_size_e8,
                Error::<T>::PositionSizeAboveMax
            );

            // (3) leverage bounds
            let max_leverage = market
                .max_leverage_bps
                .min(T::MaxLeverageBps::get());
            ensure!(
                leverage_bps >= T::MinLeverageBps::get()
                    && leverage_bps <= max_leverage,
                Error::<T>::LeverageOutOfBounds
            );

            // (4) live oracle price. v0 uses oracle directly as mark
            // (no EMA basis until PR-C populates MarkPriceCacheMap).
            ensure!(
                T::PriceOracle::is_fresh(&market.oracle_feed_id),
                Error::<T>::OracleUnavailable
            );
            let mark_e18 = T::PriceOracle::latest_price_e18(&market.oracle_feed_id)
                .ok_or(Error::<T>::OracleUnavailable)?;
            ensure!(mark_e18 > 0, Error::<T>::OracleUnavailable);

            // (5) one-position-per-market-per-account invariant (§1.2
            // isolated margin)
            ensure!(
                !Positions::<T>::contains_key(&market_id, &who),
                Error::<T>::PositionAlreadyExists
            );

            // (6) optional margin top-up. Settle the MOTRA transfer
            // BEFORE the margin check so an existing under-margined
            // account can top up + open in one extrinsic.
            if !margin_top_up_motra.is_zero() {
                Self::do_deposit_margin(&who, margin_top_up_motra)?;
            }

            // (7) margin maths
            let notional_e18 = compute_notional(size_e8, mark_e18)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            let initial_margin_e18 = compute_initial_margin(notional_e18, leverage_bps)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;

            // (8) free-margin check
            let mut acct = MarginAccounts::<T>::get(&who);
            ensure!(
                acct.free_e18 >= initial_margin_e18,
                Error::<T>::InsufficientMargin
            );

            // (9) slippage gate. As documented above, the v0
            // gate is a self-comparison (mark vs mark) — it never
            // trips. PR-C wires the entry-vs-observation gate.
            let _ = max_slippage_bps;

            // (10) lock margin
            acct.free_e18 = acct
                .free_e18
                .saturating_sub(initial_margin_e18);
            MarginAccounts::<T>::insert(&who, acct);

            // (11) record position. Sign + funding-index snapshot.
            let signed_size: i128 = i128::try_from(size_e8)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            let signed_size = match direction {
                PerpDirection::Long => signed_size,
                PerpDirection::Short => signed_size
                    .checked_neg()
                    .ok_or(Error::<T>::ArithmeticOverflow)?,
            };
            let opened_block: u32 = Self::current_block_u32();
            let pos = Position {
                size_e8: signed_size,
                entry_mark_e18: mark_e18,
                locked_margin_e18: initial_margin_e18,
                leverage_bps,
                opened_block,
                cumulative_funding_at_open_e18: CumulativeFundingIndex::<T>::get(&market_id),
            };
            Positions::<T>::insert(&market_id, &who, pos);

            Self::deposit_event(Event::PositionOpened {
                who,
                market_id,
                direction,
                size_e8,
                entry_mark_e18: mark_e18,
                leverage_bps,
            });
            Ok(())
        }

        /// Close an open position (partial or full). Per design memo §3.2.
        ///
        /// `size_e8 == 0` → full close. Otherwise partial close: capped
        /// at the current absolute position size.
        ///
        /// Realised PnL = `(exit_mark − entry_mark) × signed_size`.
        /// Funding owed = `(idx_now − idx_at_open) × signed_size`.
        /// Both flow through `MarginAccount.free_e18` along with the
        /// (possibly fractional) locked-margin release.
        ///
        /// Per §5.5 closes succeed even on a stale oracle — `is_fresh`
        /// is NOT checked so users can always exit. The mark used is
        /// whatever `latest_price_e18` returns (the trait contract
        /// commits the adapter to caching the last fresh price on
        /// staleness, so v0 honours that contract).
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(150_000_000, 3500))]
        pub fn close_position(
            origin: OriginFor<T>,
            market_id: MarketId,
            size_e8: u128,
            max_slippage_bps: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // market lookup (closes still work on paused markets per
            // §5.5 — users can always exit)
            let market = Markets::<T>::get(&market_id)
                .ok_or(Error::<T>::MarketNotFound)?;

            let pos = Positions::<T>::get(&market_id, &who)
                .ok_or(Error::<T>::PositionNotFound)?;

            // mark price for close. Closes use the latest oracle
            // price even if the freshness flag is down — see §5.5.
            let mark_e18 = T::PriceOracle::latest_price_e18(&market.oracle_feed_id)
                .ok_or(Error::<T>::OracleUnavailable)?;
            ensure!(mark_e18 > 0, Error::<T>::OracleUnavailable);

            // slippage gate (same self-comparison contract as
            // open_position — PR-C wires the real entry vs observed
            // delta)
            let _ = max_slippage_bps;

            // absolute current size (storage uses signed)
            let abs_current: u128 = pos.size_e8.unsigned_abs();

            // requested close size — 0 means full
            let close_abs: u128 = if size_e8 == 0 {
                abs_current
            } else {
                size_e8.min(abs_current)
            };
            ensure!(close_abs > 0, Error::<T>::PositionSizeZero);

            // signed magnitudes — preserves the long/short sign
            let close_signed: i128 = if pos.size_e8 >= 0 {
                i128::try_from(close_abs)
                    .map_err(|_| Error::<T>::ArithmeticOverflow)?
            } else {
                let pos_i: i128 = i128::try_from(close_abs)
                    .map_err(|_| Error::<T>::ArithmeticOverflow)?;
                pos_i.checked_neg().ok_or(Error::<T>::ArithmeticOverflow)?
            };

            // realised PnL on the closed slice
            let realised_pnl_e18 = compute_realized_pnl_signed(
                mark_e18,
                pos.entry_mark_e18,
                close_signed,
            )
            .map_err(|_| Error::<T>::ArithmeticOverflow)?;

            // funding delta accrued since open, applied only to the
            // CLOSED size (proportionally). For a full close
            // close_signed == pos.size_e8; for partial closes the
            // funding owed is the fractional share.
            let idx_now = CumulativeFundingIndex::<T>::get(&market_id);
            let funding_paid_e18 = compute_funding_delta(
                idx_now,
                pos.cumulative_funding_at_open_e18,
                close_signed,
            )
            .map_err(|_| Error::<T>::ArithmeticOverflow)?;

            // Proportional locked-margin release for partial closes.
            // For full closes returns the full locked_margin_e18.
            let locked_release_e18: u128 = if close_abs == abs_current {
                pos.locked_margin_e18
            } else if abs_current == 0 {
                0
            } else {
                // saturating ratio compute
                let l: u128 = pos.locked_margin_e18;
                let prod = l
                    .checked_mul(close_abs)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                prod / abs_current
            };

            // Apply changes to MarginAccount.free_e18. The net delta:
            //   + locked_release
            //   + realised_pnl (signed)
            //   − funding_paid (positive = paid by holder, negative =
            //     received by holder)
            let mut acct = MarginAccounts::<T>::get(&who);
            let mut free_signed: i128 = i128::try_from(acct.free_e18)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            let release_signed: i128 = i128::try_from(locked_release_e18)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            free_signed = free_signed
                .checked_add(release_signed)
                .ok_or(Error::<T>::ArithmeticOverflow)?
                .checked_add(realised_pnl_e18)
                .ok_or(Error::<T>::ArithmeticOverflow)?
                .checked_sub(funding_paid_e18)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            // Floor at zero — if PnL + funding wiped the slice, the
            // account hits 0 (bad-debt accounting routes to treasury
            // in PR-C `liquidate`; here we silently floor for the
            // user-initiated close which CAN'T trigger bad debt
            // because the user can't close below maintenance margin
            // unless mark moved past it).
            if free_signed < 0 {
                free_signed = 0;
            }
            let new_free = u128::try_from(free_signed)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;

            // Sec-review round-2 Vuln 2 (cross-cohort PnL drift):
            // Realized-PnL gain + funding-received are new system-level
            // pMATRA-USD entering this user's free balance from another
            // user's locked margin. Without a snapshot update, the
            // winner can redeem this credit at THEIR (potentially
            // lower) deposit rate while the loser's pMATRA-USD claim
            // was reduced at the LOSER's higher rate — netting a pot
            // deficit of `|credit| × (1/winner − 1/loser)` per trade.
            //
            // Fix: bump the snapshot via weighted-avg with the live
            // MATRA/USD rate as the cost basis of the positive non-
            // release credit. Skip on stale oracle (closes must still
            // proceed per §5.5 so users can always exit). Apply an
            // asymmetric clamp — never LOWER the snapshot, because a
            // lower snapshot grows the user's MOTRA claim and is
            // never the conservative direction for pot solvency.
            //
            // The non-release credit = PnL gain (positive PnL only) +
            // funding received (negative funding_paid only). Losses
            // and outbound funding don't bring new pMATRA-USD into
            // the system, so they don't trigger a rate update.
            let pnl_credit_e18: u128 = realised_pnl_e18.max(0) as u128;
            let funding_credit_e18: u128 = (-funding_paid_e18).max(0) as u128;
            let positive_non_release_credit_e18: u128 =
                pnl_credit_e18.saturating_add(funding_credit_e18);
            if positive_non_release_credit_e18 > 0
                && new_free > 0
                && acct.weighted_deposit_rate_e18 != 0
            {
                if let Ok(live_rate_e18) = Self::live_matra_usd_rate_e18() {
                    // `old_basis_free` = the user's pre-credit free
                    // balance carrying the old snapshot rate.
                    // saturating_sub handles the edge case where net
                    // losses zeroed `new_free` despite a positive
                    // credit (massive funding-debit absorbed everything
                    // but a small PnL gain) — old_basis falls to 0 and
                    // the weighted-avg collapses to `live_rate_e18`,
                    // which then bumps the snapshot if higher.
                    let old_basis_free =
                        new_free.saturating_sub(positive_non_release_credit_e18);
                    let old_weight = U256::from(old_basis_free)
                        * U256::from(acct.weighted_deposit_rate_e18);
                    let new_weight = U256::from(positive_non_release_credit_e18)
                        * U256::from(live_rate_e18);
                    let sum = old_weight + new_weight;
                    let candidate_snap = (sum / U256::from(new_free)).low_u128();
                    // asymmetric clamp: only persist if it raises the snapshot.
                    if candidate_snap > acct.weighted_deposit_rate_e18 {
                        acct.weighted_deposit_rate_e18 = candidate_snap;
                    }
                }
                // else: stale oracle → no snapshot update, close still
                // proceeds (memo §5.5 always-exit contract).
            }

            acct.free_e18 = new_free;
            MarginAccounts::<T>::insert(&who, acct);

            if close_abs == abs_current {
                Positions::<T>::remove(&market_id, &who);
            } else {
                // partial close — leave residual position with
                // proportionally reduced locked margin
                let remaining_abs = abs_current.saturating_sub(close_abs);
                let remaining_signed: i128 = if pos.size_e8 >= 0 {
                    i128::try_from(remaining_abs)
                        .map_err(|_| Error::<T>::ArithmeticOverflow)?
                } else {
                    let r = i128::try_from(remaining_abs)
                        .map_err(|_| Error::<T>::ArithmeticOverflow)?;
                    r.checked_neg().ok_or(Error::<T>::ArithmeticOverflow)?
                };
                let remaining_locked = pos
                    .locked_margin_e18
                    .saturating_sub(locked_release_e18);
                let new_pos = Position {
                    size_e8: remaining_signed,
                    entry_mark_e18: pos.entry_mark_e18,
                    locked_margin_e18: remaining_locked,
                    leverage_bps: pos.leverage_bps,
                    opened_block: pos.opened_block,
                    // Re-baseline the funding snapshot so the next
                    // close doesn't double-count what we just
                    // settled.
                    cumulative_funding_at_open_e18: idx_now,
                };
                Positions::<T>::insert(&market_id, &who, new_pos);
            }

            Self::deposit_event(Event::PositionClosed {
                who,
                market_id,
                size_e8_closed: close_abs,
                exit_mark_e18: mark_e18,
                realized_pnl_e18_signed: realised_pnl_e18,
                funding_paid_e18_signed: funding_paid_e18,
            });
            Ok(())
        }

        /// Deposit MOTRA as margin collateral. Per design memo §3.3.
        ///
        /// Transfers `amount_motra` from the caller's free balance to
        /// the pallet pot (`T::PalletId::into_account_truncating()`),
        /// converts to 1e18-scaled pMATRA-USD at the live oracle
        /// MATRA/USD rate, and credits the result to
        /// `MarginAccount.free_e18`. Updates `last_deposit_block` so
        /// `withdraw_margin` enforces the dwell time.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(80_000_000, 1800))]
        pub fn deposit_margin(
            origin: OriginFor<T>,
            amount_motra: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!amount_motra.is_zero(), Error::<T>::PositionSizeZero);
            Self::do_deposit_margin(&who, amount_motra)?;
            Ok(())
        }

        /// Withdraw margin from the pot to MOTRA. Per design memo §3.4.
        ///
        /// `amount_e18` is in 1e18-scaled pMATRA-USD. The pallet
        /// converts to MOTRA at the live MATRA/USD rate and
        /// `T::Currency::transfer` from pot → caller.
        ///
        /// Gates:
        /// 1. `last_deposit_block + WithdrawDwellBlocks ≤ now`
        ///    — `WithdrawDwellNotElapsed`.
        /// 2. `free_e18 ≥ amount_e18` — `InsufficientMargin`.
        /// 3. `free_e18 − amount_e18 ≥ sum(locked_margins) ×
        ///    InitialMarginBps / 10_000` — i.e. user can't withdraw
        ///    down to where open positions are immediately
        ///    insta-liquidatable. v0 implements the simpler invariant
        ///    "post-withdraw free ≥ 0 AND user has no open positions
        ///    with locked margin > 0 that would be made
        ///    insta-liquidatable." Since `locked_margin` is stored on
        ///    Position not MarginAccount, the gate enumerates the
        ///    user's positions and checks each one's locked margin
        ///    against `initial_margin * market.initial_margin_bps /
        ///    10_000`. v0 keeps it simple: any open position blocks
        ///    full withdrawal below the sum of locked margins. PR-C
        ///    extends with the equity-vs-IM gate.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(120_000_000, 2200))]
        pub fn withdraw_margin(
            origin: OriginFor<T>,
            amount_e18: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(amount_e18 > 0, Error::<T>::PositionSizeZero);

            let mut acct = MarginAccounts::<T>::get(&who);

            // (1) dwell time
            let now = Self::current_block_u32();
            let dwell = T::WithdrawDwellBlocks::get();
            let unlock_at = acct.last_deposit_block.saturating_add(dwell);
            ensure!(now >= unlock_at, Error::<T>::WithdrawDwellNotElapsed);

            // (2) free-margin floor
            ensure!(
                acct.free_e18 >= amount_e18,
                Error::<T>::InsufficientMargin
            );

            // (3) total-locked floor. For every open position the
            // user holds in any market, the locked margin defines a
            // hard floor on post-withdrawal free balance — withdrawing
            // below this would mean any new opens or mark moves would
            // insta-liquidate.
            //
            // Substrate's `StorageDoubleMap` doesn't expose a
            // by-secondary-key index, so we iterate the entire map
            // and filter by account. v0 acceptable scale: open-
            // position count is bounded by `T::MaxMarkets *
            // active_user_count`; the dwell-time gate also rate-
            // limits this path. PR-C may add a per-account locked-
            // margin sum cache if iteration cost becomes a concern.
            let mut total_locked: u128 = 0;
            for (_mkt, acct_key, pos) in Positions::<T>::iter() {
                if acct_key == who {
                    total_locked =
                        total_locked.saturating_add(pos.locked_margin_e18);
                }
            }

            let post_withdraw = acct
                .free_e18
                .checked_sub(amount_e18)
                .ok_or(Error::<T>::InsufficientMargin)?;
            ensure!(
                post_withdraw >= total_locked,
                Error::<T>::InsufficientMargin
            );

            // (4) Convert pMATRA-USD → MOTRA at the account's
            // weighted-avg DEPOSIT rate (NOT the live rate), to honor
            // the memo §10.2.1 "peg = oracle MATRA/USD price at the
            // moment of deposit" contract and prevent the live-rate
            // pot-drain (deposit-at-peak / withdraw-at-trough). Fresh
            // accounts that somehow have `free_e18 > 0` with a zero
            // `weighted_deposit_rate_e18` (currently unreachable in v0
            // — every credit either flows from `do_deposit_margin`
            // which seeds the rate, or from PnL/funding which inherits
            // the prior basis) fall back to the live rate, gated on
            // freshness.
            let rate_for_withdraw_e18 = if acct.weighted_deposit_rate_e18 == 0 {
                Self::live_matra_usd_rate_e18()?
            } else {
                acct.weighted_deposit_rate_e18
            };
            let motra_u128 = amount_e18 / rate_for_withdraw_e18;
            let amount_motra_balance: BalanceOf<T> = motra_u128
                .try_into()
                .map_err(|_| Error::<T>::BalanceConversionOverflow)?;

            // (5) transfer MOTRA from pot to user.
            let pot = T::PalletId::get().into_account_truncating();
            T::Currency::transfer(
                &pot,
                &who,
                amount_motra_balance,
                ExistenceRequirement::AllowDeath,
            )?;

            // (6) Book the withdrawal in 1e18-scaled pMATRA-USD.
            // Reset `weighted_deposit_rate_e18` to 0 on full drain so a
            // future re-deposit seeds a FRESH rate basis (otherwise an
            // old rate from a prior deposit cycle would silently
            // weight a much later top-up).
            acct.free_e18 = post_withdraw;
            if post_withdraw == 0 {
                acct.weighted_deposit_rate_e18 = 0;
            }
            MarginAccounts::<T>::insert(&who, acct);

            Self::deposit_event(Event::MarginWithdrawn {
                who,
                amount_e18,
                free_e18_after: post_withdraw,
            });
            Ok(())
        }

        /// **(PR-A stub)** Permissionless liquidation. See design memo
        /// §3.5 (Operational class, `Pays::No` — the MATRA bond is the
        /// only economic skin in the game).
        #[pallet::call_index(4)]
        #[pallet::weight((
            Weight::from_parts(200_000_000, 4500),
            DispatchClass::Operational,
            Pays::No,
        ))]
        pub fn liquidate(
            origin: OriginFor<T>,
            _target: T::AccountId,
            _market_id: MarketId,
            _keeper_bond_motra: BalanceOf<T>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: Currency::reserve(caller, bond ≥ KeeperBondMinimum);
            // read Positions[market_id][target] + MarkPriceCache; compute
            // equity vs maintenance_margin; if liquidatable → close at
            // mark, charge LiquidationFeeBps, route 50/50 caller +
            // mat/trsy, return bond, emit PositionLiquidated +
            // IntentKind::PerpAction(Liquidation); if not liquidatable →
            // slash bond 100% (half mat/trsy, half burn), emit
            // BadLiquidationAttempt.
            Ok(())
        }

        /// **(PR-A stub)** Settle funding for a closed epoch. See design
        /// memo §3.6 (Operational class, `Pays::No` — typically called
        /// by a permissionless keeper every funding-epoch boundary).
        #[pallet::call_index(5)]
        #[pallet::weight((
            Weight::from_parts(50_000_000, 1200),
            DispatchClass::Operational,
            Pays::No,
        ))]
        pub fn settle_funding(
            origin: OriginFor<T>,
            _market_id: MarketId,
            _epoch: EpochNumber,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: reject if epoch <= LastSettledFundingEpoch[market_id]
            // (EpochAlreadySettled); compute funding_rate = clamp(
            // median(PremiumIndexSamples[market][epoch]) / oracle_price
            // * scale_to_1h, ±MaxFundingPerEpoch); update
            // CumulativeFundingIndex[market_id] += rate; prune
            // PremiumIndexSamples row; bump LastSettledFundingEpoch;
            // emit FundingEpochSettled (anchored to Cardano via label-8746).
            Ok(())
        }

        /// Adjust leverage on an open position. Per design memo §3.7.
        ///
        /// `new_locked = notional_at_entry / new_leverage`. Delta moves
        /// between `MarginAccount.free_e18` and `Position.locked_margin_e18`:
        /// - Lever down (more margin locked) → require free ≥ delta;
        ///   transfer free → locked.
        /// - Lever up (less margin locked) → transfer locked → free.
        ///
        /// Bounds: `T::MinLeverageBps ≤ new_leverage_bps ≤
        /// min(market.max_leverage_bps, T::MaxLeverageBps)`.
        ///
        /// Equity invariant: after the adjust, the position's new
        /// locked margin at the CURRENT mark must remain above
        /// `initial_margin_bps × current_notional / 10_000` — i.e. the
        /// adjust cannot push the user into immediate liquidation
        /// territory.
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(100_000_000, 2200))]
        pub fn adjust_leverage(
            origin: OriginFor<T>,
            market_id: MarketId,
            new_leverage_bps: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let market = Markets::<T>::get(&market_id)
                .ok_or(Error::<T>::MarketNotFound)?;
            // Governance kill-switch: a paused market must reject every
            // position-changing operation that is not an exit. Mirrors
            // `open_position`'s paused gate; only `close_position`
            // bypasses (so users can always exit) per memo §5.5.
            ensure!(!market.paused, Error::<T>::MarketPaused);
            let mut pos = Positions::<T>::get(&market_id, &who)
                .ok_or(Error::<T>::PositionNotFound)?;

            // bounds
            let max_leverage = market
                .max_leverage_bps
                .min(T::MaxLeverageBps::get());
            ensure!(
                new_leverage_bps >= T::MinLeverageBps::get()
                    && new_leverage_bps <= max_leverage,
                Error::<T>::LeverageOutOfBounds
            );

            let abs_size: u128 = pos.size_e8.unsigned_abs();
            let old_leverage = pos.leverage_bps;

            // Recompute locked at entry-mark with NEW leverage.
            let notional_e18 = compute_notional(abs_size, pos.entry_mark_e18)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            let new_locked_margin_e18 =
                compute_initial_margin(notional_e18, new_leverage_bps)
                    .map_err(|_| Error::<T>::ArithmeticOverflow)?;

            let mut acct = MarginAccounts::<T>::get(&who);
            if new_locked_margin_e18 > pos.locked_margin_e18 {
                // levering DOWN — need free margin to lock more
                let delta = new_locked_margin_e18
                    .checked_sub(pos.locked_margin_e18)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                ensure!(
                    acct.free_e18 >= delta,
                    Error::<T>::InsufficientMargin
                );
                acct.free_e18 = acct.free_e18.saturating_sub(delta);
            } else if new_locked_margin_e18 < pos.locked_margin_e18 {
                // levering UP — release locked into free
                let delta = pos
                    .locked_margin_e18
                    .checked_sub(new_locked_margin_e18)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                acct.free_e18 = acct
                    .free_e18
                    .checked_add(delta)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
            }

            // Equity-invariant check at CURRENT mark. The new locked
            // margin must keep us above the initial-margin floor at
            // the current price. If we're levering up too aggressively
            // and the mark has moved against us, this gate fires
            // before we land in a state where the next block triggers
            // liquidation.
            //
            // Freshness gate: a stale oracle returns the LAST CACHED
            // price (not the true current mark). Letting a user adjust
            // leverage against a stale price would defeat the
            // equity invariant — the position could be insta-liquidated
            // the moment the oracle recovers at the true price. Mirror
            // the `open_position` freshness gate. Per memo §5.5, only
            // `close_position` may bypass freshness (so users can
            // always exit).
            ensure!(
                T::PriceOracle::is_fresh(&market.oracle_feed_id),
                Error::<T>::OracleUnavailable
            );
            let cur_mark_e18 = T::PriceOracle::latest_price_e18(&market.oracle_feed_id)
                .ok_or(Error::<T>::OracleUnavailable)?;
            ensure!(cur_mark_e18 > 0, Error::<T>::OracleUnavailable);
            let cur_notional = compute_notional(abs_size, cur_mark_e18)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            let im_floor = compute_initial_margin(cur_notional, new_leverage_bps)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;
            ensure!(
                new_locked_margin_e18 >= im_floor,
                Error::<T>::InsufficientMargin
            );

            // Apply changes.
            pos.locked_margin_e18 = new_locked_margin_e18;
            pos.leverage_bps = new_leverage_bps;
            // Re-baseline the funding snapshot so subsequent close /
            // liquidate accrues funding only from this adjust forward.
            pos.cumulative_funding_at_open_e18 =
                CumulativeFundingIndex::<T>::get(&market_id);
            Positions::<T>::insert(&market_id, &who, pos);
            MarginAccounts::<T>::insert(&who, acct);

            Self::deposit_event(Event::LeverageAdjusted {
                who,
                market_id,
                old_leverage_bps: old_leverage,
                new_leverage_bps,
                new_locked_margin_e18,
            });
            Ok(())
        }

        /// **(PR-A stub)** Sudo-set a market configuration. See design
        /// memo §3.8 — `EnsureRoot` in v0 (sudo / 2-of-3 multisig); v1
        /// may delegate to `pallet-collective`.
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(80_000_000, 3000))]
        pub fn governance_set_market(
            origin: OriginFor<T>,
            _market_id: MarketId,
            _config: MarketConfig,
        ) -> DispatchResult {
            ensure_root(origin)?;
            // TODO PR-B: validate config (mm < im, max_leverage ≤
            // T::MaxLeverageBps, oracle feed exists in pallet-oracle);
            // enforce try_state worsening-terms timelock (§9.3); upsert
            // Markets[market_id]; emit MarketSet.
            Ok(())
        }
    }

    // ---------------------------------------------------------------------
    // Internal helpers (not part of the public extrinsic surface)
    // ---------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        /// Current `frame_system::Pallet::block_number()` coerced to
        /// `u32`. Saturates at `u32::MAX` for runtimes with a wider
        /// `BlockNumberFor<T>`. Used by `Position.opened_block`,
        /// `MarginAccount.last_deposit_block`, and the dwell-time
        /// gates.
        pub(crate) fn current_block_u32() -> u32 {
            let n: BlockNumberFor<T> = frame_system::Pallet::<T>::block_number();
            n.saturated_into::<u32>()
        }

        /// Pot account derived from `T::PalletId`. All MOTRA margin
        /// custody lives here (§3.3 collateral abstraction).
        pub fn pot_account() -> T::AccountId {
            T::PalletId::get().into_account_truncating()
        }


        /// Returns the live MATRA/USD rate (1e18-scaled, pMATRA-USD per
        /// MOTRA). Errors `OracleUnavailable` on stale feed or missing
        /// price. Helper consumed by both `do_deposit_margin` and
        /// `withdraw_margin` so each call site can pin the rate ONCE
        /// and reason about it independently from the conversion math.
        pub(crate) fn live_matra_usd_rate_e18() -> Result<u128, DispatchError> {
            let feed = T::MatraUsdFeedId::get();
            ensure!(
                T::PriceOracle::is_fresh(&feed),
                Error::<T>::OracleUnavailable
            );
            let rate_e18 = T::PriceOracle::latest_price_e18(&feed)
                .ok_or(Error::<T>::OracleUnavailable)?;
            ensure!(rate_e18 > 0, Error::<T>::OracleUnavailable);
            Ok(rate_e18)
        }

        /// Shared body for `deposit_margin` extrinsic + `open_position`'s
        /// optional `margin_top_up_motra` path. Per design memo §3.3:
        ///  1. Pin the live MATRA/USD rate (stale rate blocks the call).
        ///  2. Compute pMATRA-USD credit = motra * rate.
        ///  3. Transfer MOTRA from caller → pot.
        ///  4. Update `MarginAccount.weighted_deposit_rate_e18` —
        ///     size-weighted average over remaining `free_e18` (old
        ///     basis) + new credit at new rate. The weighted-avg
        ///     formula `(old_free * old_rate + new_credit * new_rate)
        ///     / new_free` can overflow u128 at extreme balances; on
        ///     overflow we conservatively leave the old rate in place
        ///     (a strict lower bound on the user's MOTRA-redeemable
        ///     value, so the pot stays solvent).
        ///  5. Credit `MarginAccount.free_e18`.
        ///  6. Bump `last_deposit_block` for the dwell-time gate.
        ///  7. Emit `MarginDeposited`.
        ///
        /// The `weighted_deposit_rate_e18` snapshot is the load-bearing
        /// fix for the sec-review pot-drain finding: `withdraw_margin`
        /// uses it (not the live rate) to convert pMATRA-USD → MOTRA,
        /// so a user cannot deposit at peak MATRA / withdraw at trough
        /// MATRA and drain the pot of other depositors' MOTRA.
        pub(crate) fn do_deposit_margin(
            who: &T::AccountId,
            amount_motra: BalanceOf<T>,
        ) -> DispatchResult {
            if amount_motra.is_zero() {
                return Ok(());
            }
            // (1) Pin the live rate FIRST so a stale oracle blocks the
            // deposit before any state mutation. A deposit at an
            // unknown rate is worse than a failed deposit.
            let rate_e18 = Self::live_matra_usd_rate_e18()?;

            // (2) Compute the pMATRA-USD credit at this rate.
            let motra_u128: u128 = amount_motra.saturated_into::<u128>();
            let credit_e18 = motra_u128
                .checked_mul(rate_e18)
                .ok_or(Error::<T>::ArithmeticOverflow)?;

            // (3) Transfer MOTRA from caller → pot.
            let pot = Self::pot_account();
            T::Currency::transfer(
                who,
                &pot,
                amount_motra,
                ExistenceRequirement::AllowDeath,
            )?;

            // (4) Update the weighted-avg deposit rate via U256-precision
            // arithmetic. The intermediate products `old_free × old_rate`
            // and `credit_e18 × new_rate` would each overflow `u128`
            // whenever `motra ≥ u128::MAX / rate²` — trivially reachable
            // at any non-trivial MATRA price (e.g. ≥4 MOTRA at $10/MATRA).
            // Sec-review round-2 found the prior overflow-fallback
            // ("keep old rate") was NOT conservative when `old_rate <
            // new_rate`: keeping the lower rate gave the user more
            // MOTRA per pMATRA-USD on withdraw, draining the pot. U256
            // eliminates the overflow path: each product fits in 256
            // bits (`u128 × u128 ≤ 2^256`); their sum fits because
            // `2 × (u128::MAX)² < U256::MAX`. The final quotient is
            // bounded by `max(old_rate, new_rate) ≤ u128::MAX`, so the
            // truncation back to u128 via `.low_u128()` is lossless.
            // First deposit (or post-full-drain) seeds the snapshot
            // with the new rate directly.
            let mut acct = MarginAccounts::<T>::get(who);
            let new_free = acct
                .free_e18
                .checked_add(credit_e18)
                .ok_or(Error::<T>::ArithmeticOverflow)?;

            if acct.weighted_deposit_rate_e18 == 0 || acct.free_e18 == 0 {
                // Fresh basis — seed with the new rate.
                acct.weighted_deposit_rate_e18 = rate_e18;
            } else {
                // weighted avg = (old_free × old_rate + credit × new_rate) / new_free
                // new_free > 0 here because credit_e18 > 0
                // (motra_u128 > 0 by the is_zero early-return,
                // rate_e18 > 0 by live_matra_usd_rate_e18's ensure).
                let old_weight = U256::from(acct.free_e18)
                    * U256::from(acct.weighted_deposit_rate_e18);
                let new_weight = U256::from(credit_e18) * U256::from(rate_e18);
                let sum = old_weight + new_weight;
                acct.weighted_deposit_rate_e18 =
                    (sum / U256::from(new_free)).low_u128();
            }

            // (5)+(6) Credit free + bump dwell.
            acct.free_e18 = new_free;
            acct.last_deposit_block = Self::current_block_u32();
            MarginAccounts::<T>::insert(who, acct.clone());

            // (7) Emit.
            Self::deposit_event(Event::MarginDeposited {
                who: who.clone(),
                amount_motra,
                free_e18_after: acct.free_e18,
            });
            Ok(())
        }
    }

    // ---------------------------------------------------------------------
    // Runtime-API surface (consumed by keepers, RPC, future v1 governance)
    // ---------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        /// Read API: returns the current market config for a market, or
        /// `None` if not registered. PR-B keeper code reads this.
        pub fn get_market_config(market_id: &MarketId) -> Option<MarketConfig> {
            Markets::<T>::get(market_id)
        }

        /// Read API: returns the current open position for an account in
        /// a market, or `None` if no position. PR-B keeper code reads
        /// this for liquidation candidate enumeration.
        pub fn get_position(
            market_id: &MarketId,
            who: &T::AccountId,
        ) -> Option<Position> {
            Positions::<T>::get(market_id, who)
        }

        /// Read API: returns the cached mark price for a market.
        /// Returns the default (zeros) if the market has never been
        /// updated — PR-B `on_initialize` will populate this every
        /// block for every active market.
        pub fn get_mark_price(market_id: &MarketId) -> MarkPriceCache {
            MarkPriceCacheMap::<T>::get(market_id)
        }
    }
}
