//! # `pallet-perp-engine` — Materios Perp Engine v0 scaffolding
//!
//! Task #259. Design memo:
//! `/home/deci/work/perp-engine-v0-spec.md` (720 lines, locked).
//!
//! ## Scope of this skeleton (PR-A)
//!
//! What ships as **real impl** (this PR):
//! - The full type surface — [`types::MarketConfig`], [`types::Position`],
//!   [`types::MarginAccount`], [`types::MarkPriceCache`],
//!   [`types::PerpDirection`], [`types::PerpActionKind`],
//!   [`types::MarketId`].
//! - The pallet `Config` / `Event` / `Error` / `Storage` shape pinned for
//!   PR-B, including the `PriceOracle` Config-trait abstraction so the
//!   impl PR can wire `pallet-oracle::Pallet` adapter without changing
//!   the public surface.
//! - 5 unit tests covering: pallet compiles, genesis state empty, all 8
//!   extrinsics expose their call surface, default constants pinned,
//!   error variants distinct.
//!
//! What ships as **stub** (placeholders for PR-B):
//! - All 8 extrinsics — `open_position`, `close_position`,
//!   `deposit_margin`, `withdraw_margin`, `liquidate`, `settle_funding`,
//!   `adjust_leverage`, `governance_set_market` — return `Ok(())` after
//!   the origin gate. Every body carries a `TODO PR-B:` one-line
//!   description of the real impl per the design memo.
//!
//! ## Pattern alignment
//!
//! Mirrors `pallet-oracle` (PR #35) scaffolding shape. The same Config-
//! trait abstraction (`PriceOracle` here, `IsAttestorFor` there) keeps
//! the pallet independently composable in test runtimes — a runtime can
//! wire one mock for each.
//!
//! ## What is explicitly NOT in scope for PR-A
//!
//! - No dispatch logic. Every extrinsic returns `Ok(())` after
//!   `ensure_signed` / `ensure_root` so the call surface is exercisable
//!   from the runtime without state mutation.
//! - No `on_initialize` hook implementation. Mark-price update logic
//!   (§5.2) lands in PR-B.
//! - No `try_state` invariant runners. Per §4.6 the
//!   `ReservedKeeperBonds` map MUST be empty at end-of-block; this
//!   invariant lands in PR-B alongside the `liquidate` impl.
//! - No wiring into `materios-runtime`. Per the user's instruction this
//!   is PR-D after PR-B (impl bodies) + PR-C (`IntentKind::PerpAction`
//!   variant on `pallet-intent-settlement`).
//! - No `/security-review`. The scaffold has no real logic to review.
//!
//! ## Multi-PR sequence
//!
//! - **PR-A (this one)**: types + storage + extrinsic stubs.
//! - **PR-B**: extrinsic impl bodies + property tests + bench instances.
//! - **PR-C**: `IntentKind::PerpAction` variant on
//!   `pallet-intent-settlement` (§8.2).
//! - **PR-D**: wire into `materios-runtime` `construct_runtime!`, with
//!   genesis `MarketsPaused = true` kill-switch per §next-steps.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use types::{
    EpochNumber, MarginAccount, MarketConfig, MarketId, MarkPriceCache, OracleFeedId,
    PerpActionKind, PerpDirection, Position, MAX_MARKET_ID_LEN,
};

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency},
        BoundedVec, PalletId,
    };
    use frame_system::pallet_prelude::*;

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

    // `#[pallet::generate_deposit]` is intentionally omitted from this
    // scaffold-only PR — none of the stub bodies emit events yet, and
    // re-adding it without a use site triggers an unused-attribute
    // warning. PR-B re-adds:
    //   `#[pallet::generate_deposit(pub(super) fn deposit_event)]`
    // alongside the first `Self::deposit_event(...)` call site.
    #[pallet::event]
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
        PositionClosed {
            who: T::AccountId,
            market_id: MarketId,
            size_e8_closed: u128,
            exit_mark_e18: u128,
            realized_pnl_e18_signed: i128,
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
    }

    // ---------------------------------------------------------------------
    // Calls — 8 extrinsic STUBS (return Ok(()) with TODO PR-B comments)
    // ---------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// **(PR-A stub)** Open a new perpetual position. See design memo
        /// §3.1 for the full impl contract.
        ///
        /// PR-A behaviour: `ensure_signed`, then `Ok(())`. No state
        /// mutation. The call surface is exercised by the test runtime
        /// so PR-B can drop the real body in without changing the
        /// dispatch signature.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(150_000_000, 3500))]
        pub fn open_position(
            origin: OriginFor<T>,
            _market_id: MarketId,
            _direction: PerpDirection,
            _size_e8: u128,
            _leverage_bps: u32,
            _max_slippage_bps: u32,
            _margin_top_up_motra: BalanceOf<T>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: validate market active, leverage bounds, free
            // margin ≥ initial margin; read mark from MarkPriceCache;
            // record Position at cached mark; reserve margin from
            // MarginAccount.free into Position.locked_margin_e18; emit
            // PositionOpened + IntentKind::PerpAction(Open) intent.
            Ok(())
        }

        /// **(PR-A stub)** Close an open position (partial or full). See
        /// design memo §3.2.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(150_000_000, 3500))]
        pub fn close_position(
            origin: OriginFor<T>,
            _market_id: MarketId,
            _size_e8: u128,
            _max_slippage_bps: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: read Position + MarkPriceCache; compute realized
            // PnL = (exit_mark - entry_mark) * signed_size; apply funding
            // delta from CumulativeFundingIndex; release locked margin +
            // realized PnL into MarginAccount.free; delete Position row
            // if full close; emit PositionClosed + IntentKind::PerpAction(Close).
            Ok(())
        }

        /// **(PR-A stub)** Deposit MOTRA as collateral. See design memo
        /// §3.3.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(80_000_000, 1800))]
        pub fn deposit_margin(
            origin: OriginFor<T>,
            _amount_motra: BalanceOf<T>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: Currency::transfer(who → PalletId::into_account_truncating(),
            // amount); increment MarginAccount.free_e18 at the live oracle
            // MATRA/USD rate; update last_deposit_block; emit MarginDeposited.
            Ok(())
        }

        /// **(PR-A stub)** Withdraw collateral. See design memo §3.4.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(120_000_000, 2200))]
        pub fn withdraw_margin(
            origin: OriginFor<T>,
            _amount_e18: u128,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: enforce free_e18 - amount_e18 ≥ max(initial
            // margin across all open positions); enforce 24h dwell time
            // since last_deposit_block; convert pMATRA-USD → MOTRA at
            // oracle rate; Currency::transfer(PalletId → who); emit
            // MarginWithdrawn.
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

        /// **(PR-A stub)** Adjust leverage on an open position. See
        /// design memo §3.7.
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(100_000_000, 2200))]
        pub fn adjust_leverage(
            origin: OriginFor<T>,
            _market_id: MarketId,
            _new_leverage_bps: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            // TODO PR-B: read Position; recompute locked_margin = (size_e8
            // * entry_mark_e18) / new_leverage_bps; revert if new locked
            // margin pushes equity below initial margin at current mark;
            // re-baseline cumulative_funding_at_open_e18 to current
            // CumulativeFundingIndex; emit LeverageAdjusted +
            // IntentKind::PerpAction(LeverageAdjust).
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
