//! Shared type definitions for `pallet-perp-engine` v0 (task #259).
//!
//! The authoritative reference is the design memo at
//! `/home/deci/work/perp-engine-v0-spec.md` — particularly §3
//! (extrinsic surface) and §4 (storage layout). Every type below is
//! pinned to the memo's exact shape so the impl PR can drop dispatch
//! bodies in without touching the storage layout.
//!
//! ## Cross-pallet parity
//!
//! - `MarketId` is a 16-byte `BoundedVec<u8>` matching the design memo
//!   §4.1 ("e.g. `b\"ADA-PERP/USD\"`"). It is the stable handle used in
//!   events, anchoring metadata, and the new `IntentKind::PerpAction`
//!   variant landing on `pallet-intent-settlement` in a follow-up PR
//!   (per §8.2).
//! - Prices are scaled `1e18` to match `pallet-oracle::PriceFeed.last_price`
//!   when consumed via the `PriceOracle` Config-trait adapter (§5.1).
//! - Sizes are signed `i128` in `1e-8` contract units (§4.2 — "Long = +,
//!   short = −"). Decision recorded in §4.2 against the packed-sign-bit
//!   alternative.

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, BoundedVec};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

pub use parity_scale_codec as codec;

// ---------------------------------------------------------------------------
// Primitive aliases
// ---------------------------------------------------------------------------

/// Maximum length of a `MarketId` byte string. Bounded so storage keys have
/// a deterministic max-encoded length and governance can't grief by
/// registering a 1MB market handle.
///
/// 16 bytes accommodates handles up to and including `b"ETH-PERP/USDC.X"`
/// (15 ASCII chars + a future single-char suffix). Per design memo §4.1
/// the canonical v0 market handles are `b"ADA-PERP/USD"` (12 bytes),
/// `b"BTC-PERP/USD"` (12 bytes), `b"ETH-PERP/USD"` (12 bytes).
pub const MAX_MARKET_ID_LEN: u32 = 16;

/// Stable handle for a perp market. Bounded UTF-8 byte string,
/// governance-controlled — `Identity` hasher in storage maps is safe
/// because user input never lands here directly (§4.1 hasher rationale).
pub type MarketId = BoundedVec<u8, ConstU32<MAX_MARKET_ID_LEN>>;

/// Oracle feed handle, same shape as `MarketId`. Must match a key in
/// `pallet-oracle::PriceFeeds` for the impl PR's price reads to succeed.
/// Per §5.1, perp-engine reads via a `T::PriceOracle: PriceOracle`
/// adapter trait so it stays unit-testable against a mock.
pub type OracleFeedId = BoundedVec<u8, ConstU32<MAX_MARKET_ID_LEN>>;

/// Liquidation epoch / funding epoch number. Bounded `u32` because at
/// 1h epochs that's >490_000 years of headroom; the bench impact of a
/// 64-bit epoch counter on the per-position cumulative-funding storage
/// is wasted entropy.
pub type EpochNumber = u32;

// ---------------------------------------------------------------------------
// PerpDirection — long vs short, exposed in the public `open_position` API
// ---------------------------------------------------------------------------

/// User-facing position direction. The on-chain `Position.size_e8` uses
/// signed `i128` (long = +, short = −); this enum is only at the
/// `open_position` extrinsic boundary so callers don't have to know the
/// sign-bit convention.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub enum PerpDirection {
    /// Bullish: position profits when mark price rises above entry.
    /// `Position.size_e8` is stored as positive.
    Long = 0,
    /// Bearish: position profits when mark price falls below entry.
    /// `Position.size_e8` is stored as negative.
    Short = 1,
}

// ---------------------------------------------------------------------------
// MarketConfig — governance-controlled per-market parameters
// ---------------------------------------------------------------------------

/// Per-market configuration written by `governance_set_market` (§3.8) and
/// read by every position-touching extrinsic. Field semantics + governance
/// ranges are pinned in design memo §9.1 (risk parameters table).
///
/// All `*_bps` fields are basis points (1 bp = 0.01%, 10_000 = 100%).
/// Signed `maker_fee_bps` (`i32`) allows maker REBATES (negative) per
/// the v5.1 tokenomics MM-rebate program (§v0 spec §9.1 "MakerFeeBps").
#[derive(
    Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub struct MarketConfig {
    /// Stable handle for the market. Mirrored from the
    /// `Markets[market_id]` key for self-describing event emission.
    pub id: MarketId,
    /// Linked oracle feed handle. Must match a key in
    /// `pallet-oracle::PriceFeeds` for the impl PR's mark-price reads.
    pub oracle_feed_id: OracleFeedId,
    /// Initial margin requirement in bps. e.g. 1000 = 10% (= 10× leverage).
    pub initial_margin_bps: u32,
    /// Maintenance margin requirement in bps. e.g. 500 = 5%. MUST be
    /// strictly less than `initial_margin_bps` (enforced in impl PR's
    /// `governance_set_market` validation).
    pub maintenance_margin_bps: u32,
    /// Maximum leverage in bps. e.g. 2000 = 20×. The `open_position`
    /// impl rejects `leverage_bps > max_leverage_bps`.
    pub max_leverage_bps: u32,
    /// Per-epoch funding-rate magnitude cap in bps. Default 400 bps =
    /// 4% per hour (matches Hyperliquid per §2 research summary).
    pub max_funding_per_epoch_bps: u32,
    /// Liquidation fee in bps. Default 50 = 0.5% of notional. Split
    /// 50/50 between keeper and `mat/trsy` per §6.2.
    pub liquidation_fee_bps: u32,
    /// Maker fee in bps. Signed because v0 ships with maker REBATE
    /// (negative = pallet pays maker out of MM-rebate budget). Default
    /// -2 bps per §9.1.
    pub maker_fee_bps: i32,
    /// Taker fee in bps. Positive only (no taker rebates). Default 7 bps
    /// per §9.1.
    pub taker_fee_bps: u32,
    /// Notional cap per account per market. e.g. $250k = 250_000_000
    /// (1e6-scaled USD) — exact units defined in impl PR.
    pub max_position_size_e8: u128,
    /// Minimum position size in 1e-8 contract units. Dust filter.
    pub min_position_size_e8: u128,
    /// EMA window in blocks for the mark-price basis. Default 25 blocks
    /// ≈ 150s at 6s block time per §5.2.
    pub mark_ema_window_blocks: u32,
    /// Funding epoch duration in blocks. Default 600 ≈ 1h per §7.2.
    pub funding_epoch_blocks: u32,
    /// Governance kill-switch. When `true`, `open_position` +
    /// `liquidate` fail with `Error::MarketPaused`; `close_position`
    /// continues (users can always exit per §5.5).
    pub paused: bool,
}

// ---------------------------------------------------------------------------
// Position — per-account-per-market open position
// ---------------------------------------------------------------------------

/// A single open perpetual position. One row per `(MarketId, AccountId)`
/// pair per design memo §4.2 isolated-margin model — cross-margin is
/// explicitly deferred to v1 (§1.2).
///
/// PnL math:
/// ```text
/// realized_pnl_e18 = signed_size * (exit_mark_e18 - entry_mark_e18)
/// funding_owed_e18 = signed_size * (CumulativeFundingIndex[market]_now
///                                  - cumulative_funding_at_open_e18)
/// equity_e18 = locked_margin_e18 + realized_pnl_e18 - funding_owed_e18
/// ```
///
/// All sites use `checked_mul` / `saturating_*` per §10.1 risk #3.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub struct Position {
    /// Signed contract size in 1e-8 units. Positive = long, negative =
    /// short. `i128` range is ~1.7e38, so a $1B position at 1e-8 units
    /// (`size_e8 = 1e17`) fits with 21 orders of magnitude of headroom.
    pub size_e8: i128,
    /// Mark price at position open, scaled 1e18. Snapshot of
    /// `MarkPriceCache[market_id].mark_e18` at the open extrinsic's
    /// included block.
    pub entry_mark_e18: u128,
    /// Initial-margin locked at open, in 1e18-scaled pMATRA-USD.
    /// `locked_margin = (size_e8 * entry_mark_e18) / leverage_bps` per
    /// §3.1. Released back to `MarginAccount.free` on close/liquidate.
    pub locked_margin_e18: u128,
    /// User-visible leverage at last `open_position` or
    /// `adjust_leverage`. Recorded for event emission + dashboards;
    /// margin math always derives from `locked_margin_e18` directly.
    pub leverage_bps: u32,
    /// Materios block number at position open. Used for
    /// funding-accrual cross-checks + dwell-time invariants.
    pub opened_block: u32,
    /// Snapshot of `CumulativeFundingIndex[market_id]` at open. The
    /// funding owed by this position is the delta between the current
    /// index and this value times signed size — §7.4 pull-based
    /// settlement. Signed `i128` because cumulative funding can be
    /// net-positive or net-negative.
    pub cumulative_funding_at_open_e18: i128,
}

// ---------------------------------------------------------------------------
// MarginAccount — per-account free-margin balance
// ---------------------------------------------------------------------------

/// Per-account free-margin balance, in 1e18-scaled pMATRA-USD. Per §4.3,
/// `locked_margin` is stored on the `Position`, NOT on the
/// `MarginAccount` — close/liquidate touches one Position read + one
/// MarginAccount write with no cross-entry coordination.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Default,
)]
pub struct MarginAccount {
    /// pMATRA-USD free balance, 1e18-scaled. Available for opening new
    /// positions, paying funding, absorbing realized PnL.
    pub free_e18: u128,
    /// Materios block number of the most recent `deposit_margin` call.
    /// `withdraw_margin` enforces a 24h dwell time after a fresh deposit
    /// (§3.4) — same pattern as `request_credit_refund` in
    /// `pallet-intent-settlement`.
    pub last_deposit_block: u32,
}

// ---------------------------------------------------------------------------
// MarkPriceCache — per-block mark price + EMA basis
// ---------------------------------------------------------------------------

/// One row per market, updated each block by `on_initialize` (§5.2).
/// The mark price is `oracle + clamp(EMA(perp_mid - oracle), ±2%)`.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Default,
)]
pub struct MarkPriceCache {
    /// Computed mark price for the current block, 1e18-scaled.
    /// `oracle_e18 + clamp(mark_ema_basis_e18, ±MaxMarkBasisBps × oracle_e18)`.
    pub mark_e18: u128,
    /// Raw oracle price (from `pallet-oracle::LastPublishedPrice`),
    /// 1e18-scaled. Stored separately from `mark_e18` so the impl PR can
    /// distinguish "mark frozen due to stale oracle" from "mark frozen
    /// due to capped basis".
    pub oracle_e18: u128,
    /// Materios block number this cache row was last written.
    pub block: u32,
    /// Running EMA of `(perp_mid_e18 - oracle_e18)`. Signed because the
    /// CLOB perp mid can be either above or below oracle. Drives mark
    /// price AND funding-rate sampling (§7.3).
    pub mark_ema_basis_e18: i128,
}

// ---------------------------------------------------------------------------
// PerpActionKind — variant of the new IntentKind::PerpAction enum
// ---------------------------------------------------------------------------
//
// Per §8.2, position-changing extrinsics also emit an
// `IntentKind::PerpAction` intent into `pallet-intent-settlement` so the
// existing M-of-N flow attests it and the existing label-8746 Cardano
// anchor pipeline writes an L1 audit trail. The variant is defined here
// (in `pallet-perp-engine::types`) so the impl PR can wire it without a
// circular dep — `pallet-intent-settlement`'s `IntentKind` extension
// will import this type via the workspace `pallet-perp-engine` dep.

/// Sub-kind of a perp-action intent emitted into
/// `pallet-intent-settlement` on every position state change.
///
/// Per design memo §8.2 the variant is opaque to `pallet-intent-settlement`
/// — it's just another intent on the existing batch lane. The fairness-
/// proof / voucher / settle path is the same.
#[derive(
    Clone, Copy, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq,
)]
pub enum PerpActionKind {
    /// `open_position` emitted this.
    Open = 0,
    /// `close_position` emitted this.
    Close = 1,
    /// `liquidate` emitted this — `Position` was closed at mark by a
    /// keeper.
    Liquidation = 2,
    /// `adjust_leverage` emitted this — `Position.leverage_bps` and
    /// `locked_margin_e18` were rebased.
    LeverageAdjust = 3,
}
