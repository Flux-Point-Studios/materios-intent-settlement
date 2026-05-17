# Materios `pallet-perp-engine` v0 — design memo

**Status:** Draft for internal review.
**Date:** 2026-05-14.
**Author:** Agent C, task #163 (perp-engine v0 spec) — fan-out on Materios intent-settlement.
**Companion docs:** `materios-oracle-design.md`, `project_intent_settlement_wave2_status.md`, `project_cardano_market_making_thesis.md`, `project_v5_1_tokenomics.md`, `pallets/intent-settlement/src/lib.rs`.

---

## 0. Compounding leverage

This pallet compounds five existing Materios primitives and turns each into a paying customer of the others:

| Compounded primitive | What perp-engine adds to it |
|---|---|
| `pallet-intent-settlement` (M-of-N attested L2, 256-claim batches, BFPR, voucher digest, Cardano label-8746 anchor) | Every position open / close / liquidation lands as an intent inside the same batch lane that already proves out at 6.63 settled-TPS on preprod. We do not rebuild the batch path. We reuse it. |
| Materios Oracle Network (`pallet-oracle`, 20/20 trimmed median, 30s cadence, M=3 of 5 attestors, MATRA-bonded, slashable) | Becomes the *only* mark-price + funding-index source. Each new perp market is a new oracle-feed consumer. Listing a perp listing also funds an oracle bond pool. |
| Committee (Gemtek + Node-2 + Node-3 + MacBook; expandable per `project_validator_growth_plan.md`) | Same operators that attest receipts and oracle prices now sign liquidation evidence. Zero new trust roots. |
| MATRA / MOTRA dual-token model (`project_v5_1_tokenomics.md`, post-2026-05-13 billing migration) | Collateral is MATRA-pegged synthetic stable (`pMATRA-USD`); margin top-ups + liquidation fees + maker rebates flow in MOTRA. Bond-of-bad-behavior for keepers locked in MATRA. |
| Cardano-side anchoring (label 8746 checkpoint, BatchClaimVoucher path, anchor-worker hot-wallet pipeline) | Every settled funding-epoch and every liquidation publishes a Cardano L1 audit trail on the existing rails. No new Aiken validator in v0 (deferred to v1 — see §10). |

Net additive trust roots: **zero**. The new failure modes are bugs inside `pallet-perp-engine` itself; we add no oracle, no signer set, no settlement venue.

---

## 1. Goals & non-goals

### 1.1 In v0

- Isolated-margin linear perpetual futures, USD-quoted, settled in `pMATRA-USD` (Materios-native synthetic stable; collateral abstraction documented in §3).
- One market type: cross-asset perp against a price published by Materios Oracle Network (e.g., `ADA-PERP/USD`, `BTC-PERP/USD`, `ETH-PERP/USD`). Initial three markets mirror the oracle Phase 1 pair set.
- Long-or-short, 1× to `MaxLeverage` (governance-set, default 10×).
- Mark price sourced from oracle median; funding rate driven by premium-index basis between perp mid (Materios CLOB / SaturnSwap) and oracle.
- Permissionless keeper liquidations with MATRA bond + slashing-on-false-trigger.
- Funding rate accrual integrated into margin balance every funding epoch (1 hour at v0, governance-tunable).
- Cardano L1 anchor of: (a) funding-epoch settlement digests via the existing checkpoint pipeline (label 8746), (b) liquidation events via per-claim intent-settlement vouchers if the operator routes them through the Cardano leg.

### 1.2 Deferred to v1+ (non-goals)

- **Cross-margin / portfolio margin.** v0 is one position per market per account. Cross-margin opens an attack surface around joint-liquidation ordering and re-introduces the Hyperliquid clawback model. Ship isolated first, audit the math, then evaluate.
- **Multi-collateral.** v0 takes `pMATRA-USD` only. Multi-collateral requires haircut tables + price feeds per collateral asset; both are scope tax with no day-one user.
- **Advanced order types (TP/SL, OCO, post-only, reduce-only, IOC).** v0 supports market-style open/close at oracle mark plus a configurable max slippage. The CLOB-style book lives in SaturnSwap and feeds the premium-index; orders against the perp engine are settled at mark.
- **Sub-account / portfolio.** v0 is one account per `AccountId`.
- **Options / non-linear payoffs.** Linear perp only.
- **Direct-to-Cardano position custody.** Position state lives on Materios. Cardano L1 sees only digest anchors + settlement vouchers. Custody-on-Cardano with Materios as a sidecar is a v2 thesis (`project_materios_intent_settlement_dapp.md` §competitive frame).
- **Sub-block funding.** Funding epoch ≥ 1 block budget headroom (1h default = 600 blocks at 6s). Per-block funding looks tempting but rapes the on_initialize budget when N markets × M accounts iterate.
- **Insurance fund.** v0 routes liquidation residual into the existing `mat/trsy` PalletId pot. A dedicated insurance fund with auto-clawback rules is v1. v0's liquidation fee curve is conservative enough that bad-debt risk is bounded by maintenance-margin (§6.2).
- **HyperEVM-style smart-contract perp consumers.** Materios is Substrate, not EVM. ink! contract integration is a separate primitive.
- **Cross-chain margin (Cardano → Materios bridge inbound margin).** Margin enters via `credit_deposit` on the existing intent-settlement bridge path, NOT a new bridge.

---

## 2. Research summary — what we adopt and what we reject

Reviewed Hyperliquid HyperCore, dYdX v4, GMX v2 before designing.

| Design choice | What incumbents do | What v0 adopts | Reasoning |
|---|---|---|---|
| **Position accounting** | Hyperliquid: signed size. dYdX v4: signed `BigInt` in subaccount. GMX v2: long/short maps per market. | **Signed `i128` size + signed `i128` PnL**, in the same `Position` struct. | One struct, one storage entry, one math path. Long/short maps double the storage and complicate liquidation ordering. Hyperliquid + dYdX use the signed form; we follow. |
| **Mark price** | Hyperliquid: median(oracle + EMA-adjusted, on-chain mid, CEX-weighted-median). dYdX: pure oracle + premium-index for funding only. GMX: pure Chainlink. | **Median(oracle, oracle + bounded-EMA(perp_mid − oracle))**. CEX baskets are exactly what Materios Oracle Network already aggregates — we read the trimmed median straight from `pallet-oracle::LastPublishedPrice`. The EMA layer handles brief oracle gaps. | Re-implementing Hyperliquid's CEX basket inside the perp pallet would dual-publish the same data Oracle Network already provides. EMA layer keeps margin math robust during oracle outages without giving the matching engine pricing power. |
| **Funding formula** | Hyperliquid: avg(premium) + clamp(int_rate − premium, ±5bps). 1h-paid, 8h-rate. dYdX: premium/8 + interest. GMX: skew-based (long/short imbalance). | **Premium-index-only** with same clamp as Hyperliquid: `funding_rate_per_epoch = clamp(EMA(premium), ±MaxFundingPerEpoch)`. No interest-rate component in v0 (dYdX's 0.01%/8h is a fiat-rate proxy we have no use for in a MATRA-collateralized perp). | Premium-index is robust, parameter-light, and bounded. GMX's skew model is elegant but assumes a pool-LP counterparty model we don't have (and intentionally don't want — see §8). |
| **Liquidation trigger** | Hyperliquid: deterministic on-chain liquidation engine (no external bot needed). dYdX: same. GMX: any caller. | **Permissionless caller + MATRA-bonded liquidator + slashing on false trigger.** | Hyperliquid/dYdX both bake liquidation into block proposal. We piggyback on Materios block authoring instead by allowing any signer to call `liquidate`, but require a small MATRA bond at extrinsic time which is slashed if the position was not actually under-margined at the included block's mark price. Cardano-style economic security; no privileged role. |
| **Liquidation closure** | dYdX: partial allowed, configurable. Hyperliquid: full. GMX: partial-only above a threshold. | **Full closure** in v0; partial deferred to v1. Simpler, easier to audit, and one fewer dimension on the keeper's strategy surface. | We accept some on-the-margin liquidation inefficiency in exchange for one less mode of "liquidation grief." |
| **Insurance fund** | dYdX: yes, takes/pays PnL. Hyperliquid: HLP socializes losses. GMX: pool LPs absorb. | **No v0 insurance fund.** Liquidation residual routes to `mat/trsy`. Maintenance margin is sized so liquidation at MM still leaves positive equity in expectation. Bad-debt events kick a governance circuit-breaker (§6.5). | Insurance funds are correct long-term but require care; they are v1. v0's job is to ship a correct primitive. |
| **Settlement model** | Hyperliquid: continuous (HyperCore). dYdX: matching + clearing per block. GMX: pool counterparty per fill. | **Discrete: every position open/close lands as an `IntentKind::PerpAction` intent inside the existing `submit_batch_intents` + M-of-N + `settle_batch_atomic` path.** We do not bypass the attested-settlement L2 — we extend it. | This is the compounding-leverage move. Perp ops settle on the same lane that already does 6.63 settled-TPS today; the path scales with whatever `settle_batch_atomic` scales to (target 10k user-TPS per `project_materios_10k_tps_plan.md`). |
| **Maker/taker fees** | Hyperliquid: 0.025% / 0.06%. dYdX: tier-based. GMX: 0.05% + spread. | **Maker rebate paid in MOTRA, taker fee paid in MOTRA**, with the rebate funded by the existing `MM-rebate program` budget from §v5.1 tokenomics (5M MATRA over 24mo, decaying 50%/yr — earmark 30% of that bucket for perp markets in year 1). | Reuses the rebate primitive already approved. MOTRA-denominated keeps the cost dimension regenerative. |

---

## 3. Extrinsic surface

All eight v0 extrinsics live in `pallet-perp-engine`. They are user-facing and signed by an `AccountId` origin unless marked otherwise. The pallet-call-index numbers are nominal — final indices will be appended at construct_runtime time per `feedback_pallet_index_shift.md`.

### 3.1 `open_position`

```rust
#[pallet::call_index(0)]
#[pallet::weight((Weight::from_parts(150_000_000, 3500), DispatchClass::Normal, Pays::Yes))]
pub fn open_position(
    origin: OriginFor<T>,
    market_id: MarketId,
    direction: PerpDirection,        // Long | Short
    size_e8: u128,                   // 1e-8 contract units (positive magnitude)
    leverage_bps: u32,               // 100 = 1x, 1000 = 10x, etc.
    max_slippage_bps: u32,           // reject if entry deviates >X bps from mark
    margin_top_up_motra: Balance,    // optional: take this much from free margin
) -> DispatchResult
```

- `ensure_signed(origin)` for the user.
- No committee signature required at this layer — the open is a user intent. M-of-N attestation happens via the existing intent-settlement pipeline when this lands as a `PerpAction` intent (§8).
- Verifies `market_id` is active in `Markets` storage and not paused.
- Verifies leverage ≤ `MaxLeverage::get(market_id)`.
- Verifies free margin in the user's `MarginAccount` ≥ initial margin = `(size_e8 * mark_price_e18) / (leverage_bps * 100)`.
- Reads mark price from `MarkPriceCache` (populated each block from oracle — §5).
- Records the position open at the cached mark.
- Reserves initial margin from `MarginAccount.free` into `MarginAccount.locked_per_market[market_id]`.
- Idempotent on `(submitter, nonce)` via Materios's existing nonce model.
- Weight assumption: 1 storage read (Markets), 2 reads (MargAcct, MarkPriceCache), 2 writes (Position upsert, MargAcct). ~150M ref_time per `feedback_keeper_serial_inclusion_is_the_bottleneck.md` style accounting; `proof_size` ~3500 because we touch four small storage maps.

### 3.2 `close_position`

```rust
#[pallet::call_index(1)]
#[pallet::weight((Weight::from_parts(150_000_000, 3500), DispatchClass::Normal, Pays::Yes))]
pub fn close_position(
    origin: OriginFor<T>,
    market_id: MarketId,
    size_e8: u128,                   // 0 = close all; else partial close
    max_slippage_bps: u32,
) -> DispatchResult
```

- `ensure_signed(origin)`.
- Lookups: `Positions[market_id][who]`, `MarkPriceCache[market_id]`.
- Compute realized PnL = `(exit_mark - entry_mark) * signed_size`.
- Apply settled funding accrued since position open (delta of `CumulativeFundingIndex[market_id]` between open block and current block).
- Release locked margin + realized PnL into `MarginAccount.free`.
- If `size_e8 == 0` or matches full position, delete `Position` row and free its `locked_per_market` slot.
- Same weight assumption as `open_position`.

### 3.3 `deposit_margin`

```rust
#[pallet::call_index(2)]
#[pallet::weight(Weight::from_parts(80_000_000, 1800))]
pub fn deposit_margin(
    origin: OriginFor<T>,
    amount_motra: Balance,           // user provides via Currency::transfer
) -> DispatchResult
```

- `ensure_signed(origin)`.
- `Currency::transfer(who, &PalletId::into_account(), amount_motra)` — moves MOTRA from the user's free balance to the perp pallet's pot account.
- Increments `MarginAccount.free` for the user by an equivalent `pMATRA-USD` value at the *governance-set MATRA/USD peg rate from the oracle* (§3-collateral abstraction). v0 ships with peg = oracle MATRA/USD price at the moment of deposit; the user takes peg risk between deposit and withdrawal (this is the same model every USD-quoted exchange uses when the user deposits in a native token).
- No M-of-N gate. User-controlled deposit.

### 3.4 `withdraw_margin`

```rust
#[pallet::call_index(3)]
#[pallet::weight(Weight::from_parts(120_000_000, 2200))]
pub fn withdraw_margin(
    origin: OriginFor<T>,
    amount_e18: u128,                // amount in pMATRA-USD 1e18-scaled
) -> DispatchResult
```

- `ensure_signed(origin)`.
- Enforces: free margin after withdrawal ≥ max(`InitialMargin` across all open positions × current notional). I.e., user cannot withdraw to where they'd be immediately liquidatable.
- Converts pMATRA-USD back to MOTRA at the live oracle MATRA/USD; transfers MOTRA from the pallet pot to the user.
- 24h dwell time before withdraw if a fresh deposit landed (idempotency + bridge-deposit-replay protection, same pattern as `request_credit_refund` in `pallet-intent-settlement`).

### 3.5 `liquidate`

```rust
#[pallet::call_index(4)]
#[pallet::weight((Weight::from_parts(200_000_000, 4500), DispatchClass::Operational, Pays::No))]
pub fn liquidate(
    origin: OriginFor<T>,
    target: T::AccountId,
    market_id: MarketId,
    keeper_bond_motra: Balance,      // must be ≥ KeeperBondMinimum
) -> DispatchResult
```

- `ensure_signed(origin)` — anyone can call.
- Caller posts a MATRA-denominated bond (taken from caller via `Currency::reserve`) of at least `KeeperBondMinimum`. The bond stays locked until §6.3 evaluates the trigger.
- Pallet reads `Positions[market_id][target]`. If no open position → `Error::NoPosition`.
- Reads `MarkPriceCache[market_id]` *at the included block* (i.e., the block in which this extrinsic landed) — NOT the caller-asserted price. This is the structural correctness gate: the bond gets slashed if the actual on-chain mark at the included block is above maintenance margin (i.e., the call should not have triggered).
- If position equity at mark < maintenance margin → close at mark, charge `LiquidationFeeBps` (default 50 = 0.5%) of notional to position's margin, route fee 50/50 between caller (as keeper reward in MOTRA) and `mat/trsy`. Return the keeper bond.
- If position equity at mark ≥ maintenance margin → bond slashed 100%, half to `mat/trsy`, half burned. Emit `BadLiquidationAttempt` event.
- Operational class, `Pays::No` so a successful liquidation is gas-free to the keeper. The bond is the only economic skin in the game (which is exactly what we want — a wrong keeper pays, a right keeper doesn't).
- No sig-verify in this extrinsic itself — the *evidence* is the on-chain mark price at the included block, and committee already attested that via oracle.

### 3.6 `settle_funding`

```rust
#[pallet::call_index(5)]
#[pallet::weight((Weight::from_parts(50_000_000, 1200), DispatchClass::Operational, Pays::No))]
pub fn settle_funding(
    origin: OriginFor<T>,
    market_id: MarketId,
    epoch: u32,
) -> DispatchResult
```

- `ensure_signed(origin)` — permissionless, but typically called by a Materios keeper service every funding epoch boundary (1 hour by default).
- Pallet computes the funding rate for the just-closed epoch from `PremiumIndexSamples[market_id]` (which an offchain worker has been writing every block since the epoch opened — see §7.3).
- Updates `CumulativeFundingIndex[market_id]` += `funding_rate * epoch_duration`. This is the **pull-based settlement primitive** — individual positions absorb funding lazily on their next `close_position` or `liquidate` call (no per-position iteration in `settle_funding`).
- Emits `FundingEpochSettled { market_id, epoch, rate_e18_signed, new_cumulative_index_e18_signed }`. The event is anchored to Cardano via the existing label-8746 checkpoint pipeline.
- Idempotent: `settle_funding(epoch)` is a no-op if `epoch ≤ LastSettledFundingEpoch[market_id]`.

### 3.7 `adjust_leverage`

```rust
#[pallet::call_index(6)]
#[pallet::weight(Weight::from_parts(100_000_000, 2200))]
pub fn adjust_leverage(
    origin: OriginFor<T>,
    market_id: MarketId,
    new_leverage_bps: u32,
) -> DispatchResult
```

- `ensure_signed(origin)`.
- Requires an open position in the market.
- Recomputes locked margin = `(size_e8 * entry_mark_e18) / new_leverage_bps`.
- Reverts if the new locked margin would push margin equity below initial margin at current mark.
- Allows "leverage up" (reduces locked margin) and "leverage down" (increases locked margin).
- Bounded by `MaxLeverage::get(market_id)` and `MinLeverage = 100 (= 1×)`.

### 3.8 `governance_set_market`

```rust
#[pallet::call_index(7)]
#[pallet::weight(Weight::from_parts(80_000_000, 3000))]
pub fn governance_set_market(
    origin: OriginFor<T>,                       // EnsureRoot
    market_id: MarketId,
    config: MarketConfig,                       // see §4.1
) -> DispatchResult
```

- `EnsureRoot` (sudo / 2-of-3 multisig). v0 has no token-vote DAO; v1 may delegate to `pallet-collective`.
- Adds, updates, or pauses a market.
- Validates oracle feed id exists in `pallet-oracle::PriceFeeds`.
- Cannot be called while there are any open positions in the market with parameters strictly worse for users than the new config (encoded as a `try_state` invariant).

---

## 4. Storage layout

### 4.1 `MarketConfig` and `Markets` map

```rust
#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Clone)]
pub struct MarketConfig {
    /// Stable handle for the market. Bytes used for events + anchoring.
    pub id: MarketId,                         // BoundedVec<u8, ConstU32<16>>, e.g. b"ADA-PERP/USD"
    /// Linked oracle feed (matches pallet-oracle::PriceFeeds key).
    pub oracle_feed_id: BoundedVec<u8, ConstU32<16>>,
    pub initial_margin_bps: u32,              // e.g. 1000 = 10%
    pub maintenance_margin_bps: u32,          // e.g. 500  = 5%
    pub max_leverage_bps: u32,                // e.g. 2000 = 20x cap
    pub max_funding_per_epoch_bps: u32,       // clamp on absolute funding-rate magnitude per epoch
    pub liquidation_fee_bps: u32,             // e.g. 50 = 0.5%
    pub maker_fee_bps: i32,                   // negative = rebate
    pub taker_fee_bps: u32,                   // positive = fee
    pub max_position_size_e8: u128,           // notional cap per account per market
    pub min_position_size_e8: u128,           // dust filter
    pub mark_ema_window_blocks: u32,          // EMA window for mark price (default 25 blocks ≈ 150s)
    pub funding_epoch_blocks: u32,            // default 600 blocks ≈ 1h
    pub paused: bool,                         // governance kill-switch
}

#[pallet::storage]
pub type Markets<T: Config> = StorageMap<
    _,
    Identity,                                 // MarketId is already a small bounded byte string — Identity is fine
    MarketId,
    MarketConfig,
    OptionQuery,
>;
```

- Hasher choice: `Identity` for `Markets` because `MarketId` is governance-controlled bounded bytes (16-byte cap), not user-supplied → no first-key DoS via collision crafting. Matches the rationale in `pallet-oracle`'s `PriceFeeds` storage.

### 4.2 `Position` and `Positions` double map

```rust
#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Clone, Copy)]
pub struct Position {
    pub size_e8: i128,                        // signed; positive = long, negative = short
    pub entry_mark_e18: u128,                 // mark price at open, 1e18-scaled
    pub locked_margin_e18: u128,              // pMATRA-USD locked as initial margin
    pub leverage_bps: u32,                    // user-visible leverage at last adjust
    pub opened_block: BlockNumber,
    pub cumulative_funding_at_open_e18: i128, // snapshot of CumulativeFundingIndex at open
}

#[pallet::storage]
pub type Positions<T: Config> = StorageDoubleMap<
    _,
    Identity,                                 // MarketId — bounded byte string, governance-set
    MarketId,
    Blake2_128Concat,                         // AccountId — user-supplied, MUST be crypto hasher
    T::AccountId,
    Position,
    OptionQuery,
>;
```

- Hasher rationale: first key `Identity` because `MarketId` is governance-only. Second key `Blake2_128Concat` because `AccountId` is user-controlled and we cannot tolerate first-key collision attacks.
- `i128` size: signed, in 1e-8 contract units. Long = +, short = −. `entry_mark_e18` is the 1e18-scaled price at open. `cumulative_funding_at_open_e18` is the funding index *delta* anchor — see §7.
- Why `i128` instead of `u128 + sign_bit` (the third option in the brief): a packed sign bit is one bit cheaper at rest but every arithmetic site needs branching to reconstruct the signed value, and Rust's saturating-i128 ops are well audited in `sp-arithmetic::FixedI128`. The single-storage-entry win of a packed sign is dwarfed by the bug surface of bespoke sign handling. **Decision: signed `i128`.**

### 4.3 `MarginAccount` map

```rust
#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Clone)]
pub struct MarginAccount {
    pub free_e18: u128,                       // pMATRA-USD free balance
    pub last_deposit_block: BlockNumber,      // dwell-time guard for withdraw
}

#[pallet::storage]
pub type MarginAccounts<T: Config> = StorageMap<
    _,
    Blake2_128Concat,                         // AccountId — user-supplied
    T::AccountId,
    MarginAccount,
    ValueQuery,
>;
```

- `locked_margin` is *stored on the Position*, not on the MarginAccount, so close/liquidate touches one Position read + one MarginAccount write — no cross-entry coordination.
- Hasher: `Blake2_128Concat` because `AccountId` is user-supplied.

### 4.4 `MarkPriceCache` and `OraclePriceSnapshot`

```rust
#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, PartialEq, Eq, Clone, Copy)]
pub struct MarkPriceCache {
    pub mark_e18: u128,                       // computed mark price for the block
    pub oracle_e18: u128,                     // raw oracle price (from pallet-oracle)
    pub block: BlockNumber,                   // when mark was computed
    pub mark_ema_basis_e18: i128,             // running EMA of (perp_mid - oracle) — see §5
}

#[pallet::storage]
pub type MarkPriceCacheMap<T: Config> = StorageMap<
    _,
    Identity,                                 // MarketId — governance-set
    MarketId,
    MarkPriceCache,
    ValueQuery,
>;
```

- One row per market. Updated in `on_initialize` (§5.2).
- Hasher: `Identity` — same rationale as `Markets`.

### 4.5 `FundingRate` state

```rust
#[pallet::storage]
pub type CumulativeFundingIndex<T: Config> = StorageMap<
    _, Identity, MarketId, i128, ValueQuery,
>;

#[pallet::storage]
pub type PremiumIndexSamples<T: Config> = StorageDoubleMap<
    _, Identity, MarketId,
    Identity, u32,                             // funding_epoch number (small u32, governance-bounded)
    BoundedVec<i128, ConstU32<<<T as Config>::MaxFundingSamplesPerEpoch as Get<u32>>>>,
    ValueQuery,
>;

#[pallet::storage]
pub type LastSettledFundingEpoch<T: Config> =
    StorageMap<_, Identity, MarketId, u32, ValueQuery>;
```

- `PremiumIndexSamples` is the only unbounded-looking storage. Bounded by `MaxFundingSamplesPerEpoch` — see §7.3. Pruned eagerly when `settle_funding(epoch)` runs.
- `CumulativeFundingIndex` is signed `i128` because cumulative funding can be net-positive or net-negative over a market's life.

### 4.6 `KeeperBond` reservations

```rust
#[pallet::storage]
pub type ReservedKeeperBonds<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    (T::AccountId, MarketId, T::AccountId),    // (keeper, market, target)
    Balance,
    OptionQuery,
>;
```

- Tracks open liquidation-bond reservations. Released atomically inside `liquidate` after evaluation. This map should be empty at the end of every block (any entry is a logic bug → covered by `try_state`).

---

## 5. Oracle dependency

### 5.1 What perp-engine reads from Materios Oracle Network

Three reads, all from `pallet-oracle` storage exposed via a `T::PriceOracle: PriceOracle` Config-trait abstraction (so the perp pallet stays unit-testable against a `MockPriceOracle`):

```rust
pub trait PriceOracle {
    /// Latest published price for the feed, scaled 1e18. Returns the
    /// trimmed-median value last published to Materios (NOT to Cardano L1 —
    /// the L1 anchor lags by 20-60s and is too stale for mark price).
    fn latest_price_e18(feed_id: &[u8]) -> Result<u128, OracleError>;

    /// Age of the latest price in blocks at the current block height.
    fn price_age_blocks(feed_id: &[u8]) -> u32;

    /// True iff the feed is currently un-paused, has ≥ M signatures in its
    /// most recent slot, and `price_age_blocks < FreshnessLimit`.
    fn is_fresh(feed_id: &[u8]) -> bool;
}
```

Wired in production to `pallet-oracle::Pallet<Runtime>` via an adapter type that reads `LastPublishedPrice` per `materios-oracle-design.md §6.1`.

### 5.2 Mark price computation

Each block, `on_initialize` iterates active (un-paused) markets and updates `MarkPriceCacheMap`:

```text
oracle_price = T::PriceOracle::latest_price_e18(market.oracle_feed_id)
perp_mid     = SaturnSwap CLOB mid price (read via T::ClobPriceFeed; v0 ships with adapter to SaturnSwap)
ema_basis    = ema(prev_ema_basis, (perp_mid - oracle_price), window = mark_ema_window_blocks)
mark_price   = oracle_price + clamp(ema_basis, ±MaxMarkBasisBps × oracle_price)
```

This is the Hyperliquid mark formula, simplified — we drop the CEX-basket median because Materios Oracle Network already supplies the trimmed median over multiple CEXes (`materios-oracle-design.md §2.1`). The EMA layer handles the case where (a) the oracle hasn't refreshed yet within the 30s cadence, or (b) the SaturnSwap CLOB diverges briefly from oracle.

`MaxMarkBasisBps` defaults to 200 (2%) — i.e., mark cannot deviate more than 2% from oracle in either direction, no matter what the CLOB mid says. This is the structural protection against mark-price manipulation via thin CLOB liquidity.

### 5.3 Funding rate basis

Funding rate per epoch comes from the same EMA basis, sampled each block via offchain hook (`on_finalize` writes a sample into `PremiumIndexSamples[market][current_epoch]`). When `settle_funding(epoch)` runs:

```text
funding_rate_e18_signed =
    clamp(
        median(PremiumIndexSamples[market][epoch]) / oracle_price * funding_epoch_blocks / 600,
        ±MaxFundingPerEpoch
    )
```

The `/ 600` term normalizes the rate to a fixed 1h-equivalent regardless of how `funding_epoch_blocks` is configured, so dashboards can display a comparable "8h rate" for parity with CEX displays.

### 5.4 Liquidation trigger threshold

`liquidate(target, market_id)` reads `MarkPriceCacheMap[market_id].mark_e18` *at the included block*. There is no separate "liquidation price" oracle — the entire system is mark-price-driven. This is by design: a separate liquidation oracle would split the trust surface.

### 5.5 Freshness requirement

The pallet refuses to update `MarkPriceCacheMap` for a market if `T::PriceOracle::is_fresh(market.oracle_feed_id) == false`. If the oracle is stale, the existing cached mark *expires* after `FreshnessLimitBlocks` (default 50 blocks ≈ 5 minutes), at which point:

1. `open_position` calls fail with `Error::MarkStale`. Users cannot open new positions on a stale market.
2. `liquidate` calls fail with `Error::MarkStale`. Liquidations are paused. **This protects users from being liquidated on stale data.**
3. `close_position` continues to work, but at the *last fresh mark*. Users can always exit.
4. `settle_funding` is skipped (its premium samples are also stale).

Per `materios-oracle-design.md §12.2 Risk 2`, when all attestors are down the pallet emits a `LastPublishedPrice` stale-flag event, and we propagate that into the perp engine as `MarkStale`.

---

## 6. Liquidation model

### 6.1 Trigger

Position is liquidatable when:

```text
equity = locked_margin
       + signed_size * (current_mark - entry_mark)
       - cumulative_funding_paid(position)

if equity < maintenance_margin_e18 = (|signed_size| * current_mark * mm_bps) / 10_000:
    LIQUIDATABLE
```

`current_mark = MarkPriceCacheMap[market_id].mark_e18` at the call's included block. No external assertion of price — pallet uses its own cache.

### 6.2 Closure

**Full closure** at `current_mark` in v0. The closed position pays:

- `LiquidationFeeBps` of notional (e.g., 0.5% of size × mark) — split 50/50 between keeper and `mat/trsy`.
- Any negative PnL out of `locked_margin`.
- Returns positive residual margin (if any) to `MarginAccount.free`.
- If `locked_margin < |PnL| + liquidation_fee` → bad debt. v0 routes bad debt to `mat/trsy` (treasury absorbs). Tracked via `BadDebtAccumulated` storage value; if total bad debt over a 24h window exceeds `BadDebtCircuitBreakerThreshold`, the market auto-pauses (§6.5).

### 6.3 Permissionless trigger + bond + slashing

Per §3.5: any signer can call `liquidate(target, market)`. They post a `KeeperBondMinimum` MATRA bond at call time. The pallet evaluates the trigger using *its own cached mark* — caller cannot lie about price.

- Trigger valid → bond returned, keeper rewarded with 50% of liquidation fee in MOTRA.
- Trigger invalid (position equity ≥ MM at included block's mark) → bond slashed 100%, half to `mat/trsy`, half burned. The MATRA-bond slash means attempting an unwarranted liquidation has direct economic cost.

This permissionless-keeper-with-bond model is the deliberate choice over dYdX's "matchmaking node liquidates as a privileged role" pattern. It removes the privileged role entirely and replaces it with on-chain bonded keepers. Same trust shape as Cardano SPOs.

### 6.4 Bond economics

```text
KeeperBondMinimum = max(
    100 MATRA,                                  // floor
    50% × max_expected_liquidation_fee_one_market  // calibrated to break even on grief
)
```

For a $10k position at 0.5% liquidation fee = $50 of value at stake; a 100 MATRA bond at ~$0.05/MATRA = $5 is enough to deter spam-liquidations on small positions but small enough that legitimate keepers post it casually. Governance can bump per market via `MarketConfig`.

### 6.5 Bad-debt circuit breaker

If a market accumulates `> BadDebtCircuitBreakerThresholdE18` of bad debt within `BadDebtWindowBlocks`:

1. Market auto-pauses (no new opens, no liquidations).
2. Existing positions can still `close_position`.
3. Governance must un-pause after investigation.

Same pattern as `pallet-oracle::PriceDeviationFlagged` circuit breaker (`materios-oracle-design.md §7.4`).

---

## 7. Funding rate

### 7.1 Model — premium-index, hourly default

Per §2 research summary, we adopt **premium-index funding** with no interest-rate component:

```text
funding_rate_per_epoch = clamp(
    EMA(premium_samples_in_epoch) / oracle_price * scale_to_1h,
    ±MaxFundingPerEpoch
)
```

`MaxFundingPerEpoch` defaults to **400 bps per epoch (= 4%/hour cap, matching Hyperliquid)**. Governance can lower this for less-volatile markets.

### 7.2 Epoch cadence

`funding_epoch_blocks` per market, default 600 blocks ≈ 1 hour at 6s block time. Governance-tunable per market. Per-block funding is explicitly out of scope — see §1.2.

### 7.3 Sample collection

Each block, `on_finalize` writes the latest premium-index sample to `PremiumIndexSamples[market][current_epoch]`. The sample is `mark_ema_basis_e18` from `MarkPriceCacheMap[market]` (the same EMA that drives mark price).

`MaxFundingSamplesPerEpoch` is `funding_epoch_blocks` (one sample per block), bounded so a 1h epoch at 6s = 600 samples → ~10 KB per market per epoch in storage worst-case. Pruned by `settle_funding`.

### 7.4 Payer / receiver mechanics

Funding is a **pull-based settlement**, not push. The pallet does NOT iterate positions on settlement:

1. Every position stores `cumulative_funding_at_open_e18` (the snapshot of `CumulativeFundingIndex[market]` at open).
2. `settle_funding(epoch)` updates `CumulativeFundingIndex[market]` += `funding_rate_per_epoch`. O(1) cost per epoch per market.
3. On `close_position` or `liquidate`, the position pays/receives funding:

```text
funding_owed_e18 = signed_size * (CumulativeFundingIndex[market]_now - position.cumulative_funding_at_open_e18)
```

Positive `funding_owed_e18` means the position pays (this happens when longs were paying shorts and you held long; or when shorts were paying longs and you held short). Deducted from `locked_margin` first, then `MarginAccount.free`.

Why pull-based: iterating every position per market per hour is O(N × M) and bounds chain TPS. dYdX v4 also lazy-settles funding into subaccount balances for the same reason. Hyperliquid pushes funding per block per position because HyperCore has a different exec model (no FRAME).

### 7.5 Interaction with margin

- Funding owed eats into margin equity before liquidation check.
- A position can be liquidated *because* of accrued funding even if mark price barely moved — same semantics as every centralized perp.
- On `adjust_leverage`, accrued funding is rolled into the position's stored values (i.e., we re-baseline `cumulative_funding_at_open_e18` to current).

---

## 8. Batch settlement integration

### 8.1 Decision: reuse `pallet-intent-settlement`

Position-changing extrinsics (`open_position`, `close_position`, `liquidate`) **also emit an `IntentKind::PerpAction` intent** into `pallet-intent-settlement`. The intent carries the position-change digest. The existing M-of-N flow attests it; the existing `settle_batch_atomic` path closes it; the existing label-8746 anchor pipeline writes a Cardano L1 audit trail.

This is the central compounding move. It means:

1. **Throughput**: perp opens/closes ride the same 6.63 settled-TPS-and-climbing path that intent-settlement already proves out. No separate batch lane to maintain.
2. **Auditability**: every position change is anchored on Cardano with the existing keeper, the existing voucher CBOR, the existing Aiken validator (extended for `PerpAction` kind in v1 — v0 ships with the anchor as a self-payment label-8746 metadata note, like W2.3 did).
3. **Settlement-finality semantics**: a position is *Materios-final* the moment the extrinsic lands (1 block, ~6s). It becomes *attested-final* when M-of-N committee attests (3 sigs, typically within 18s). It becomes *Cardano-final* when the next checkpoint anchors it (≤2 minutes typical). The user-visible UX matches `project_materios_intent_settlement_dapp.md`'s Q10 copy verbatim: 6s confirmation, sub-minute Cardano settlement.

### 8.2 The new `IntentKind::PerpAction` variant

Extend `pallet-intent-settlement::types::IntentKind`:

```rust
pub enum IntentKind {
    BuyPolicy { ... },         // existing
    RequestPayout { ... },     // existing
    RefundCredit { ... },      // existing
    PerpAction {               // NEW — added by pallet-perp-engine
        market_id: BoundedVec<u8, ConstU32<16>>,
        action: PerpActionKind,
        size_e8: i128,
        mark_e18_at_action: u128,
        keeper_account: Option<AccountId>,    // populated only if liquidation
    },
}

pub enum PerpActionKind {
    Open,
    Close,
    Liquidation,
    LeverageAdjust,
}
```

The variant is opaque to `pallet-intent-settlement`; from its perspective `PerpAction` is just another intent. The fairness-proof / voucher / settle path is the same.

### 8.3 Why NOT a separate `settle_batch_perp` extrinsic

Three reasons.

1. **Compounding leverage**: writing a parallel batch path duplicates 2400 LOC of audited extrinsic-settlement code in `pallet-intent-settlement`. We *do not write that*. We extend the existing primitive.
2. **Single Cardano anchor lane**: anchoring perp-action settlements and policy-claim settlements on the same label-8746 checkpoint stream is one Cardano hot-wallet pipeline, one anchor-worker, one events-indexer entry.
3. **Operator economics**: keepers, attestors, anchor-workers — all already exist, all are already paid in MOTRA per `pallet-billing` Phase 2.A. Adding a parallel pipeline forks the economic model.

### 8.4 Cost on the existing intent-settlement path

Per `project_spec207_pipeline_collapse_20260427.md`, the post-spec-207 batch path settles 256 user-intents in 4 extrinsics at 6.63 settled-TPS, 0.07% ref_time, 12.66% proof_size. Perp actions are smaller payloads than `BuyPolicy` (no 114-byte Cardano addr, no oracle evidence). v0 expects to ride the same 6.63 TPS lane without additional pressure, then scale alongside `pallet-intent-settlement` as it does (Track-B BFPR multi-leaf voucher batching keeper density per `project_materios_10k_tps_plan.md`).

---

## 9. Risk parameters

### 9.1 v0 defaults

| Parameter | Default | Governance range |
|---|---:|---|
| `MaxLeverage` | 10× | 1× – 20× |
| `InitialMargin` | 10% (= 10× leverage) | 5% – 100% |
| `MaintenanceMargin` | 5% | 1% – 50% (must be < InitialMargin) |
| `MaxPositionSize` per market | $250k notional | $1k – $10M |
| `MinPositionSize` per market | $10 notional | $1 – $1k |
| `LiquidationFeeBps` | 50 (0.5%) | 10 – 500 |
| `MaxFundingPerEpoch` | 400 bps/h (4%/h) | 50 – 1000 |
| `KeeperBondMinimum` | 100 MATRA | 10 – 10_000 |
| `FreshnessLimitBlocks` | 50 (~5 min) | 10 – 600 |
| `MarkEmaWindowBlocks` | 25 (~150s) | 5 – 600 |
| `FundingEpochBlocks` | 600 (~1h) | 60 – 14_400 |
| `MaxMarkBasisBps` | 200 (2%) | 50 – 1000 |
| `BadDebtCircuitBreakerThresholdE18` | $10_000 | $100 – $1_000_000 |
| `BadDebtWindowBlocks` | 14_400 (~24h) | 600 – 100_800 |
| `MakerFeeBps` | -2 (rebate) | -50 – +100 |
| `TakerFeeBps` | 7 | 0 – 100 |

### 9.2 Initial market set

Three markets at v0 launch — mirrors `materios-oracle-design.md` Phase 1 pair set:

| Market id | Oracle feed | Notes |
|---|---|---|
| `ADA-PERP/USD` | `ADA/USD` | Native Cardano token. The flagship market. |
| `BTC-PERP/USD` | `BTC/USD` | Highest-volume universal asset. |
| `ETH-PERP/USD` | `ETH/USD` | Cross-chain reference. |

USDT/USD and USDC/USD are oracle feeds at Phase 2 of the oracle plan; we do not need them as perp markets (no one wants leveraged stablecoin exposure).

### 9.3 Governance update protocol

`governance_set_market` for any update; updates that worsen user terms (raise MM, lower max position, raise fee) must be timelock-delayed by `MarketUpdateTimelockBlocks` (default 14_400 = 24h, matches `pallet-committee-governance::TimelockPeriod`). Updates that improve terms apply immediately.

---

## 10. Migration risks & open questions

### 10.1 Migration risks

1. **Pallet-index drift.** Per `feedback_pallet_index_shift.md`, inserting `pallet-perp-engine` in `construct_runtime!` must be at the end. Any tooling that hardcodes pallet indices (anchor-worker event decoders, keeper RPC slot expectations) drifts otherwise. *Mitigation: append after `pallet-oracle`, audit `feedback_pallet_index_shift.md` consumers list before merge.*

2. **`IntentKind` variant extension.** Adding a `PerpAction` variant to `pallet-intent-settlement::types::IntentKind` is a breaking SCALE-encoding change for any consumer that decoded the old enum. *Mitigation: bump `SettlementVersion` (Config item already exists per `lib.rs:468`), domain-separating every committee pre-image post-bump. Pre-bump bundles cannot collide with post-bump bundles.*

3. **Margin accounting precision.** pMATRA-USD is 1e18-scaled; oracle prices are 1e18-scaled; size is 1e-8. Product `size_e8 * price_e18 = 1e10`-scaled — well within `i128` (range ~1.7e38). *Risk: an overflow bug in margin math is catastrophic.* *Mitigation: every multiplication uses `checked_mul`; property tests in `proptest.rs` enforce invariants (equity = locked + signed_size × (mark − entry) − funding_owed across 10^5 randomized scenarios); benchmark suite under `runtime-benchmarks` feature for weight; full coverage in TDD per CLAUDE.md doctrine.*

4. **Funding-sample storage churn.** `PremiumIndexSamples` is the only multi-row-per-epoch storage. Bounded at 600 entries × 16 bytes × N markets. At 3 initial markets that's ~30KB per epoch. *Mitigation: `settle_funding` prunes the epoch's samples immediately after computing the median.*

5. **Liquidation MEV.** Keepers competing for liquidations may bid up extrinsic priority. *Mitigation: `Pays::No` on `liquidate` means the only cost is the MATRA bond, and the bond is returned on a legitimate liquidation — no fee-bidding war. First-keeper-to-include wins; ties broken by Substrate's tip auction, which is acceptable.*

6. **Cardano anchor lag for perp actions.** Perp position state changes are *Materios-final* in 6s, but *Cardano-attested* in 20–60s. A user closing a position and immediately withdrawing margin can do so before Cardano sees the close. *Mitigation: this is the same as the existing intent-settlement UX — Materios is the authority on Materios state, Cardano is an audit trail, not a settlement gate. The user-visible copy from `project_materios_intent_settlement_dapp.md` Q10 already explains this.*

7. **Mark-price oracle outage.** If `pallet-oracle` goes stale (e.g., all 5 attestors offline simultaneously), the perp engine freezes mark updates per §5.5. *Risk: prolonged outage means positions can't be liquidated and bad debt can grow if the underlying market moves. **The mitigation is the right one**: pause both opens and liquidations, let users close at the last fresh mark, and rely on the oracle's own circuit breaker (Phase 2 slashing + governance unpause).*

8. **`MarkPriceCache` block-time drift in tests.** Test runtimes that mock `BlockNumber` need the same `BlockNumberFor<T>: Into<u64> + Copy` bounds that `pallet-intent-settlement` already requires. *Mitigation: copy the same trait bound pattern from `pallets/intent-settlement/src/lib.rs:887`.*

### 10.2 Open questions (to resolve before code lands)

1. **`pMATRA-USD` collateral abstraction — is it a real token or a virtual scaling unit?** v0 treats it as a virtual unit: MOTRA is the on-chain token, pMATRA-USD is the internal accounting unit at the live oracle MATRA/USD rate. *Tradeoff: simple, no new pallet. Risk: users carry peg-volatility risk between deposit and withdrawal.* Real-token alternative (a separate `pallet-pmatra` minting an actual asset) is heavier but enables MATRA-stable trades across other Materios primitives. **Recommendation: ship v0 as virtual unit, decide on real-token in v1 based on user feedback.**

2. **Premium-index sampling source — SaturnSwap CLOB mid only, or also Cardano AMM mid?** Cardano AMM mids lag by 20s + batcher rounding. SaturnSwap CLOB is faster but launches with v5.1 (still-shipping). v0 launches as oracle-only mark with `mark_ema_basis_e18 == 0` until SaturnSwap is live → funding rate is effectively zero until premium-index has real signal. *This is acceptable* (no leverage trading until both oracle and CLOB are live; v0 ships in lockstep with `materios-oracle-design.md` Phase 2 and SaturnSwap launch).

3. **Should liquidations also slash a maintenance-margin tax to the bond pool, like the `pallet-oracle::AttestorBonds` reserve?** Open. Would create a dedicated insurance fund for v1 to inherit. *Recommendation: deferred to v1; v0's `mat/trsy` routing is fine for the initial size of book.*

4. **Maker-rebate budget split.** §v5.1 tokenomics earmarked 5M MATRA across 24mo for the CLOB MM rebate program; how much of that flows to perp markets versus spot CLOB? *Recommendation: 30% to perp markets in year 1, weighted by realized volume — published as a `MakerRebateBudget` storage value, drained per epoch.*

5. **Should `liquidate` accept a `target_size_e8` to allow partial?** v0 says no (full only); v1 yes. Partial liquidations are a useful product but the math gets thornier and the keeper-strategy space grows. *Recommendation: leave for v1.*

6. **TEE-attested mark price feed.** `pallet-tee-attestation` is live (`project_wave3_phase2_e2e_milestone_20260513.md`). A Pixel StrongBox-attested mark price would harden against oracle attestor collusion. *Recommendation: keep on the radar for v2; v0/v1 trust the oracle median, which is already deeply decentralized.*

---

## Decisions captured in this memo

| Decision | Value |
|---|---|
| Position accounting | Single `Position` struct with signed `i128` size + signed `i128` funding cumulative; no long/short maps |
| Mark price source | `pallet-oracle::LastPublishedPrice` + bounded EMA basis vs SaturnSwap CLOB mid |
| Funding model | Premium-index, hourly (600 blocks), capped at 4%/epoch, pull-based settlement |
| Liquidation trigger | Permissionless caller with `KeeperBondMinimum` MATRA bond; slashed 100% on false trigger |
| Liquidation closure | Full only in v0 (partial deferred) |
| Insurance fund | None in v0; bad debt → `mat/trsy`; circuit breaker on accumulation |
| Settlement primitive | Reuse `pallet-intent-settlement::settle_batch_atomic` via new `IntentKind::PerpAction` |
| Collateral | Virtual `pMATRA-USD` unit; on-chain backing in MOTRA at live oracle rate |
| Maker / taker | -2 / +7 bps, rebate funded from existing v5.1 MM-rebate bucket (30% earmark to perps year-1) |
| Markets at launch | ADA-PERP/USD, BTC-PERP/USD, ETH-PERP/USD |
| Max leverage at launch | 10×, governance-extensible to 20× |
| Mark freshness | 50 blocks (~5 min); stale → opens + liquidations paused, closes still work |

---

## Next steps

1. **Internal review of this memo.** Specifically: collateral abstraction choice (open question 1), `IntentKind` variant decision, default risk parameters.
2. **Pin canonical pre-images** for any new committee-signed payloads — none in v0 since `liquidate` uses oracle mark as evidence rather than committee signature, but if v1 adds a sig-attested liquidation flow, the pre-image must include `materios_chain_id` per `feedback_mofn_hash_determinism.md`.
3. **Scaffold `pallet-perp-engine`** under `pallets/perp-engine/` in the existing `materios-intent-settlement` repo. TDD-first per CLAUDE.md doctrine: failing tests for `open_position` happy path, slippage rejection, leverage cap, freshness gate, before any production code.
4. **Land via multisig sudo runtime upgrade** on preprod once initial test suite + `try_state` invariants pass. Genesis kill-switch (`MarketsPaused = true`) so the pallet lands inert and is activated per-market by governance.
5. **First live market** at ADA-PERP/USD on preprod, M=2 attestors, max position $1k, max leverage 3×. Soak 7 days before lifting limits.

This memo is the design contract. Code that diverges from it MUST update this memo in the same PR.
