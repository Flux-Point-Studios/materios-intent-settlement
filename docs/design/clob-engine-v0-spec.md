# Materios `pallet-clob` v0 — design memo

**Status:** Draft for internal review
**Author:** Materios core (this agent)
**Date:** 2026-05-17
**Companion docs:** `perp-engine-v0-spec.md`, `mm-rebate-program-design.md`, `settle-claim-l1-verification-design.md`, `mon-phase1-aegis-extend-design.md`, `materios-oracle-design.md`, `project_cardano_market_making_thesis.md`, `project_v5_1_tokenomics.md`

---

## 0. Compounding leverage

Per CLAUDE.md doctrine: name the asset this makes more valuable, the moment it ships.

1. **SaturnSwap (the brand)** — currently runs an off-chain orderbook + Hydra-L2 settlement. The very reason Materios exists is so SaturnSwap is not constrained by Hydra throughput, head-channel ceremony, and the eUTxO contention model. Shipping `pallet-clob` is the move that takes SaturnSwap from "Cardano CLOB on a Hydra head" → "Cardano CLOB on a Cardano-anchored L2 that does 250+ substrate TPS today."

2. **`pallet-intent-settlement`** — the settlement bond + slash pattern, the M-of-N committee, the voucher pipeline, and the Cardano L1 label-8746 anchor flow are all reused. `pallet-clob` does NOT introduce a new trust root.

3. **`pallet-mm-rebate`** — the maker-rebate program (designed at `mm-rebate-program-design.md`, 5M MATRA / 24mo / bonded-permissionless) only matters once a real book exists. Shipping `pallet-clob` unblocks shipping `pallet-mm-rebate` for production effect.

4. **`pallet-oracle`** — the M=3 attested median oracle (5 pairs live as of 2026-05-15) becomes the mark-price source for CLOB circuit breakers (deviation halts, fat-finger rejection). No new oracle infra.

5. **`pallet-perp-engine`** — already references and reads from the same oracle. Spot CLOB + perp-engine on the same chain means: traders deposit collateral once, route between spot and perp natively, hedge basis trades on a single venue. Materios becomes the first L2 in the Cardano ecosystem where this is possible.

6. **MATRA demand pressure** — every CLOB trade pays a taker fee partly into `mat/trsy`. Every market-maker that wants the rebate must bond MATRA. The CLOB is the venue that turns the v5.1 tokenomics curve into pull-through demand.

If `pallet-clob` ships well, every existing Materios primitive (oracle, intent-settlement, perp-engine, anchor-worker, mm-rebate, committee-governance) goes up in value the same day.

---

## 1. Goals & non-goals

### 1.1 In v0

- **Spot order book** with limit + market + IOC + FOK + post-only orders, price-time priority, on-block matching.
- **Multi-asset balances** via Substrate's `pallet-assets` (standard, audited, maintained). Materios chain runs a single instance.
- **Cardano-side bridging** for Cardano-native tokens via the same voucher-mint pipeline `pallet-intent-settlement` already uses. v0 supports **ADA** (wrap → wADA) and **USDC** (wrap → wUSDC, assuming a Cardano-issued USDC; otherwise USDC defers to v1).
- **3 initial markets**: `MATRA/wADA`, `wADA/wUSDC`, `MATRA/wUSDC`. Governance-gated `register_market`.
- **Maker / taker fee model** with rebate hook into `pallet-mm-rebate`.
- **Per-block trade batch** anchored to Cardano L1 via the existing label-8746 anchor-worker pipeline. No bespoke anchoring.
- **Circuit breakers**: oracle-deviation halt (if mark spread > N bps from oracle median, halt the market), fill-rate ceiling (max-fills-per-block).
- **Self-trade prevention** (`cancel-both` default, configurable per-order).
- **Permissionless market making** — no whitelist. Bond via `pallet-mm-rebate` is the only entry gate, and only for rebate eligibility, not for posting orders.
- **No leverage**, **no margin**, **no liquidations** — those live in `pallet-perp-engine`. Spot is spot.

### 1.2 Deferred to v1+ (non-goals)

- Stop-loss, trailing-stop, iceberg, hidden, conditional, OCO orders. (Add when there's a demonstrated MM ask.)
- Concentrated-liquidity AMM pools alongside the book (SaturnSwap's existing AMM design lives separately — `pallet-amm` is its own future memo).
- Non-Cardano-native asset bridging (BTC, ETH, USDT). Wait for a bridged-asset audit + a counterparty bridge primitive.
- Cross-margining with `pallet-perp-engine`. v0: a wallet holds MATRA + wADA balances separately, perp engine holds its own MarginAccount. Unify in v1.
- Permissioned order types (e.g., RFQ, dark book). Out of scope.
- Decoupling the matcher from on-block execution. v0 = synchronous matching at end of each block. If TPS pressure demands, v1 considers a `pallet-clob-batcher` keeper.

---

## 2. Research summary — what we adopt and what we reject

| Source | Adopt | Reject |
|---|---|---|
| **Hyperliquid (perp + spot, on-block matching)** | Price-time FIFO, on-block matching, sub-block determinism, single venue for spot + perp. | Centralized sequencer (we have decentralized M-of-N already from `pallet-perp-engine` proof of concept), single-asset margin (CLOB stays multi-asset). |
| **dYdX v4 (CosmosSDK app-chain)** | Native pallet on the L2, no smart-contract overhead, governance-gated market registration. | The custom Cosmos consensus — we already run partner-chains Aura + GRANDPA, no reason to fork it. |
| **Serum (Solana CLOB)** | Discrete-event price-time priority. Crank-keeper pattern as a v1 fallback. | The crank-keeper-must-run-frequently model — we have deterministic blocks and `on_initialize`, no off-chain crank required for v0. |
| **GMX / dYdX perp** | N/A — perps already designed in `pallet-perp-engine`. | N/A |
| **SaturnSwap existing Hydra orderbook** | Maker-volume indexing pattern (PR #4 records to L1), GraphQL surface shape for the frontend. | Hydra L2 head-channel settlement — the whole reason we're building this pallet. Replace it. |
| **Substrate `pallet-assets`** | Use unmodified as the asset ledger. Multi-asset support, mint/burn governance, freeze/thaw built-in. | Don't write a custom multi-asset ledger. |
| **Polkadot SDK `frame-system::on_initialize`** | Run the matching engine at the start of each block, deterministic, weight-budgeted. | Don't run matching at end-of-block (`on_finalize`) — that limits proof_size and is less ergonomic for events ordering. |

---

## 3. Asset model

### 3.1 Why `pallet-assets` vs custom

Reuse `pallet-assets` from `polkadot-stable2409-4` (the SDK tag the chain already pins). Audited, maintained, supports mint/burn/freeze/thaw/destroy, exposes `Inspect` + `Mutate` traits that `pallet-clob` can hold-balance-for-orders against.

Custom multi-asset would mean: re-implementing balance maps, freeze logic, transfer hooks, fee withdrawals, dust handling, and `total_issuance` tracking. ~3k LoC of code that already exists, audited, in the standard library. Not building that.

### 3.2 Asset registration + governance

Each tradeable token is an `AssetId: u32`. Registration is sudo-only (same 2-of-3 multisig as every other governance op):

```rust
Sudo.assets.create(id, admin, min_balance)
Sudo.assets.set_metadata(id, name, symbol, decimals)
Sudo.assets.set_team(id, issuer, admin, freezer)  // bridge pallet as issuer
```

The bridge pallet (`pallet-bridge`, §10) is the issuer for any wrapped Cardano-native token. `mint` happens when the wrap voucher resolves; `burn` happens when the user requests unwrap.

### 3.3 Initial asset set (v0)

| Asset id | Symbol | Decimals | Origin | Notes |
|---:|---|---:|---|---|
| 1 | MATRA | 18 | native | Materios native, app-layer asset. Already exists. |
| 2 | MOTRA | 18 | native | Gas / tx-fee asset. **Not tradeable** on CLOB v0 — gas-only, no market registered for MOTRA pairs. |
| 100 | wADA | 6 | bridge | Wrap of Cardano L1 ADA via `pallet-bridge`. 6-decimal to match Cardano lovelace. |
| 101 | wUSDC | 6 | bridge | Wrap of Cardano-issued USDC (e.g., Anzens / USDM-style). 6-decimal. **GATED on availability of a Cardano-native USDC at v0 ship time.** If unavailable, defer to v1; ship v0 with wADA + MATRA only. |

v0 markets:
- `MATRA/wADA` (base/quote) — primary launch market, MM-rebate eligible
- `wADA/wUSDC` — secondary launch market (only if wUSDC ships in v0)
- `MATRA/wUSDC` — secondary launch market (only if wUSDC ships in v0)

---

## 4. Extrinsic surface

10 dispatchables in v0.

### 4.1 `register_market` (sudo-only)

```rust
pub fn register_market(
    origin: OriginFor<T>,
    market_id: MarketId,        // BoundedVec<u8, ConstU32<32>>, e.g. b"MATRA/wADA"
    config: MarketConfig,
) -> DispatchResult
```

`MarketConfig`:
- `base_asset: AssetId`
- `quote_asset: AssetId`
- `tick_size_e18: u128` (price granularity, e.g. 0.0001 wADA per MATRA = 1e14)
- `lot_size_e8: u64` (base-asset size granularity)
- `min_order_size_e8: u64` (dust filter)
- `max_order_size_e8: u64` (fat-finger ceiling)
- `maker_fee_bps: i32` (signed — negative = rebate)
- `taker_fee_bps: u32`
- `oracle_pair_label: Option<BoundedVec<u8, _>>` (for circuit breaker; `None` = breaker disabled)
- `oracle_deviation_halt_bps: u32` (e.g. 500 = 5% — halt market if mark deviates beyond this from oracle median)
- `max_fills_per_block: u32` (rate-limit per market per block — protects block weight)
- `paused: bool`

Validation gates (`Error<T>` enum):
- `MarketAlreadyExists` — duplicate `market_id`
- `BaseAssetEqQuoteAsset` — can't trade an asset against itself
- `UnknownAsset` — base/quote not registered with `pallet-assets`
- `TickSizeZero`, `LotSizeZero`, `MinSizeAboveMax` — sanity
- `MakerFeeOutOfBounds`, `TakerFeeOutOfBounds` — `|maker_fee_bps| <= 1000` (10%), `taker_fee_bps <= 1000`
- `OracleDeviationHaltOutOfBounds` — `<= 10000` (100%)

Emits `Event::MarketRegistered { market_id, base_asset, quote_asset, maker_fee_bps, taker_fee_bps, paused }`.

### 4.2 `place_order`

```rust
pub fn place_order(
    origin: OriginFor<T>,
    market_id: MarketId,
    side: Side,                  // Buy | Sell
    order_type: OrderType,       // Limit | Market | IOC | FOK | PostOnly
    price_e18: u128,             // ignored for Market
    size_e8: u64,                // in base-asset units
    self_trade_prevention: STP,  // CancelBoth (default) | CancelMaker | CancelTaker | None
) -> DispatchResult
```

Returns no value on chain (event-based); SDK derives `order_id` from the emitted `OrderPlaced` event.

Validation:
- `MarketUnknown` / `MarketPaused`
- `OrderSizeOutOfRange` (`< min` or `> max`)
- `OrderSizeNotLotAligned` (`size_e8 % lot_size_e8 != 0`)
- `PriceNotTickAligned` (Limit/IOC/FOK/PostOnly only)
- `InsufficientBalance` — caller doesn't hold enough quote (Buy) or base (Sell)
- `OracleCircuitBreakerTripped` — mark price is `> oracle_deviation_halt_bps` away from the oracle median (for markets with `oracle_pair_label = Some`)
- `MaxFillsPerBlockReached` — per-market block budget exhausted (caller can retry next block)
- `PostOnlyWouldMatch` — PostOnly order would have crossed; reject without resting

On success:
- Reserve the caller's funds (base for Sell, quote+taker_fee for Buy) via `pallet-assets.hold`.
- Insert into the book at the appropriate price level (or match immediately, depending on order type).
- Emit `OrderPlaced` for the rest portion (if any).
- Emit `OrderFilled` for each match generated, including `maker_order_id` for the resting counter-party.

### 4.3 `cancel_order`

```rust
pub fn cancel_order(origin: OriginFor<T>, market_id: MarketId, order_id: OrderId) -> DispatchResult
```

- `OrderUnknown` — order_id not in the book
- `NotOrderOwner` — caller's account doesn't match `order.owner`

Releases the reserved funds for the unfilled remainder. Emits `OrderCancelled { order_id, remaining_size_e8 }`.

### 4.4 `cancel_all_orders`

```rust
pub fn cancel_all_orders(
    origin: OriginFor<T>,
    market_id: Option<MarketId>,  // None = all markets
) -> DispatchResult
```

Iterates over the caller's `OrdersByOwner` set and emits one `OrderCancelled` per. Weight-capped at `MaxCancelsPerCall = 256` per dispatch. Caller can re-dispatch if their book footprint exceeds the cap.

### 4.5 `place_batch_orders`

```rust
pub fn place_batch_orders(
    origin: OriginFor<T>,
    orders: BoundedVec<PlaceOrderArgs, ConstU32<64>>,
) -> DispatchResult
```

MM efficiency: place up to 64 orders in one extrinsic. Atomic — if any one fails validation, the whole batch reverts. Each individual order is treated as if dispatched in sequence.

### 4.6 `governance_set_market_params` (sudo-only)

```rust
pub fn governance_set_market_params(
    origin: OriginFor<T>,
    market_id: MarketId,
    new_config: MarketConfigUpdate,  // Option<> for each field
) -> DispatchResult
```

Updates a subset of fields (fee bps, deviation halt threshold, paused flag, max_fills_per_block) on an existing market. Cannot change base/quote asset, tick size, or lot size (would require migration); to change those, register a new market.

### 4.7 `governance_pause_market` / `governance_unpause_market` (sudo-only)

Fast-path pause for incidents. When paused, `place_order` rejects with `MarketPaused`. Existing orders remain on the book; `cancel_order` still works.

### 4.8 `reserve_mm_bond` / `release_mm_bond`

Bond reservation for `pallet-mm-rebate` integration. Same shape as `pallet-perp-engine::reserve_keeper_bond`. The CLOB pallet doesn't enforce the bond — it just provides the bond-reservation API that `pallet-mm-rebate` calls when an MM registers.

(Could also live in `pallet-mm-rebate` itself; pin location at impl time. Leaning toward keeping bonded state in `pallet-mm-rebate` to keep `pallet-clob` storage shape focused.)

---

## 5. Storage layout

### 5.1 `Markets` map

```rust
#[pallet::storage]
pub type Markets<T: Config> = StorageMap<
    _, Blake2_128Concat, MarketId, MarketConfig, OptionQuery,
>;
```

### 5.2 Order book — `Bids` and `Asks`

Two `StorageDoubleMap`s per market, keyed by `(MarketId, OrderBookKey)`. `OrderBookKey` is constructed so the iteration order is price-time priority:

```rust
pub struct OrderBookKey {
    pub price_e18_inverted: u128,    // for bids: u128::MAX - price (so highest bid sorts first)
    pub seq: u64,                     // monotonic per-block insertion sequence (time priority)
}
```

For asks, `price_e18_inverted` is just `price_e18` so lowest ask sorts first. Substrate's `StorageDoubleMap` with `Blake2_128Concat` on the key gives deterministic ordered iteration via `iter_prefix`.

```rust
#[pallet::storage]
pub type Bids<T: Config> = StorageDoubleMap<
    _, Blake2_128Concat, MarketId, Blake2_128Concat, OrderBookKey, Order<T>, OptionQuery,
>;
#[pallet::storage]
pub type Asks<T: Config> = StorageDoubleMap<
    _, Blake2_128Concat, MarketId, Blake2_128Concat, OrderBookKey, Order<T>, OptionQuery,
>;
```

Storage cost note: `Order` is ~80 bytes; at 10k resting orders per market the worst-case proof_size is ~800kB, well under the 5MB block budget. We don't expect more than a few thousand resting orders per market in v0.

### 5.3 `Order` struct

```rust
pub struct Order<T: Config> {
    pub order_id: OrderId,           // u64, global monotonic via NextOrderId
    pub owner: T::AccountId,
    pub side: Side,
    pub order_type: OrderType,
    pub price_e18: u128,
    pub size_e8: u64,                // total size
    pub filled_e8: u64,              // cumulative fills against this order
    pub stp: STP,
    pub created_block: BlockNumber,
}
```

### 5.4 `OrdersByOwner` reverse index

```rust
#[pallet::storage]
pub type OrdersByOwner<T: Config> = StorageDoubleMap<
    _, Blake2_128Concat, T::AccountId, Blake2_128Concat, OrderId, MarketId, OptionQuery,
>;
```

Lets `cancel_all_orders` iterate over a single owner's footprint without scanning the whole book.

### 5.5 `NextOrderId`

```rust
#[pallet::storage]
pub type NextOrderId<T: Config> = StorageValue<_, OrderId, ValueQuery>;
```

Monotonic. Increments on every successful `place_order`. Never resets, even if the order doesn't rest (e.g., fully-matched IOC). The ID is the canonical reference for indexers + UI.

### 5.6 `FillsThisBlock` rate-limit counter

```rust
#[pallet::storage]
pub type FillsThisBlock<T: Config> = StorageMap<
    _, Blake2_128Concat, MarketId, u32, ValueQuery,
>;
```

Reset in `on_initialize`. Incremented each fill. Order placement that would push past `max_fills_per_block` rejects with `MaxFillsPerBlockReached`.

### 5.7 `BlockTradeBatch` (anchor input)

```rust
#[pallet::storage]
pub type BlockTradeBatch<T: Config> = StorageMap<
    _, Blake2_128Concat, BlockNumber, BoundedVec<TradeAnchorEntry, ConstU32<1024>>, ValueQuery,
>;
```

End-of-block snapshot of all fills in this block. Consumed by the anchor-worker, written into the next Cardano label-8746 batch. Pruned after `AnchorRetentionBlocks = 7200` (~12 hours at 6s blocks) to keep storage bounded.

`TradeAnchorEntry`:
```rust
{
  market_id, maker_order_id, taker_order_id,
  price_e18, size_e8, maker_fee_e8_signed, taker_fee_e8,
  maker_owner_32, taker_owner_32,
}
```

---

## 6. Matching engine

### 6.1 Price-time priority (FIFO at each price level)

Standard CLOB semantics. At each price level, the order that arrived first (lowest `seq`) fills first. Across price levels, the most aggressive price fills first (highest bid / lowest ask).

### 6.2 Matching trigger: synchronous on `place_order`

Matching happens **inside** `place_order` itself, not deferred to `on_initialize`. Reasoning:
- Substrate's per-extrinsic weight model already accounts for `n` storage reads / writes during dispatch.
- Synchronous matching means the user gets `OrderFilled` events in the same block as the place, no latency.
- Block-end batching (`on_initialize`) adds complexity (deferred-fill queue) for no user benefit. The perp-engine MarkPriceCache runs in `on_initialize` because it's a chain-wide oracle write, not a per-order operation. CLOB matching is per-order.

### 6.3 Order type semantics

| Type | Matches resting? | Rests if unfilled? | Reject conditions |
|---|---|---|---|
| `Limit` | Yes, up to its limit price | Yes | tick/lot misalignment, STP collisions |
| `Market` | Yes, no price constraint | No (any unfilled portion is dropped) | Empty book on the opposite side → `MarketEmpty` error |
| `IOC` (immediate-or-cancel) | Yes, up to its limit price | No | Same as Limit |
| `FOK` (fill-or-kill) | Yes, only if can fully fill | No | `FOKWouldNotFullyFill` if not enough liquidity |
| `PostOnly` | No — rejects if would cross | Yes | `PostOnlyWouldMatch` if would cross |

### 6.4 Self-trade prevention (STP)

When a new order would match against a resting order from the same owner:

- `CancelBoth` (default) — cancel the maker order, cancel the unfilled portion of the taker. No fill recorded.
- `CancelMaker` — cancel the maker, keep filling the taker against the next maker.
- `CancelTaker` — cancel the unfilled portion of the taker, keep the maker.
- `None` — allow the self-trade. (Useful for wash-trading prevention testing; **not** recommended in production. Doc-flagged as such.)

### 6.5 Partial fills + crossing

A single `place_order` can generate up to `max_fills_per_block` fills if it sweeps multiple price levels. Each fill emits its own `OrderFilled` event. The cumulative `filled_e8` on the taker order tracks total volume filled. If `filled_e8 < size_e8` after sweeping all crossable resting orders:
- Limit / PostOnly → rest on the book at the original limit price (PostOnly only if it never crossed in the first place).
- Market / IOC / FOK → cancel the unfilled remainder.

### 6.6 Tick + lot + min/max enforcement

- `price_e18 % tick_size_e18 == 0` for Limit/IOC/FOK/PostOnly.
- `size_e8 % lot_size_e8 == 0` always.
- `min_order_size_e8 <= size_e8 <= max_order_size_e8`.

Market orders skip price validation but enforce lot + size bounds.

### 6.7 Crossed-book invariant

Property test (must hold in every block):
```
For every market, after all fills resolve:
  best_bid_price_e18 < best_ask_price_e18
  (or one side is empty)
```

Asserted in `try_state` (run in tests, optionally in benchmarks). Violation = chain bug, halt + sudo migration.

---

## 7. Fee model

### 7.1 Maker / taker fee accrual

On each fill:
- **Taker** pays `size_quote * taker_fee_bps / 10000` to the fee account `mat/clob` (a derived sovereign account).
- **Maker** receives `size_quote * (-maker_fee_bps) / 10000` (rebate) from `mat/clob` IF `maker_fee_bps < 0`, OR pays `size_quote * maker_fee_bps / 10000` to `mat/clob` IF `maker_fee_bps > 0`.
- `mat/clob` solvency invariant: `taker_fee_in >= |maker_rebate_out|`. If `|maker_fee_bps| > taker_fee_bps`, the chain refuses market registration.

v0 default fee bps per market (governance can update via `governance_set_market_params`):
- `taker_fee_bps = 7` (0.07%)
- `maker_fee_bps = -2` (0.02% rebate)
- Net to `mat/clob` = 5 bps per filled trade.

### 7.2 Hook into `pallet-mm-rebate`

`pallet-mm-rebate` reads `BlockTradeBatch` (the per-block fills snapshot) to compute MM volume share over a rolling 14-day window. Accruals come from `mat/clob` (the fee pot funded by net taker-minus-maker fees) plus the 5M-MATRA emission schedule from the rebate program treasury (`mat/mmrb`).

The split — fee-pot rebates (continuous) vs treasury emissions (24-month decay) — is the cross-document binding between this memo and `mm-rebate-program-design.md`. The CLOB pallet itself doesn't compute rebate tiers; it just emits the fill events that `pallet-mm-rebate` consumes.

### 7.3 Fee router (`mat/trsy`, `mat/mmrb`)

Periodic sweep extrinsic `sweep_clob_fees_to_treasury(amount)` moves accumulated `mat/clob` balance to `mat/trsy` (after deducting whatever rebates `pallet-mm-rebate` has accrued claims for). Sudo-callable. Defaults to monthly cadence.

---

## 8. Settlement integration

### 8.1 Decision: spot trades do NOT route through `pallet-intent-settlement`

Reasoning:
- The CLOB matching IS the settlement. There's no off-chain leg that needs M-of-N attestation for "did this trade actually happen?" — the chain itself has the canonical event.
- `pallet-intent-settlement` exists for cases where the settlement evidence lives off-chain (Cardano L1 voucher mints, insurance oracle evidence, etc.). A spot match between two Materios accounts has no such evidence requirement.
- Routing every fill through M-of-N attestation would add ~6 blocks of latency (one round of attestation) for zero security benefit.

### 8.2 Cardano L1 audit trail

Every block's `BlockTradeBatch` IS rolled into the next label-8746 anchor batch via the existing anchor-worker pipeline. So:
- **Local audit:** the Materios chain itself has the canonical fill record. No need to look at Cardano L1 for normal use.
- **Hard audit:** the anchor-worker periodically commits `merkle_root(BlockTradeBatch)` to Cardano as part of the same checkpoint that already covers OrinqReceipts + IntentSettlement. Provides an external L1 timestamp + immutable trail for regulators / disputes.

### 8.3 Bridge interaction (deposit / withdraw)

Bridge events (wrap / unwrap of wADA, wUSDC) DO route through `pallet-intent-settlement` because they're cross-chain. The CLOB pallet only sees `pallet-assets` balances — it doesn't care whether the underlying is bridged or native.

---

## 9. Risk parameters

### 9.1 v0 defaults (per market)

| Param | Default | Rationale |
|---|---:|---|
| `tick_size_e18` | depends on quote-asset price scale | Coarse enough to deter latency-bot spam, fine enough for retail UX |
| `lot_size_e8` | 1_000_000 (= 0.01 base unit) | Min retail unit; aligns with Cardano 6-decimal lovelace where applicable |
| `min_order_size_e8` | 10_000_000 (= 0.10 base unit) | Dust filter |
| `max_order_size_e8` | 100_000_000_000_000 (= 1_000_000 base) | Fat-finger ceiling, fits in u64 with room |
| `maker_fee_bps` | -2 | -0.02% rebate |
| `taker_fee_bps` | 7 | 0.07% |
| `oracle_deviation_halt_bps` | 500 | 5% — generous; can tighten per market post-launch |
| `max_fills_per_block` | 256 | Hard ceiling per market per block; ~1500 weight units worst case |
| `paused` | true | All new markets start paused; sudo unpauses after MM bond deposits + book seeding |

### 9.2 Initial market set

Already enumerated in §3.3. Conservative — three markets, two assets (wADA, MATRA) if wUSDC delays.

### 9.3 Circuit breakers

Two breakers in v0:

1. **Oracle-deviation halt** — if the book's last-trade price deviates from `pallet-oracle.median(oracle_pair_label)` by more than `oracle_deviation_halt_bps` (default 5%), the next `place_order` reverts with `OracleCircuitBreakerTripped`. Existing orders + `cancel_order` still work. Auto-resumes when the spread re-narrows. Same model as Hyperliquid mark-band protection.

2. **Fill-rate ceiling** — `FillsThisBlock[market] < max_fills_per_block`. Protects against pathological cascades; usually irrelevant (256 fills is a lot for a single block).

Deferred to v1+: stale-oracle halt, max-position checks (those belong in perp not spot), funding-payment integration (N/A for spot).

### 9.4 Governance update protocol

Same 2-of-3 multisig sudo as every other governance op (`5D1Anh…` per `feedback_partner_chains_governance_single_key_v6.md`). Param updates are non-migrating — they just update `MarketConfig`. Spec_version bump only if storage layout changes.

---

## 10. Cross-chain asset bridging

### 10.1 Wrap (Cardano L1 → Materios)

User flow:
1. User locks ADA in `pallet-bridge`'s Aiken validator on Cardano (same pattern as the perp-engine voucher pipeline).
2. M-of-N attestor committee observes the lock on Cardano L1, attests via `attest_bridge_lock(lock_evidence)` on Materios.
3. After threshold met, `pallet-bridge.mint_wrapped(beneficiary, asset_id, amount)` is callable; the assigned issuer (`pallet-bridge` itself, via root signer) mints `wADA` into the user's Materios balance.

This reuses `pallet-intent-settlement`'s `submit_intent` → `attest_intent` → `request_voucher` → settlement pipeline almost verbatim. The settlement-side payout writes a `pallet-assets.mint` instead of an `ADA → beneficiary` transfer; otherwise identical.

### 10.2 Unwrap (Materios → Cardano L1)

User flow:
1. User calls `pallet-bridge.request_unwrap(asset_id, amount, cardano_beneficiary_addr)` on Materios. This burns the wrapped balance via `pallet-assets.burn` and emits an `UnwrapRequested` event.
2. M-of-N attestors observe the event, sign a Cardano-side release datum, anchor-worker submits the Cardano tx releasing the locked ADA from the validator.
3. Cardano `Spent` event on the validator UTxO → attestors observe → `attest_unwrap_settled(...)` finalizes on Materios.

### 10.3 Aiken validator surface per asset

One Aiken validator per asset (or one parameterized validator with per-asset script hashes). Each validator's datum captures `(asset_id, amount, beneficiary, m_of_n_committee_root)` and its redeemer verifies M-of-N signatures over the unwrap message.

For v0 we ship one validator (`bridge_v1`) parameterized by asset; the same script hash handles ADA today, USDC tomorrow.

### 10.4 v0 scope

Wrap ADA only. wUSDC defers if there's no Cardano-issued USDC primitive at ship time. Multichain bridges (BTC, ETH, USDT off-Cardano) are explicitly out of scope — they require independent bridge infrastructure not in our build path.

---

## 11. SDK surface

Extend the existing `@fluxpointstudios/materios-intent-settlement-sdk` package with a `ClobClient` (or co-locate in a new `@fluxpointstudios/materios-clob-sdk` if the dep surface diverges enough).

```ts
import { ClobClient } from "@fluxpointstudios/materios-clob-sdk";

const clob = new ClobClient({
  materiosRpcUrl: "wss://materios.fluxpointstudios.com/preprod-rpc",
  signerUri: process.env.MATERIOS_MNEMONIC,
});

// Place
const { orderId, txHash } = await clob.placeOrder({
  market: "MATRA/wADA",
  side: "Buy",
  type: "Limit",
  price: 0.25n,           // 0.25 wADA per MATRA
  size: 100n,             // 100 MATRA
  timeInForce: "GTC",
  stp: "CancelBoth",
});

// Cancel
await clob.cancelOrder({ market: "MATRA/wADA", orderId });

// Subscribe to book
const unsub = clob.subscribeBook("MATRA/wADA", (snapshot) => {
  console.log("best bid:", snapshot.bids[0]);
  console.log("best ask:", snapshot.asks[0]);
});

// Subscribe to my fills
const unsub2 = clob.subscribeMyFills((fill) => {
  console.log(`Filled ${fill.size} @ ${fill.price} on ${fill.market}`);
});
```

~2-3k LoC of TypeScript on top of existing `IntentSettlementClient` + polkadot.js patterns. Builders + canonical payload hashing + balance queries.

---

## 12. Keeper / indexer surface

- **No matcher needed** (matching is on-block, deterministic).
- **Book snapshotter** — daemon that subscribes to `Bids` + `Asks` storage and exposes a REST/WS `/api/book/:market` endpoint for the SaturnSwap frontend. Lives in the existing demo/server pattern (`materios-perp-demo` shape) or extends Node-3's events-indexer.
- **Trade tape indexer** — subscribes to `OrderFilled` events, persists to SQLite, exposes `/api/trades/:market?since=<block>`. Same shape as the existing Node-3 events-indexer.
- **Cardano anchor inspector** — `/api/anchor/:cardano_tx_hash` endpoint that returns the Materios `BlockTradeBatch` merkle leaves the anchor commits to. Audit trail UX.

Estimate: ~1.5k LoC of TypeScript across snapshotter + indexer extension. Reuses existing event-indexer infrastructure on Node-3.

---

## 13. Migration risks & open questions

### 13.1 Migration risks

- **First multi-asset migration** — chain has never had `pallet-assets` before. Genesis spec needs to include the pallet with empty maps; spec_version bump must NOT migrate existing MATRA/MOTRA balances (those stay in their respective pallets, NOT in pallet-assets). Test: a node with the old runtime can decode `pallet-assets::Account<T>` storage at block 0 after the upgrade.
- **Order book storage at scale** — at the proof_size limits, if a single market accumulates >10k resting orders the per-block proof can blow past the 5MB limit. The per-block fill rate ceiling helps, but order REST isn't fill-limited. Mitigation: pre-launch benchmark of a synthetic 50k-order book + a `governance_purge_stale_orders` extrinsic to evict orders older than N blocks.
- **PostOnly + STP interaction** — a PostOnly order with `STP=CancelBoth` that would self-trade has two reasons to reject; pin the precedence (STP cancels first, then PostOnly's `would-cross` check no longer triggers). Test this explicitly.
- **Fee account dust** — `mat/clob` accumulates dust from rounding; without a sweep extrinsic it grows unboundedly. Sweep monthly via sudo.

### 13.2 Open questions (resolve before code lands)

1. **wUSDC source** — does a Cardano-native USDC exist with sufficient liquidity for the wrap voucher pipeline to make sense at v0 launch? If no, v0 ships with `MATRA/wADA` only; wUSDC + wUSDC pairs land in v0.5.

2. **`pallet-mm-rebate` location** — does the bond reservation live in `pallet-clob` or `pallet-mm-rebate`? Leaning rebate-pallet to keep CLOB storage focused, but the rebate pallet needs access to per-fill events anyway. Pin at impl time.

3. **STP default** — `CancelBoth` is the safest default but is the most-rebate-killing for MMs (a self-cross cancels their resting). `CancelMaker` is more MM-friendly but exposes them to wash-trading accusations. Decision: `CancelBoth` default for v0; MMs can opt into `CancelMaker` per-order.

4. **Per-market vs global STP** — does each market get its own STP default, or is the per-order arg always used? Decision: per-order arg required for now (no per-market default).

5. **Oracle pair binding** — for `MATRA/wADA`, the relevant oracle pair is... none of the 5 currently published (ADA/USD, BTC/USD, ETH/USD, USDT/USD, USDC/USD). Need to either (a) add `MATRA/USD` to the Aegis publisher set (synthetic, since MATRA isn't traded yet outside this CLOB), or (b) ship `MATRA/wADA` with the circuit breaker disabled in v0, accept the risk, and add the oracle pair when a real price emerges. Decision: (b) — disable breaker on `MATRA/wADA` in v0; add it once the market has 7 days of clean trading. Discuss before locking.

6. **Order-id collision in batch** — `place_batch_orders` increments `NextOrderId` once per order in the batch. If the batch reverts, the IDs get burned (no rollback of the counter). Acceptable — gaps in order_id space are fine. Note in indexer docs.

---

## Decisions captured in this memo

| Decision | Choice | Rationale §ref |
|---|---|---|
| Asset ledger | `pallet-assets` (unmodified) | §3.1 |
| Matching trigger | Synchronous in `place_order` | §6.2 |
| Settlement layer | Direct ledger update, NOT routed through `pallet-intent-settlement` | §8.1 |
| L1 audit trail | Existing label-8746 anchor-worker, with new `BlockTradeBatch` payload | §8.2 |
| v0 markets | `MATRA/wADA` + (`wADA/wUSDC` + `MATRA/wUSDC` if wUSDC ships) | §3.3 |
| Initial fee defaults | -2 / 7 bps (maker rebate / taker fee) | §7.1 |
| STP default | `CancelBoth` | §6.4 |
| Order types in v0 | Limit, Market, IOC, FOK, PostOnly | §6.3 |
| Bridge surface in v0 | Wrap ADA only (wUSDC gated, others deferred) | §10.4 |
| Bond location | `pallet-mm-rebate` owns it; `pallet-clob` emits fill events only | §4.8, §7.2 |
| Circuit breaker on `MATRA/wADA` | Disabled in v0 (no oracle pair yet) | §13.2 q5 |

---

## Next steps

PR chain shape (mirrors `pallet-perp-engine`'s PR-A → PR-E):

1. **PR-A — scaffolding + types + storage** (~1.5k LoC, 3 days)
   - `pallet-clob` crate + Config + Storage maps + types (no extrinsics yet)
   - `pallet-assets` wired into `construct_runtime` + governance bootstrap
   - First 3 assets registered (MATRA already exists; wADA + wUSDC via sudo)
   - 50 unit tests for storage shapes + invariants

2. **PR-B — `place_order` + `cancel_order` + matching engine** (~3k LoC, 5-7 days)
   - The core matching loop. Limit + Market first; IOC/FOK/PostOnly stacked on
   - STP semantics
   - Crossed-book + monotonic-order-id property tests
   - Fee accrual into `mat/clob`
   - ~100 unit tests; 3 sec-review rounds expected here

3. **PR-C — `register_market` + `governance_set_market_params` + circuit breakers** (~1k LoC, 3 days)
   - Market registration body
   - Oracle deviation halt integration with `pallet-oracle`
   - Fill-rate ceiling
   - Pause / unpause
   - ~30 unit tests

4. **PR-D — batch placement + cancel-all + `OrdersByOwner` index** (~1k LoC, 3 days)
   - `place_batch_orders` (up to 64-deep)
   - `cancel_all_orders` (up to 256-deep)
   - Reverse-index storage
   - ~20 unit tests

5. **PR-E — `pallet-bridge` (wrap/unwrap)** (~2k LoC, 5-7 days)
   - Materios-side bridge pallet
   - Aiken validator for ADA wrap
   - Keeper extension for bridge-event observation
   - ~60 unit tests; sec-review for the M-of-N attestation reuse

6. **PR-F — runtime wire-up + spec-N ceremony + benchmarks** (~500 LoC, 3 days)
   - `construct_runtime!` integration
   - WASM build + spec_version bump (probably spec-228+)
   - frame-benchmarking weights for every extrinsic
   - Multisig sudo ceremony script
   - Pre-fund `mat/clob`, register initial markets, unpause `MATRA/wADA`

7. **PR-G — SDK + indexer + keeper** (~3k LoC, 5-7 days; parallelizable with PR-F)
   - `ClobClient` in the SDK
   - Book snapshotter daemon
   - Trade tape indexer extension on Node-3
   - End-to-end demo against preprod

**Total realistic agent-team window: 4-5 weeks calendar, ~30 days of focused work, parallelizable down to ~3 weeks if PR-E (bridge) and PR-B (matching engine) run on independent branches.**

Sec-review CLEAN gates on every PR. Production-quality first try, same posture as perp-engine v0.

After this lands: `pallet-mm-rebate` v0 (designed in `mm-rebate-program-design.md`) is the next pallet, and the SaturnSwap frontend rewires from Hydra to Materios — both tracked separately.
