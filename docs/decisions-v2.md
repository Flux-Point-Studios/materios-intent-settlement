# Aegis-on-Materios — Product Decisions v2 (Wave 3 Open Questions)

**Author:** Claude Code agent `materios-aegis-product-v2-openq-2026-04-20`
**Date:** 2026-04-20
**Status:** Draft — awaiting Nathaniel review on product-flag rows.
**Predecessor:** `/home/deci/materios-intent-settlement-decisions.md` (v1, locked 2026-04-20 AM).
**Repo target:** `Flux-Point-Studios/aegis-parametric-insurance-dev` (private). Platform primitive lives in `Flux-Point-Studios/materios-intent-settlement` per v1 locked monorepo-split decision.

These six questions were surfaced in v1's "Questions NOT in the doc" section. They do **not** block Wave 2 (pallet + Aiken library); they **do** block Wave 3 (Aegis dApp build). Engineering-default rows can start immediately once Wave 2 ships; product-flagged rows need sign-off first.

---

## Summary table

| # | Question | Proposed default | Product / engineering? |
|---|---|---|---|
| 1 | Pool utilization + solvency bounds | Target 50% utilization, hard cap 75%; enforced at `submit_intent` by committee via a `PoolUtilization` pallet-storage struct updated on every bind/expire/claim; keeper-free oracle read | **product** (the cap is a public promise) |
| 2 | Premium pricing oracle | `PremiumPolicy` trait on the Aiken validator with three shipped impls: (a) `FlatRate` v1, (b) `LinearInStrikeDistance` v1.5, (c) `BlackScholesWithIV` v2 (gated on a live Block-Scholes-style IV feed for ADA) | **product** (v1 flat-rate is a simplification users will feel) |
| 3 | LP lifecycle + redemption | Cooldown-window redemption: LP signals intent, 7-day notice, redeemed pro-rata of pool NAV minus outstanding-claim reserve; no haircut in normal conditions, pro-rata haircut only during an active claim-batch | **product** (affects LP marketing) |
| 4 | Regulatory classification + US geofence | Classify as "parametric cover product, non-US only, non-accredited-OK under Cayman/BVI wrapper TBD"; frontend geofence via IP + wallet screening (TRM-lite) + on-sign attestation; validator does NOT reject US-flagged claims (enforcement at frontend + legal wrapper, not at Aiken layer); pre-empt NY BitLicense + CA DFPI + TX SSB by frontend-blocking those three states explicitly | **product** (legal + comms) |
| 5 | Cardano halt / L1-degradation circuit breaker | Committee-side: pause attestations after 3 consecutive missed Cardano blocks (~60s gap); resume after 3 consecutive produced. UI: banner "Cardano L1 is degraded — settlement paused, your claim is safe and will process when L1 recovers." TTLs auto-extend by the pause duration. If >24h: committee issues a `degradation_extension` attestation extending ALL outstanding policy expiries by the observed halt window; anchored to Cardano once L1 is back | **product** (the UX promise matters) |
| 6 | Multi-product validator registry pattern | Ship `aegis-policy-v1` as single-product-per-deployment for v1; add `aegis-policy-v2-registry` as a separate track post-mainnet once a second product line (depeg, weather) actually has a customer | **engineering with product input** |

---

## Q1 — Pool utilization + solvency bounds

### Proposed default

Hard cap: **75%** of pool NAV as outstanding coverage. Target: **50%** — above which `PremiumPolicy` (Q2) scales premiums up. Enforced at `submit_intent` time via a Materios pallet-storage value `PoolUtilization { total_nav, outstanding_coverage }` updated on every `BindPolicy`, `ExpirePolicy`, `SettleClaim`. Committee rejects any intent that would push utilization above the cap.

Enforced on Materios, not Cardano. The Aiken validator trusts the committee; committee can't lie without a detectable fairness-proof violation (outstanding-coverage is anchored in every batch — auditors can recompute from the Cardano UTxO set).

### Alternatives

- **Alt A: Enforce at Cardano validator level.** Pros: trustless. Cons: requires a utilization-ledger UTxO that every bind mutates, which serializes all binds into one contention point. Kills throughput.
- **Alt B: Dynamic cap based on pool age + realized loss ratio.** Sophisticated but requires real loss data we don't have. Ship simple, iterate.
- **Alt C: No cap.** First catastrophe wipes LP confidence (ref: undercollateralized DeFi insurance protocols that died 2021–2022).

### Reasoning

Nexus Mutual runs at ~20% effective utilization (MCR = Active Cover / 4.8) — extreme but explains its runway. Parametric cover with narrow trigger ranges (ADA/USD strike) has lower correlated-loss risk than smart-contract cover, so 50%/75% is safely higher than Nexus. The 25% buffer covers a simultaneous-claim event; Q2 premium scaling absorbs the soft signal before the hard cap. Hard cap is a circuit breaker, not a normal operating constraint.

### Needs Nathaniel decision

Approve 50%/75% or propose different numbers; confirm the cap is a public marketing claim.

---

## Q2 — Premium pricing oracle

### Proposed default: `PremiumPolicy` pluggable trait, three impls shipped over time

Aiken validator exposes a `PremiumPolicy` datum: `(Variant, Params)`. At bind time the validator computes expected premium and rejects if user-paid < computed.

1. **`FlatRate(bps)` — v1 (ships Wave 3).** e.g. 200 bps of face, per 7-day term. No oracle. Users know cost upfront.
2. **`LinearInStrikeDistance { base_bps, slope, utilization_surcharge }` — v1.5, ~3 months post-launch.** Scales with strike distance (via Charli3 spot) and pool utilization. Still deterministic.
3. **`BlackScholesWithIV { iv_feed_policy_id, iv_feed_asset_name }` — v2, gated on live ADA IV feed** (Block Scholes is the likely provider; none exists today). Validator reads BSM inputs from an oracle UTxO and computes premium on-chain.

LPs don't set premium directly. They set a per-pool "minimum acceptable rate" governance parameter; if computed premium drops below floor, that pool stops accepting binds. Opt-out, not per-policy bidding.

### Alternatives

- **Alt A: LP bonding curve — LPs quote a premium ladder.** Pros: market-discovered. Cons: requires a second orderbook on Materios; doubles intent-settlement complexity for one product.
- **Alt B: Flat rate forever, no pluggable trait.** Minimum complexity but leaves money on the table (near-the-money covers should cost more) and v2 upgrades require full validator rewrite.
- **Alt C: Offchain pricing oracle — FPS publishes a signed price.** Breaks the "committee never asserts a price" invariant from v1 Q4.

### Reasoning

Pluggable-trait lets us ship simple (flat) now without repainting architecture later. Lyra/Derive and Deri proved Black-Scholes AMM pricing works on-chain but only with a reliable IV feed — none exists for ADA yet. Linear-in-strike-distance is the honest middle ground, matching how traditional weather/catastrophe parametric insurance is priced. Trait surface on Aiken is small: one `verify_premium(...) -> bool` pure function. Upgrade from v1 to v1.5 = redeploy validator + migrate pools on expiry (live policies undisturbed).

### Needs Nathaniel decision

Approve flat-rate for v1; confirm LP-floor escape hatch; roadmap v1.5/v2 on the tokenomics + docs calendar.

---

## Q3 — LP lifecycle + redemption

### Proposed default: cooldown-window redemption + pro-rata haircut only during an active claim-batch

1. **Deposit.** LP sends ADA to the pool-custody validator; receives pool-share tokens (Cardano native token, policy ID = pool validator hash; 1 share = 1 unit of NAV at deposit).
2. **Earn.** Premium income accrues; shares grow proportionally in NAV.
3. **Request redeem.** LP calls `request_redemption(amount)` on Materios; balance locks (non-transferable); **7-day cooldown** starts.
4. **Execute redeem.** After cooldown, LP calls `execute_redemption` on Cardano (direct-path, no committee). Aiken validator releases pro-rata share of non-reserved NAV (= NAV − outstanding-claim-reserve). In normal operation LP gets full pro-rata NAV; during an active claim batch LPs are blocked and the cooldown clock pauses.
5. **Catastrophe haircut.** If a claim batch settles mid-cooldown, LP's payout drops with pool NAV pro-rata — no separate haircut math.

### Alternatives

- **Alt A: Wait-until-expiry.** Fairest to policyholders but 90-day policies = 90-day LP illiquidity. Kills the LP product.
- **Alt B: No cooldown, pro-rata haircut at redemption.** Full liquidity but creates a bank-run dynamic — first-redeemer gets better pricing than last-redeemer (opposite of v1 Q8 fairness).
- **Alt C: Lockup tranches (30d / 90d / 180d).** UX complex; tranches look like a fund product (regulatory red flag per Q4).

### Reasoning

Cooldown windows are how mature DeFi handles deposit-vs-liability tension (Lido stETH unstaking, Compound vault exit delay). 7 days = asset feels liquid, but bank-run can't drain during a catastrophe. The "pause during claim batches" rule is the real innovation — prevents LP redemption and claim settlement from colliding, which killed Cover Protocol in 2021. Indigo's CDP-redemption structure (2% fee split 1%/1%) inspires the "redemption as settled on-chain event" framing, but we take no fee on normal LP exits (premiums already pay the protocol).

### Needs Nathaniel decision

Approve 7-day cooldown (vs 5/14/30); confirm "pause during claim batches" as a product promise; approve pool-share as a Cardano native token (vs a Materios pallet-balance).

---

## Q4 — Regulatory classification + US geofence

### Proposed default: "parametric cover product, non-US only, via offshore legal wrapper (BVI or Cayman TBD), with layered US + state geofence at the frontend"

**Legal classification (how we talk about it):**
- **Marketing copy:** "parametric cover" or "parametric protection." Never "insurance" (regulated term in most US states + EU), never "derivative" (CFTC trigger), never bare "policy."
- **Legal memo:** commissioned from a crypto-native firm (Cleary, DLA Piper, Perkins Coie). Target: letter classifying parametric cover as a "conditional payment product" under Cayman/BVI law. Budget: $15–30K.
- **Wrapper entity:** BVI or Cayman Foundation Company. Standard DeFi precedent (Maker, Lido, Aave). Setup ~$30–50K + ~$15K/year.

**US geofence (layered):**
1. **IP block** at frontend (Vercel edge geo API) for US + OFAC-sanctioned jurisdictions.
2. **Wallet screening** (TRM Labs lite) for OFAC-flagged addresses — Uniswap precedent (2022–ongoing).
3. **On-sign attestation.** Before bind/claim, user signs "I am not a US person, not in {state list}, understand this is parametric cover not insurance." Stored off-chain for dispute response.
4. **No validator-level US rejection.** Aiken validator doesn't know jurisdiction. Deliberate: validator can't verify out-of-band data, and gating it would kill the direct-path fallback.

**State-level pre-empted blocks (beyond US-wide):** NY (BitLicense), CA (2024 DFA Law), TX (SSB aggressive on synthetics). Blocked at frontend by IP + KYC signal.

**Does the validator reject US-flagged claims? No.** The validator is jurisdictionally neutral; enforcement is frontend + legal wrapper. If a US person evades the geofence via raw tx, FPS's position is "we didn't offer it, they self-served" — the OlympusDAO / Aave / Uniswap posture.

### Alternatives

- **Alt A: US-only with licensed insurance carrier.** Biggest market but $5–20M licensing, 18–36 months, and "parametric crypto insurance" isn't a licensable product in most states. Not viable for v1.
- **Alt B: No geofence.** FPS is a DE Inc with a named founder — not acceptable per `feedback_us_token_launch_regulatory.md`.
- **Alt C: Classify as prediction market (Kalshi precedent).** CFTC DCM licensing is slower + more expensive than offshore. Also conflates hedging with gambling.

### Reasoning

Offshore-foundation-for-non-US-retail is the 2024–2026 standard for DeFi products that can't wait for US regulatory clarity (Maker, Lido, Aave precedent). Costs money but is the only path that ships in 2026 without a 3-year licensing journey. US is explicitly out-of-scope for Aegis v1 revenue; US-compliant variant can come later via Reg CE or a carrier partner. The legal memo matters not because it protects us, but because having-a-memo-on-file is a material mitigating factor in SEC/CFTC enforcement precedent.

### Needs Nathaniel decision

Approve offshore-wrapper path (or escalate US-compliant / kill); approve $15–30K memo budget; approve state blocklist (NY/CA/TX minimum; OR/WA?); confirm no validator-level geofence.

---

## Q5 — Cardano halt / L1-degradation failure mode

### Proposed default: tiered circuit breaker + degradation banner + auto-TTL-extension for >24h halts

**Committee-side:**
1. **Detect.** Daemon watches Cardano via Ogmios + db-sync. No new Cardano block for 60s (~3 blocks at 20s cadence) → enter `Degraded`.
2. **Pause.** While `Degraded`, committee stops signing intent→voucher transitions. Pending intents frozen at current state (not expired). New `submit_intent` calls on Materios still succeed but sit unattested.
3. **Resume.** After 3 consecutive Cardano blocks (~60s healthy), exit `Degraded`. Backlog processed FCFS per v1 Q8 fairness.
4. **Long-halt extension.** If `Degraded` lasts >24h cumulative, committee publishes `DegradationExtension` attestation on Materios listing the halt window. All pending intents + policies with `expiry_slot` within 48h of halt-end get TTLs extended by halt duration + 1h buffer. Anchored to Cardano on recovery (label 8746).

**User-facing UI:**
- **Banner:** "Cardano L1 is experiencing a brief delay. Your {policy|claim|bind} is safe and will continue processing automatically when L1 recovers."
- **Direct-path Claim button disabled during `Degraded`** (the Cardano validator needs L1 blocks to settle; direct-path doesn't help).
- **LP cooldown clock pauses** during degradation (see Q3).

**Recovery:** normal batch resumes on exit. No TTL extension for <24h halts (Jan 2023 halt was 7min; matches precedent). Post-mortem anchored for every `Degraded` event >5 min.

### Alternatives

- **Alt A: No circuit breaker.** Keepers submit batches that fail at the Cardano validator (stale oracle UTxO); wasted fees and noisy logs.
- **Alt B: Auto-refund in-flight intents after N minutes.** User might prefer to wait — their trigger already fired, a refund = lost payout. Also a DoS vector (attacker triggers Cardano blip → mass refunds).
- **Alt C: Bridge to another L1 for settlement.** Cross-chain fraught, out of scope, worse trust than the halt itself.

### Reasoning

Jan 2023 Cardano halt is the natural experiment: 50–60% of nodes dropped, block times degraded to 1.5–2 minutes for 3 blocks, total impact ~7 minutes. Ouroboros degrades, doesn't fail. Expected failure mode = brief, self-healing, not 24h outage. Design matches: pause briefly, communicate, resume. The 24h TTL-extension threshold covers tail-risk only; a user's 7-day policy shouldn't silently expire because L1 was down 3 days. Extension attestation is anchored to Cardano post-recovery so there's an immutable record the committee didn't fabricate it. Also interacts with Q4: "your cover is safe during L1 degradation" is a regulatory claim we need to honor to avoid reclassification as a "non-guaranteed payment" product.

### Needs Nathaniel decision

Approve 60s detection + 24h TTL-extension + post-recovery anchor mechanism; sign off on banner copy (becomes whitepaper boilerplate).

---

## Q6 — Multi-product validator registry pattern

### Proposed default: **single-product-per-deployment for v1. Ship the registry pattern only after a second product line has a real customer.**

For Wave 3, Aegis ships `aegis-policy-v1` with ONE product: ADA/USD strike parametric cover. The Charli3 feed is hardcoded (per v1 Q4). Each future product (ADA/BTC strike, USDM depeg, weather/temperature derivatives) gets a fresh validator deployment, fresh Aiken code, fresh audit, fresh pool.

The registry pattern (`aegis-policy-v2-registry`) — where a single validator deployment reads a `ProductConfig` datum and serves any registered product from the same codebase — is a **separate track**, gated on:
- Second product line actually having a signed customer
- Materios governance pallet (v1 locked decision) being mature enough to govern registry registrations
- Audit budget for the registry-specific code (substantially larger audit surface)

### Alternatives

- **Alt A: Registry on day 1.** Every new product is a potential backdoor into unrelated products; registry is a new attack vector. Indigo V2 spent most of 2024 on a similar refactor.
- **Alt B: Hybrid — registry for homogeneous (crypto strike), per-deployment for exotic (weather).** Two code paths, double audit cost, no full benefit of either.

### Reasoning

Registry benefit is amortized across N products; N=1 means no amortization. Ship simple, prove PMF with ADA/USD strike, then decide if products 2+3+4 warrant the registry investment. The v1 Aiken code should be written with registry-readiness in mind (pure verification functions, clean datum scheme, no hardcoded feed assumptions inside the core) — this is cheap at design time but expensive to retrofit later.

### Needs Nathaniel decision

Confirm single-product v1 + future-track registry; confirm Aiken code should be registry-ready at no extra cost (my rec: yes).

---

## Cross-cutting observations

1. **Q1 ↔ Q3.** LP redemption uses `outstanding_coverage` as the reserve. At 75% cap, redemption pulls from the 25% unused buffer first; if fully committed, redemption scales pro-rata. Document this in the LP FAQ.

2. **Q2 ↔ Q4.** Black-Scholes pricing looks derivative-like to regulators (options → swap classification). Flat-rate looks more insurance-like. V1's flat-rate choice is therefore also a regulatory-positioning choice. Preserve that framing in the Q4 legal memo.

3. **Q5 ↔ IDP panic.** Materios has its own degradation mode (sc_epoch boundary, per `feedback_iog_idp_none_panic.md`). Committee daemon should distinguish "Cardano degraded" vs "Materios degraded" in telemetry and UI. Don't conflate.

4. **Q4 is the only blocking item.** Q1/Q2/Q3/Q5/Q6 can start engineering once Wave 2 ships. Q4 needs outside counsel before a go-live date is set. Commission the memo this week in parallel; treat it as a gate on mainnet (not testnet demo).

5. **Midnight ZK is phase-2 for all six.** Q1 utilization, Q2 premium computation, Q3 LP positions, Q4 jurisdictional attestation — all have ZK-privacy upgrades on the roadmap. Note in `project_midnight_poc_findings.md`, don't front-load.

6. **Committee expansion (2-of-7 → 5-of-11) becomes more material with Q5.** A 2-of-7 during a Cardano halt hits availability risk (any 2 offline = frozen). 5-of-11 requires 6 up. Flag to the committee-expansion workstream as a robustness motivator.

---

## Handoff notes

**Wave 3 engineering mapping:**

- **Q1** → `pallet_aegis::pool_utilization` storage + `submit_intent` pre-check. ~2 days.
- **Q2** → Aiken `PremiumPolicy` trait + `FlatRate` impl for v1. ~3 days. v1.5/v2 impls land as separate waves.
- **Q3** → `pallet_aegis::lp_lifecycle` (cooldown scheduler, `request_redemption` / `execute_redemption`) + Cardano pool-share mint policy. ~1 week across pallet + Aiken.
- **Q4** → blocked on legal memo; frontend geofence + state-list is ~2 days engineering, but go-live gate is legal.
- **Q5** → committee-daemon `DegradedState` handler + `DegradationExtension` attestation + pallet TTL extension logic + UI banner. ~1 week across daemon + pallet + frontend.
- **Q6** → design discipline. V1 Aiken code must be modular (pure verification functions, clean datum scheme) to keep v2 registry cheap.

**Doc updates to land alongside v2:**

- `project_materios_intent_settlement_dapp.md` — append v2-resolution in status section.
- `project_security_followups.md` — add Q4 legal memo as a mainnet gate.
- Q1 utilization + Q5 degradation parameters should be governance-tunable storage, consistent with `ATTESTATION_REWARD_PER_SIGNER` / `ATTESTATION_ERA_CAP`.

**Next agent dispatches:**

- Legal memo RFP drafter — 1-page brief + 3-firm shortlist. Runs in parallel with Wave 2.
- Aiken `PremiumPolicy` trait designer — trait sig + `FlatRate` impl before Wave 3 starts.
- Committee-expansion continuation — Q5 adds robustness motivator to the existing scoping agent.

**One-shot decision block for Nathaniel:**

1. Q1 — approve 50% / 75% target/cap?
2. Q2 — approve flat-rate v1 + pluggable-trait architecture?
3. Q3 — approve 7-day cooldown + pause-during-claims?
4. Q4 — approve offshore-wrapper + $15–30K legal memo budget + state blocklist (NY, CA, TX)?
5. Q5 — approve 60s detection + 24h TTL-extension threshold + banner copy?
6. Q6 — confirm single-product v1, registry-ready Aiken code, registry deployment as separate future track?

Six thumbs-ups = Wave 3 has zero open product questions and TDD can start immediately after Wave 2 ships.

— end —
