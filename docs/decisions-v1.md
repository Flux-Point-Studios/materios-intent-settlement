# Aegis / Materios Intent-Settlement Layer — Open Questions v1 Resolutions

**Author:** Claude Code agent `aegis-materios-open-questions-2026-04-20`
**Date:** 2026-04-20
**Status 2026-04-20 PM: LOCKED by Nathaniel.** All 6 product decisions + repo strategy + committee expansion resolved. See "Locked decisions" below. Engineering can start TDD build immediately on the engineering-default items (Q2/Q4/Q7/Q9/Q11); Wave 1 spec agent dispatched for interface-contract resolution.

## Locked decisions (2026-04-20)

| # | Decision |
|---|---|
| Q1 | **ADA credits.** TODO: MATRA once mainnet price/liquidity exists. |
| Q3 | **ADA bond for v1.** v1.5 prep workstream: publish a MATRA/ADA Charli3 feed (see Charli3 SDK docs for publishing flow) so the MATRA-bond variant can land in v1.5. |
| Q5 | **Build in the existing private fork** at `Flux-Point-Studios/aegis-parametric-insurance-dev` (already private, already forked from hackathon origin). Do NOT touch the public hackathon repo. The new Aiken validator library goes here, not in a standalone repo. |
| Q6 | **Proper governance pallet NOW (not v1.5).** Ship `pallet_committee_governance` as Wave-2 deliverable alongside `pallet_intent_settlement`. Initial authorization still via 2-of-3 Nate+K2+K3 multisig-sudo + 24h timelock + public announcement; the pallet is the on-chain record-of-truth and the Cardano mirror. DAO-vote migration is v2. |
| Q8 | **Pro-rata scaling + FCFS tiebreak + anchored fairness-proof.** Approved as proposed. |
| Q10 | **Public copy approved** as proposed: *"6-second confirmation on Materios, settles on Cardano in the next batch window (typically under a minute), and a direct-to-Cardano fallback is one click away if the committee ever delays you."* |
| Repo | **Monorepo-split.** New repo `Flux-Point-Studios/materios-intent-settlement` = platform primitive (pallet + keeper + SDK). Existing private repo `Flux-Point-Studios/aegis-parametric-insurance-dev` = Aiken validators + Aegis dApp + frontend, consumes the primitive. |
| Committee expansion | **Run 2-of-7 → 5-of-11 in parallel**, gate Aegis mainnet launch on it. Does NOT gate preprod demo. |
| Engineering defaults (Q2/Q4/Q7/Q9/Q11) | **Approved as proposed.** Engineering starts with these implementations. |

Follow-up workstreams kicked off:
- Wave 1 spec agent — interface contracts (pallet ↔ Aiken ↔ keeper)
- v2 open-questions agent — resolve 6 new questions surfaced in "Questions NOT in the doc" section below
- Committee-expansion scoping agent — 2-of-7 → 5-of-11 rollout plan (new attestor selection, timing, mainnet gate sequencing)
**Input doc:** https://github.com/Flux-Point-Studios/aegis-parametric-insurance-dev/pull/1 (`docs/materios-integration/README.md`, branch `materios-integration`, 336 lines)
**Memory refs used:** `project_materios_architecture.md`, `project_spo_crossvalidation.md`, `project_v5_chain.md`, `project_v5_1_tokenomics.md`, `project_cardano_l1_metadata_labels.md`, `feedback_cardano_explorer.md`, `feedback_materios_mempool_ops.md`, `feedback_iog_idp_none_panic.md`, `reference_orynq_mcp.md`, `project_midnight_poc_findings.md`.

> **Doc corrections to land before engineering starts.** The design doc asserts a "3-of-8" Materios committee; live preprod v5 is **7 members, threshold 2** (4 validators + 3 external attestors, per `project_spo_crossvalidation.md`). That doesn't materially change the architecture but every code/copy reference to "3-of-8" must be rewritten as "M-of-N where current preprod is 2-of-7, mainnet target TBD (see Q6)". Second correction: the doc mentions MATRA as a fee token; MATRA is the capital/transferable token, **MOTRA** is the non-transferable decaying fee token (`project_v5_chain.md`, `feedback_materios_architecture.md`). Anywhere premiums or bonds are denominated in "MATRA" that's correct; anywhere a gas/relayer fee is implied, that's MOTRA.

---

## Summary table

| # | Question | Proposed default | Needs Nathaniel decision? |
|---|---|---|---|
| 1 | Credit denomination for pre-fund | **ADA** (native, no token-risk, best liquidity on Cardano today) | **YES — product** |
| 2 | Refund path for unused credits | User-initiated `withdraw_credit` on Materios → keeper batches a Cardano refund tx from the premium-collector script; minimum 1-epoch dwell; keeper keeps 50 bps (capped 1 ADA) | NO — engineering |
| 3 | Bond currency + slashing | **ADA-denominated bond** on Cardano (not MATRA) for v1; switch to MATRA once there's a live cMATRA market + oracle | **YES — product** |
| 4 | Charli3 oracle trust | Hardcode the feed's policy ID + asset name per product (strike-price feed) in the Aiken validator; Cardano validator re-reads oracle at tx-time; committee only *schedules*, never asserts price | NO — engineering |
| 5 | Aiken validator ownership | **Build our own** `aegis-policy-v1` Aiken validators from scratch under Flux Point Studios, additive to the hackathon branch; do NOT touch hackathon-graded repo | **YES — product** (confirms scope) |
| 6 | Committee pubkey rotation on Cardano | v1: 2-of-3 multisig-sudo admin-rotation + 24h timelock + public announcement; v1.5: on-chain governance via a dedicated `pallet_committee_governance` that mirrors to Cardano via anchor tx | **YES — product** |
| 7 | State reconciliation / stale intent GC | Intents auto-expire after `IntentTTL` Materios blocks (default 1 hour = 600 blocks); expired intents refundable; Cardano-side policy expiry is the source of truth and committee daemon watches for it | NO — engineering |
| 8 | Committee fairness in liquidity run | Pro-rata scaling + FCFS tiebreak. Committee signs a per-batch fairness-proof (sorted intent-hash list + pro-rata math) anchored with the bundle | **YES — product** (fairness model is a marketing claim) |
| 9 | Keeper fee currency + payer | **ADA, paid from the Cardano-side batch output** (deducted from pool, not from user). Fee = base (0.5 ADA) + 50 bps × batched value, capped at 2% of batch | NO — engineering |
| 10 | Timing honesty in product copy | See Q10 paragraph below — lead with "6-second confirmation, settles on Cardano in the next batch window" | NO — engineering (but needs comms sign-off) |
| 11 | Direct-path Claim fallback spec | Existing `Claim` redeemer unchanged; UI exposes a "Claim directly on Cardano" button after voucher-wait > 10 minutes; ~1.5 ADA fee + ~30s wait; no committee signature needed | NO — engineering |

---

## Q1 — Credit denomination for pre-fund pattern

### Proposed default: **ADA**

ADA is the only asset with guaranteed liquidity on Cardano today, no token-contract risk, no stablecoin peg assumption, and no dependence on a MATRA mainnet that **does not exist yet** (`project_v5_chain.md` confirms preprod only; mainnet token has no market price). Aegis sells parametric insurance priced against ADA-denominated underlyings — denominating premiums in ADA avoids an FX leg entirely.

### Alternatives
- **Alt A: cUSD / USDM / iUSD.** Pros: stable premium accounting for users; insurance is typically priced in dollars. Cons: each stablecoin has independent de-peg risk (iUSD has had historical issues); liquidity is fragmented across Minswap + WingRiders + SundaeSwap; adding a stablecoin dependency couples Aegis uptime to that issuer's uptime. **Reconsider for v1.5 once we pick one winner.**
- **Alt B: MATRA.** Pros: captures value to our own token; circular flywheel. Cons: no mainnet MATRA yet, no price discovery, preprod-only (`project_materios_architecture.md`). Hard-blocker for v1.
- **Alt C: Basket.** Pros: user optionality. Cons: 3× the integration work, makes keeper/oracle accounting painful. Kill for v1.

### Reasoning
Premiums are low-value, high-frequency. ADA is universally available. The pre-fund script address accepts ADA deposits, keeper watches for them via `submit_intent`-referenced tx hashes, writes `Credits<AccountId>` on Materios. No token contract = no additional audit surface.

### What Nathaniel needs to decide
Whether to carry a stablecoin add-on into v1 scope (my rec: no — ship ADA-only, add stable in v1.5).

---

## Q2 — Refund path for unused credits

### Proposed default
User calls `pallet_aegis::request_credit_refund(amount)` on Materios → intent is committee-attested (2-of-N) → keeper includes a refund output in the next batch Cardano tx, drawn from the premium-collector script (redeemer `RefundCredit{voucher}`). Minimum **1 epoch (5 days on preprod Cardano)** dwell before refund is eligible (prevents round-trip arb if ADA moves). Keeper earns 50 bps of refund amount, capped at 1 ADA.

### Alternatives
- **Alt A: Automatic expiry-triggered refund.** Pros: zero user action. Cons: lots of dust refunds; user may have moved wallets; keeper-initiated refund to a script-derived stealth address gets messy.
- **Alt B: Credits are non-refundable, convert to a transferable SBT on Materios.** Pros: simple. Cons: regulatorily looks like an unregistered gift card; `feedback_us_token_launch_regulatory.md` flags this as an avoid-zone for a DE Inc.

### Reasoning
User-initiated refund keeps the UX honest (explicit withdrawal = explicit intent), gives us a natural dwell window to batch efficiently, and avoids building dust-sweep automation. Refund redeemer on the premium-collector script is additive, same Aiken structure as `BatchClaimVoucher`.

### What Nathaniel needs to decide
Nothing — this is an engineering-default.

---

## Q3 — Bond currency + slashing (if we offer a MATRA-bond variant)

### Proposed default: **Do not ship a MATRA-bond premium variant in v1. Ship ADA pre-fund only.** If v1.5 adds a bond variant, denominate the bond in **ADA on Cardano** (not MATRA), with on-Cardano slashing to the pool script.

### Alternatives
- **Alt A: MATRA bond on Materios.** Pros: captures value to our chain. Cons: **circular pricing problem** — if MATRA price crashes, bond becomes under-collateralized precisely when it's being slashed, which further depresses the price. No MATRA mainnet market (`project_materios_architecture.md`) to source a reliable oracle price anyway. Slashing requires a live cMATRA Cardano market, which v5.1 tokenomics (`project_v5_1_tokenomics.md`) notes is launching on SaturnSwap CLOB but has not yet happened.
- **Alt B: Hybrid — MATRA bond with ADA liquidation backstop.** Pros: some value capture. Cons: 2× the complexity, still needs the MATRA oracle, and now also needs a liquidation keeper on Materios. Overkill for v1.

### Reasoning
Deterrent math for an ADA bond: if Aegis policy face value = $X and delinquency risk = 2%, bond = 3× expected loss = $0.06·X, minimum 5 ADA floor. Slashed bond flows to the pool script, adding to LP yield. Simple, works today.

MATRA-bonds become viable once (a) cMATRA/ADA market is live on SaturnSwap with $250K depth (v5.1 target), (b) a Charli3 feed publishes MATRA/ADA on Cardano, and (c) the bridge pallet is production-audited (`project_materios_bridge.md` notes this is early-stage).

### What Nathaniel needs to decide
Whether to explicitly deprioritize MATRA-bonds from the v1 scope so we don't accidentally build it. My rec: yes, defer to v1.5 gated on cMATRA listing.

---

## Q4 — Charli3 oracle trust integration

### Proposed default
The Aiken validator hardcodes (policy_id, asset_name) for the Charli3 feed relevant to each product (e.g. ADA/USD strike). At tx time, the validator re-reads the Charli3 datum from the referenced oracle UTxO — **the committee never asserts a price value**, it only asserts "this oracle UTxO is the one to consult for this claim." Feed rotation = new deployed validator version. Bad data (feed goes stale > N slots) = validator rejects the voucher, user falls back to direct-path Claim (Q11).

### Alternatives
- **Alt A: Committee maintains an allowlist of valid oracle UTxOs and signs "this is the current canonical one."** Pros: faster feed swaps. Cons: committee gains ability to substitute feeds, which breaks the "committee can't fabricate payouts" invariant.
- **Alt B: Multi-feed with median (Charli3 + Orcfax + SundaeSwap).** Pros: defense in depth. Cons: 3 integrations, 3 points of failure, slows validator CPU budget.

### Reasoning
The invariant in the design doc ("committee cannot fabricate oracle events") requires Cardano re-verifies. Hardcoding the feed policy_id achieves that. Charli3's ADA/USD feed is battle-tested and is what FluidTokens + Indigo already depend on. This mirrors how Indigo Protocol's CDP validators gate on Charli3.

### What Nathaniel needs to decide
Nothing — engineering decision. But flag: whenever we rotate feeds we redeploy the validator, which means existing policy UTxOs need migration. Plan for that in the Aiken code (support "old feed policy_id OR new feed policy_id" during transition).

---

## Q5 — Aiken validator ownership + coordination

### Proposed default: **Build our own `aegis-policy-v1` Aiken validators from scratch** in a new Flux Point Studios repo (e.g. `aegis-aiken-v1`). Do **NOT** modify the hackathon-graded repo's validators. The design doc's "additive new `BatchClaimVoucher` redeemer on policy validator" should be read as "new redeemer on OUR validator, which is a fresh implementation based on the same insurance semantics."

### Alternatives
- **Alt A: Fork the hackathon validators and add the redeemer.** Pros: leverages research already done. Cons: conflates hackathon grading surface (frozen) with Materios-integration production code (iterating). Merging back is messy.
- **Alt B: License an existing parametric insurance Aiken codebase from another team (Indigo, Lenfi, etc.).** Pros: audit shortcut. Cons: none of them are parametric-insurance-specific; we'd pay for a worse fit.

### Reasoning
The hackathon repo is being judged — touching it mid-judge is a brand risk. Aegis on Materios is a Flux Point Studios product, not a hackathon entry. A clean-room Aiken implementation under our own GitHub org aligns with the `reference_flux_point_repos.md` ecosystem-repo map. Reuses research from the hackathon work without taking on the coordination + submission freezes.

### What Nathaniel needs to decide
Confirm the new repo name + whether to house it in `Flux-Point-Studios/*` or a subdirectory of the existing `materios` monorepo. My rec: standalone repo (easier to audit independently).

---

## Q6 — Committee pubkey rotation governance on Cardano

### Proposed default
**v1 (6-month window):** `CommitteePubkeySet` is a protocol parameter on the Aiken validator, updatable by the same 2-of-3 Nate+K2+K3 multisig-sudo that governs the Materios chain today (`reference_multisig_sudo.md`). 24h timelock + public announcement on GitBook before any rotation takes effect. Rotation tx hash anchored to Materios under label 8746 (`project_cardano_l1_metadata_labels.md`) for audit-trail.

**v1.5 (post-mainnet):** add `pallet_committee_governance` that holds elected attestor set on Materios; a rotation tx is composed off-chain from Materios state + signed by 2-of-3 sudo; ultimately migrates to council voting.

**v2:** Full on-chain DAO vote with quorum. Out of scope for this design.

### Alternatives
- **Alt A: Keeper-triggered rotation, committee signs for itself.** Pros: decentralized from day 1. Cons: committee-signs-its-own-turnover is a governance anti-pattern; any captured committee would self-perpetuate.
- **Alt B: Skip governance entirely, keys are forever.** Pros: simplest. Cons: first lost/leaked key = full pool at risk.

### Reasoning
The committee is currently 4 validators + 3 attestors (`project_spo_crossvalidation.md`). The 4 validators already rotate via mainchain Ariadne selection (partner-chains); the 3 attestors are permissioned. Until attestor-selection is decentralized via Ariadne (not on the roadmap for 2026 per `project_v5_1_tokenomics.md`), admin-rotation is honest and not a downgrade from the rest of the stack.

Critically: the committee expansion implied by the design doc ("3-of-8") doesn't exist. We need to decide between:
1. Stay 2-of-7, accept a narrower trust base
2. Expand to something like 5-of-11 pre-mainnet (adds 4 external attestors)

Expansion also helps Q8 (fairness) — more signers = harder to collude on ordering.

### What Nathaniel needs to decide
Whether to target a committee expansion before shipping Aegis-on-Materios v1. My rec: ship with current 2-of-7 for preprod demo, expand to 5-of-11 before any mainnet value is at risk.

---

## Q7 — State reconciliation + stale intent GC

### Proposed default
Intents include a `ttl_block: u32` field (default 600 blocks = ~1 hour at 6s blocks). On-chain expiry in `on_initialize`: if `now > ttl_block`, intent is marked `Expired` and credits are auto-refunded to the depositor. Claims have a longer TTL: 28,800 blocks (~48 hours). Cardano-side policy expiry is watched by the committee daemon (mirrors how the Charli3 oracle watcher works per the design doc); when the Cardano validator Expires a policy, the committee posts an `expire_policy_mirror` attestation on Materios to clean local state.

If the committee goes offline mid-attestation, intents stall at `Pending` until TTL. No state corruption because nothing is irreversibly committed until Cardano confirms. Worst case: users wait up to `IntentTTL` for automatic refund.

### Alternatives
- **Alt A: Keeper garbage-collects (permissionless).** Pros: no `on_initialize` overhead. Cons: requires a keeper economic incentive for GC work (fees on an empty refund are negative) — means we'd have to subsidize GC.
- **Alt B: Users manually garbage-collect their own intents.** Pros: simplest code. Cons: griefing vector — stale intents clog the attestor queue forever if user abandons wallet.

### Reasoning
On-chain TTL expiry is the idiomatic Substrate pattern (mirrors how `pallet_orinq_receipts` handles receipt expiry per `feedback_materios_mempool_ops.md`). It's bounded work per block (iterate pending intents scheduled for this block) — acceptable with capped per-block attestation throughput. Covers both the liveness failure mode and ghost-user abandonment.

### What Nathaniel needs to decide
Nothing — engineering default. Note: `IntentTTL` becomes a governance-tunable storage value (similar to `ATTESTATION_REWARD_PER_SIGNER` per `project_v5_1_tokenomics.md`).

---

## Q8 — Committee fairness in a liquidity run

### Proposed default: **Pro-rata scaling with FCFS tiebreak, fairness-proof per batch.**

If pool can't cover all triggered claims at face value, each beneficiary receives `(pool_balance × my_claim) / sum(all_claims_this_window)`. Within a time slice (1 hour), ordering is strictly first-come-first-served by `intent_submission_block` (with `intent_hash` as tiebreak for same-block ties). The committee signs the sorted list + the pro-rata math, anchored with the bundle to Cardano under label 8746.

### Alternatives
- **Alt A: FCFS only, no scaling.** Pros: simplest. Cons: a bank-run dynamic emerges — early claimants get 100%, late claimants get 0, everyone rushes. Bad for insurance UX; claim arrival time is often correlated with the trigger event being visible, so "slow to notice" isn't the same as "less deserving."
- **Alt B: Auction — claims bid priority.** Pros: market-clearing. Cons: insurance customers expect fairness, not auctions; terrible brand.
- **Alt C: Pro-rata only, no FCFS.** Pros: maximally fair. Cons: requires closing a window before paying anyone, delays payouts by `window_size` for everyone.

### Reasoning
Pro-rata + FCFS is how traditional insurance handles catastrophe-load years (ask any reinsurer). FCFS within a window preserves "I submitted first" intuition. Pro-rata across the window prevents bank-run dynamics.

The fairness-proof (sorted list + math) is the audit hook — anyone can verify the committee ordered fairly by reading the anchor and recomputing. Third-party auditors (security-review firms, Flux Point Studios internal audits) check that the committee daemon code matches the anchored proof.

### What Nathaniel needs to decide
This is a public-facing fairness claim; marketing will want to articulate it. My rec: "pro-rata in catastrophe scenarios, FCFS in normal conditions, provable on Cardano." One sentence for the landing page.

---

## Q9 — Keeper fee currency + payer

### Proposed default: **ADA, paid from the Cardano-side batch output, deducted from pool.** Fee structure: base 0.5 ADA (covers tx fee) + 50 bps × batched value, capped at 2% of batch total. Any keeper who submits a valid batch tx gets the fee at the Cardano output.

### Alternatives
- **Alt A: Per-intent micropayment in MOTRA on Materios.** Pros: captures some fee value to our chain. Cons: no MOTRA mainnet + `feedback_materios_mempool_ops.md` shows MOTRA accounting is complex enough without adding keeper-fee accounting.
- **Alt B: User pays keeper fee out-of-pocket per claim.** Pros: aligned incentive. Cons: user had a bad day (their insurance triggered!) + now also has to pay a fee — bad UX, and for small claims the fee eats the payout.

### Reasoning
Pool-paid keeper fees are analogous to how traditional insurance pays claims-adjusters out of the loss reserve. 50 bps + cap prevents fee extraction on large claims. The Aiken `BatchClaimVoucher` redeemer validates the fee output against the protocol parameter so the keeper can't self-assign a larger fee.

### What Nathaniel needs to decide
Nothing — engineering default.

---

## Q10 — Timing honesty in product copy

### Proposed default (one paragraph, public-facing)

> **How it feels to use Aegis.** When you sign a policy or request a claim, Aegis confirms your action on Materios in about six seconds — you see it land, you get a receipt, and the committee has already started moving. Cardano is the source of truth for your money, and that settlement happens in the next batch window — typically under a minute, and always provably anchored to Cardano mainnet. So: instant confirmation, fast finality on Cardano, and if the committee ever delays you, a direct-to-Cardano fallback path is one click away.

### Why this works
- Names actual numbers (6s, "under a minute", 10-minute fallback threshold) — defensible against audit.
- Names what Cardano does and what Materios does separately.
- Surfaces the committee-censorship mitigation without making it sound like a risk.
- No jargon ("batched settlement", "pro-rata scaling", "voucher") unless the reader wants more.

### Alternatives tested and rejected
- "Instant insurance on Cardano" — implies Cardano itself is instant, which invites "actually Cardano takes 20s to a minute" rebuttals.
- "Lightning-fast parametric insurance" — Lightning is a Bitcoin brand, causes confusion.
- "Aegis gives you Web2 speed and Web3 security" — cliché, also the grownup crypto audience recoils from "Web2 speed."

### What Nathaniel needs to decide
Sign off on the phrasing or suggest tweaks; this becomes the default product description in the explainer, pitch deck, landing page.

---

## Q11 — Direct-path Claim fallback spec

### Proposed default

**Trigger:** 10 minutes after `request_payout` on Materios with no voucher issued, UI surfaces a "Claim on Cardano directly" button. (10 min picked because typical batch window is ≤ 1 min; 10 min = 10× slack = committee is definitely AWOL or refusing.)

**Flow:**
1. User clicks "Claim on Cardano directly"
2. Wallet builds a Cardano tx calling the existing `Claim` redeemer on `aegis-policy-v1`
3. Tx references Charli3 oracle UTxO directly + user's policy UTxO + pool UTxO
4. Aiken validator independently verifies oracle strike, policy terms, pool solvency
5. Payout hits user's address in ~30 seconds (one Cardano block)
6. User pays full Cardano tx fee (~1.5 ADA — larger than batched because it's not amortized)
7. Materios `Claim<H256>` is retroactively marked `SettledDirect` when committee daemon observes the Cardano tx

**Gotchas + edge cases:**
- **No keeper needed.** User signs + submits the Cardano tx from their own wallet. This is the whole point of the fallback — it bypasses every Materios actor including keepers.
- **No committee sig required.** The validator's `Claim` redeemer verifies Charli3 directly without needing a committee attestation (same as pre-Materios Aegis).
- **Frontend UX clue.** The button is disabled until 10 min. The UI shows a countdown ("Direct-path Claim available in 7 minutes") so users understand the fallback exists.
- **Race condition.** User submits direct-path Claim at t=11 min, committee also publishes a voucher at t=12 min. The second tx fails at the Cardano validator (policy UTxO already consumed) — correct behavior, no funds at risk.
- **Expired policies.** If policy is past `expiry_slot`, direct-path also supports `Expire` redeemer — user is still in control.

### Alternatives
- **Alt A: Fallback window = 1 hour.** Pros: committee has more time. Cons: 1 hour of user anxiety ≠ a good insurance UX.
- **Alt B: No UI-surfaced fallback — must know to do it manually.** Pros: less complexity. Cons: defeats the purpose; only power-users get the censorship-mitigation.

### What Nathaniel needs to decide
Nothing — engineering default. Confirm the 10-minute threshold at product review.

---

## Cross-cutting observations

1. **Q1+Q3 interact.** If premiums are ADA (Q1) and bonds (if we add them) are also ADA (Q3), the accounting is simple: all user-facing value on Cardano is ADA, all fee/gas on Materios is MOTRA (auto-generated per `project_v5_chain.md`). MATRA never appears in the Aegis v1 user flow.

2. **Q6+Q8 interact.** Committee expansion from 2-of-7 to 5-of-11 materially improves both rotation governance *and* ordering fairness. Recommend running this expansion as an independent workstream, separate from Aegis but blocking mainnet launch of Aegis. See `project_security_followups.md` for pre-mainnet gates.

3. **Q4+Q11 interact.** Direct-path Claim requires the Aiken validator to independently verify Charli3 (Q4 hardcodes the feed there). This means the feed policy_id is effectively a protocol-level fact the validator bakes in, which is exactly why Q6 rotation of the committee pubkey is a *separate* axis from rotating the oracle feed.

4. **Materios anchor reuse is FREE.** Per `project_cardano_l1_metadata_labels.md`, label 8746 + `materios-anchor-v2` schema + `cardano-mainnet-anchor.mnemonic` wallet is already in production. Every Aegis batch can be auto-anchored with zero additional infra. This is a marketing win ("every claim is anchored to Cardano mainnet"), not just an engineering convenience.

5. **Timing coherence with the Cardano epoch.** The committee daemon runs hourly (`sc_epoch` = 1h per `feedback_iog_idp_none_panic.md`). Aegis TTLs and fairness windows should be set to multiples of this — 1h intent TTL, 48h claim TTL both align cleanly. Don't invent exotic timescales.

6. **Midnight ZK is a phase-2 story.** `project_midnight_poc_findings.md` shows we have live Compact-on-Midnight infra. Natural v2 upgrade: committee publishes a ZK proof that "this voucher batch was correctly computed from attested oracle reads + pool state" *without* revealing individual policyholder positions. Privacy preservation for the institutional insurance customer. Note this as roadmap, don't force it into v1.

7. **Cert-daemon reuse.** The design doc says "reuse cert-daemon pattern." Confirmed — the Python cert-daemon at `operator-kit@cdc35c2` already signs attestations with a shared keypair, handles retries, publishes to blob gateway, and submits receipts. Swap the payload format from `orynq receipt` to `aegis attestation` — same machinery.

---

## Questions NOT in the doc that we should add

1. **Reinsurance / pool-solvency bounds.** When does the pool stop accepting new policies? What's the max outstanding coverage vs. pool TVL ratio? Currently unaddressed. Recommend a `PoolUtilization` protocol parameter (target 40%, hard cap 70%) enforced at `submit_intent` time by committee attestors.

2. **Premium pricing oracle.** Who decides what a policy *costs*? Is premium a function of strike distance + term + TVL utilization, or set by LPs? Currently absent from the doc. Recommend a `PremiumPolicy` pluggable trait (initial impl: Black-Scholes with Charli3 IV feed, fallback: linear-in-strike-distance).

3. **LP lifecycle + redemption.** The doc mentions "LP tokens on Cardano" but not how LPs redeem when the pool has outstanding policies. Standard answer: redemption waits until policies expire OR LP takes a pro-rata haircut. Needs explicit spec.

4. **Regulatory classification.** Parametric insurance is an "insurance product" in some jurisdictions, a "derivative" in others, and an "NFT" to the SEC if you're lucky. `feedback_us_token_launch_regulatory.md` flags this zone. At minimum we need a "not available to US persons" geofence story for v1, same as most Cardano DeFi.

5. **Materios ↔ Cardano anchor lag catastrophic-failure mode.** If Cardano halts (as it did briefly in 2023), what happens to in-flight Materios intents? Propose: committee pauses attestations after 3 consecutive missed Cardano blocks; users are told "Cardano L1 is degraded" rather than silently stalling.

6. **Multi-product support.** `aegis-policy-v1` supports one product per validator deployment. Do we want a registry pattern so `aegis-policy-v1` can serve multiple insurance products (ADA/USD strike, ADA/BTC strike, depeg insurance for USDM) from the same validator? Affects Q4 + Q6 (feed registration becomes a runtime operation, not a redeploy).

---

## Handoff notes

- This doc is decision-ready for Nathaniel's review. Questions flagged **YES — product** (1, 3, 5, 6, 8, 10) need explicit sign-off before engineering starts TDD.
- All other questions (2, 4, 7, 9, 11) are engineering defaults; engineering can start immediately with the proposals above and refactor if Nathaniel objects.
- Doc corrections to land in the design doc: (a) "3-of-8" → "M-of-N, currently 2-of-7", (b) any "MATRA gas" → "MOTRA gas".
- Update referenced Cardano explorer links in any generated comms to cexplorer.io per `feedback_cardano_explorer.md`.
- Next step after Nathaniel signs off: `/tdd-team` dispatch to build `pallet_aegis` scaffolding + `aegis-aiken-v1` repo in parallel.

— end —
