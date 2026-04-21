# Materios Committee Expansion — 2-of-7 → 5-of-11

**Status:** DRAFT plan, research-only. No outreach, no provisioning, no chain-state changes.
**Author:** materios-committee-expansion-5of11-2026-04-20
**Date:** 2026-04-20
**Trace:** `b97c2435-a828-4ab2-a8b2-cbe4ae3be448` (public)
**Gates:** Aegis **mainnet** launch. Does NOT gate Aegis preprod demo.
**Parallelizable with:** Aegis dApp build — this workstream runs independently; only the mainnet cutover needs to synchronize.

---

## One-Page Execution Plan

A chronological sequence of concrete steps from today (2026-04-20) through 5-of-11 live on mainnet. **Decision points for Nathaniel marked `⟐`.**

| # | Step | Owner | ETA | Decision gate |
|---|------|-------|-----|---------------|
| 1 | Freeze candidate shortlist from §1 | Nate | +1 day | ⟐ **GATE-1:** approve 6–8 candidates + pitch copy |
| 2 | Send personalized outreach emails | Nate | +2 days | — |
| 3 | Collect acceptances (first 4) | Nate | +7–14 days | ⟐ **GATE-2:** ≥4 accepts → continue, else fallback (3-of-9) |
| 4 | Spec chain-side storage change, dry-run extrinsic on preprod | Nate | parallel | — |
| 5 | Onboard each attestor on **preprod v5**: mnemonic, `install.sh`, heartbeat, MOTRA bootstrap, bond, `join_committee` | Nate + attestor | 30–60 min each (parallelizable) | — |
| 6 | Verify roster = 11; threshold still 2/7, **do not flip yet** | Nate | +0 | — |
| 7 | Flip threshold to 5/11 on **preprod** via multisig-sudo (§3) | Nate+K2+K3 | +5 min | ⟐ **GATE-3** |
| 8 | 48h soak on 5/11, no stalls | passive | 48 h | ⟐ **GATE-4:** clean → approve mainnet |
| 9 | Ship mainnet chain-spec with 5/11 in genesis | Nate | cutover day | — |
| 10 | Aegis mainnet launches with 5/11 live | Aegis team | T+0 | — |

**Fallback branches at each gate:**
- **GATE-2 fails (< 4 acceptances in 14 days):** drop to 3-of-9 (need 2 new attestors), same process. See §4 and §5.
- **GATE-3 fails (something breaks at 11 members before threshold flip):** revert roster to last-good state via **Cardano `permissioned_candidates` policy update**, NOT via `rotate_authorities` (see `feedback_rotate_authorities_wedge.md`). Flip back after investigation.
- **GATE-4 fails:** freeze at 2/7 for mainnet, treat expansion as Phase-2 post-launch.

---

## 1. Attestor Recruitment

### 1.1 Current roster (verified, 2026-04-20)

From `project_spo_crossvalidation.md` lines 9-14, committee has 7 members:

| # | Role | Identity | Infrastructure |
|---|------|---------|-----------------|
| 1 | Validator | Gemtek (Nate) | Home lab, public IP, primary bootnode |
| 2 | Validator | Node-2 | LAN, Gemtek cluster |
| 3 | Validator | Node-3 | LAN, Gemtek cluster + hosts db-sync |
| 4 | Validator | MacBook | Native arm64, SSH-tunneled to shared Postgres |
| 5 | Attestor | GoFigureMatra | External, onboarded via `install.sh` |
| 6 | Attestor | SuNewbie | External, onboarded via `install.sh` |
| 7 | Attestor | punkr-Draupnir | External, onboarded via `install.sh` |

**Threshold:** 2 (very low, demo-grade).

### 1.2 Target roster (8 attestors → 11 total)

Keep 4 validators (Gemtek/Node-2/Node-3/MacBook) as-is. Bring attestors from 3 → 7.
Need **4 new attestors**. Target pool: shortlist 6–8 candidates, send 8 outreaches, accept first 4 that respond within 14 days.

### 1.3 Candidate shortlist

Criteria applied (lean — public info only):
- **Infra track record:** Verifiable Cardano mainnet pool or Midnight/partner-chain operator history.
- **Single-pool / mission-driven preference:** No pool-cluster operators (CSPA members preferred — reputational signal).
- **Existing partner-chain fluency:** Operators already running an IOG partner-chain (Midnight) or SPO-cross-validation-capable tooling cut onboarding friction dramatically.
- **Ecosystem alignment:** Cardano DeFi / infrastructure teams whose uptime benefits from Materios being solid.
- **Geographic distribution:** Prefer non-US for regulatory distancing of the committee.
- **No doxxed-criminal history / no SEC action / no known rug history.**

| # | Candidate | Why | Contact | Risk |
|---|-----------|-----|---------|------|
| A | **EASY1** (Giovanni Gargiulo) | Runs infra for World Mobile, SundaeSwap, **Midnight** — direct partner-chain experience. Single-pool CSPA, ~6yr SPO. | easystakepool.com | None found. Institutional-grade. |
| B | **AHLNET** (AHL) | Eternl wallet core dev. 15+yr IT ops, bare-metal Sweden. Single-pool. | ahlnet.nu | Eternl integration = upside. |
| C | **Anastasia Labs** | PRAGMA member. Transaction-builder infra. | anastasialabs.com | Corp not SPO — needs MoU. |
| D | **TxPipe** | SuperNode operator, open-source RPC backs dozens of wallets. PRAGMA. | txpipe.io | Corp — ditto. |
| E | **Blink Labs** | PRAGMA founding member. Cardano infra at scale. | blinklabs.io | Corp. |
| F | **Charli3** | Building own Substrate partner-chain fork; existing oracle-node operator network. | charli3.io | Oracle overlap — frame as reciprocal. |
| G | **Demeter** | Managed Cardano infra across mainnet/preprod/preview. Already runs capable nodes. | demeter.run | Managed-service business model. |
| H | **CSPA member w/ high pledge** (Spire, Cardanians.io, Nordic, etc.) | Community/decentralization signal. | singlepoolalliance.net | Lower brand weight, easier yield. |

**Priority 1 (send first, most reputational upside): A, B, F.**
**Priority 2 (high-likelihood-of-yes, institutional): C, D, E.**
**Priority 3 (fallback if P1+P2 slow): G, H.**

### 1.4 Outreach email template

> Subject: Materios committee expansion — inviting [name] as an attestor
>
> Hi [name],
>
> Materios is a Cardano partner-chain built on the IOG partner-chains-node toolkit (same stack Midnight uses). It's live on preprod with a 7-member federated committee (4 validators we run + 3 external attestors). Before mainnet we want to take the committee to 11 members with a 5-of-11 threshold, and you're someone whose operational track record we trust.
>
> **What we're asking:** run one attestor node (a cert-daemon + a light Materios node). Install is a single bash script that takes ~30 seconds including key-gen, faucet drip, and MOTRA bootstrap. Hardware is minimal — a cheap VPS is fine. Once live, the node signs attestations from the global pool (your share is pro-rata). You stay an attestor; you do not become a validator (no Cardano stake commitment required).
>
> **What you get:** preprod-only at first (testnet tokens only). On mainnet launch (tentatively Q3 2026), attestors earn MATRA emissions from our 65M-MATRA attestor reserve, with dynamic per-signer rewards and a per-receipt fee share (80/20 signer/treasury split).
>
> **Commitment:** 24/7 best-effort uptime, patching within 24 h of a pushed image, responsive on a Signal/Telegram incident channel. No financial obligation beyond a 1K MATRA attestor bond (we front the preprod MATRA).
>
> Public roadmap + architecture: [link]. Open-source: [repo]. Happy to jump on a call.
>
> — Nathaniel, Flux Point Studios

### 1.5 Technical/operational bar

- **Uptime:** 95% monthly soft target (no slashing at that level on preprod).
- **Patch cadence:** apply pushed operator-kit images within 24 h of a security announcement.
- **Monitoring:** subscribe to the Materios incidents channel (Discord/Signal — TBD); respond to @mentions within 4 h.
- **Security hygiene:** follow `feedback_key_management.md` (mnemonic-derived keys, `author_insertKey`, never `rotateKeys`). No seed phrases in Git/CI/shared docs.
- **Public-key-leak history:** zero active unpatched leaks disqualifies (we rotated our own 2026-04-17, so the bar is met-by-example).

---

## 2. Onboarding Mechanics

### 2.1 Per-attestor flow (verified against v5, 2026-04-18)

From `project_v5_chain.md` + `project_spo_crossvalidation.md`:

1. Attestor runs `curl -sSL https://materios.fluxpointstudios.com/install.sh | bash` (or cloned from `Flux-Point-Studios/materios-operator-kit`).
2. Installer auto-creates mnemonic at `~/materios-attestor/.secret-mnemonic` (or reuses existing — supports re-install).
3. Installer starts `materios-node` container pinned to `ghcr.io/flux-point-studios/materios-node:v3` (note: tag still named `:v3` — this is the multi-tag alias, actual v5 WASM overrides are pulled at runtime). On Apple Silicon the installer sets `platform: linux/amd64`.
4. Installer starts `cert-daemon` with same mnemonic.
5. Installer POSTs to faucet → **single 30-sec HTTP request** that triggers: DB registration + ADA-side faucet drip + Alice-delegated MOTRA bootstrap (~300M MOTRA) + sudo bond registration.
6. First cert-daemon poll calls `orinqReceipts.join_committee(1_000 * 10^6)` (1K MATRA bond, v5 6-dec).
7. Chain emits a `CommitteeJoined` event; attestor is in the active set after the next session rotation.

**Verified timing (from SuNewbie/GoFigureMatra/punkr-Draupnir onboarding, 2026-04-17):** ~30 s from `bash` invocation to "Online" on explorer.

### 2.2 Pre-flight checks before flipping threshold

Before step 7 (threshold flip) on the execution plan, verify:
- All 11 `sessionCommitteeManagement.currentCommittee` entries are signing certs (check via explorer / `/preprod-events/attestor-history`).
- No cert-daemon is stuck in a retry loop (check `daemon-state.json` against genesis — `feedback_rotate_authorities_wedge.md` notes a self-heal fix in operator-kit `cdc35c2`, older images need manual wipe).
- Bonded amount per new attestor ≥ `BondRequirement` (currently 1K MATRA).
- All 4 new attestors have authored at least 10 certs in the observation window (proves signing key correctly loaded).

### 2.3 Duration estimate

- **Parallel onboarding (recommended):** 2–3 attestors at a time, ~60 min per batch (includes coaching). 4 attestors total → 2 batches → **~2 hours** of Nate's time, spread over whatever window the attestors are available.
- **Sequential onboarding (conservative):** ~45 min per attestor × 4 = **3 hours** of Nate's time.
- **Wall-clock (attestor-availability-gated):** 7–14 days from GATE-1 to "all 4 onboarded" — depends on scheduling, not on technical work.

---

## 3. Chain-Side Changes

### 3.1 What we're actually changing

Two storage values in `sessionCommitteeManagement` (IOG's `pallet-session-validator-management`): `ThresholdNumerator: u16` (2) and `ThresholdDenominator: u16` (7). Roster is `CommitteeMembers`, rebuilt each MC epoch from Cardano `permissioned_candidates` — so roster-expansion is **Cardano-side**, threshold-flip is **Materios-sudo**.

**Critical safety (`feedback_rotate_authorities_wedge.md`):** **never** `rotate_authorities` or any GRANDPA-direct path. Roster changes route through `permissioned_candidates`; Ariadne rebuilds at next MC epoch.

### 3.2 Exact extrinsic sequence

**Step A — Add 4 new attestors (Cardano-side):** For each new attestor, (1) they generate sidechain key (mnemonic-derived per `feedback_key_management.md`), (2) Nate collects 3-tuple (sidechain/aura/grandpa pubs), (3) Nate submits a Cardano tx via `smart-contracts upsert-permissioned-candidates` (partner-chains-node-v1.8.0) — **batch all 4 upserts into one tx** to save 3 epoch-boundary waits, (4) wait ~1 h for MC epoch boundary, (5) verify `sessionCommitteeManagement.nextCommittee` includes them.

**Step B — Raise threshold to 5/11 (Materios-sudo, AFTER all 11 are signing):** Extrinsic `sudo.sudoAs(multisig_sudo, sessionCommitteeManagement.setThreshold(5, 11))`. If no dedicated setter exists, equivalent is `system.setStorage` with `ThresholdNumerator/Denominator` keys (compute keys from live metadata — DO NOT hardcode). Multisig 2-of-3 same path as v3 genesis seed / runtime upgrade #6908 / dev-key eviction #8535; see `reference_multisig_sudo.md`. Use `signAndSend` callback form (`feedback_faucet_tx_submission.md`) to confirm inclusion. Tx cost negligible; allocate 10M MOTRA to sudo account for headroom.

### 3.3 Rollback plan

If threshold flip breaks cert production:

**A. Threshold 5/11 live, certs not progressing:** multisig-sudo revert to `setThreshold(2, 11)` — keep roster, drop threshold. Buys debug time.

**B. One or more new attestors bad (flaky/wrong keys/misbehaving):** Cardano-side `permissioned_candidates` upsert removing bad entries. Ariadne rebuilds next MC epoch. Will cause brief threshold mismatch (5/9 effective); if liveness issue, chain A+B.

**C. Deeper wedge (GRANDPA stuck, set-id drift):** `feedback_rotate_authorities_wedge.md` territory. Try (1) `--wasm-runtime-overrides` patched runtime (viable per 2026-04-20 IDP-None recovery), then (2) chain reset (`feedback_chain_reset_runbook.md`). **Never** attempt `rotate_authorities` — irrecoverable trap.

### 3.4 No chain reset required

Both threshold values and roster are runtime-mutable storage; adding attestors is Cardano-policy-driven. No migration code, no chain reset, no spec-version bump needed for this workstream. (Contrast: v3→v4→v5 decimal changes all required resets.)

---

## 4. Sequencing + Gates

### 4.1 Before Aegis mainnet

Must complete:
- ✅ Committee at 5-of-11 on preprod, 48 h clean soak.
- ✅ Cardano-side `permissioned_candidates` policy updated for mainnet with all 11 members' sidechain keys.
- ✅ Mainnet chain-spec genesis seeded with threshold=5, denominator=11 (avoids the flip-in-flight risk).

Does NOT need to complete:
- ❌ Blocks Aegis preprod demo. Preprod can demo at 2-of-7 just fine; expansion is a mainnet concern.

### 4.2 Parallel-safe with Aegis build

- Attestor recruitment emails — pure comms work, zero Aegis overlap.
- Attestor onboarding on preprod — uses install.sh which has no Aegis-specific state.
- Threshold-flip testing on preprod — uses same sudo path that Aegis doesn't touch.

The only Aegis-blocking step is at mainnet cutover day, and even there it's just "genesis includes committee=11, threshold=5" vs. "genesis includes committee=7, threshold=2" — a chain-spec JSON edit, not a runtime change.

### 4.3 Minimum viable expansion (fallback)

If we cannot secure 4 qualified attestors by mainnet target date:

| Threshold | # members | Liveness floor | Collusion bar | Note |
|-----------|-----------|---------------|---------------|------|
| 2-of-7 (current) | 7 | any 6 offline → dead | 2 colluders captures | Demo-grade only |
| **3-of-9** | 9 | any 7 offline → dead | 3 colluders captures | **Acceptable MVP** |
| **5-of-11** | 11 | any 7 offline → dead | 5 colluders captures | **Target** |
| 7-of-13 | 13 | any 7 offline → dead | 7 colluders captures | Phase-2 post-mainnet |

**3-of-9 is the documented fallback.** It requires only 2 new attestors instead of 4, still materially improves both Q6 (rotation) and Q8 (fairness) governance claims, and is achievable with just the P1 candidates (A, B, F) if even one of the P1 outreaches yields. Threshold math is worse (a 3-colluder set captures) but the jump from 2-of-7 to 3-of-9 is still the single largest governance improvement per-capita we've made.

### 4.4 Aegis-mainnet go/no-go decision tree

```
Is committee at 5-of-11 on preprod with 48h soak?
├── YES → Ship mainnet at 5-of-11. ✅
└── NO → Is 3-of-9 ready?
     ├── YES → Ship mainnet at 3-of-9, publish expansion roadmap for phase 2. ⚠️ (degraded but acceptable)
     └── NO → Ship mainnet at 2-of-7, publish expansion roadmap, compensate with stronger public language about "initial federated launch". ⚠️⚠️ (last resort)
```

---

## 5. Risks

### 5.1 Reputational risk per candidate

None of the P1/P2 candidates above have public knowledge of:
- Active SEC action.
- Rug-pull history.
- Publicly-leaked seed phrase or validator key.
- Sanctions-list membership.

Two soft concerns:
- **Charli3 overlap:** Their own Substrate-based partner-chain fork is in research (Fund 12 Catalyst proposal). Could frame Materios attestor role as competitive signal. Mitigation: offer reciprocal attestor seat on Charli3's chain when it launches.
- **Anastasia/TxPipe/Blink/Demeter as company rather than individual operator:** Ops continuity depends on corporate life, not a single operator's commitment. Mitigation: MoU clarifying "best-effort, no SLA penalty, 90-day notice to exit."

Before sending outreach, do a final sanity check: search `gh api` for each candidate's GitHub org for recent suspicious activity, check X/Twitter for current controversy. Nothing hidden from training-data cutoff should matter if search is clean right now.

### 5.2 Collusion risk — quantified

| Committee | Corrupt-signers to capture | Max honest-minority loss | Liveness breakpoint |
|-----------|---------------------------|-------------------------|---------------------|
| 2-of-7 | 2 | 5 honest → still captured | 6 offline = dead |
| 3-of-9 | 3 | 6 honest → still captured | 7 offline = dead |
| **5-of-11** | **5** | **6 honest → still safe** | **7 offline = dead** |

**Key improvement:** at 2-of-7, you need to trust that **any two** committee members aren't colluding — 21 pairs, a 9% collusion probability per-pair-per-year aggregates to ~89% at least-one-collusion in the first year. At 5-of-11, you need **any five** — 462 such sets, and no small subset of doxxed operators can collude without catching one of the independent P1/P2 candidates. The math gets meaningfully harder.

**Fairness (Q8) angle:** at 2-of-7 the pro-rata signer ordering is statistically noisy — any single attestor gets picked ~2/7 = 28.5% of the time. At 5-of-11 it's 5/11 = 45.4%, smoother distribution, harder to claim bias.

### 5.3 Can't find 4 qualified attestors — fallback plan

Already documented in §4.3. **Pre-commit to 3-of-9 as acceptable MVP.** Publish the expansion roadmap regardless — "committee will grow to 5-of-11 within the first 3 mainnet epochs" is a credible and verifiable commitment.

### 5.4 Operational risks during transition

- **Transient liveness wobble while MC epoch catches up.** After a `permissioned_candidates` upsert, there's a ~1-hour window between committee-sets. Certs keep signing at the old roster; new attestors aren't active yet. Normal, not a liveness failure.
- **cert-daemon state-wipe footgun.** New attestors running images pre-`cdc35c2` may cache stale genesis. Must be checked before they're flipped live.
- **Pallet index drift (`feedback_pallet_index_shift.md`).** Not triggered here — we're not adding pallets — but noted so we don't accidentally ship alongside a Treasury-insert PR.

### 5.5 Key-management failure modes

- Attestor publishes mnemonic (via accidental git-push, env-var leak, etc.). Impact: attestor gets replaced via `permissioned_candidates` policy removal + re-onboard. At 5-of-11, one compromised key doesn't move the threshold.
- Attestor loses their server irrecoverably. Impact: same — remove from policy, drop to 5-of-10 until replaced, still safe.
- Attestor signs something malicious. Impact: requires 4 more colluders; detection via Aegis attestor-history dashboard.

---

## 6. Cost Estimate

### 6.1 Cardano (ADA)

`permissioned_candidates` upserts batch into 1 tx ≈ 5 ADA per network (preprod + mainnet = ~10 ADA). No new SPO registrations required — attestors are permissioned, don't need their own pool.

### 6.2 Materios (MATRA / MOTRA)

Preprod drip per new attestor already in place — 300M MOTRA bootstrap + 1K MATRA bond from alice_faucet 10M endowment, negligible. Mainnet cMATRA drip from 65M attestor reserve: ~500 MATRA × 4 = 2K MATRA runway. Mainnet bond (refundable) 1K × 4 = 4K MATRA (Component 8, PR #7).

### 6.3 Hardware

2-vCPU / 4GB / 50GB SSD VPS is enough (~$5–10/mo). Existing SPOs already run mainnet-spec boxes — attestor role is ~10% marginal cost.

### 6.4 Payment policy

**No recruitment bounty.** Cardano SPO culture rejects pay-to-play — corrosive to mission-driven framing.
**Emissions share promised** from 65M attestor reserve per `project_v5_1_tokenomics.md` (80/20 signer/treasury fee split, dynamic per-signer rewards per PR #7). Early 11-member committee gets elevated per-head rate before scale dilution (~30–50K MATRA/yr/attestor vs. 2K/yr at 3K-attestor target).
**No SAFT/equity** — strategic bucket reserved for Orion+1.

### 6.5 Nate's time

| Task | Hours |
|------|-------|
| Shortlist finalization + pitch-copy review | 2 |
| 8 outreach emails | 2 |
| Responding to questions | 4 |
| Onboarding 4 attestors (1 h each) | 4 |
| Threshold-flip extrinsic + soak monitoring | 2 |
| **Total** | **~14 hours** spread over 2–3 weeks |

Roughly 7% of a sprint; fully parallelizable with Aegis.

---

## Appendix A — Source references

- `project_spo_crossvalidation.md` (roster verification, v3 chain state, install.sh behavior)
- `project_v5_chain.md` (6-dec MATRA, v5 genesis, cert-daemon state wipes)
- `project_v5_1_tokenomics.md` (attestor emissions, bond, fee split design)
- `project_preprod_spo_pool.md` (for our own SPO example, partner-chain-registration pattern)
- `feedback_rotate_authorities_wedge.md` (**CRITICAL:** correct rotation path is Cardano `permissioned_candidates`, NEVER `rotate_authorities`)
- `feedback_key_management.md` (mnemonic-derived keys via `author_insertKey`)
- `feedback_chain_reset_runbook.md` (last-resort recovery)
- `feedback_faucet_tx_submission.md` (signAndSend callback form for inclusion confirmation)
- `reference_multisig_sudo.md` (2-of-3 multisig sudo call pattern)

Web (SPO reputation research, public-data only): Midnight mainnet trusted node operators announcement (institutional benchmark); CSPA / singlepoolalliance.net directory; EASY1 (easystakepool.com, SundaeSwap/Midnight operator); AHLNET (ahlnet.nu, Eternl core dev); PRAGMA association (Blink Labs + dcSpark + Sundae Labs + TxPipe + Cardano Foundation); Charli3 (charli3.io); Anastasia Labs (anastasialabs.com).

---

**End of plan.** Next action: Nate reviews + approves at GATE-1 (step 1 of execution plan).
