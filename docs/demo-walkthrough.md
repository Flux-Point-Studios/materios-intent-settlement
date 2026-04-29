# Materios Intent-Settlement — Demo Walkthrough

**Audience:** Nathaniel, IOG partner-chain review team, strategic investor diligence.
**Status at publication:** 2026-04-20. Scaffold landed; awaiting Team A/B/C PRs for green.
**Spec:** [`docs/spec-v1.md`](./spec-v1.md) §7.4.

This doc walks through exactly what a reviewer sees when they run `pnpm demo` from
`e2e/`. It is designed so a non-engineer can open the cexplorer.io links, see the
txs land, and believe the "it all works" claim without reading a line of code.

## One-paragraph summary

A user on Materios submits an intent ("I want to buy a parametric-insurance policy"). The
committee — 2-of-7 Materios validators holding dedicated ed25519 attestation keys —
signs a voucher authorizing payout on Cardano preprod. A keeper (committee-operated in
v0.1) picks up the vouchered batch from Materios, builds a Cardano tx that consumes
pool-custody UTxOs and produces beneficiary payouts, and submits it. The Aiken validator (`aegis-policy-v1`)
verifies M-of-N committee sigs over the Blake2b-256 domain-tagged pre-image and releases
the funds. The keeper then calls `settle_claim` back on Materios, closing the loop. A
parallel anchor worker writes the BatchFairnessProof digest to Cardano under metadata
label 8746 for forensic traceability. Every step is auditable from a public explorer.

## The 8 steps, with reviewer-visible artifacts

### Step 1 — Aiken validators are deployed to Cardano preprod

| Thing | Where it is |
|-------|-------------|
| `aegis-policy-v1` script hash | `<populated by Team B>` |
| `premium-collector` script hash | `<populated by Team B>` |
| `pool-custody` script hash | `<populated by Team B>` |
| Deploy tx (preprod) | `<https://preprod.cexplorer.io/tx/... — populated by Team B>` |

One-time setup: Team B publishes `aegis-parametric-insurance-dev` PR with the validators
compiled against the locked `AegisPolicyParams` (committee set, threshold 2, Charli3
feed id, Materios genesis hash `0xbc0531cb...`). Team D updates `config/preprod.json`.

### Step 2 — Submit an intent on Materios preprod

```ts
await api.tx.intentSettlement.submitIntent({
  BuyPolicy: {
    productId: '0x...ADA/USD...',
    strike: 500_000n,            // 0.50 ADA × 10^6 per spec §7.4
    termSlots: 86_400,
    premiumAda: 1_000_000n,      // 1 tADA
    beneficiaryCardanoAddr: <bytes of test addr>,
  },
}).signAndSend(submitter, { nonce: -1 }, ({ status, events }) => {
  // capture IntentSubmitted event → intentId
});
```

**Artifact:** Materios block with `IntentSubmitted { intent_id, submitter, nonce }` event.
Viewable at `https://materios.saturnswap.io/#/explorer` or via Polkadot-JS Apps.

### Step 3 — Committee attestation (Team C cert-daemon)

Within 6 Materios blocks (~36 seconds), 2-of-7 committee members' cert-daemons observe
the new intent, sign the IntentId pre-image with their `//aegis` ed25519 keys, and post
an M-of-N bundle via `attest_intent`. The `IntentAttested { intent_id, attestors }`
event fires.

**Artifact:** `IntentAttested` event carrying ≥ 2 distinct committee pubkeys.

### Step 4 — Voucher issuance

Once attested, the committee (via the same cert-daemon) packages the intent into a
`Voucher` (spec §1.7), computes the BFPR over the batch, signs both digests with ed25519,
and posts `request_voucher`. The `VoucherIssued { claim_id, voucher_digest, fairness_proof_digest }`
event fires.

**Artifact:** `VoucherIssued` event + retrievable `Voucher` struct via runtime API
`IntentSettlementRuntimeApi::get_voucher(claim_id)`.

### Step 5 — Keeper pickup + Cardano submit

Team C's keeper polls `get_pending_batches` every 6s. On seeing a vouchered claim it:
1. Reads pool-custody + premium-collector UTxOs via Kupo.
2. Builds a Cardano tx with `BatchClaimVoucher` redeemer (committee sigs + voucher + BFPR).
3. Produces payouts to beneficiary + a bounded keeper fee (spec §5.4).
4. Attaches metadata label 8746 with the BFPR digest in `ext.fairness_proof_digest`.
5. Submits via Ogmios; waits `k = 2160` slots for finality.
6. Calls `settle_claim(claim_id, cardano_tx_hash, settled_direct=false)` on Materios.

**Artifact:** `ClaimSettled { claim_id, cardano_tx_hash }` event on Materios.

### Step 6 — Cardano UTxO-set verification

The demo queries Kupo `/matches/<pool_custody_address>?unspent` and confirms:
- The pre-batch UTxO is spent (absent from `?unspent` list).
- A new UTxO at `beneficiary_cardano_addr` has `coins >= expected_payout - keeper_fee`.

Plus it fetches metadata on the batch tx and asserts `label 8746` payload contains the
Materios genesis hash `bc0531cb...` and the BFPR digest from step 4.

### Step 7 — Reviewer-clickable cexplorer link

The demo prints:

```
[7/8] cexplorer.io (preprod) link for reviewer
     https://preprod.cexplorer.io/tx/<cardano_tx_hash>
```

Open it. You should see:
- Inputs: 1 pool-custody UTxO + 1 keeper fee-input UTxO.
- Outputs: 1 payout to beneficiary + 1 keeper fee + 1 pool-custody change.
- Metadata tab: label `8746` with a JSON payload starting `{"p":"materios","v":2,...}`.
- If the optional per-high-value-claim POI anchor was also submitted, label `2222` is
  present in a separate tx (spec §6.4).

### Step 8 — Fairness-proof audit

The demo independently recomputes `pro_rata_scale_bps`, `awarded_amounts_ada[]`,
and the BFPR digest from the sorted intent list + pool balance. Asserts byte-for-byte
equality with the committee-signed proof. See `e2e/src/fairness.ts` for the reference
implementation. Spec §1.6 invariants are all checked.

## FAQ

**Q: Is this running on mainnet?**
No. Preprod only. `config/mainnet.json` is a placeholder and `loadConfig('mainnet')`
refuses to load without an explicit env-var override. Spec §6.6 gates mainnet cutover on
committee expansion to 5-of-11 + audit.

**Q: What happens if the committee is offline?**
Intents TTL-expire (~1h on Materios). Premium is refunded to the submitter's ADA credit.
Spec §2.3 handles this in `on_initialize`.

**Q: What if a keeper submits a forged voucher?**
The Aiken validator rejects: committee sigs must be valid ed25519 from pubkeys in
`CommitteePubkeySet`, ≥ threshold distinct. A forged committee sig from a non-member
pubkey gets `verify_committee_sigs` returning `False` and the tx fails.

**Q: What metadata labels are used?**
- `8746` = `materios-anchor-v2` batch-level anchor (every keeper batch).
- `2222` = `poi-anchor-v1` for high-value individual claims (> 10k ADA payout; optional).

## Links reviewers should click once the demo is green

| What | Link |
|------|------|
| Materios preprod explorer | [materios.saturnswap.io/#/explorer](https://materios.saturnswap.io/#/explorer) |
| Cardano preprod explorer | [preprod.cexplorer.io](https://preprod.cexplorer.io) |
| Team A PR (pallets) | *<populated when PR opens>* |
| Team B PR (Aiken validators) | *<populated when PR opens>* |
| Team C PR (keeper + SDK) | *<populated when PR opens>* |
| Team D PR (this demo) | `Flux-Point-Studios/materios-intent-settlement#<tbd>` |

## For IOG reviewers specifically

This demo exercises the same `materios-anchor-v2` schema (label 8746) that the live
Materios v5 chain already writes to Cardano mainnet for checkpointing — just with an
`ext.fairness_proof_digest` addition (additive, backward-compatible per spec §6.6).
The committee signature scheme is ed25519 (spec §1.5) precisely so Aiken / Plutus V3's
builtin `verify_ed25519_signature` can verify without a custom primitive; every other
IOG-partner-chain reference uses the same choice for the same reason.
