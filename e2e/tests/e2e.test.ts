/**
 * E2E demo spec — described with vitest so it can gate PRs via CI.
 *
 * STRATEGY:
 *   - describe.skip(...) the full flow by default so CI doesn't hit preprod
 *     on every PR.
 *   - describe.todo(...) each step that depends on Team A / B / C PRs.
 *   - When MATERIOS_E2E_LIVE=1 is set + validators-deployed check passes,
 *     the full flow runs end-to-end. That env var is only set in the
 *     dedicated `e2e-preprod.yml` workflow (see `.github/workflows`).
 */
import { describe, expect, it } from 'vitest';

import { loadConfig, validatorsDeployed } from '../src/config.js';

const LIVE = process.env.MATERIOS_E2E_LIVE === '1';

describe('E2E demo — spec §7.4', () => {
  it('config loads cleanly', () => {
    const cfg = loadConfig('preprod');
    expect(cfg.network).toBe('preprod');
  });

  // Gate: only run the full flow in LIVE mode with validators deployed.
  const cfg = loadConfig('preprod');
  const canRun = LIVE && validatorsDeployed(cfg);

  (canRun ? describe : describe.skip)('live preprod flow', () => {
    // When Teams A/B/C have all landed and MATERIOS_E2E_LIVE=1 + validators
    // are populated, this block is implemented by shelling into
    // scripts/full-demo.ts and asserting its exit code + captured tx hash.
    // Until then, mark each of the 8 steps as describe.todo so the
    // expected narrative is visible in test output.
  });

  describe.todo('step 1: Team B validators deployed to Cardano preprod', () => {
    // DEPENDS ON: Flux-Point-Studios/aegis-parametric-insurance-dev Team B PR.
    // ACCEPTANCE: config/preprod.json.aegisValidators.* populated with real
    //            addresses + deployedInTx = a valid preprod tx hash.
  });

  describe.todo('step 2: submit_intent on Materios preprod', () => {
    // DEPENDS ON: Team A's pallet_intent_settlement PR registering the
    //            `intentSettlement.submitIntent(kind)` extrinsic.
    // ACCEPTANCE: test account submits BuyPolicy intent; IntentSubmitted
    //            event emitted with a valid 32-byte IntentId.
  });

  describe.todo('step 3: committee attestation via cert-daemon (Team C)', () => {
    // DEPENDS ON: Team C's cert-daemon extension signing with the
    //            aegis-attestor ed25519 key (//aegis derivation).
    // ACCEPTANCE: within 6 Materios blocks, the intent status transitions
    //            Pending → Attested; IntentAttested event emitted with the
    //            committee member pubkeys in `attestors`.
  });

  describe.todo('step 4: request_voucher + committee signing threshold', () => {
    // DEPENDS ON: Team A's request_voucher extrinsic + Team C's keeper
    //            voucher-signing loop.
    // ACCEPTANCE: VoucherIssued event emitted with voucher_digest +
    //            fairness_proof_digest. Voucher committee_sigs >= threshold.
  });

  describe.todo('step 5: keeper builds Cardano tx, submits, calls settle_claim', () => {
    // DEPENDS ON: Team C's keeper service deployed on Node-3 for preprod.
    // ACCEPTANCE: Within keeper cycle (~6s poll), a Cardano tx is submitted
    //            to preprod; ClaimSettled event emitted on Materios with
    //            the cardano_tx_hash.
  });

  describe.todo('step 6: Aiken validator accepted the voucher', () => {
    // DEPENDS ON: Team B's aegis-policy-v1 BatchClaimVoucher redeemer.
    // ACCEPTANCE: tx on Cardano preprod lands (via Kupo /matches); datum
    //            at pool-custody script consistent with voucher payout.
  });

  describe.todo('step 7: cexplorer.io/preprod link generated for reviewer', () => {
    // ACCEPTANCE: the Cardano tx hash is present in the Kupo UTxO set and
    //            the https://preprod.cexplorer.io/tx/<hash> URL returns 200.
  });

  describe.todo('step 8: fairness-proof audit re-derives awarded amounts', () => {
    // DEPENDS ON: Team A's runtime-API `get_voucher` + BatchFairnessProof
    //            event payload.
    // ACCEPTANCE: assertFairnessProofMatches() passes with pool balance
    //            read from the pool-custody UTxO; BFPR digest recomputed
    //            locally matches the committee-signed digest byte-for-byte.
  });
});
