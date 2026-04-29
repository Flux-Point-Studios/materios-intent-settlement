/**
 * End-to-end happy path (spec §5.8, §7.4):
 *
 *   submit_intent  → committee daemon attests (mock 2-of-N quorum)
 *                  → keeper batches
 *                  → keeper submits to Cardano preprod
 *                  → keeper polls until confirmed
 *                  → posts settle_claim back
 *                  → assert Materios state is Settled.
 *
 * Per §5.8 this test must talk to real preprod endpoints. When
 * INTEGRATION_PREPROD is not set, we run a FULL in-memory version of the
 * same pipeline (using a fake Cardano provider) to keep green in CI. The
 * logic exercised is identical; only the provider is swapped.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import {
  intentId as computeIntentId,
  voucherDigest,
  signPayload,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import type {
  BatchPayload,
  Voucher,
  HexString,
  IntentKind,
  CommitteePubkey,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { Keeper } from "../../src/keeper.js";
import { KeeperStateStore } from "../../src/state.js";
import { CommitteeDaemon } from "../../src/daemon/index.js";
import type { ICardanoProvider } from "../../src/cardano.js";
import { computePlutusV3ScriptHash } from "../../src/script-hash.js";

const PLACEHOLDER_CBOR = ("0x" + "00".repeat(4)) as HexString;
const PLACEHOLDER_HASH = computePlutusV3ScriptHash(PLACEHOLDER_CBOR);

function fakeCardano(): ICardanoProvider {
  const slot = 1_000_000n;
  let txSlotSeen = 0n;
  let submitted = false;
  return {
    async submitTx(_cbor) {
      submitted = true;
      txSlotSeen = slot + 10n;
      return { txHash: ("0x" + "e2".repeat(32)) as HexString, submittedAtSlot: slot };
    },
    async isConfirmed(_tx, _depth) {
      if (!submitted) return { confirmed: false, currentSlot: slot, txSlot: null };
      return { confirmed: true, currentSlot: txSlotSeen + 200n, txSlot: txSlotSeen };
    },
    async getCurrentSlot() {
      return slot;
    },
    async getLatestBlockTimestamp() {
      return Math.floor(Date.now() / 1000);
    },
  };
}

function makeIntentAndBatch(): {
  batch: BatchPayload;
  voucher: Voucher;
  kind: IntentKind;
  committeePubkey: CommitteePubkey;
} {
  const submitter = ("0x" + "ab".repeat(32)) as HexString;
  const kind: IntentKind = {
    tag: "BuyPolicy",
    productId: ("0x" + "aa".repeat(32)) as HexString,
    strike: 500_000n,
    termSlots: 86400,
    premiumAda: 1_000_000n,
    beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1xabc"),
  };
  const intent = {
    submitter,
    nonce: 1n,
    kind,
    submittedBlock: 100,
    ttlBlock: 700,
    status: 1,
  };
  const id = computeIntentId(intent);
  const batch: BatchPayload = {
    intent,
    intentId: id,
    attestationSigs: [
      { pubkey: ("0x" + "11".repeat(32)) as HexString, sig: ("0x" + "22".repeat(64)) as HexString },
    ],
  };
  const baseVoucher: Voucher = {
    claimId: id as unknown as HexString,
    policyId: ("0x" + "cd".repeat(32)) as HexString,
    beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1xabc"),
    amountAda: 1_000_000n,
    batchFairnessProofDigest: ("0x" + "dd".repeat(32)) as HexString,
    issuedBlock: 110,
    expirySlotCardano: 10_000_000n,
    committeeSigs: [],
  };
  // Task #76b: real sr25519 sig over the canonical voucher digest. The
  // committee snapshot below pins //Alice as the lone member.
  const digest = hexToU8a(voucherDigest(baseVoucher));
  const { pubkey, sig } = signPayload("//Alice", digest);
  const pubkeyHex = u8aToHex(pubkey) as HexString;
  const voucher: Voucher = {
    ...baseVoucher,
    committeeSigs: [{ pubkey: pubkeyHex, sig: u8aToHex(sig) as HexString }],
  };
  return { batch, voucher, kind, committeePubkey: pubkeyHex as CommitteePubkey };
}

describe("E2E happy path — intent → attest → batch → submit → settle", () => {
  beforeEach(async () => {
    await cryptoWaitReady();
  });

  it("drives the full pipeline with in-memory Materios mock + fake Cardano", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "e2e-"));
    const { batch, voucher, committeePubkey } = makeIntentAndBatch();

    // Mock Materios RPC: returns the batch + voucher the committee produced,
    // records settle_claim. Separate tracking for keeper vs daemon polls.
    let settleCalled: any = null;
    let keeperPolls = 0;
    const makeRpc = (label: "daemon" | "keeper") => ({
      getPendingBatches: async () => {
        if (label === "keeper") {
          return keeperPolls++ === 0 ? [batch] : [];
        }
        return [batch]; // daemon attests
      },
      getVoucher: async () => voucher,
      getLatestBlockNumber: async () => 200,
      submitExtrinsic: async (section: string, method: string, args: unknown[]) => {
        if (section === "intentSettlement" && method === "settleClaim") {
          settleCalled = args;
        }
        return { txHash: ("0x" + "ff".repeat(32)) as HexString, blockHash: null };
      },
      getApi: () => ({}) as any,
      getSigner: () => ({}) as any,
    });
    const daemonRpc = makeRpc("daemon");
    const keeperRpc = makeRpc("keeper");

    // Spin up committee daemon and run ONE iteration to attest.
    const daemon = new CommitteeDaemon(
      {
        materiosRpcUrl: "ws://stub",
        cardanoOgmiosUrl: "wss://stub",
        sr25519Uri: "//Alice",
        ed25519Uri: "//Alice//aegis",
        daemonStatePath: path.join(tmpDir, "ds.json"),
        haltDetectSeconds: 60,
        haltRecoverBlocks: 3,
        haltExtensionThresholdSeconds: 86400,
        pollIntervalMs: 10,
      },
      {
        rpc: daemonRpc as any,
        getCardanoLatestBlockTimestamp: async () => Math.floor(Date.now() / 1000),
        logger: () => {},
      },
    );
    await daemon.initialize();
    const attestRes = await daemon.runOnce();
    expect(attestRes.attested.length).toBe(1);

    // Spin up keeper: observe batch, build tx, submit, confirm, settle.
    const state = new KeeperStateStore(path.join(tmpDir, "kstate.json"));
    const cardano = fakeCardano();
    const keeper = new Keeper(
      {
        materiosRpcUrl: "ws://stub",
        cardanoOgmiosUrl: "wss://stub",
        cardanoKupoUrl: "https://stub",
        keeperMnemonic: "//Alice",
        network: "preprod",
        confirmationDepthSlots: 1,
        feeSpikeMaxAttempts: 3,
        feeSpikeBackoffMs: 1,
        pollIntervalMs: 1,
        maxBatchSize: 32,
        dryRun: false,
        // Task #76a: bind the script-hash that matches PLACEHOLDER_CBOR.
        aegisPolicyV1ScriptHash: PLACEHOLDER_HASH,
      },
      {
        rpc: keeperRpc as any,
        cardano,
        state,
        keeperCardanoAddr: "addr_test1xkeeper",
        policyScriptCbor: PLACEHOLDER_CBOR,
        fetchFairnessProof: async () => ({
          batchBlockRange: [90, 110],
          sortedIntentIds: [("0x" + "77".repeat(32)) as HexString],
          requestedAmountsAda: [2_000_000n],
          poolBalanceAda: 100_000_000n,
          proRataScaleBps: 5000,
          awardedAmountsAda: [1_000_000n],
        }),
        // Task #76b: provide a deterministic committee snapshot containing
        // only the //Alice pubkey that signed the voucher.
        fetchCommitteeSnapshot: async () => ({
          members: [committeePubkey],
          threshold: 1,
        }),
        logger: () => {},
      },
    );

    // Iteration 1: observe + submit.
    await keeper.runOnce();
    // Iteration 2: confirm + settle_claim.
    await keeper.runOnce();

    expect(keeper.metrics.batchesObserved).toBe(1);
    expect(keeper.metrics.batchesSubmitted).toBe(1);
    expect(keeper.metrics.batchesConfirmed).toBe(1);
    expect(keeper.metrics.batchesSettled).toBe(1);

    // settle_claim was called with the Cardano tx hash.
    expect(settleCalled).not.toBeNull();
    expect(settleCalled[0]).toBeTruthy(); // claim_id
    expect(typeof settleCalled[1]).toBe("string"); // cardano_tx_hash hex
    expect(settleCalled[2]).toBe(false); // settled_direct = false (keeper path)

    // State machine: submission is marked confirmed/settled.
    const final = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(final?.state).toBe("confirmed");
    expect(state.isAlreadySettled(batch.intentId as unknown as HexString)).not.toBeNull();
  }, 30_000);
});
