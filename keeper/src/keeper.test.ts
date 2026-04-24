/**
 * Keeper logic tests — all failure modes per spec §5.6.
 *
 * These tests stub @polkadot/api (one layer) and plug in a FakeCardanoProvider
 * that exposes the ICardanoProvider surface. The Keeper itself runs
 * unmodified; we exercise its orchestration decisions.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Keeper } from "./keeper.js";
import { KeeperStateStore } from "./state.js";
import type { ICardanoProvider, SubmittedTx } from "./cardano.js";
import type {
  BatchPayload,
  KeeperConfig,
  Voucher,
  BatchFairnessProof,
  HexString,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { intentId as computeIntentId } from "@fluxpointstudios/materios-intent-settlement-sdk";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

function makeKind(nonce: number) {
  return {
    tag: "RefundCredit" as const,
    amountAda: BigInt(10_000 + nonce),
  };
}

function makeBatch(nonce: number, submitter: HexString = ("0x" + "ab".repeat(32)) as HexString): BatchPayload {
  const kind = makeKind(nonce);
  const id = computeIntentId({
    submitter,
    nonce: BigInt(nonce),
    kind,
    submittedBlock: 100,
  });
  return {
    intent: {
      submitter,
      nonce: BigInt(nonce),
      kind,
      submittedBlock: 100,
      ttlBlock: 700,
      status: 1, // Attested
    },
    intentId: id,
    attestationSigs: [
      {
        pubkey: ("0x" + "11".repeat(32)) as HexString,
        sig: ("0x" + "22".repeat(64)) as HexString,
      },
    ],
  };
}

function makeVoucher(id: HexString): Voucher {
  return {
    claimId: id,
    policyId: ("0x" + "ee".repeat(32)) as HexString,
    beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1xyz"),
    amountAda: 10_000_000n,
    batchFairnessProofDigest: ("0x" + "dd".repeat(32)) as HexString,
    issuedBlock: 110,
    expirySlotCardano: 5_000_000n,
    committeeSigs: [
      { pubkey: ("0x" + "11".repeat(32)) as HexString, sig: ("0x" + "22".repeat(64)) as HexString },
    ],
  };
}

function makeValidBfpr(): BatchFairnessProof {
  return {
    batchBlockRange: [90, 110],
    sortedIntentIds: [("0x" + "77".repeat(32)) as HexString],
    requestedAmountsAda: [20_000_000n],
    poolBalanceAda: 100_000_000n,
    proRataScaleBps: 5000, // 50%
    awardedAmountsAda: [10_000_000n],
  };
}

function fakeRpc(overrides: Record<string, any> = {}) {
  return {
    getPendingBatches: vi.fn().mockResolvedValue([]),
    getVoucher: vi.fn().mockResolvedValue(null),
    getLatestBlockNumber: vi.fn().mockResolvedValue(200),
    submitExtrinsic: vi.fn().mockResolvedValue({ txHash: "0x" + "aa".repeat(32), blockHash: null }),
    ...overrides,
  };
}

function fakeCardano(overrides: Partial<ICardanoProvider> = {}): ICardanoProvider {
  const slot = 1_000_000n;
  return {
    submitTx: vi.fn().mockResolvedValue({
      txHash: ("0x" + "cd".repeat(32)) as HexString,
      submittedAtSlot: slot,
    } satisfies SubmittedTx),
    isConfirmed: vi.fn().mockResolvedValue({
      confirmed: true,
      currentSlot: slot + 3000n,
      txSlot: slot,
    }),
    getCurrentSlot: vi.fn().mockResolvedValue(slot),
    getLatestBlockTimestamp: vi.fn().mockResolvedValue(Math.floor(Date.now() / 1000)),
    ...overrides,
  };
}

const baseConfig: KeeperConfig = {
  materiosRpcUrl: "ws://stub",
  cardanoOgmiosUrl: "wss://stub",
  cardanoKupoUrl: "https://stub",
  keeperMnemonic: "//Alice",
  network: "preprod",
  confirmationDepthSlots: 120,
  feeSpikeMaxAttempts: 3,
  feeSpikeBackoffMs: 1,
  pollIntervalMs: 10,
  maxBatchSize: 32,
  dryRun: false,
};

describe("Keeper.runOnce — happy path", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-"));
  });

  it("observes → submits → confirms → settles an attested+vouchered batch", async () => {
    const batch = makeBatch(1);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const cardano = fakeCardano();
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      logger: () => {},
    });

    const metricsFirst = await keeper.runOnce();
    expect(metricsFirst.batchesObserved).toBe(1);
    expect(metricsFirst.batchesSubmitted).toBe(1);

    // Second iteration — the submission should be reconciled to settled.
    const metricsSecond = await keeper.runOnce();
    expect(metricsSecond.batchesConfirmed).toBeGreaterThanOrEqual(1);
    expect(metricsSecond.batchesSettled).toBeGreaterThanOrEqual(1);

    // settle_claim extrinsic was called with the full 4-arg shape
    // (claimId, cardanoTxHash, settledDirect, signatures).
    expect(rpc.submitExtrinsic).toHaveBeenCalledWith(
      "intentSettlement",
      "settleClaim",
      expect.arrayContaining([expect.any(String)]),
    );
    const settleCall = rpc.submitExtrinsic.mock.calls.find(
      (c) => c[0] === "intentSettlement" && c[1] === "settleClaim",
    );
    expect(settleCall).toBeDefined();
    const [, , args] = settleCall!;
    expect(args).toHaveLength(4);
    // args[2] = settled_direct boolean (M=1 keeper path always false —
    // settled_direct=true is reserved for the 10-min direct-path fallback
    // spec §5.7, not the keeper-batch path).
    expect(args[2]).toBe(false);
    // args[3] = signatures Vec<(CommitteePubkey, CommitteeSig)>. M=1 for
    // now: the keeper's own mnemonic signs the canonical payload and that
    // single entry must satisfy the pallet's threshold (runtime sets
    // DefaultMinSignerThreshold = 1 initially).
    const signatures = args[3] as Array<[string, string]>;
    expect(Array.isArray(signatures)).toBe(true);
    expect(signatures).toHaveLength(1);
    const [pubkey, sig] = signatures[0]!;
    // sr25519 pubkeys are 32 bytes = 66 hex chars incl. "0x".
    expect(pubkey).toMatch(/^0x[0-9a-f]{64}$/);
    // sr25519 sigs are 64 bytes = 130 hex chars incl. "0x".
    expect(sig).toMatch(/^0x[0-9a-f]{128}$/);
  });
});

describe("Keeper.runOnce — failure modes", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-"));
  });

  it("double-submit idempotency: already-settled claim is skipped", async () => {
    const batch = makeBatch(2);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const cardano = fakeCardano();
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));
    // Pre-mark this claim as settled.
    state.recordObservation(batch.intentId as unknown as HexString, 100);
    state.markSettled(batch.intentId as unknown as HexString, ("0x" + "ff".repeat(32)) as HexString);

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(keeper.metrics.batchesSubmitted).toBe(0);
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });

  it("orphan rollback: tx slot goes null → submission reset to observed", async () => {
    const batch = makeBatch(3);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    // After the rollback is detected, don't re-surface the batch on the next
    // poll (Materios would have marked it back to a non-attested state).
    const getPending = vi
      .fn()
      .mockResolvedValueOnce([batch])
      .mockResolvedValue([]);
    const rpc = fakeRpc({
      getPendingBatches: getPending,
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });

    const cardano = fakeCardano({
      // Always return orphaned — the keeper should detect and reset.
      isConfirmed: vi
        .fn()
        .mockResolvedValue({ confirmed: false, currentSlot: 100n, txSlot: null }),
    });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      logger: () => {},
    });

    await keeper.runOnce(); // submits, then reconcile sees orphan
    expect(keeper.metrics.orphanRollbacks).toBe(1);
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("observed");
  });

  it("fee-spike retry: transient submit failure → retried with bump", async () => {
    const batch = makeBatch(4);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });

    const submitTx = vi
      .fn()
      .mockRejectedValueOnce(new Error("fee too low"))
      .mockResolvedValue({ txHash: ("0x" + "cd".repeat(32)) as HexString, submittedAtSlot: 0n });
    const cardano = fakeCardano({ submitTx });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(submitTx).toHaveBeenCalledTimes(2);
    expect(keeper.metrics.feeSpikeRetries).toBeGreaterThanOrEqual(1);
  });

  it("fee-spike retry exhausted: gives up after maxAttempts", async () => {
    const batch = makeBatch(5);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const submitTx = vi.fn().mockRejectedValue(new Error("fee too low"));
    const cardano = fakeCardano({ submitTx });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(
      { ...baseConfig, feeSpikeMaxAttempts: 2 },
      {
        rpc: rpc as any,
        cardano,
        state,
        keeperCardanoAddr: "addr_test1keeper",
        policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
        fetchFairnessProof: async () => makeValidBfpr(),
        logger: () => {},
      },
    );

    await keeper.runOnce();
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("failed");
    expect(sub?.lastError).toMatch(/fee too low/);
  });

  it("committee sig missing → no submit, committeeSigFailures++", async () => {
    const batch = makeBatch(6);
    const voucher: Voucher = { ...makeVoucher(batch.intentId as unknown as HexString), committeeSigs: [] };
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const cardano = fakeCardano();
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(keeper.metrics.committeeSigFailures).toBe(1);
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });

  it("invalid fairness proof → refuse to submit", async () => {
    const batch = makeBatch(7);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const cardano = fakeCardano();
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const bad: BatchFairnessProof = { ...makeValidBfpr(), proRataScaleBps: 99_999 };
    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => bad,
      logger: () => {},
    });

    await keeper.runOnce();
    expect(cardano.submitTx).not.toHaveBeenCalled();
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("failed");
  });

  it("Cardano halt detected → keeper pauses (does not submit)", async () => {
    const batch = makeBatch(8);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    // Only surface the batch on the SECOND poll, by which time halt is live.
    const getPending = vi
      .fn()
      .mockResolvedValueOnce([]) // warm-up iteration
      .mockResolvedValue([batch]);
    const rpc = fakeRpc({
      getPendingBatches: getPending,
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });

    let now = 1000;
    const cardano = fakeCardano({
      // Cardano timestamp never advances — always 990.
      getLatestBlockTimestamp: vi.fn().mockResolvedValue(990),
    });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      clock: () => now,
      logger: () => {},
    });

    // Warm up the detector: fresh block at t=1000 (delta 10s, healthy).
    await keeper.runOnce();
    // Advance wall clock >60s past last known block. Halt triggers.
    now = 1120;
    await keeper.runOnce();

    expect(keeper.metrics.currentlyPaused).toBe(true);
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });

  it("dry-run mode skips actual Cardano submit but records submission", async () => {
    const batch = makeBatch(9);
    const voucher = makeVoucher(batch.intentId as unknown as HexString);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const cardano = fakeCardano();
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(
      { ...baseConfig, dryRun: true },
      {
        rpc: rpc as any,
        cardano,
        state,
        keeperCardanoAddr: "addr_test1keeper",
        policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
        fetchFairnessProof: async () => makeValidBfpr(),
        logger: () => {},
      },
    );

    await keeper.runOnce();
    expect(cardano.submitTx).not.toHaveBeenCalled();
    expect(keeper.metrics.batchesSubmitted).toBe(1);
  });

  it("voucher not yet issued → skips cleanly", async () => {
    const batch = makeBatch(10);
    const rpc = fakeRpc({
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(null),
    });
    const cardano = fakeCardano();
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: ("0x" + "00".repeat(4)) as HexString,
      fetchFairnessProof: async () => makeValidBfpr(),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(cardano.submitTx).not.toHaveBeenCalled();
    expect(keeper.metrics.batchesObserved).toBe(1);
  });
});
