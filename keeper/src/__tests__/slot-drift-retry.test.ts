/**
 * Slot-drift retry tests (issue #16, #17).
 *
 * Covers:
 *   - buildBatchTx rejects missing currentSlot at runtime (type guard)
 *   - Keeper retries on slot-mismatch up to MAX_RETRIES then succeeds
 *   - Keeper does NOT retry on non-slot errors (insufficient funds, etc.)
 *   - Keeper throws after MAX_RETRIES slot-mismatch attempts
 *   - Keeper reads a fresh tip on every retry (getCurrentSlot spy)
 */

import { describe, it, expect, vi, beforeEach, beforeAll } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import { Keeper } from "../keeper.js";
import { KeeperStateStore } from "../state.js";
import { buildBatchTx } from "../cardano.js";
import {
  buildAndSubmitWithSlotRetry,
  isSlotDriftError,
  SLOT_ERROR_SIGNATURES,
  SlotDriftExhaustedError,
} from "../slot-retry.js";
import { computePlutusV3ScriptHash } from "../script-hash.js";
import type { ICardanoProvider, SubmittedTx } from "../cardano.js";
import type {
  BatchPayload,
  Voucher,
  KeeperConfig,
  HexString,
  CommitteePubkey,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import {
  intentId as computeIntentId,
  computeKeeperFeeLovelace,
  voucherDigest,
  signPayload,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";

beforeAll(async () => {
  await cryptoWaitReady();
});

const PLACEHOLDER_CBOR = ("0x" + "00".repeat(4)) as HexString;
const PLACEHOLDER_HASH = computePlutusV3ScriptHash(PLACEHOLDER_CBOR);

// ------------------------------ test fixtures -----------------------------

function makeBatch(nonce: number): BatchPayload {
  const submitter = ("0x" + "ab".repeat(32)) as HexString;
  const kind = { tag: "RefundCredit" as const, amountAda: BigInt(10_000 + nonce) };
  const id = computeIntentId({ submitter, nonce: BigInt(nonce), kind, submittedBlock: 100 });
  return {
    intent: {
      submitter,
      nonce: BigInt(nonce),
      kind,
      submittedBlock: 100,
      ttlBlock: 700,
      status: 1,
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
      {
        pubkey: ("0x" + "11".repeat(32)) as HexString,
        sig: ("0x" + "22".repeat(64)) as HexString,
      },
    ],
  };
}

/**
 * Voucher with real sr25519 sigs from the supplied seed list. The
 * returned `pubkeys` array can be plugged directly into a Keeper
 * `fetchCommitteeSnapshot` so the Task #76b verify gate accepts it.
 */
function makeSignedVoucher(
  id: HexString,
  seeds: string[] = ["//Alice"],
): { voucher: Voucher; pubkeys: CommitteePubkey[] } {
  const base: Voucher = {
    claimId: id,
    policyId: ("0x" + "ee".repeat(32)) as HexString,
    beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1xyz"),
    amountAda: 10_000_000n,
    batchFairnessProofDigest: ("0x" + "dd".repeat(32)) as HexString,
    issuedBlock: 110,
    expirySlotCardano: 5_000_000n,
    committeeSigs: [],
  };
  const digest = hexToU8a(voucherDigest(base));
  const sigs: Array<{ pubkey: HexString; sig: HexString }> = [];
  const pubkeys: CommitteePubkey[] = [];
  for (const seed of seeds) {
    const { pubkey, sig } = signPayload(seed, digest);
    const pkHex = u8aToHex(pubkey) as HexString;
    sigs.push({ pubkey: pkHex, sig: u8aToHex(sig) as HexString });
    pubkeys.push(pkHex as CommitteePubkey);
  }
  return { voucher: { ...base, committeeSigs: sigs }, pubkeys };
}

function makeBfpr() {
  return {
    batchBlockRange: [90, 110] as [number, number],
    sortedIntentIds: [("0x" + "77".repeat(32)) as HexString],
    requestedAmountsAda: [20_000_000n],
    poolBalanceAda: 100_000_000n,
    proRataScaleBps: 5000,
    awardedAmountsAda: [10_000_000n],
  };
}

function fakeRpc(batches: BatchPayload[], voucher: Voucher) {
  return {
    getPendingBatches: vi.fn().mockResolvedValue(batches),
    getVoucher: vi.fn().mockResolvedValue(voucher),
    getLatestBlockNumber: vi.fn().mockResolvedValue(200),
    submitExtrinsic: vi
      .fn()
      .mockResolvedValue({ txHash: "0x" + "aa".repeat(32), blockHash: null }),
  };
}

function fakeCardano(overrides: Partial<ICardanoProvider> = {}): ICardanoProvider {
  return {
    submitTx: vi.fn().mockResolvedValue({
      txHash: ("0x" + "cd".repeat(32)) as HexString,
      submittedAtSlot: 1_000_000n,
    } satisfies SubmittedTx),
    isConfirmed: vi.fn().mockResolvedValue({
      confirmed: true,
      currentSlot: 1_003_000n,
      txSlot: 1_000_000n,
    }),
    getCurrentSlot: vi.fn().mockResolvedValue(1_000_000n),
    getLatestBlockTimestamp: vi
      .fn()
      .mockResolvedValue(Math.floor(Date.now() / 1000)),
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
  feeSpikeMaxAttempts: 1, // disable fee-spike retry so slot-drift is the only retry layer under test
  feeSpikeBackoffMs: 1,
  pollIntervalMs: 10,
  maxBatchSize: 32,
  dryRun: false,
  // Task #76a: keeper constructor refuses to start without a script-hash
  // binding for POLICY_SCRIPT_CBOR.
  aegisPolicyV1ScriptHash: PLACEHOLDER_HASH,
};

// --------------------------- issue #16: runtime guard ----------------------

describe("issue #16: buildBatchTx requires currentSlot", () => {
  const totalAwarded = makeBfpr().awardedAmountsAda.reduce((a, b) => a + b, 0n);

  it("test_buildBatchTx_rejects_missing_currentSlot: runtime throws explicit error", async () => {
    // Bypass TS with `as any` to simulate a JS caller / permissive compile.
    await expect(
      buildBatchTx({
        voucher: makeVoucher(("0x" + "aa".repeat(32)) as HexString),
        fairnessProof: makeBfpr(),
        keeperAddr: "addr_test1keeper",
        keeperFeeLovelace: computeKeeperFeeLovelace(totalAwarded),
        policyScriptCbor: "0x00" as HexString,
        poolUtxoRef: { txHash: ("0x" + "00".repeat(32)) as HexString, outputIndex: 0 },
        policyUtxoRefs: [],
        metadataLabel8746Payload: {},
        currentSlot: undefined as unknown as bigint,
      }),
    ).rejects.toThrow(/currentSlot is required/);
  });

  it("test_buildBatchTx_rejects_missing_currentSlot: null is also rejected", async () => {
    await expect(
      buildBatchTx({
        voucher: makeVoucher(("0x" + "aa".repeat(32)) as HexString),
        fairnessProof: makeBfpr(),
        keeperAddr: "addr_test1keeper",
        keeperFeeLovelace: computeKeeperFeeLovelace(totalAwarded),
        policyScriptCbor: "0x00" as HexString,
        poolUtxoRef: { txHash: ("0x" + "00".repeat(32)) as HexString, outputIndex: 0 },
        policyUtxoRefs: [],
        metadataLabel8746Payload: {},
        currentSlot: null as unknown as bigint,
      }),
    ).rejects.toThrow(/currentSlot is required/);
  });
});

// --------------------- issue #17: keeper slot-drift retry ------------------

describe("issue #17: keeper slot-drift retry", () => {
  let tmpDir: string;
  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "slot-retry-"));
  });

  it("test_keeper_retries_on_slot_mismatch: 2 slot-mismatch failures → 3rd succeeds", async () => {
    const batch = makeBatch(1);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
    const rpc = fakeRpc([batch], voucher);

    // submit fails with slot-mismatch twice, succeeds third time.
    const submitTx = vi
      .fn()
      .mockRejectedValueOnce(new Error("tx rejected: validity range upper_bound 100 != current slot 101"))
      .mockRejectedValueOnce(new Error("OutsideValidityIntervalUTxO: slot 102 not in [101,101]"))
      .mockResolvedValue({
        txHash: ("0x" + "cd".repeat(32)) as HexString,
        submittedAtSlot: 103n,
      } satisfies SubmittedTx);

    // getCurrentSlot returns a new slot per call so the retry sees fresh tips.
    const slots = [100n, 101n, 102n, 103n];
    let slotIdx = 0;
    const getCurrentSlot = vi.fn().mockImplementation(async () => slots[slotIdx++] ?? 200n);

    const cardano = fakeCardano({ submitTx, getCurrentSlot });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();

    expect(submitTx).toHaveBeenCalledTimes(3);
    expect(keeper.metrics.batchesSubmitted).toBe(1);
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    // runOnce also reconciles in-flight submissions — the state may have
    // advanced from "submitted" to "confirmed" in the same tick. Either is
    // a success outcome; what matters is we didn't stall or fail.
    expect(["submitted", "confirmed"]).toContain(sub?.state);
  });

  it("test_keeper_does_not_retry_on_non_slot_error: insufficient funds → 1 attempt, fails", async () => {
    const batch = makeBatch(2);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
    const rpc = fakeRpc([batch], voucher);

    const submitTx = vi.fn().mockRejectedValue(new Error("InsufficientFundsUTxO: not enough ada"));
    const cardano = fakeCardano({ submitTx });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();

    expect(submitTx).toHaveBeenCalledTimes(1);
    expect(keeper.metrics.batchesSubmitted).toBe(0);
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("failed");
    expect(sub?.lastError).toMatch(/InsufficientFundsUTxO/);
  });

  it("test_keeper_throws_after_max_retries: 3 slot-mismatch failures → marked failed", async () => {
    const batch = makeBatch(3);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
    const rpc = fakeRpc([batch], voucher);

    const submitTx = vi
      .fn()
      .mockRejectedValue(new Error("tx rejected: validity range check failed"));
    const cardano = fakeCardano({ submitTx });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();

    // Exactly MAX_RETRIES (3) attempts, all fail, submission marked failed.
    expect(submitTx).toHaveBeenCalledTimes(3);
    expect(keeper.metrics.batchesSubmitted).toBe(0);
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("failed");
    // Aggregated error payload includes per-attempt slot info for forensics.
    expect(sub?.lastError).toMatch(/slot-drift retries exhausted after 3 attempts/);
    expect(sub?.lastError).toMatch(/attempt=0/);
    expect(sub?.lastError).toMatch(/attempt=2/);
  });

  it("test_keeper_reads_fresh_tip_on_each_retry: getCurrentSlot called per attempt", async () => {
    const batch = makeBatch(4);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
    const rpc = fakeRpc([batch], voucher);

    const submitTx = vi
      .fn()
      .mockRejectedValueOnce(new Error("validity range upper_bound != current slot"))
      .mockResolvedValue({
        txHash: ("0x" + "cd".repeat(32)) as HexString,
        submittedAtSlot: 1_000_001n,
      } satisfies SubmittedTx);
    const getCurrentSlot = vi
      .fn()
      .mockResolvedValueOnce(1_000_000n)
      .mockResolvedValueOnce(1_000_001n);
    const cardano = fakeCardano({ submitTx, getCurrentSlot });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();

    // One getCurrentSlot call per submit attempt (2 attempts in this test).
    expect(getCurrentSlot).toHaveBeenCalledTimes(2);
    expect(submitTx).toHaveBeenCalledTimes(2);
    expect(keeper.metrics.batchesSubmitted).toBe(1);
  });
});

// ----------------- isSlotDriftError + SLOT_ERROR_SIGNATURES ---------------

describe("issue #17: slot-drift error classification", () => {
  it("isSlotDriftError matches each signature (case-insensitive)", () => {
    for (const sig of SLOT_ERROR_SIGNATURES) {
      expect(isSlotDriftError(new Error(`tx rejected: ${sig.toUpperCase()}`))).toBe(true);
      expect(isSlotDriftError(new Error(`tx rejected: ${sig}`))).toBe(true);
    }
  });

  it("isSlotDriftError rejects unrelated errors", () => {
    expect(isSlotDriftError(new Error("InsufficientFundsUTxO"))).toBe(false);
    expect(isSlotDriftError(new Error("BadSignature"))).toBe(false);
    expect(isSlotDriftError(new Error("fee too low"))).toBe(false);
    expect(isSlotDriftError(new Error("ECONNREFUSED"))).toBe(false);
  });

  it("isSlotDriftError handles non-Error throwables", () => {
    expect(isSlotDriftError("validity range wrong")).toBe(true);
    expect(isSlotDriftError({ msg: "nothing to see" })).toBe(false);
    expect(isSlotDriftError(null)).toBe(false);
    expect(isSlotDriftError(undefined)).toBe(false);
  });

  it("SlotDriftExhaustedError carries per-attempt failure info", async () => {
    const provider = { getCurrentSlot: vi.fn().mockResolvedValue(42n) };
    const buildAndSubmit = vi
      .fn()
      .mockRejectedValue(new Error("validity range drifted"));

    await expect(
      buildAndSubmitWithSlotRetry(provider as any, buildAndSubmit, {
        maxRetries: 3,
        backoffMs: [1, 1, 1],
      }),
    ).rejects.toThrow(SlotDriftExhaustedError);

    try {
      await buildAndSubmitWithSlotRetry(provider as any, buildAndSubmit, {
        maxRetries: 3,
        backoffMs: [1, 1, 1],
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SlotDriftExhaustedError);
      const sde = err as SlotDriftExhaustedError;
      expect(sde.attempts).toHaveLength(3);
      expect(sde.attempts[0]?.attempt).toBe(0);
      expect(sde.attempts[2]?.attempt).toBe(2);
      expect(sde.attempts.every((a) => a.currentSlot === 42n)).toBe(true);
    }
  });

  it("backoff timing: retries respect [250, 500, 1000] by default", async () => {
    const provider = { getCurrentSlot: vi.fn().mockResolvedValue(1n) };
    const sleepSpy = vi.fn().mockResolvedValue(undefined);
    const buildAndSubmit = vi
      .fn()
      .mockRejectedValueOnce(new Error("validity range drift"))
      .mockRejectedValueOnce(new Error("validity range drift"))
      .mockResolvedValue({
        txHash: "0xdeadbeef" as HexString,
        submittedAtSlot: 1n,
      } satisfies SubmittedTx);

    await buildAndSubmitWithSlotRetry(provider as any, buildAndSubmit, {
      sleep: sleepSpy,
    });

    // Two retries were triggered → sleep called with 250 then 500.
    expect(sleepSpy).toHaveBeenCalledTimes(2);
    expect(sleepSpy).toHaveBeenNthCalledWith(1, 250);
    expect(sleepSpy).toHaveBeenNthCalledWith(2, 500);
  });
});
