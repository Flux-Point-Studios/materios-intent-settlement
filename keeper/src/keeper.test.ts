/**
 * Keeper logic tests — all failure modes per spec §5.6.
 *
 * These tests stub @polkadot/api (one layer) and plug in a FakeCardanoProvider
 * that exposes the ICardanoProvider surface. The Keeper itself runs
 * unmodified; we exercise its orchestration decisions.
 */

import { describe, it, expect, vi, beforeEach, beforeAll } from "vitest";
import { Keeper } from "./keeper.js";
import { KeeperStateStore } from "./state.js";
import type { ICardanoProvider, SubmittedTx } from "./cardano.js";
import type {
  BatchPayload,
  KeeperConfig,
  Voucher,
  BatchFairnessProof,
  HexString,
  CommitteePubkey,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import {
  intentId as computeIntentId,
  voucherDigestWithAddress,
  encodeType0AddressCbor,
  splitType0AddressBytes,
  signPayload,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { computePlutusV3ScriptHash } from "./script-hash.js";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

// Cryptographic primitives for sr25519 require WASM init (#76b voucher
// sig verify path uses sr25519Verify under the hood).
beforeAll(async () => {
  await cryptoWaitReady();
});

// Placeholder POLICY_SCRIPT_CBOR used by every test. The real-time
// computed hash is plumbed through `baseConfig.aegisPolicyV1ScriptHash` so
// the keeper constructor's task #76a script-hash gate accepts it.
const PLACEHOLDER_CBOR = ("0x" + "00".repeat(4)) as HexString;
const PLACEHOLDER_HASH = computePlutusV3ScriptHash(PLACEHOLDER_CBOR);

// #73 + #79: pinned chain-identity tuple. Pallet uses `0x42*28` for its
// in-runtime parity tests, but the keeper's #76a startup gate enforces
// `aegisPolicyV1ScriptHash == blake2b_224(0x03||CBOR)`, so we pin to
// the actual hash of the placeholder CBOR. `signedBy` and the keeper
// `verifyVoucherSigs` both use this same constant, so digests match.
const TEST_CHAIN_ID: HexString = ("0x" + "73".repeat(32)) as HexString;
const TEST_AEGIS_SCRIPT_HASH: HexString = PLACEHOLDER_HASH;
const TEST_NETWORK_MAGIC = 1;
const TEST_SETTLEMENT_VERSION = 1;

/**
 * #79: build a 57-byte CIP-0019 type-0 address. The chain-identity-bound
 * `voucherDigestWithAddress` derivation requires a real type-0 layout so
 * `splitType0AddressBytes` doesn't reject the input.
 */
function type0Address(fill: number): Uint8Array {
  const out = new Uint8Array(57);
  out[0] = 0x01;
  for (let i = 1; i < 57; i++) out[i] = fill & 0xff;
  return out;
}

/**
 * Build a Voucher whose `committeeSigs` are real sr25519 signatures over
 * the canonical voucherDigestWithAddress. The returned bundle pairs
 * (alice pubkey, sig) so the test can register `alice` as a committee
 * member and the sig-verify gate (#76b) will pass.
 */
function makeSignedVoucher(
  id: HexString,
  signers: string[] = ["//Alice"],
  overrides: Partial<Voucher> = {},
): { voucher: Voucher; pubkeys: CommitteePubkey[] } {
  const base: Voucher = {
    claimId: id,
    policyId: ("0x" + "ee".repeat(32)) as HexString,
    beneficiaryCardanoAddr: type0Address(0xab),
    amountAda: 10_000_000n,
    batchFairnessProofDigest: ("0x" + "dd".repeat(32)) as HexString,
    issuedBlock: 110,
    expirySlotCardano: 5_000_000n,
    committeeSigs: [],
    ...overrides,
  };
  const hashes = splitType0AddressBytes(base.beneficiaryCardanoAddr);
  const cbor = encodeType0AddressCbor(hashes);
  const digestHex = voucherDigestWithAddress({
    claimId: base.claimId,
    policyId: base.policyId,
    beneficiaryAddressCbor: cbor,
    amountAda: base.amountAda,
    batchFairnessProofDigest: base.batchFairnessProofDigest,
    issuedBlock: base.issuedBlock,
    expirySlotCardano: base.expirySlotCardano,
    materiosChainId: TEST_CHAIN_ID,
    networkMagic: TEST_NETWORK_MAGIC,
    aegisPolicyV1ScriptHash: TEST_AEGIS_SCRIPT_HASH,
    settlementVersion: TEST_SETTLEMENT_VERSION,
  });
  const digestBytes = hexToU8a(digestHex);
  const sigs: Array<{ pubkey: HexString; sig: HexString }> = [];
  const pubkeys: CommitteePubkey[] = [];
  for (const seed of signers) {
    const { pubkey, sig } = signPayload(seed, digestBytes);
    const pkHex = u8aToHex(pubkey) as HexString;
    sigs.push({ pubkey: pkHex, sig: u8aToHex(sig) as HexString });
    pubkeys.push(pkHex as CommitteePubkey);
  }
  return { voucher: { ...base, committeeSigs: sigs }, pubkeys };
}

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
    // Default committee state used by Task #76b voucher-sig verification.
    // Tests that need a specific membership snapshot override this.
    getCommitteeState: vi.fn().mockResolvedValue({
      members: [],
      threshold: 1,
      lastMirror: null,
    }),
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
  // Task #76a: must be set so the keeper's startup script-hash check
  // accepts PLACEHOLDER_CBOR.
  aegisPolicyV1ScriptHash: PLACEHOLDER_HASH,
  // #73: pinned chain-identity tuple matching the pallet integration
  // runtime. `makeSignedVoucher` signs digests bound to these constants
  // so the keeper's #76b verify-before-submit gate accepts.
  materiosChainId: TEST_CHAIN_ID,
  networkMagic: TEST_NETWORK_MAGIC,
  settlementVersion: TEST_SETTLEMENT_VERSION,
  // Task #266 (mis-sec P0): Cardano genesis pin + finality floor for the
  // new attested-settle pair. Fakecardano returns currentSlot - txSlot
  // = 3000 (≈150 blocks at 20s/slot), so any minFinalityDepth <= 150
  // passes the keeper's pre-check.
  mainchainGenesisHash: ("0x" + "65".repeat(32)) as HexString,
  minFinalityDepth: 15,
};

describe("Keeper.runOnce — happy path", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-"));
  });

  it("observes → submits → confirms → settles an attested+vouchered batch", async () => {
    const batch = makeBatch(1);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    const metricsFirst = await keeper.runOnce();
    expect(metricsFirst.batchesObserved).toBe(1);
    expect(metricsFirst.batchesSubmitted).toBe(1);

    // Second iteration — the submission should be reconciled to settled.
    const metricsSecond = await keeper.runOnce();
    expect(metricsSecond.batchesConfirmed).toBeGreaterThanOrEqual(1);
    expect(metricsSecond.batchesSettled).toBeGreaterThanOrEqual(1);

    // Task #266 (mis-sec P0): keeper now fires the attested-settle pair
    // (request_settle + attest_settle) in place of the legacy settle_claim.
    // Both extrinsics MUST land in order for the claim to flip to settled.
    const requestCall = rpc.submitExtrinsic.mock.calls.find(
      (c) => c[0] === "intentSettlement" && c[1] === "requestSettle",
    );
    expect(requestCall).toBeDefined();
    const [, , reqArgs] = requestCall!;
    expect(reqArgs).toHaveLength(4);
    // reqArgs[2] = settled_direct boolean — M=1 keeper path is always
    // false; settled_direct=true is reserved for the 10-min direct-path
    // fallback (spec §5.7), not the keeper-batch path.
    expect(reqArgs[2]).toBe(false);
    // reqArgs[3] = SettlementEvidence object with all six pinned fields.
    const evidence = reqArgs[3] as Record<string, unknown>;
    expect(evidence).toHaveProperty("cardano_tx_hash");
    expect(evidence).toHaveProperty("observed_at_depth");
    expect(evidence).toHaveProperty("observed_slot");
    expect(evidence).toHaveProperty("beneficiary_addr_hash");
    expect(evidence).toHaveProperty("amount_lovelace");
    expect(evidence).toHaveProperty("mainchain_genesis_hash");

    const attestCall = rpc.submitExtrinsic.mock.calls.find(
      (c) => c[0] === "intentSettlement" && c[1] === "attestSettle",
    );
    expect(attestCall).toBeDefined();
    const [, , attestArgs] = attestCall!;
    expect(attestArgs).toHaveLength(2);
    // attestArgs[1] = M-of-N signature bundle. M=1 in the keeper interim.
    const signatures = attestArgs[1] as Array<[string, string]>;
    expect(Array.isArray(signatures)).toBe(true);
    expect(signatures).toHaveLength(1);
    const [pubkey, sig] = signatures[0]!;
    expect(pubkey).toMatch(/^0x[0-9a-f]{64}$/);
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
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(keeper.metrics.batchesSubmitted).toBe(0);
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });

  it("orphan rollback: tx slot goes null → submission reset to observed", async () => {
    const batch = makeBatch(3);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce(); // submits, then reconcile sees orphan
    expect(keeper.metrics.orphanRollbacks).toBe(1);
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("observed");
  });

  it("fee-spike retry: transient submit failure → retried with bump", async () => {
    const batch = makeBatch(4);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(submitTx).toHaveBeenCalledTimes(2);
    expect(keeper.metrics.feeSpikeRetries).toBeGreaterThanOrEqual(1);
  });

  it("fee-spike retry exhausted: gives up after maxAttempts", async () => {
    const batch = makeBatch(5);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
        policyScriptCbor: PLACEHOLDER_CBOR,
        fetchFairnessProof: async () => makeValidBfpr(),
        fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
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
    // Build a voucher with NO committee sigs to exercise the early-out
    // committeeSigFailures counter (separate from the #76b cryptographic
    // verify path tested elsewhere).
    const { voucher: signed, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
    const voucher: Voucher = { ...signed, committeeSigs: [] };
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(keeper.metrics.committeeSigFailures).toBe(1);
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });

  it("invalid fairness proof → refuse to submit", async () => {
    const batch = makeBatch(7);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => bad,
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(cardano.submitTx).not.toHaveBeenCalled();
    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    expect(sub?.state).toBe("failed");
  });

  it("Cardano halt detected → keeper pauses (does not submit)", async () => {
    const batch = makeBatch(8);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
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
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
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
        policyScriptCbor: PLACEHOLDER_CBOR,
        fetchFairnessProof: async () => makeValidBfpr(),
        fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
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
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      // No voucher means the gate isn't reached; provide a snapshot
      // anyway so the keeper init path stays uniform.
      fetchCommitteeSnapshot: async () => ({ members: [], threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();
    expect(cardano.submitTx).not.toHaveBeenCalled();
    expect(keeper.metrics.batchesObserved).toBe(1);
  });
});
