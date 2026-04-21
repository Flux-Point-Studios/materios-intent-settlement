/**
 * Committee daemon tests — halt circuit breaker, attestation emission,
 * DegradationExtension publishing. Uses //Alice derivations for sr25519 +
 * ed25519 keys.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { CommitteeDaemon } from "./index.js";
import type { BatchPayload, HexString } from "@fluxpointstudios/materios-intent-settlement-sdk";
import { intentId as computeIntentId } from "@fluxpointstudios/materios-intent-settlement-sdk";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

function makeBatch(nonce: number): BatchPayload {
  const submitter = ("0x" + "ab".repeat(32)) as HexString;
  const kind = { tag: "RefundCredit" as const, amountAda: BigInt(nonce) };
  const id = computeIntentId({ submitter, nonce: BigInt(nonce), kind, submittedBlock: 100 });
  return {
    intent: { submitter, nonce: BigInt(nonce), kind, submittedBlock: 100, ttlBlock: 700, status: 1 },
    intentId: id,
    attestationSigs: [],
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

describe("CommitteeDaemon", () => {
  let tmpDir: string;

  beforeEach(async () => {
    await cryptoWaitReady();
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "daemon-"));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("initialize loads keys, saveState round-trips", async () => {
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
        rpc: fakeRpc() as any,
        getCardanoLatestBlockTimestamp: async () => Math.floor(Date.now() / 1000),
      },
    );
    await daemon.initialize();
    await daemon.saveState();
    const raw = await fs.readFile(path.join(tmpDir, "ds.json"), "utf-8");
    const parsed = JSON.parse(raw);
    expect(parsed.lastProcessedBlock).toBeDefined();
  });

  it("attests pending batches (produces both sr25519 and ed25519 sigs)", async () => {
    const batch = makeBatch(1);
    const rpc = fakeRpc({ getPendingBatches: vi.fn().mockResolvedValue([batch]) });

    const now = Math.floor(Date.now() / 1000);
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
        rpc: rpc as any,
        getCardanoLatestBlockTimestamp: async () => now,
        clock: () => now,
        logger: () => {},
      },
    );
    await daemon.initialize();
    const res = await daemon.runOnce();
    expect(res.attested.length).toBe(1);
    expect(res.attested[0]!.sr25519Sig.length).toBe(2 + 64 * 2); // 64-byte sig hex
    expect(res.attested[0]!.ed25519Sig.length).toBe(2 + 64 * 2);
    expect(res.attested[0]!.ed25519PubKey.length).toBe(2 + 32 * 2);
  });

  it("pauses attestation during Cardano halt", async () => {
    const batch = makeBatch(2);
    const rpc = fakeRpc({ getPendingBatches: vi.fn().mockResolvedValue([batch]) });

    let now = 1000;
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
        rpc: rpc as any,
        getCardanoLatestBlockTimestamp: async () => 990, // stale
        clock: () => now,
        logger: () => {},
      },
    );
    await daemon.initialize();
    // warm up with fresh timestamp
    await daemon.runOnce();
    now = 1120;
    const res = await daemon.runOnce();
    expect(daemon.isPaused()).toBe(true);
    expect(res.attested).toHaveLength(0);
  });

  it("publishes DegradationExtension on >24h halt recovery", async () => {
    const rpc = fakeRpc();
    let now = 900;
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
        rpc: rpc as any,
        getCardanoLatestBlockTimestamp: async () => lastTs,
        clock: () => now,
        logger: () => {},
      },
    );
    await daemon.initialize();

    let lastTs: number | null = 900;
    // Healthy tick
    await daemon.runOnce();
    // Halt
    now = 900 + 70;
    await daemon.runOnce();
    // Long halt — 25h passes, no blocks
    now = 900 + 25 * 3600;
    await daemon.runOnce();
    expect(daemon.getHaltState().inHalt).toBe(true);

    // Recovery — 3 fresh blocks over next 30s.
    lastTs = 900 + 25 * 3600 + 1;
    now = 900 + 25 * 3600 + 10;
    await daemon.runOnce();
    lastTs = 900 + 25 * 3600 + 2;
    now = 900 + 25 * 3600 + 20;
    await daemon.runOnce();
    lastTs = 900 + 25 * 3600 + 3;
    now = 900 + 25 * 3600 + 30;
    const res = await daemon.runOnce();

    expect(res.extensionPublished).not.toBeNull();
    expect(res.extensionPublished?.haltSeconds).toBeGreaterThanOrEqual(24 * 3600);
    expect(res.extensionPublished?.extendAllTtlsBy).toBe((res.extensionPublished?.haltSeconds ?? 0) + 3600);
  });

  it("does NOT publish DegradationExtension on short halt recovery", async () => {
    const rpc = fakeRpc();
    let now = 900;
    let lastTs: number | null = 900;
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
        rpc: rpc as any,
        getCardanoLatestBlockTimestamp: async () => lastTs,
        clock: () => now,
        logger: () => {},
      },
    );
    await daemon.initialize();
    await daemon.runOnce();
    now = 970;
    await daemon.runOnce(); // halt
    expect(daemon.isPaused()).toBe(true);
    // 3 recoveries soon.
    for (let i = 1; i <= 3; i++) {
      lastTs = 900 + i;
      now = 970 + i * 10;
      const res = await daemon.runOnce();
      if (i === 3) expect(res.extensionPublished).toBeNull(); // short halt
    }
  });

  it("signVoucher returns ed25519 pubkey + sig", async () => {
    const rpc = fakeRpc();
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
        rpc: rpc as any,
        getCardanoLatestBlockTimestamp: async () => 1000,
      },
    );
    await daemon.initialize();
    const v = {
      claimId: ("0x" + "11".repeat(32)) as HexString,
      policyId: ("0x" + "22".repeat(32)) as HexString,
      beneficiaryCardanoAddr: new Uint8Array([1, 2, 3]),
      amountAda: 1n,
      batchFairnessProofDigest: ("0x" + "33".repeat(32)) as HexString,
      issuedBlock: 1,
      expirySlotCardano: 1n,
      committeeSigs: [],
    };
    const sig = daemon.signVoucher(v);
    expect(sig.pubkey.length).toBe(2 + 32 * 2);
    expect(sig.sig.length).toBe(2 + 64 * 2);
  });
});
