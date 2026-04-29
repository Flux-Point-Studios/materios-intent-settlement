/**
 * Task #76b — keeper-side voucher committee-sig verification.
 *
 * Asserts that:
 *   - a voucher with valid sigs from current committee members ACCEPTS.
 *   - a voucher with a tampered sig REJECTS (no Cardano tx submitted).
 *   - a voucher signed by a non-member REJECTS.
 *   - a voucher with a duplicate signer REJECTS.
 *   - an empty sigs list REJECTS.
 *   - integration: Keeper.processBatch increments
 *     `voucherSigVerifyFailures` and DOES NOT call `cardano.submitTx`
 *     when the voucher fails verification.
 */

import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  verifyVoucherSigs,
} from "./voucher-sig-verify.js";
import type { ChainIdentity } from "./voucher-sig-verify.js";
import { Keeper } from "./keeper.js";
import { KeeperStateStore } from "./state.js";
import { computePlutusV3ScriptHash } from "./script-hash.js";
import type { ICardanoProvider, SubmittedTx } from "./cardano.js";
import type {
  BatchPayload,
  Voucher,
  KeeperConfig,
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

beforeAll(async () => {
  await cryptoWaitReady();
});

const PLACEHOLDER_CBOR = ("0x" + "00".repeat(4)) as HexString;
const PLACEHOLDER_HASH = computePlutusV3ScriptHash(PLACEHOLDER_CBOR);

// #73 + #79: pinned chain-identity tuple. The pallet integration runtime
// uses `TestAegisPolicyV1ScriptHash = 0x42*28` for its parity tests, but
// the keeper's task #76a startup gate enforces
// `blake2b_224(0x03||POLICY_SCRIPT_CBOR) == aegisPolicyV1ScriptHash`. To
// keep both invariants honest in this in-process test we pin
// `aegisPolicyV1ScriptHash` to the actual hash of the placeholder CBOR
// — the digest computation is symmetric across `signedBy` and
// `verifyVoucherSigs` as long as both sides use the same constant.
const TEST_CHAIN_ID: HexString = ("0x" + "73".repeat(32)) as HexString;
const TEST_AEGIS_SCRIPT_HASH: HexString = PLACEHOLDER_HASH;
const TEST_NETWORK_MAGIC = 1;
const TEST_SETTLEMENT_VERSION = 1;
const TEST_CHAIN_IDENTITY: ChainIdentity = {
  materiosChainId: TEST_CHAIN_ID,
  networkMagic: TEST_NETWORK_MAGIC,
  aegisPolicyV1ScriptHash: TEST_AEGIS_SCRIPT_HASH,
  settlementVersion: TEST_SETTLEMENT_VERSION,
};

/**
 * #79: build a 57-byte CIP-0019 type-0 address buffer with `fill` as the
 * body byte. The `voucherDigestWithAddress` derivation requires a real
 * type-0 layout (header || payment_hash(28) || stake_hash(28)) so the
 * SDK's `splitType0AddressBytes` doesn't reject the input. Tests pin a
 * deterministic fill byte per voucher so digests don't accidentally
 * collide across cases.
 */
function type0Address(fill: number): Uint8Array {
  const out = new Uint8Array(57);
  out[0] = 0x01;
  for (let i = 1; i < 57; i++) out[i] = fill & 0xff;
  return out;
}

// -- Voucher builders -------------------------------------------------------

function freshVoucher(
  claimId: HexString = ("0x" + "07".repeat(32)) as HexString,
  addrFill = 0xab,
): Voucher {
  return {
    claimId,
    policyId: ("0x" + "ee".repeat(32)) as HexString,
    beneficiaryCardanoAddr: type0Address(addrFill),
    amountAda: 10_000_000n,
    batchFairnessProofDigest: ("0x" + "dd".repeat(32)) as HexString,
    issuedBlock: 110,
    expirySlotCardano: 5_000_000n,
    committeeSigs: [],
  };
}

/**
 * Compute the canonical voucher digest the same way `verifyVoucherSigs`
 * does — split → cbor → voucherDigestWithAddress with the pinned test
 * chain-identity tuple. The `signedBy` helper signs THIS exact digest so
 * the verify gate accepts.
 */
function testVoucherDigest(voucher: Voucher): HexString {
  const hashes = splitType0AddressBytes(voucher.beneficiaryCardanoAddr);
  const cbor = encodeType0AddressCbor(hashes);
  return voucherDigestWithAddress({
    claimId: voucher.claimId,
    policyId: voucher.policyId,
    beneficiaryAddressCbor: cbor,
    amountAda: voucher.amountAda,
    batchFairnessProofDigest: voucher.batchFairnessProofDigest,
    issuedBlock: voucher.issuedBlock,
    expirySlotCardano: voucher.expirySlotCardano,
    materiosChainId: TEST_CHAIN_IDENTITY.materiosChainId,
    networkMagic: TEST_CHAIN_IDENTITY.networkMagic,
    aegisPolicyV1ScriptHash: TEST_CHAIN_IDENTITY.aegisPolicyV1ScriptHash,
    settlementVersion: TEST_CHAIN_IDENTITY.settlementVersion,
  });
}

function signedBy(voucher: Voucher, seeds: string[]): {
  voucher: Voucher;
  pubkeys: CommitteePubkey[];
} {
  const digest = hexToU8a(testVoucherDigest(voucher));
  const sigs: Array<{ pubkey: HexString; sig: HexString }> = [];
  const pubkeys: CommitteePubkey[] = [];
  for (const seed of seeds) {
    const { pubkey, sig } = signPayload(seed, digest);
    const pkHex = u8aToHex(pubkey) as HexString;
    sigs.push({ pubkey: pkHex, sig: u8aToHex(sig) as HexString });
    pubkeys.push(pkHex as CommitteePubkey);
  }
  return { voucher: { ...voucher, committeeSigs: sigs }, pubkeys };
}

/** Build a verifyVoucherSigs options bag with the pinned test chain-identity tuple. */
function verifyOpts(
  pubkeys: readonly CommitteePubkey[],
  threshold: number,
): Parameters<typeof verifyVoucherSigs>[1] {
  return {
    committeeMembers: pubkeys,
    threshold,
    chainIdentity: TEST_CHAIN_IDENTITY,
  };
}

// -------------------------------------------------------------------------
// Pure-function unit tests for verifyVoucherSigs.
// -------------------------------------------------------------------------

describe("verifyVoucherSigs (Task #76b)", () => {
  it("accepts a voucher with N valid sigs and threshold N", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice", "//Bob"]);
    const res = verifyVoucherSigs(voucher, verifyOpts(pubkeys, 2));
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.verifiedCount).toBe(2);
      expect(res.threshold).toBe(2);
    }
  });

  it("accepts a voucher with M valid sigs and threshold ≤ M", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice", "//Bob"]);
    const res = verifyVoucherSigs(voucher, verifyOpts(pubkeys, 1));
    expect(res.ok).toBe(true);
  });

  it("rejects an empty committeeSigs list", () => {
    const v = freshVoucher();
    const res = verifyVoucherSigs(
      v,
      verifyOpts([("0x" + "ff".repeat(32)) as CommitteePubkey], 1),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("no_signatures");
  });

  it("rejects a voucher whose sig was tampered with", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice"]);
    // Flip a byte in the signature.
    const tamperedSig = ("0x" +
      "ff" +
      voucher.committeeSigs[0]!.sig.slice(4)) as HexString;
    const tampered: Voucher = {
      ...voucher,
      committeeSigs: [{ pubkey: voucher.committeeSigs[0]!.pubkey, sig: tamperedSig }],
    };
    const res = verifyVoucherSigs(tampered, verifyOpts(pubkeys, 1));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("insufficient_unique_valid_sigs");
  });

  it("rejects a voucher signed by a non-committee-member", () => {
    const { voucher } = signedBy(freshVoucher(), ["//Eve"]);
    // Committee snapshot does NOT include Eve.
    const aliceOnly = signedBy(freshVoucher(), ["//Alice"]);
    const res = verifyVoucherSigs(voucher, verifyOpts(aliceOnly.pubkeys, 1));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("non_member_signer");
  });

  it("rejects a voucher with duplicate signer (matches pallet DuplicateSigner)", () => {
    const v = freshVoucher();
    const digest = hexToU8a(testVoucherDigest(v));
    const { pubkey, sig } = signPayload("//Alice", digest);
    const pkHex = u8aToHex(pubkey) as HexString;
    const dup: Voucher = {
      ...v,
      committeeSigs: [
        { pubkey: pkHex, sig: u8aToHex(sig) as HexString },
        { pubkey: pkHex, sig: u8aToHex(sig) as HexString },
      ],
    };
    const res = verifyVoucherSigs(
      dup,
      verifyOpts([pkHex as CommitteePubkey], 1),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("duplicate_signer");
  });

  it("rejects when sig count meets threshold but only some are crypto-valid", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice", "//Bob"]);
    // Tamper with Bob's sig but keep Alice's intact.
    const tampered: Voucher = {
      ...voucher,
      committeeSigs: [
        voucher.committeeSigs[0]!,
        {
          pubkey: voucher.committeeSigs[1]!.pubkey,
          sig: ("0x" +
            "ff" +
            voucher.committeeSigs[1]!.sig.slice(4)) as HexString,
        },
      ],
    };
    const res = verifyVoucherSigs(tampered, verifyOpts(pubkeys, 2));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("insufficient_unique_valid_sigs");
  });

  it("returns bad_pubkey_format on malformed pubkey", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice"]);
    const malformed: Voucher = {
      ...voucher,
      committeeSigs: [{ pubkey: "not-a-hex-string" as HexString, sig: voucher.committeeSigs[0]!.sig }],
    };
    const res = verifyVoucherSigs(malformed, verifyOpts(pubkeys, 1));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("bad_pubkey_format");
  });

  it("returns bad_sig_format on malformed sig", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice"]);
    const malformed: Voucher = {
      ...voucher,
      committeeSigs: [{ pubkey: voucher.committeeSigs[0]!.pubkey, sig: "0xbad" as HexString }],
    };
    const res = verifyVoucherSigs(malformed, verifyOpts(pubkeys, 1));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("bad_sig_format");
  });

  it("rejects threshold == 0 (defensive — pallet would too)", () => {
    const { voucher, pubkeys } = signedBy(freshVoucher(), ["//Alice"]);
    const res = verifyVoucherSigs(voucher, verifyOpts(pubkeys, 0));
    expect(res.ok).toBe(false);
  });
});

// -------------------------------------------------------------------------
// Integration: Keeper.processBatch must reject an unverifiable voucher
// BEFORE paying Cardano fees.
// -------------------------------------------------------------------------

function makeKind(nonce: number) {
  return { tag: "RefundCredit" as const, amountAda: BigInt(10_000 + nonce) };
}

function makeBatch(nonce: number): BatchPayload {
  const submitter = ("0x" + "ab".repeat(32)) as HexString;
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

function fakeCardano(overrides: Partial<ICardanoProvider> = {}): ICardanoProvider {
  const slot = 1_000_000n;
  return {
    submitTx: vi.fn().mockResolvedValue({
      txHash: ("0x" + "cd".repeat(32)) as HexString,
      submittedAtSlot: slot,
    } satisfies SubmittedTx),
    isConfirmed: vi.fn().mockResolvedValue({
      confirmed: false,
      currentSlot: slot,
      txSlot: null,
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
  feeSpikeMaxAttempts: 1,
  feeSpikeBackoffMs: 1,
  pollIntervalMs: 10,
  maxBatchSize: 32,
  dryRun: false,
  aegisPolicyV1ScriptHash: PLACEHOLDER_HASH,
  // #73: Keeper.processBatch passes these into verifyVoucherSigs when
  // sig-verifying a voucher. The values match the pinned test
  // chain-identity tuple `signedBy` uses to produce sigs, so the
  // end-to-end gate accepts.
  materiosChainId: TEST_CHAIN_ID,
  networkMagic: TEST_NETWORK_MAGIC,
  settlementVersion: TEST_SETTLEMENT_VERSION,
};

describe("Keeper.processBatch — Task #76b end-to-end gate", () => {
  let tmpDir: string;
  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "k76b-"));
  });

  it("ACCEPTS a voucher with valid sigs from current committee members", async () => {
    const batch = makeBatch(1);
    const { voucher, pubkeys } = signedBy(
      freshVoucher(batch.intentId as unknown as HexString),
      ["//Alice"],
    );
    const cardano = fakeCardano();
    const rpc = {
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
      getLatestBlockNumber: vi.fn().mockResolvedValue(200),
      submitExtrinsic: vi.fn().mockResolvedValue({
        txHash: ("0x" + "00".repeat(32)) as HexString,
        blockHash: null,
      }),
      getCommitteeState: vi.fn().mockResolvedValue({
        members: pubkeys,
        threshold: 1,
        lastMirror: null,
      }),
    };
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

    // Sig verify counter stays at zero — the voucher was accepted.
    expect(keeper.metrics.voucherSigVerifyFailures).toBe(0);
    // submitTx WAS called — the keeper paid the Cardano fee for a verified voucher.
    expect(cardano.submitTx).toHaveBeenCalledTimes(1);
    expect(keeper.metrics.batchesSubmitted).toBe(1);
  });

  it("REJECTS a voucher with a tampered sig — NO Cardano tx submitted", async () => {
    const batch = makeBatch(2);
    const { voucher, pubkeys } = signedBy(
      freshVoucher(batch.intentId as unknown as HexString),
      ["//Alice"],
    );
    // Flip the first byte of the signature.
    const tampered: Voucher = {
      ...voucher,
      committeeSigs: [
        {
          pubkey: voucher.committeeSigs[0]!.pubkey,
          sig: ("0x" + "ff" + voucher.committeeSigs[0]!.sig.slice(4)) as HexString,
        },
      ],
    };

    const cardano = fakeCardano();
    const rpc = {
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(tampered),
      getLatestBlockNumber: vi.fn().mockResolvedValue(200),
      submitExtrinsic: vi.fn().mockResolvedValue({
        txHash: ("0x" + "00".repeat(32)) as HexString,
        blockHash: null,
      }),
      getCommitteeState: vi.fn().mockResolvedValue({
        members: pubkeys,
        threshold: 1,
        lastMirror: null,
      }),
    };
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

    // The defensive metric bumped.
    expect(keeper.metrics.voucherSigVerifyFailures).toBe(1);
    // CRITICAL: submitTx must NOT have been called — this is the whole
    // point of the local pre-verify gate.
    expect(cardano.submitTx).not.toHaveBeenCalled();
    expect(keeper.metrics.batchesSubmitted).toBe(0);
  });

  it("REJECTS a voucher signed by a non-member — NO Cardano tx submitted", async () => {
    const batch = makeBatch(3);
    // Sign as Eve, but pin the committee snapshot to Alice only.
    const { voucher } = signedBy(
      freshVoucher(batch.intentId as unknown as HexString),
      ["//Eve"],
    );
    const aliceOnly = signedBy(freshVoucher(), ["//Alice"]);

    const cardano = fakeCardano();
    const rpc = {
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
      getLatestBlockNumber: vi.fn().mockResolvedValue(200),
      submitExtrinsic: vi.fn().mockResolvedValue({
        txHash: ("0x" + "00".repeat(32)) as HexString,
        blockHash: null,
      }),
      getCommitteeState: vi.fn().mockResolvedValue({
        members: aliceOnly.pubkeys,
        threshold: 1,
        lastMirror: null,
      }),
    };
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeBfpr(),
      fetchCommitteeSnapshot: async () =>
        ({ members: aliceOnly.pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();

    expect(keeper.metrics.voucherSigVerifyFailures).toBe(1);
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });

  it("does NOT mark the submission failed on snapshot-stale rejection — leaves it for retry", async () => {
    // Eve signs but the snapshot only has Alice; on the first tick the
    // sig-verify fails but the local state should remain at "observed" so
    // a future tick (with a refreshed snapshot or recovered voucher) can
    // try again. Otherwise an Aiken validator outage that briefly returns
    // a stale committee would permanently strand vouchers.
    const batch = makeBatch(4);
    const { voucher } = signedBy(
      freshVoucher(batch.intentId as unknown as HexString),
      ["//Eve"],
    );
    const aliceOnly = signedBy(freshVoucher(), ["//Alice"]);

    const cardano = fakeCardano();
    const rpc = {
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
      getLatestBlockNumber: vi.fn().mockResolvedValue(200),
      submitExtrinsic: vi.fn().mockResolvedValue({
        txHash: ("0x" + "00".repeat(32)) as HexString,
        blockHash: null,
      }),
      getCommitteeState: vi.fn().mockResolvedValue({
        members: aliceOnly.pubkeys,
        threshold: 1,
        lastMirror: null,
      }),
    };
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));

    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeBfpr(),
      fetchCommitteeSnapshot: async () =>
        ({ members: aliceOnly.pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();

    const sub = state.snapshot.submissions[batch.intentId as unknown as HexString];
    // Submission state is "observed" (recorded by recordObservation), NOT
    // "failed" — failure here would prevent a legitimate retry.
    if (sub) {
      expect(sub.state).toBe("observed");
    }
    expect(cardano.submitTx).not.toHaveBeenCalled();
  });
});
