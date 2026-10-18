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
  ClaimId,
  KeeperConfig,
  Voucher,
  BatchFairnessProof,
  HexString,
  CommitteePubkey,
  SettlementEvidence,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import {
  DispatchFailedError,
  TransactionRejectedError,
  intentId as computeIntentId,
  voucherDigestWithAddress,
  encodeType0AddressCbor,
  splitType0AddressBytes,
  settleClaimAttestedPayload,
  signPayload,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { FakeSettlementChain } from "../tests/support/fake-settlement-chain.js";
import type { StcaPayload } from "../tests/support/fake-settlement-chain.js";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { computePlutusV3ScriptHash } from "./script-hash.js";
import { promises as fs, readFileSync } from "node:fs";
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

/** The STCA payload the pallet rebuilds for `voucher`'s claim. */
function stcaFor(voucher: Voucher): StcaPayload {
  const voucherDigest = voucherDigestWithAddress({
    claimId: voucher.claimId,
    policyId: voucher.policyId,
    beneficiaryAddressCbor: encodeType0AddressCbor(
      splitType0AddressBytes(voucher.beneficiaryCardanoAddr as Uint8Array),
    ),
    amountAda: voucher.amountAda,
    batchFairnessProofDigest: voucher.batchFairnessProofDigest,
    issuedBlock: voucher.issuedBlock,
    expirySlotCardano: voucher.expirySlotCardano,
    materiosChainId: TEST_CHAIN_ID,
    networkMagic: TEST_NETWORK_MAGIC,
    aegisPolicyV1ScriptHash: TEST_AEGIS_SCRIPT_HASH,
    settlementVersion: TEST_SETTLEMENT_VERSION,
  });
  return (claimId, evidence, settledDirect) =>
    settleClaimAttestedPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId,
      voucherDigest,
      cardanoTxHash: evidence.cardano_tx_hash,
      settledDirect,
      beneficiaryAddrHash: evidence.beneficiary_addr_hash,
      amountLovelace: evidence.amount_lovelace,
      observedAtDepth: evidence.observed_at_depth,
      observedSlot: evidence.observed_slot,
      mainchainGenesisHash: evidence.mainchain_genesis_hash,
    });
}

/** Mock RPC whose settlement calls run against `chain`. */
function fakeRpc(overrides: Record<string, any> = {}, chain = new FakeSettlementChain(("0x" + "00".repeat(32)) as HexString, () => new Uint8Array())) {
  const settlement = chain.rpc();
  return {
    ...settlement,
    submitExtrinsic: vi.fn(settlement.submitExtrinsic),
    getPendingBatches: vi.fn().mockResolvedValue([]),
    getVoucher: vi.fn().mockResolvedValue(null),
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

const CARDANO_TX = ("0x" + "cd".repeat(32)) as HexString;
const UNFUNDED_ALERT = "keeper account cannot pay for settlement; top up the keeper account";
const ATTACKER = ("0x" + "e1".repeat(32)) as HexString;

/** A batch, its signed voucher and a keeper settling against a fake chain. */
function settlementHarness(
  tmpDir: string,
  nonce: number,
  options: { cardano?: ICardanoProvider; batchesOnce?: boolean } = {},
) {
  const batch = makeBatch(nonce);
  const { voucher, pubkeys } = makeSignedVoucher(batch.intentId as unknown as HexString);
  const claimId = batch.intentId as unknown as ClaimId;
  const keeperKey = pubkeys[0] as unknown as HexString;
  const chain = new FakeSettlementChain(keeperKey, stcaFor(voucher));
  const rpc = fakeRpc(
    {
      getPendingBatches: options.batchesOnce
        ? vi.fn().mockResolvedValueOnce([batch]).mockResolvedValue([])
        : vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    },
    chain,
  );
  const statePath = path.join(tmpDir, `st-${nonce}.json`);
  const state = new KeeperStateStore(statePath);
  const logs: Array<{ level: string; msg: string }> = [];
  const cardano = options.cardano ?? fakeCardano();
  const keeperWith = (store: KeeperStateStore) =>
    new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano,
      state: store,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: (level, msg) => logs.push({ level, msg }),
    });
  const keeper = keeperWith(state);
  /** A fresh keeper process over whatever the state file holds. */
  const restart = async () => keeperWith(await KeeperStateStore.load(statePath));
  /** The evidence the keeper derives for its confirmed payout. */
  const honest: SettlementEvidence = {
    cardano_tx_hash: CARDANO_TX,
    observed_at_depth: 150,
    observed_slot: 1_000_000n,
    beneficiary_addr_hash: ("0x" + "ab".repeat(28)) as HexString,
    amount_lovelace: voucher.amountAda,
    mainchain_genesis_hash: baseConfig.mainchainGenesisHash,
  };
  const methods = () => chain.calls.map((call) => (call.failure ? `${call.method}:${call.failure}` : call.method));
  const submission = () => state.snapshot.submissions[claimId];
  return { batch, voucher, claimId, keeperKey, chain, rpc, state, statePath, keeper, restart, logs, honest, methods, submission };
}

describe("Keeper.runOnce — happy path", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-"));
  });

  it.each([500n, 0n])(
    "settles on chain, then releases its bond of max(MinSettlementBond %s, 1) after the hold",
    async (minimumBond) => {
      const h = settlementHarness(tmpDir, 1);
      h.chain.constants.minSettlementBond = minimumBond;
      const bond = minimumBond || 1n;

      expect((await h.keeper.runOnce()).batchesSubmitted).toBe(1);
      const settled = await h.keeper.runOnce();

      expect(settled.batchesSettled).toBe(1);
      expect(h.chain.settled.has(h.claimId)).toBe(true);
      expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
      expect(h.methods()).toEqual(["requestSettle", "attestSettle"]);
      const [, , requestArgs] = h.rpc.submitExtrinsic.mock.calls[0]!;
      expect(requestArgs).toEqual([h.claimId, CARDANO_TX, false, h.honest, bond]);
      expect(h.chain.reservedBalance(h.keeperKey)).toBe(bond);

      await h.keeper.runOnce();
      expect(h.methods()).toEqual(["requestSettle", "attestSettle"]);

      h.chain.block += h.chain.constants.bondReleaseDelayBlocks;
      const released = await h.keeper.runOnce();
      expect(h.methods()).toEqual(["requestSettle", "attestSettle", "releaseSettlementBond"]);
      expect(released.bondsReleased).toBe(1);
      expect(h.chain.reservedBalance(h.keeperKey)).toBe(0n);
      expect(h.chain.freeBalance(h.keeperKey)).toBe(10_000n);
      expect(h.state.trackedBonds()).toEqual([]);
    },
  );
});

describe("Keeper settlement against chain state", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-"));
  });

  it("supersedes an unattestable request that front-ran it", async () => {
    const h = settlementHarness(tmpDir, 21);
    h.chain.fund(ATTACKER, 500n);
    h.chain.fileRequest(ATTACKER, h.claimId, { ...h.honest, observed_slot: 999n }, 500n);

    await h.keeper.runOnce();
    await h.keeper.runOnce();

    expect(h.methods()).toEqual(["supersedeSettlementRequest"]);
    expect(h.chain.settled.has(h.claimId)).toBe(true);
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
    expect(h.chain.reservedBalance(ATTACKER)).toBe(0n);
    expect(h.chain.freeBalance(ATTACKER)).toBe(500n);
    expect(h.chain.reservedBalance(h.keeperKey)).toBe(0n);
  });

  it("waits out requests it cannot supersede or attest alone, then releases its bond", async () => {
    const h = settlementHarness(tmpDir, 22);
    h.chain.threshold = 2;
    h.chain.fund(ATTACKER, 500n);
    h.chain.fileRequest(ATTACKER, h.claimId, { ...h.honest, observed_at_depth: 2_160 }, 500n);
    const expiry = h.chain.block + h.chain.constants.settlementRequestTtl + 1;

    await h.keeper.runOnce();
    await h.keeper.runOnce();
    expect(h.methods()).toEqual(["supersedeSettlementRequest:InsufficientSignatures"]);
    expect(h.state.snapshot.submissions[h.claimId]?.retryAtBlock).toBe(expiry);
    expect(h.state.isAlreadySettled(h.claimId)).toBeNull();

    await h.keeper.runOnce();
    expect(h.methods()).toHaveLength(1);

    h.chain.block = expiry;
    await h.keeper.runOnce();
    expect(h.methods().slice(1)).toEqual(["requestSettle", "attestSettle:InsufficientSignatures"]);
    expect(h.chain.reservedBalance(ATTACKER)).toBe(0n);
    expect(h.chain.reservedBalance(h.keeperKey)).toBe(500n);
    expect(h.state.snapshot.submissions[h.claimId]?.retryAtBlock).toBe(
      expiry + h.chain.constants.settlementRequestTtl + 1,
    );

    await h.keeper.runOnce();
    expect(h.methods()).toHaveLength(3);
    expect(h.state.isAlreadySettled(h.claimId)).toBeNull();

    h.chain.attestAsCommittee(h.claimId);
    await h.keeper.runOnce();
    expect(h.methods()).toHaveLength(3);
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();

    h.chain.block += h.chain.constants.bondReleaseDelayBlocks;
    await h.keeper.runOnce();
    expect(h.methods().slice(3)).toEqual(["releaseSettlementBond"]);
    expect(h.chain.reservedBalance(h.keeperKey)).toBe(0n);
  });

  it("attests a matching request filed by another keeper instead of filing its own", async () => {
    const h = settlementHarness(tmpDir, 23);
    const otherKeeper = ("0x" + "e2".repeat(32)) as HexString;
    h.chain.fund(otherKeeper, 500n);
    h.chain.fileRequest(otherKeeper, h.claimId, { ...h.honest, observed_at_depth: 100 }, 500n);

    await h.keeper.runOnce();
    await h.keeper.runOnce();

    expect(h.methods()).toEqual(["attestSettle"]);
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
    expect(h.chain.attested.get(h.claimId)?.requester).toBe(otherKeeper);
    expect(h.state.trackedBonds()).toEqual([]);
  });

  it("alerts and keeps the claim open when it cannot fund the bond", async () => {
    const h = settlementHarness(tmpDir, 24);
    h.chain.fund(h.keeperKey, -10_000n);

    const metrics = await h.keeper.runOnce();

    expect(h.methods()).toEqual(["requestSettle:InsufficientBalance"]);
    expect(metrics.settleDispatchFailures).toBe(1);
    expect(h.state.isAlreadySettled(h.claimId)).toBeNull();
    expect(h.logs).toContainEqual({ level: "error", msg: UNFUNDED_ALERT });

    h.chain.fund(h.keeperKey, 10_000n);
    h.chain.block = h.submission()!.retryAtBlock!;
    await h.keeper.runOnce();
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
  });

  it("alerts when the pool rejects the filing for an unpaid fee, and backs off", async () => {
    const h = settlementHarness(tmpDir, 33);
    h.chain.beforeSubmit = (method) => {
      if (method === "requestSettle") {
        throw new TransactionRejectedError(
          "intentSettlement.requestSettle",
          1010,
          "Invalid Transaction: Inability to pay some fees , e.g. account balance too low",
        );
      }
    };

    await h.keeper.runOnce();

    expect(h.methods()).toEqual(["requestSettle:Rejected:1010"]);
    expect(h.logs).toContainEqual({ level: "error", msg: UNFUNDED_ALERT });
    expect(h.submission()).toMatchObject({ state: "submitted", retryAtBlock: h.chain.block + 10 });
    await h.keeper.runOnce();
    expect(h.methods()).toHaveLength(1);
  });

  it("backs off exponentially after failed filings instead of paying a fee every tick", async () => {
    const h = settlementHarness(tmpDir, 32);
    h.chain.beforeSubmit = (method) => {
      if (method === "requestSettle") {
        throw new DispatchFailedError(
          "intentSettlement.requestSettle",
          "intentSettlement",
          "WrongMainchainGenesis",
          ("0x" + "bb".repeat(32)) as HexString,
        );
      }
    };
    const start = h.chain.block;

    await h.keeper.runOnce();
    await h.keeper.runOnce();
    expect(h.methods()).toEqual(["requestSettle:WrongMainchainGenesis"]);
    expect(h.submission()?.retryAtBlock).toBe(start + 10);

    h.chain.block = start + 10;
    await h.keeper.runOnce();
    expect(h.methods()).toHaveLength(2);
    expect(h.submission()?.retryAtBlock).toBe(start + 30);

    h.chain.beforeSubmit = () => {};
    h.chain.block = start + 30;
    await h.keeper.runOnce();
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
  });

  it("defers a payout shallower than the runtime's MinFinalityDepth", async () => {
    const h = settlementHarness(tmpDir, 34);
    h.chain.constants.minFinalityDepth = 200;

    await h.keeper.runOnce();
    expect(h.methods()).toEqual([]);

    h.chain.constants.minFinalityDepth = 15;
    await h.keeper.runOnce();
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
  });

  it("marks a claim settled only once its settlement is finalized", async () => {
    const h = settlementHarness(tmpDir, 29);
    h.chain.finalityLag = 2;

    await h.keeper.runOnce();
    await h.keeper.runOnce();
    expect(h.methods()).toEqual(["requestSettle", "attestSettle"]);
    expect(h.state.isAlreadySettled(h.claimId)).toBeNull();

    h.chain.block += 2;
    await h.keeper.runOnce();
    expect(h.methods()).toHaveLength(2);
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
  });

  it("persists bond tracking before filing and releases a bond whose filing outcome was lost", async () => {
    const h = settlementHarness(tmpDir, 30);
    let trackedOnDisk: string[] = [];
    h.chain.beforeSubmit = (method) => {
      if (method === "requestSettle") {
        trackedOnDisk = Object.keys(JSON.parse(readFileSync(h.statePath, "utf-8")).heldBonds ?? {});
      }
    };
    h.chain.afterInclusion = (method) => {
      if (method === "requestSettle") throw new Error("WebSocket closed after broadcast");
    };

    await h.keeper.runOnce();
    expect(trackedOnDisk).toEqual([h.claimId]);
    expect(h.methods()).toEqual(["requestSettle"]);

    h.chain.afterInclusion = () => {};
    await h.keeper.runOnce();
    expect(h.methods()).toEqual(["requestSettle", "attestSettle"]);
    h.chain.block += h.chain.constants.bondReleaseDelayBlocks;
    await h.keeper.runOnce();
    expect(h.methods().at(-1)).toBe("releaseSettlementBond");
    expect(h.chain.reservedBalance(h.keeperKey)).toBe(0n);
  });

  it("after a restart, releases a bond it holds on chain but no longer tracks", async () => {
    const h = settlementHarness(tmpDir, 31);
    await h.keeper.runOnce();
    expect(h.chain.reservedBalance(h.keeperKey)).toBe(500n);
    const written = JSON.parse(readFileSync(h.statePath, "utf-8"));
    delete written.heldBonds;
    await fs.writeFile(h.statePath, JSON.stringify(written));

    const restarted = await h.restart();
    h.chain.block += h.chain.constants.bondReleaseDelayBlocks;
    await restarted.runOnce();

    expect(h.methods()).toEqual(["requestSettle", "attestSettle", "releaseSettlementBond"]);
    expect(h.chain.reservedBalance(h.keeperKey)).toBe(0n);
  });

  it("claims at most the runtime's MaxObservedDepth", async () => {
    const h = settlementHarness(tmpDir, 27);
    h.chain.constants.maxObservedDepth = 100;

    await h.keeper.runOnce();

    expect(h.methods()).toEqual(["requestSettle", "attestSettle"]);
    expect((h.chain.calls[0]!.args[3] as SettlementEvidence).observed_at_depth).toBe(100);
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
  });

  it("keeps ticking and persisting when the bond sweep cannot read the runtime", async () => {
    const h = settlementHarness(tmpDir, 28);
    await h.keeper.runOnce();
    expect(h.state.trackedBonds()).toEqual([h.claimId]);
    h.rpc.getSettlementConstants = () => {
      throw new Error("runtime lacks intentSettlement.bondReleaseDelayBlocks");
    };

    await expect(h.keeper.runOnce()).resolves.toBeDefined();

    expect(h.logs).toContainEqual({ level: "error", msg: "bond release sweep failed" });
    expect(h.state.trackedBonds()).toEqual([h.claimId]);
  });

  it("records a claim settled by someone else without submitting", async () => {
    const isConfirmed = vi
      .fn()
      .mockResolvedValueOnce({ confirmed: false, currentSlot: 1_000_010n, txSlot: 1_000_000n })
      .mockResolvedValue({ confirmed: true, currentSlot: 1_003_000n, txSlot: 1_000_000n });
    const h = settlementHarness(tmpDir, 25, { cardano: fakeCardano({ isConfirmed }) });

    await h.keeper.runOnce();
    h.chain.settle(h.claimId);
    await h.keeper.runOnce();

    expect(h.methods()).toEqual([]);
    expect(h.state.isAlreadySettled(h.claimId)).not.toBeNull();
  });

  it("keeps a confirmed payout through provider errors and files when the blocking request expires", async () => {
    const isConfirmed = vi
      .fn()
      .mockResolvedValueOnce({ confirmed: true, currentSlot: 1_003_000n, txSlot: 1_000_000n })
      .mockRejectedValueOnce(new Error("kupo timeout"))
      .mockResolvedValue({ confirmed: false, currentSlot: 1_003_000n, txSlot: null });
    const h = settlementHarness(tmpDir, 26, {
      cardano: fakeCardano({ isConfirmed }),
      batchesOnce: true,
    });
    h.chain.threshold = 2;
    h.chain.fund(ATTACKER, 500n);
    h.chain.fileRequest(ATTACKER, h.claimId, { ...h.honest, observed_slot: 999n }, 500n);
    const expiry = h.chain.block + h.chain.constants.settlementRequestTtl + 1;

    await h.keeper.runOnce();
    await h.keeper.runOnce();
    await h.keeper.runOnce();
    expect(h.methods()).toEqual(["supersedeSettlementRequest:InsufficientSignatures"]);
    expect(isConfirmed).toHaveBeenCalledTimes(1);
    expect(h.submission()).toMatchObject({ state: "submitted", cardanoTxHash: CARDANO_TX });

    h.chain.block = expiry;
    await h.keeper.runOnce();
    expect(h.submission()).toMatchObject({ state: "submitted", cardanoTxHash: CARDANO_TX });
    expect(h.logs).toContainEqual({ level: "warn", msg: "Cardano confirmation check failed" });

    await h.keeper.runOnce();
    expect(h.methods().slice(1)).toEqual(["requestSettle", "attestSettle:InsufficientSignatures"]);
    expect(h.chain.requests.get(h.claimId)?.evidence.observed_slot).toBe(1_000_000n);
    expect(h.chain.reservedBalance(ATTACKER)).toBe(0n);
    expect(h.submission()).toMatchObject({ state: "submitted", cardanoTxHash: CARDANO_TX });
    expect(h.state.trackedBonds()).toEqual([h.claimId]);
  });
});

describe("Keeper.runOnce — failure modes", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-"));
  });

  it("files no settlement request when the runtime lacks a settlement constant", async () => {
    const batch = makeBatch(1);
    const { voucher, pubkeys } = makeSignedVoucher(
      batch.intentId as unknown as HexString,
    );
    const rpc = fakeRpc({
      getSettlementConstants: () => {
        throw new Error("runtime lacks intentSettlement.minSettlementBond");
      },
      getPendingBatches: vi.fn().mockResolvedValue([batch]),
      getVoucher: vi.fn().mockResolvedValue(voucher),
    });
    const state = new KeeperStateStore(path.join(tmpDir, "st.json"));
    const keeper = new Keeper(baseConfig, {
      rpc: rpc as any,
      cardano: fakeCardano(),
      state,
      keeperCardanoAddr: "addr_test1keeper",
      policyScriptCbor: PLACEHOLDER_CBOR,
      fetchFairnessProof: async () => makeValidBfpr(),
      fetchCommitteeSnapshot: async () => ({ members: pubkeys, threshold: 1 }),
      logger: () => {},
    });

    await keeper.runOnce();
    const metrics = await keeper.runOnce();

    expect(metrics.batchesSettled).toBe(0);
    expect(rpc.submitExtrinsic.mock.calls.some((c) => c[1] === "requestSettle")).toBe(false);
    expect(state.snapshot.settledClaims).toEqual({});
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
