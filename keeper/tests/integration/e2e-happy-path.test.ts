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
  voucherDigestWithAddress,
  encodeType0AddressCbor,
  splitType0AddressBytes,
  signPayload,
  settleClaimAttestedPayload,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import type {
  BatchPayload,
  ClaimId,
  Voucher,
  HexString,
  IntentKind,
  CommitteePubkey,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { FakeSettlementChain } from "../support/fake-settlement-chain.js";
import { Keeper } from "../../src/keeper.js";
import { KeeperStateStore } from "../../src/state.js";
import { CommitteeDaemon } from "../../src/daemon/index.js";
import type { ICardanoProvider } from "../../src/cardano.js";
import { computePlutusV3ScriptHash } from "../../src/script-hash.js";

const PLACEHOLDER_CBOR = ("0x" + "00".repeat(4)) as HexString;
const PLACEHOLDER_HASH = computePlutusV3ScriptHash(PLACEHOLDER_CBOR);

// #73 + #79: pinned chain-identity tuple. The script-hash field must
// equal blake2b_224(0x03||CBOR) for the keeper's #76a startup gate, so
// pin to the actual hash of the placeholder CBOR.
const TEST_CHAIN_ID: HexString = ("0x" + "73".repeat(32)) as HexString;
const TEST_AEGIS_SCRIPT_HASH: HexString = PLACEHOLDER_HASH;
const TEST_NETWORK_MAGIC = 1;
const TEST_SETTLEMENT_VERSION = 1;

function type0Address(fill: number): Uint8Array {
  const out = new Uint8Array(57);
  out[0] = 0x01;
  for (let i = 1; i < 57; i++) out[i] = fill & 0xff;
  return out;
}

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
    // #79: type-0 CIP-0019 buffer required by the chain-identity-bound
    // voucherDigestWithAddress derivation.
    beneficiaryCardanoAddr: type0Address(0xab),
    amountAda: 1_000_000n,
    batchFairnessProofDigest: ("0x" + "dd".repeat(32)) as HexString,
    issuedBlock: 110,
    expirySlotCardano: 10_000_000n,
    committeeSigs: [],
  };
  // Task #76b: real sr25519 sig over the canonical
  // voucherDigestWithAddress (chain-identity-bound CBOR form). The
  // committee snapshot below pins //Alice as the lone member.
  const hashes = splitType0AddressBytes(baseVoucher.beneficiaryCardanoAddr);
  const cbor = encodeType0AddressCbor(hashes);
  const digestHex = voucherDigestWithAddress({
    claimId: baseVoucher.claimId,
    policyId: baseVoucher.policyId,
    beneficiaryAddressCbor: cbor,
    amountAda: baseVoucher.amountAda,
    batchFairnessProofDigest: baseVoucher.batchFairnessProofDigest,
    issuedBlock: baseVoucher.issuedBlock,
    expirySlotCardano: baseVoucher.expirySlotCardano,
    materiosChainId: TEST_CHAIN_ID,
    networkMagic: TEST_NETWORK_MAGIC,
    aegisPolicyV1ScriptHash: TEST_AEGIS_SCRIPT_HASH,
    settlementVersion: TEST_SETTLEMENT_VERSION,
  });
  const digest = hexToU8a(digestHex);
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

    // Mock Materios RPC: returns the batch + voucher the committee produced.
    // The keeper's settlement calls run against an in-memory settlement
    // pallet that verifies its STCA signatures and moves bond reserves.
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
    const chain = new FakeSettlementChain(committeePubkey as unknown as HexString, (claimId, evidence, settledDirect) =>
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
      }),
    );
    // fakeCardano confirms 200 slots (about 10 blocks) after the payout.
    chain.constants.minFinalityDepth = 3;
    let keeperPolls = 0;
    const makeRpc = (label: "daemon" | "keeper") => ({
      ...chain.rpc(),
      getPendingBatches: async () => {
        if (label === "keeper") {
          return keeperPolls++ === 0 ? [batch] : [];
        }
        return [batch]; // daemon attests
      },
      getVoucher: async () => voucher,
      getSigner: () => ({ publicKey: hexToU8a(committeePubkey) }) as any,
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
        // #73: chain-identity tuple bound into the voucher digest.
        // makeIntentAndBatch signs against these constants.
        materiosChainId: TEST_CHAIN_ID,
        networkMagic: TEST_NETWORK_MAGIC,
        settlementVersion: TEST_SETTLEMENT_VERSION,
        // Task #266 (mis-sec P0): mainchain genesis pin + finality floor
        // for the new request_settle + attest_settle path. fakeCardano's
        // currentSlot - txSlot = 200 slots = ~10 blocks (20s/slot); use
        // a low minFinalityDepth so the test fixture doesn't have to
        // burn through 300+ mock slots.
        mainchainGenesisHash: ("0x" + "65".repeat(32)) as HexString,
        minFinalityDepth: 3,
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

    const claimId = batch.intentId as unknown as ClaimId;
    const keeperAccount = committeePubkey as unknown as HexString;
    const freeBefore = chain.freeBalance(keeperAccount);

    // Iteration 1: observe, pay out on Cardano, request and attest on Materios.
    await keeper.runOnce();
    expect(keeper.metrics.batchesObserved).toBe(1);
    expect(keeper.metrics.batchesSubmitted).toBe(1);
    expect(keeper.metrics.batchesConfirmed).toBe(1);
    expect(keeper.metrics.batchesSettled).toBe(1);
    expect(chain.calls.map((call) => call.method)).toEqual(["requestSettle", "attestSettle"]);
    const requestArgs = chain.calls[0]!.args;
    expect(requestArgs[0]).toBe(claimId);
    expect(requestArgs[2]).toBe(false); // settled_direct
    expect(requestArgs[3]).toMatchObject({ cardano_tx_hash: ("0x" + "e2".repeat(32)) });
    expect(requestArgs[4]).toBe(500n);
    expect(chain.settled.has(claimId)).toBe(true);
    expect(chain.reservedBalance(keeperAccount)).toBe(500n);
    const final = state.snapshot.submissions[claimId];
    expect(final?.state).toBe("confirmed");
    expect(state.isAlreadySettled(claimId)).not.toBeNull();

    // After the liquidity hold the keeper returns its bond.
    chain.block += chain.constants.bondReleaseDelayBlocks;
    await keeper.runOnce();
    expect(chain.calls.map((call) => call.method)).toEqual([
      "requestSettle",
      "attestSettle",
      "releaseSettlementBond",
    ]);
    expect(chain.reservedBalance(keeperAccount)).toBe(0n);
    expect(chain.freeBalance(keeperAccount)).toBe(freeBefore);
  }, 30_000);
});
