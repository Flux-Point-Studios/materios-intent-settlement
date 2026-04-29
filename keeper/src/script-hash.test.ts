/**
 * Task #76a — keeper startup script-hash verification.
 *
 * Asserts:
 *   - hash-match → ok (returns the computed hash)
 *   - hash-mismatch → throws PolicyScriptHashMismatchError
 *   - missing/empty expected hash → throws (fail-closed)
 *   - bad CBOR shape → throws
 *   - Plutus V3 language tag is included in the hash pre-image
 *   - Keeper constructor surfaces the same gate
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  computePlutusV3ScriptHash,
  verifyPolicyScriptHash,
  PolicyScriptHashMismatchError,
} from "./script-hash.js";
import { Keeper } from "./keeper.js";
import { KeeperStateStore } from "./state.js";
import type { ICardanoProvider } from "./cardano.js";
import type {
  HexString,
  KeeperConfig,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { blake2AsU8a, cryptoWaitReady } from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

beforeAll(async () => {
  await cryptoWaitReady();
});

const SAMPLE_CBOR = ("0x" + "deadbeef") as HexString;

function expectedHashFor(cborHex: HexString): HexString {
  // Mirror the impl's Plutus V3 language tag prepend for parity.
  const cborBytes = hexToU8a(cborHex);
  const tagged = new Uint8Array(cborBytes.length + 1);
  tagged[0] = 0x03;
  tagged.set(cborBytes, 1);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fn = blake2AsU8a as unknown as (
    data: Uint8Array,
    bitLength: number,
  ) => Uint8Array;
  return u8aToHex(fn(tagged, 224)) as HexString;
}

describe("computePlutusV3ScriptHash", () => {
  it("produces a 28-byte (56-hex) blake2b_224 digest with V3 language tag", () => {
    const h = computePlutusV3ScriptHash(SAMPLE_CBOR);
    expect(h).toMatch(/^0x[0-9a-f]{56}$/);
    // Must equal the manual reproduction (with 0x03 prefix).
    expect(h).toBe(expectedHashFor(SAMPLE_CBOR));
  });

  it("rejects non-0x-prefixed input", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => computePlutusV3ScriptHash("deadbeef" as any)).toThrow(/0x-prefixed/);
  });

  it("rejects empty CBOR", () => {
    expect(() => computePlutusV3ScriptHash("0x" as HexString)).toThrow(
      /empty CBOR payload/,
    );
  });

  it("two different CBOR payloads produce different hashes", () => {
    const a = computePlutusV3ScriptHash(("0x" + "00".repeat(8)) as HexString);
    const b = computePlutusV3ScriptHash(("0x" + "ff".repeat(8)) as HexString);
    expect(a).not.toBe(b);
  });
});

describe("verifyPolicyScriptHash", () => {
  it("returns ok when hash matches", () => {
    const expected = computePlutusV3ScriptHash(SAMPLE_CBOR);
    const res = verifyPolicyScriptHash(SAMPLE_CBOR, expected);
    expect(res.ok).toBe(true);
    expect(res.computedHash).toBe(expected);
  });

  it("throws PolicyScriptHashMismatchError when hash differs", () => {
    const wrongHash = ("0x" + "00".repeat(28)) as HexString;
    let caught: unknown = null;
    try {
      verifyPolicyScriptHash(SAMPLE_CBOR, wrongHash);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(PolicyScriptHashMismatchError);
    expect((caught as Error).message).toMatch(/script-hash mismatch/);
    expect((caught as PolicyScriptHashMismatchError).expectedHash).toBe(wrongHash);
  });

  it("throws on missing expected hash (fail-closed for #76a)", () => {
    expect(() => verifyPolicyScriptHash(SAMPLE_CBOR, null)).toThrow(
      /aegisPolicyV1ScriptHash is missing/,
    );
    expect(() => verifyPolicyScriptHash(SAMPLE_CBOR, undefined)).toThrow(
      /aegisPolicyV1ScriptHash is missing/,
    );
  });

  it("throws on malformed expected hash (wrong byte length)", () => {
    // 27 bytes → not 28
    const tooShort = ("0x" + "ab".repeat(27)) as HexString;
    expect(() => verifyPolicyScriptHash(SAMPLE_CBOR, tooShort)).toThrow(
      /must be 28 bytes/,
    );
  });

  it("is case-insensitive on the expected hash", () => {
    const expected = computePlutusV3ScriptHash(SAMPLE_CBOR);
    const upper = ("0x" + expected.slice(2).toUpperCase()) as HexString;
    expect(() => verifyPolicyScriptHash(SAMPLE_CBOR, upper)).not.toThrow();
  });
});

// -------------------------------------------------------------------------
// Constructor-level gate: the Keeper must refuse to construct when its
// `aegisPolicyV1ScriptHash` does not bind the supplied policyScriptCbor.
// -------------------------------------------------------------------------

function fakeCardano(): ICardanoProvider {
  const slot = 1_000_000n;
  return {
    submitTx: async () => ({
      txHash: ("0x" + "cd".repeat(32)) as HexString,
      submittedAtSlot: slot,
    }),
    isConfirmed: async () => ({ confirmed: true, currentSlot: slot, txSlot: slot }),
    getCurrentSlot: async () => slot,
    getLatestBlockTimestamp: async () => Math.floor(Date.now() / 1000),
  };
}

function fakeRpc() {
  return {
    getPendingBatches: async () => [],
    getVoucher: async () => null,
    getLatestBlockNumber: async () => 0,
    submitExtrinsic: async () => ({
      txHash: ("0x" + "00".repeat(32)) as HexString,
      blockHash: null,
    }),
    getCommitteeState: async () => ({ members: [], threshold: 1, lastMirror: null }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
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
};

describe("Keeper constructor — Task #76a script-hash gate", () => {
  it("succeeds when CBOR matches configured aegisPolicyV1ScriptHash", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "k76a-"));
    const cbor = ("0x" + "ab".repeat(8)) as HexString;
    const goodConfig: KeeperConfig = {
      ...baseConfig,
      aegisPolicyV1ScriptHash: computePlutusV3ScriptHash(cbor),
    };
    expect(() => {
      new Keeper(goodConfig, {
        rpc: fakeRpc(),
        cardano: fakeCardano(),
        state: new KeeperStateStore(path.join(tmpDir, "st.json")),
        keeperCardanoAddr: "addr_test1keeper",
        policyScriptCbor: cbor,
        logger: () => {},
      });
    }).not.toThrow();
  });

  it("refuses to construct on script-hash mismatch", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "k76a-"));
    const cbor = ("0x" + "ab".repeat(8)) as HexString;
    const badHash = ("0x" + "00".repeat(28)) as HexString;
    const badConfig: KeeperConfig = {
      ...baseConfig,
      aegisPolicyV1ScriptHash: badHash,
    };
    expect(() => {
      new Keeper(badConfig, {
        rpc: fakeRpc(),
        cardano: fakeCardano(),
        state: new KeeperStateStore(path.join(tmpDir, "st.json")),
        keeperCardanoAddr: "addr_test1keeper",
        policyScriptCbor: cbor,
        logger: () => {},
      });
    }).toThrow(PolicyScriptHashMismatchError);
  });

  it("refuses to construct when aegisPolicyV1ScriptHash is missing entirely", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "k76a-"));
    const cbor = ("0x" + "ab".repeat(8)) as HexString;
    expect(() => {
      // No aegisPolicyV1ScriptHash field at all — the historic vulnerable
      // shape that allowed an unbound POLICY_SCRIPT_CBOR.
      new Keeper(baseConfig, {
        rpc: fakeRpc(),
        cardano: fakeCardano(),
        state: new KeeperStateStore(path.join(tmpDir, "st.json")),
        keeperCardanoAddr: "addr_test1keeper",
        policyScriptCbor: cbor,
        logger: () => {},
      });
    }).toThrow(/aegisPolicyV1ScriptHash is missing/);
  });
});
