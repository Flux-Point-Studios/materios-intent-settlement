import { describe, it, expect, vi } from "vitest";
import {
  buildAegisPolicyParams,
  buildPremiumDepositDatum,
  buildRefundCredit,
  buildRefundDeposit,
  buildSinglePointValidityRange,
  assertSinglePointValidityRange,
  collectMintSignatories,
  canonicalVoucherBody,
} from "./builders.js";
import type { HexString, ISignerWallet } from "./index.js";

const ANCHOR_ADDR_RAW = (() => {
  const payment = [
    0x95, 0x78, 0x87, 0x10, 0x0e, 0xbe, 0x5f, 0x9b, 0x0f, 0x9f, 0x24, 0x96, 0x8f, 0x02,
    0x1e, 0xf7, 0x05, 0xb2, 0x5c, 0x7a, 0xaa, 0x63, 0x32, 0x58, 0xe2, 0x88, 0xe0, 0xae,
  ];
  const stake = [
    0x1f, 0xe3, 0x62, 0x22, 0xd4, 0xd4, 0x5a, 0x1c, 0x70, 0xbf, 0xb9, 0x4b, 0x65, 0xb3,
    0xb8, 0xce, 0x1a, 0xdf, 0x2a, 0x94, 0x91, 0x3d, 0x67, 0xc3, 0x22, 0x12, 0x69, 0x4c,
  ];
  const raw = new Uint8Array(57);
  raw[0] = 0x01;
  raw.set(payment, 1);
  raw.set(stake, 29);
  return raw;
})();

describe("buildAegisPolicyParams", () => {
  it("defaults aegisPolicyV1ScriptHash to null when omitted", () => {
    const params = buildAegisPolicyParams({
      committeePubkeySet: [],
      committeeThreshold: 2,
      minFairnessProofSigCount: 2,
      charli3OracleRef: { txHash: "0xdeadbeef" as HexString, outputIndex: 0 },
      charli3FeedPolicyId: "0xcafe" as HexString,
      charli3FeedAssetName: "0xbabe" as HexString,
      materiosChainId: ("0x" + "00".repeat(32)) as HexString,
      poolCustodyScriptHash: ("0x" + "aa".repeat(28)) as HexString,
      premiumCollectorScriptHash: ("0x" + "bb".repeat(28)) as HexString,
      settlementVersion: 1,
      oracleFreshnessSlots: 300,
    });
    expect(params.aegisPolicyV1ScriptHash).toBeNull();
  });

  it("preserves explicitly-set script hash", () => {
    const pinned = ("0x" + "cc".repeat(28)) as HexString;
    const params = buildAegisPolicyParams({
      committeePubkeySet: [],
      committeeThreshold: 2,
      minFairnessProofSigCount: 2,
      charli3OracleRef: { txHash: "0xdeadbeef" as HexString, outputIndex: 0 },
      charli3FeedPolicyId: "0xcafe" as HexString,
      charli3FeedAssetName: "0xbabe" as HexString,
      materiosChainId: ("0x" + "00".repeat(32)) as HexString,
      poolCustodyScriptHash: ("0x" + "aa".repeat(28)) as HexString,
      premiumCollectorScriptHash: ("0x" + "bb".repeat(28)) as HexString,
      settlementVersion: 1,
      oracleFreshnessSlots: 300,
      aegisPolicyV1ScriptHash: pinned,
    });
    expect(params.aegisPolicyV1ScriptHash).toBe(pinned);
  });
});

describe("buildPremiumDepositDatum", () => {
  it("requires a 57-byte depositor address", () => {
    expect(() =>
      buildPremiumDepositDatum({
        depositorMateriosAccount: ("0x" + "01".repeat(32)) as HexString,
        depositorCardanoAddr: new Uint8Array(56),
        depositedAtSlot: 100n,
        depositId: ("0x" + "02".repeat(32)) as HexString,
        amountAda: 1_000_000n,
        productId: ("0x" + "00".repeat(32)) as HexString,
      }),
    ).toThrow();
  });

  it("rejects non-positive amount_ada", () => {
    expect(() =>
      buildPremiumDepositDatum({
        depositorMateriosAccount: ("0x" + "01".repeat(32)) as HexString,
        depositorCardanoAddr: ANCHOR_ADDR_RAW,
        depositedAtSlot: 100n,
        depositId: ("0x" + "02".repeat(32)) as HexString,
        amountAda: 0n,
        productId: ("0x" + "00".repeat(32)) as HexString,
      }),
    ).toThrow();
  });

  it("builds a datum with all B-8 fields populated", () => {
    const d = buildPremiumDepositDatum({
      depositorMateriosAccount: ("0x" + "01".repeat(32)) as HexString,
      depositorCardanoAddr: ANCHOR_ADDR_RAW,
      depositedAtSlot: 100n,
      depositId: ("0x" + "02".repeat(32)) as HexString,
      amountAda: 1_000_000n,
      productId: ("0x" + "00".repeat(32)) as HexString,
    });
    expect(d.depositorCardanoAddr).toEqual(ANCHOR_ADDR_RAW);
    expect(d.amountAda).toBe(1_000_000n);
  });
});

describe("buildRefundCredit / buildRefundDeposit", () => {
  const common = {
    voucherBytes: new Uint8Array([1, 2, 3]),
    sigs: [],
    amountAda: 5_000_000n,
    beneficiary: ANCHOR_ADDR_RAW,
    policyId: ("0x" + "ab".repeat(32)) as HexString,
    issuedBlock: 100,
    expirySlotCardano: 99_999n,
    claimId: ("0x" + "cc".repeat(32)) as HexString,
    bfpDigest: ("0x" + "de".repeat(32)) as HexString,
    currentSlot: 50_000n,
  };

  it("derives beneficiaryBytes from the raw address", () => {
    const r = buildRefundCredit(common);
    expect(r.beneficiaryBytes.length).toBe(80);
    // matches the Aiken pinned CBOR for the anchor address
    expect(r.beneficiaryBytes[0]).toBe(0xd8);
    expect(r.beneficiaryBytes[79]).toBe(0xff);
  });

  it("pre-computes a voucher digest callers can cross-check", () => {
    const r = buildRefundCredit(common);
    expect(r.precomputedVoucherDigest).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("RefundDeposit shape matches RefundCredit shape", () => {
    const a = buildRefundCredit(common);
    const b = buildRefundDeposit(common);
    expect(a.beneficiaryBytes).toEqual(b.beneficiaryBytes);
    expect(a.precomputedVoucherDigest).toEqual(b.precomputedVoucherDigest);
  });
});

describe("buildSinglePointValidityRange / assertSinglePointValidityRange", () => {
  it("creates [slot, slot] from a single slot", () => {
    const r = buildSinglePointValidityRange(42n);
    expect(r.lowerBound).toBe(42n);
    expect(r.upperBound).toBe(42n);
  });

  it("assertSinglePointValidityRange accepts matching single-point ranges", () => {
    const r = buildSinglePointValidityRange(100n);
    expect(assertSinglePointValidityRange(r, 100n)).toEqual({ ok: true });
  });

  it("rejects non-single-point ranges", () => {
    const bad = { lowerBound: 100n, upperBound: 101n };
    const out = assertSinglePointValidityRange(bad, 100n);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toMatch(/not a single point/);
  });

  it("rejects upper bound != current slot", () => {
    const r = buildSinglePointValidityRange(100n);
    const out = assertSinglePointValidityRange(r, 101n);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toMatch(/!= current slot/);
  });
});

describe("collectMintSignatories", () => {
  it("returns the wallet's payment hash + signed tx witness", async () => {
    const wallet: ISignerWallet = {
      getPaymentKeyHash: vi
        .fn()
        .mockResolvedValue(("0x" + "aa".repeat(28)) as HexString),
      signTxBody: vi.fn().mockResolvedValue("0xdeadbeef" as HexString),
    };
    const out = await collectMintSignatories(wallet, "0x00" as HexString);
    expect(out.paymentKeyHash).toBe("0x" + "aa".repeat(28));
    expect(out.witnessCborHex).toBe("0xdeadbeef");
    expect(wallet.signTxBody).toHaveBeenCalledWith("0x00");
  });

  it("throws if payment key hash is not 28 bytes", async () => {
    const wallet: ISignerWallet = {
      getPaymentKeyHash: vi.fn().mockResolvedValue("0x1234" as HexString),
      signTxBody: vi.fn().mockResolvedValue("0xff" as HexString),
    };
    await expect(
      collectMintSignatories(wallet, "0x00" as HexString),
    ).rejects.toThrow(/28-byte/);
  });
});

describe("canonicalVoucherBody", () => {
  it("produces a 196-byte body for type-0 addresses", () => {
    const body = canonicalVoucherBody({
      claimId: ("0x" + "cc".repeat(32)) as HexString,
      policyId: ("0x" + "ab".repeat(32)) as HexString,
      beneficiaryAddressCbor: new Uint8Array(80),
      amountAda: 10_000_000n,
      batchFairnessProofDigest: ("0x" + "de".repeat(32)) as HexString,
      issuedBlock: 42,
      expirySlotCardano: 99_999n,
    });
    // 32 + 32 + 80 + 8 + 32 + 4 + 8 = 196
    expect(body.length).toBe(196);
  });
});
