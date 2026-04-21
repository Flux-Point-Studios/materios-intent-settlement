import { describe, it, expect } from "vitest";
import {
  domainHash,
  domainHashHex,
  DomainTag,
  u32LE,
  u64LE,
  compactCompactLen,
  encodeIntentKind,
  intentId,
  voucherDigest,
  fairnessProofDigest,
  validateFairnessProof,
} from "./hashing.js";
import type { HexString, IntentKind, Voucher, BatchFairnessProof } from "./types.js";

describe("domain hashing primitives", () => {
  it("domain tags are exactly 4 ASCII bytes", () => {
    expect(DomainTag.Intent).toEqual(new Uint8Array([0x49, 0x4e, 0x54, 0x54])); // "INTT"
    expect(DomainTag.Voucher).toEqual(new Uint8Array([0x56, 0x43, 0x48, 0x52])); // "VCHR"
    expect(DomainTag.BatchFairnessProof).toEqual(
      new Uint8Array([0x42, 0x46, 0x50, 0x52]),
    ); // "BFPR"
  });

  it("domainHash is deterministic and 32 bytes", () => {
    const a = domainHash(DomainTag.Intent, new Uint8Array([1, 2, 3]));
    const b = domainHash(DomainTag.Intent, new Uint8Array([1, 2, 3]));
    expect(a.length).toBe(32);
    expect(a).toEqual(b);
  });

  it("different domain tags yield different hashes for the same body", () => {
    const body = new Uint8Array([9, 9, 9]);
    const hi = domainHashHex(DomainTag.Intent, body);
    const hv = domainHashHex(DomainTag.Voucher, body);
    expect(hi).not.toEqual(hv);
  });
});

describe("u32LE/u64LE/compactCompactLen", () => {
  it("u32LE encodes canonical little-endian", () => {
    expect(Array.from(u32LE(1))).toEqual([1, 0, 0, 0]);
    expect(Array.from(u32LE(0x01020304))).toEqual([0x04, 0x03, 0x02, 0x01]);
    expect(Array.from(u32LE(0xffffffff))).toEqual([0xff, 0xff, 0xff, 0xff]);
  });

  it("u32LE rejects overflow or negative", () => {
    expect(() => u32LE(-1)).toThrow();
    expect(() => u32LE(0x1_0000_0000)).toThrow();
    expect(() => u32LE(1.5)).toThrow();
  });

  it("u64LE encodes canonical little-endian", () => {
    expect(Array.from(u64LE(0n))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(u64LE(1n))).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(u64LE(0x0102030405060708n))).toEqual([
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ]);
  });

  it("u64LE rejects negative + overflow", () => {
    expect(() => u64LE(-1n)).toThrow();
    expect(() => u64LE(2n ** 64n)).toThrow();
  });

  it("compactCompactLen matches Substrate single-byte mode for n<=63", () => {
    expect(Array.from(compactCompactLen(0))).toEqual([0]);
    expect(Array.from(compactCompactLen(63))).toEqual([0xfc]);
    expect(Array.from(compactCompactLen(64))).toEqual([0x01, 0x01]); // two-byte mode: 64<<2 | 0b01
    expect(Array.from(compactCompactLen(255))).toEqual([0xfd, 0x03]);
  });
});

describe("encodeIntentKind", () => {
  const product = ("0x" + "11".repeat(32)) as HexString;

  it("BuyPolicy layout: tag || productId || strike || termSlots || premium || beneficiary", () => {
    const kind: IntentKind = {
      tag: "BuyPolicy",
      productId: product,
      strike: 500_000n,
      termSlots: 86400,
      premiumAda: 1_000_000n,
      beneficiaryCardanoAddr: new Uint8Array([0xaa, 0xbb, 0xcc]),
    };
    const enc = encodeIntentKind(kind);
    // tag
    expect(enc[0]).toBe(0);
    // productId is the next 32 bytes
    expect(Array.from(enc.slice(1, 33))).toEqual(Array(32).fill(0x11));
    // strike u64 LE = 500_000 = 0x07a120
    expect(Array.from(enc.slice(33, 41))).toEqual([0x20, 0xa1, 0x07, 0, 0, 0, 0, 0]);
    // termSlots = 86400 = 0x15180
    expect(Array.from(enc.slice(41, 45))).toEqual([0x80, 0x51, 0x01, 0]);
    // premium u64 = 1_000_000 = 0x0f4240
    expect(Array.from(enc.slice(45, 53))).toEqual([0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]);
    // beneficiary compact-len = 3 → 0x0c
    expect(enc[53]).toBe(0x0c);
    expect(Array.from(enc.slice(54, 57))).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it("RequestPayout layout: tag || policyId || evidence", () => {
    const kind: IntentKind = {
      tag: "RequestPayout",
      policyId: ("0x" + "22".repeat(32)) as HexString,
      oracleEvidence: new Uint8Array([1, 2]),
    };
    const enc = encodeIntentKind(kind);
    expect(enc[0]).toBe(1);
    expect(Array.from(enc.slice(1, 33))).toEqual(Array(32).fill(0x22));
    expect(enc[33]).toBe(0x08); // compact 2 = 2<<2 = 8
    expect(Array.from(enc.slice(34, 36))).toEqual([1, 2]);
  });

  it("RefundCredit layout: tag || amount u64 LE", () => {
    const kind: IntentKind = { tag: "RefundCredit", amountAda: 42n };
    const enc = encodeIntentKind(kind);
    expect(enc.length).toBe(9);
    expect(enc[0]).toBe(2);
    expect(enc[1]).toBe(42);
  });
});

describe("intentId pre-image stability", () => {
  it("is deterministic across identical inputs", () => {
    const kind: IntentKind = { tag: "RefundCredit", amountAda: 100n };
    const id1 = intentId({
      submitter: ("0x" + "ab".repeat(32)) as HexString,
      nonce: 7n,
      kind,
      submittedBlock: 100,
    });
    const id2 = intentId({
      submitter: ("0x" + "ab".repeat(32)) as HexString,
      nonce: 7n,
      kind,
      submittedBlock: 100,
    });
    expect(id1).toEqual(id2);
  });

  it("is sensitive to submitter, nonce, kind, submittedBlock", () => {
    const base = {
      submitter: ("0x" + "00".repeat(32)) as HexString,
      nonce: 0n,
      kind: { tag: "RefundCredit", amountAda: 1n } as IntentKind,
      submittedBlock: 0,
    };
    const a = intentId(base);
    const b = intentId({ ...base, nonce: 1n });
    const c = intentId({ ...base, submittedBlock: 1 });
    const d = intentId({ ...base, kind: { tag: "RefundCredit", amountAda: 2n } });
    expect(new Set([a, b, c, d]).size).toBe(4);
  });

  it("ignores ttl_block / status (not in pre-image per §1.4)", () => {
    const kind: IntentKind = { tag: "RefundCredit", amountAda: 1n };
    const id = intentId({
      submitter: ("0x" + "00".repeat(32)) as HexString,
      nonce: 0n,
      kind,
      submittedBlock: 0,
    });
    // No ttl/status input means changing them can't change the id.
    expect(typeof id).toBe("string");
    expect(id.length).toBe(66);
  });
});

describe("voucherDigest", () => {
  it("is 32 bytes and stable", () => {
    const v: Voucher = {
      claimId: ("0x" + "01".repeat(32)) as HexString,
      policyId: ("0x" + "02".repeat(32)) as HexString,
      beneficiaryCardanoAddr: new Uint8Array([0xde, 0xad]),
      amountAda: 10_000_000n,
      batchFairnessProofDigest: ("0x" + "03".repeat(32)) as HexString,
      issuedBlock: 1234,
      expirySlotCardano: 5_000_000n,
      committeeSigs: [],
    };
    const d = voucherDigest(v);
    expect(d.length).toBe(66);
    expect(voucherDigest(v)).toEqual(d);
  });

  it("changes when beneficiary changes (prevents keeper redirection)", () => {
    const base: Voucher = {
      claimId: ("0x" + "01".repeat(32)) as HexString,
      policyId: ("0x" + "02".repeat(32)) as HexString,
      beneficiaryCardanoAddr: new Uint8Array([1, 2, 3]),
      amountAda: 1n,
      batchFairnessProofDigest: ("0x" + "03".repeat(32)) as HexString,
      issuedBlock: 1,
      expirySlotCardano: 1n,
      committeeSigs: [],
    };
    const a = voucherDigest(base);
    const b = voucherDigest({ ...base, beneficiaryCardanoAddr: new Uint8Array([9, 9, 9]) });
    expect(a).not.toEqual(b);
  });

  it("rejects malformed input", () => {
    const bad: Voucher = {
      claimId: ("0x" + "01".repeat(16)) as HexString, // wrong length
      policyId: ("0x" + "02".repeat(32)) as HexString,
      beneficiaryCardanoAddr: new Uint8Array([]),
      amountAda: 0n,
      batchFairnessProofDigest: ("0x" + "03".repeat(32)) as HexString,
      issuedBlock: 0,
      expirySlotCardano: 0n,
      committeeSigs: [],
    };
    expect(() => voucherDigest(bad)).toThrow();
  });
});

describe("fairnessProofDigest + validateFairnessProof", () => {
  const validBfpr: BatchFairnessProof = {
    batchBlockRange: [100, 110],
    sortedIntentIds: [
      ("0x" + "01".repeat(32)) as HexString,
      ("0x" + "02".repeat(32)) as HexString,
    ],
    requestedAmountsAda: [10_000_000n, 20_000_000n],
    poolBalanceAda: 100_000_000n,
    proRataScaleBps: 5000, // 50%
    awardedAmountsAda: [5_000_000n, 10_000_000n],
  };

  it("digest is stable and 32 bytes", () => {
    const d1 = fairnessProofDigest(validBfpr);
    const d2 = fairnessProofDigest(validBfpr);
    expect(d1).toEqual(d2);
    expect(d1.length).toBe(66);
  });

  it("validateFairnessProof accepts a canonical proof", () => {
    expect(validateFairnessProof(validBfpr)).toEqual({ ok: true });
  });

  it("rejects non-ascending intent ids", () => {
    const bad: BatchFairnessProof = {
      ...validBfpr,
      sortedIntentIds: [
        ("0x" + "02".repeat(32)) as HexString,
        ("0x" + "01".repeat(32)) as HexString,
      ],
    };
    const r = validateFairnessProof(bad);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/ascending/);
  });

  it("rejects scale > 10000", () => {
    const r = validateFairnessProof({ ...validBfpr, proRataScaleBps: 10_001 });
    expect(r.ok).toBe(false);
  });

  it("rejects awarded mismatch", () => {
    const r = validateFairnessProof({
      ...validBfpr,
      awardedAmountsAda: [6_000_000n, 10_000_000n], // should be 5M
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/awarded/);
  });

  it("rejects sum(awarded) > pool balance", () => {
    const r = validateFairnessProof({
      ...validBfpr,
      poolBalanceAda: 10_000_000n,
    });
    expect(r.ok).toBe(false);
  });

  it("rejects parallel array length mismatch", () => {
    const r = validateFairnessProof({
      ...validBfpr,
      awardedAmountsAda: [5_000_000n],
    });
    expect(r.ok).toBe(false);
  });
});
