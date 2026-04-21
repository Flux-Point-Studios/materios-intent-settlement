/**
 * Canonical hashing helpers mirroring spec §1.1–1.4.
 *
 * Every byte here must be bit-identical to what pallet_intent_settlement
 * produces on Materios AND what the Aiken validator reconstructs on Cardano.
 *
 * Correctness-by-construction target: see tests/hashing.test.ts and the
 * Aiken-parity fuzz harness under tests/integration/scale-parity.test.ts.
 */

import { blake2AsU8a } from "@polkadot/util-crypto";
import { u8aConcat, u8aToHex, hexToU8a, stringToU8a } from "@polkadot/util";
import type {
  Intent,
  IntentKind,
  IntentId,
  Voucher,
  BatchFairnessProof,
  HexString,
} from "./types.js";

/** Domain tags (§1.1). */
export const DomainTag = {
  Intent: stringToU8a("INTT"),
  Policy: stringToU8a("POLY"),
  Claim: stringToU8a("CLAM"),
  Voucher: stringToU8a("VCHR"),
  BatchFairnessProof: stringToU8a("BFPR"),
  CommitteeSet: stringToU8a("CMTT"),
} as const;

export type DomainTagName = keyof typeof DomainTag;

/** domain_hash(tag, body) → 32-byte Blake2b-256. */
export function domainHash(tag: Uint8Array, body: Uint8Array): Uint8Array {
  return blake2AsU8a(u8aConcat(tag, body), 256);
}

export function domainHashHex(tag: Uint8Array, body: Uint8Array): HexString {
  return u8aToHex(domainHash(tag, body)) as HexString;
}

/** Little-endian u64. */
export function u64LE(value: bigint): Uint8Array {
  if (value < 0n) throw new Error(`u64LE: negative value ${value}`);
  if (value > 0xffffffffffffffffn) throw new Error(`u64LE: overflow ${value}`);
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Little-endian u32. */
export function u32LE(value: number): Uint8Array {
  if (value < 0 || !Number.isInteger(value)) {
    throw new Error(`u32LE: bad value ${value}`);
  }
  if (value > 0xffffffff) throw new Error(`u32LE: overflow ${value}`);
  const out = new Uint8Array(4);
  out[0] = value & 0xff;
  out[1] = (value >>> 8) & 0xff;
  out[2] = (value >>> 16) & 0xff;
  out[3] = (value >>> 24) & 0xff;
  return out;
}

/**
 * SCALE-encode a BoundedVec<u8, N> as a compact-length prefix followed by bytes.
 * (Substrate compact-int encoding: single-byte mode covers 0..=63.)
 */
export function compactCompactLen(n: number): Uint8Array {
  if (n < 0) throw new Error("negative length");
  if (n <= 0x3f) {
    return new Uint8Array([n << 2]);
  }
  if (n <= 0x3fff) {
    const v = (n << 2) | 0b01;
    return new Uint8Array([v & 0xff, (v >>> 8) & 0xff]);
  }
  if (n <= 0x3fffffff) {
    const v = (n << 2) | 0b10;
    return new Uint8Array([
      v & 0xff,
      (v >>> 8) & 0xff,
      (v >>> 16) & 0xff,
      (v >>> 24) & 0xff,
    ]);
  }
  throw new Error(`compact len > u32 not supported here (${n})`);
}

function encodeBytesWithCompactLen(b: Uint8Array): Uint8Array {
  return u8aConcat(compactCompactLen(b.length), b);
}

/** SCALE-encode IntentKind. Tag is 1-byte discriminant matching Rust enum order. */
export function encodeIntentKind(kind: IntentKind): Uint8Array {
  switch (kind.tag) {
    case "BuyPolicy": {
      const tag = new Uint8Array([0]);
      const productId = hexToU8a(kind.productId); // 32B
      if (productId.length !== 32) throw new Error("productId must be 32B");
      const strike = u64LE(kind.strike);
      const termSlots = u32LE(kind.termSlots);
      const premium = u64LE(kind.premiumAda);
      const beneficiary = encodeBytesWithCompactLen(kind.beneficiaryCardanoAddr);
      return u8aConcat(tag, productId, strike, termSlots, premium, beneficiary);
    }
    case "RequestPayout": {
      const tag = new Uint8Array([1]);
      const policyId = hexToU8a(kind.policyId);
      if (policyId.length !== 32) throw new Error("policyId must be 32B");
      const evidence = encodeBytesWithCompactLen(kind.oracleEvidence);
      return u8aConcat(tag, policyId, evidence);
    }
    case "RefundCredit": {
      const tag = new Uint8Array([2]);
      const amount = u64LE(kind.amountAda);
      return u8aConcat(tag, amount);
    }
  }
}

/**
 * IntentId pre-image per §1.4:
 *   submitter (32B) || nonce (u64 LE) || scale_encode(IntentKind) || submitted_block (u32 LE)
 * NOTE: ttl_block and status are NOT in the pre-image (state fields).
 */
export function intentIdPreimage(intent: {
  submitter: HexString;
  nonce: bigint;
  kind: IntentKind;
  submittedBlock: number;
}): Uint8Array {
  const submitter = hexToU8a(intent.submitter);
  if (submitter.length !== 32) throw new Error("submitter must be 32B");
  return u8aConcat(
    submitter,
    u64LE(intent.nonce),
    encodeIntentKind(intent.kind),
    u32LE(intent.submittedBlock),
  );
}

export function intentId(intent: Pick<Intent, "submitter" | "nonce" | "kind" | "submittedBlock">): IntentId {
  return domainHashHex(DomainTag.Intent, intentIdPreimage(intent)) as IntentId;
}

/**
 * Voucher digest (§1.7):
 *   claim_id (32B) || policy_id (32B) || beneficiary_addr_bytes ||
 *   amount_ada (u64 LE) || bfpr_digest (32B) || issued_block (u32 LE) ||
 *   expiry_slot_cardano (u64 LE)
 *
 * Note beneficiary_addr_bytes is encoded with compact-length prefix here to
 * stay unambiguous; the Aiken validator mirrors this exact layout.
 */
export function voucherDigest(voucher: Voucher): HexString {
  const claimId = hexToU8a(voucher.claimId);
  const policyId = hexToU8a(voucher.policyId);
  const bfprDigest = hexToU8a(voucher.batchFairnessProofDigest);
  if (claimId.length !== 32) throw new Error("claimId must be 32B");
  if (policyId.length !== 32) throw new Error("policyId must be 32B");
  if (bfprDigest.length !== 32) throw new Error("bfpr digest must be 32B");

  const body = u8aConcat(
    claimId,
    policyId,
    encodeBytesWithCompactLen(voucher.beneficiaryCardanoAddr),
    u64LE(voucher.amountAda),
    bfprDigest,
    u32LE(voucher.issuedBlock),
    u64LE(voucher.expirySlotCardano),
  );
  return domainHashHex(DomainTag.Voucher, body);
}

/**
 * Voucher digest with beneficiary as Plutus V3 Data CBOR (three-way parity).
 *
 * Matches Team B's merged Aiken `canonical_voucher_body` which raw-concats
 * the CBOR-encoded beneficiary (NO SCALE length prefix). Use this for any
 * voucher that will be verified against aegis-policy-v1 on Cardano.
 *
 * Anchored in `docs/test-vectors.json::voucher_digest_with_address` at
 * `ae73d78970eb486376fb9d5e4d00cba0a5b2a2200c935d942cc258b12a7f8405`.
 */
export function voucherDigestWithAddress(args: {
  claimId: HexString;
  policyId: HexString;
  /** Plutus V3 Data CBOR of the beneficiary Address — use `encodeType0AddressCbor`. */
  beneficiaryAddressCbor: Uint8Array;
  amountAda: bigint;
  batchFairnessProofDigest: HexString;
  issuedBlock: number;
  expirySlotCardano: bigint;
}): HexString {
  const claimId = hexToU8a(args.claimId);
  const policyId = hexToU8a(args.policyId);
  const bfpr = hexToU8a(args.batchFairnessProofDigest);
  if (claimId.length !== 32) throw new Error("claimId must be 32B");
  if (policyId.length !== 32) throw new Error("policyId must be 32B");
  if (bfpr.length !== 32) throw new Error("bfpr digest must be 32B");

  const body = u8aConcat(
    claimId,
    policyId,
    args.beneficiaryAddressCbor,
    u64LE(args.amountAda),
    bfpr,
    u32LE(args.issuedBlock),
    u64LE(args.expirySlotCardano),
  );
  return domainHashHex(DomainTag.Voucher, body);
}

/**
 * BatchFairnessProof digest (§1.6):
 *   domain_hash(b"BFPR", scale_encode(BatchFairnessProof))
 *
 * SCALE layout for BoundedVec<T> matches Vec<T>: compact-length prefix +
 * concatenated element encodings.
 */
export function fairnessProofDigest(bfpr: BatchFairnessProof): HexString {
  const parts: Uint8Array[] = [
    u32LE(bfpr.batchBlockRange[0]),
    u32LE(bfpr.batchBlockRange[1]),
    compactCompactLen(bfpr.sortedIntentIds.length),
  ];
  for (const id of bfpr.sortedIntentIds) {
    const b = hexToU8a(id);
    if (b.length !== 32) throw new Error("intentId must be 32B");
    parts.push(b);
  }
  parts.push(compactCompactLen(bfpr.requestedAmountsAda.length));
  for (const amt of bfpr.requestedAmountsAda) parts.push(u64LE(amt));
  parts.push(u64LE(bfpr.poolBalanceAda));
  parts.push(u32LE(bfpr.proRataScaleBps));
  parts.push(compactCompactLen(bfpr.awardedAmountsAda.length));
  for (const amt of bfpr.awardedAmountsAda) parts.push(u64LE(amt));

  return domainHashHex(DomainTag.BatchFairnessProof, u8aConcat(...parts));
}

/**
 * Validates fairness-proof invariants per §1.6 before the keeper tries to
 * submit a batch. Cheap local pre-check; Aiken validator re-checks on-chain.
 */
export function validateFairnessProof(bfpr: BatchFairnessProof): { ok: true } | { ok: false; reason: string } {
  if (bfpr.proRataScaleBps > 10_000) {
    return { ok: false, reason: "pro_rata_scale_bps > 10000" };
  }
  if (
    bfpr.sortedIntentIds.length !== bfpr.requestedAmountsAda.length ||
    bfpr.sortedIntentIds.length !== bfpr.awardedAmountsAda.length
  ) {
    return { ok: false, reason: "parallel array length mismatch" };
  }
  // Strictly ascending intent IDs (byte-lex)
  for (let i = 1; i < bfpr.sortedIntentIds.length; i++) {
    const prev = bfpr.sortedIntentIds[i - 1]!;
    const curr = bfpr.sortedIntentIds[i]!;
    if (prev >= curr) {
      return { ok: false, reason: "sortedIntentIds not strictly ascending" };
    }
  }
  // awarded == requested * scale / 10000
  const scale = BigInt(bfpr.proRataScaleBps);
  let totalAwarded = 0n;
  for (let i = 0; i < bfpr.sortedIntentIds.length; i++) {
    const req = bfpr.requestedAmountsAda[i]!;
    const award = bfpr.awardedAmountsAda[i]!;
    const expected = (req * scale) / 10_000n;
    if (expected !== award) {
      return { ok: false, reason: `awarded[${i}] != requested * scale / 10000` };
    }
    totalAwarded += award;
  }
  if (totalAwarded > bfpr.poolBalanceAda) {
    return { ok: false, reason: "sum(awarded) > pool_balance_ada" };
  }
  return { ok: true };
}
