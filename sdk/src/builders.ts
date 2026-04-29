/**
 * Redeemer / datum builders for the Aiken-side schema merged in Team B's
 * round-2 PR (aegis-policy-v1 on aegis-parametric-insurance-dev main).
 *
 * Scope of this module:
 *   - `AegisPolicyParams` helpers (script-hash stub until blueprint lands)
 *   - `PremiumDepositDatum` builder (new B-8 fields)
 *   - `buildRefundCredit` / `buildRefundDeposit` redeemer builders
 *   - `buildSinglePointValidityRange` for the strict-equality slot binding
 *   - `collectMintSignatories` stub for wallet signature collection
 *
 * All byte-level encoders are pure — they output `Uint8Array`s and hex
 * strings that keepers + tx builders (Lucid, mesh-js) can slot directly into
 * their CBOR assembly. This module does NOT import any Cardano tx-builder
 * (Lucid / MeshTxBuilder / pallas) to keep the SDK's runtime surface small.
 */

import { u8aToHex } from "@polkadot/util";
import {
  encodeType0AddressCbor,
  splitType0AddressBytes,
} from "./cardano-address.js";
import { u32LE, u64LE, voucherDigestWithAddress } from "./hashing.js";
import type {
  AdaLovelace,
  AegisPolicyParams,
  BlockNumber,
  ClaimId,
  CommitteePubkey,
  CommitteeSig,
  HexString,
  PolicyId,
  PremiumDepositDatum,
  RefundRedeemerFields,
  ScriptHash,
  SlotNumber,
  ValidityRange,
} from "./types.js";

// ---------------------------------------------------------------------------
// (1) Script-hash param-wire
// ---------------------------------------------------------------------------

/**
 * Build an `AegisPolicyParams` struct with a nullable `aegisPolicyV1ScriptHash`
 * (the deploy-time value from `aiken blueprint apply`). Callers pass `null`
 * until the mainnet blueprint is produced; once the hash is known, the SDK
 * bundle ships a pinned value.
 */
export function buildAegisPolicyParams(
  params: Omit<AegisPolicyParams, "aegisPolicyV1ScriptHash"> & {
    aegisPolicyV1ScriptHash?: ScriptHash | null;
  },
): AegisPolicyParams {
  return {
    ...params,
    aegisPolicyV1ScriptHash: params.aegisPolicyV1ScriptHash ?? null,
  };
}

// ---------------------------------------------------------------------------
// (2) PremiumDeposit datum builder (B-8 fields)
// ---------------------------------------------------------------------------

/**
 * Build a `PremiumDepositDatum` with the two new B-8 fields:
 * `depositorCardanoAddr` and `amountAda`.
 *
 * The depositor address MUST be the raw 57-byte CIP-0019 type-0 address of
 * the wallet that funded this UTxO — the Aiken validator enforces that
 * refunds return to THIS address (attacker-controlled redeemer beneficiary
 * fields alone are insufficient per round-2 security review B-8).
 */
export function buildPremiumDepositDatum(args: {
  depositorMateriosAccount: HexString;
  depositorCardanoAddr: Uint8Array;
  depositedAtSlot: SlotNumber;
  depositId: HexString;
  amountAda: AdaLovelace;
  productId: HexString;
}): PremiumDepositDatum {
  if (args.depositorCardanoAddr.length !== 57) {
    throw new Error(
      `depositorCardanoAddr must be 57 bytes (CIP-0019 type-0), got ${args.depositorCardanoAddr.length}`,
    );
  }
  if (args.amountAda <= 0n) {
    throw new Error("amountAda must be positive");
  }
  return {
    depositorMateriosAccount: args.depositorMateriosAccount,
    depositorCardanoAddr: args.depositorCardanoAddr,
    depositedAtSlot: args.depositedAtSlot,
    depositId: args.depositId,
    amountAda: args.amountAda,
    productId: args.productId,
  };
}

// ---------------------------------------------------------------------------
// (3) RefundCredit / RefundDeposit redeemer builders (B-8 fields)
// ---------------------------------------------------------------------------

/**
 * Build a `RefundCredit` redeemer payload for aegis-policy-v1. The new B-8
 * fields `beneficiaryBytes` + `policyId` are derived from inputs; we also
 * pre-compute the expected voucher digest so callers can assert it matches
 * what the committee signed before attempting submission.
 *
 * #73 / #79: voucherDigestWithAddress now requires the chain-identity tuple
 * (materiosChainId, networkMagic, aegisPolicyV1ScriptHash, settlementVersion)
 * to bind the digest to the specific Materios chain + Cardano network +
 * deployed policy + settlement-protocol version.
 */
export function buildRefundCredit(args: {
  voucherBytes: Uint8Array;
  sigs: Array<{ pubkey: CommitteePubkey; sig: CommitteeSig }>;
  amountAda: AdaLovelace;
  /** Raw 57-byte CIP-0019 type-0 address of the refund destination. */
  beneficiary: Uint8Array;
  policyId: PolicyId;
  issuedBlock: BlockNumber;
  expirySlotCardano: SlotNumber;
  claimId: ClaimId;
  bfpDigest: HexString;
  currentSlot: SlotNumber;
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  /** #73: Cardano network magic (1 = preprod, 764824073 = mainnet). */
  networkMagic: number;
  /** #73: 28-byte deployed `aegis_policy_v1` blake2b224 hash. */
  aegisPolicyV1ScriptHash: HexString;
  /** #73: settlement-protocol semver. */
  settlementVersion: number;
}): RefundRedeemerFields & { precomputedVoucherDigest: HexString } {
  const hashes = splitType0AddressBytes(args.beneficiary);
  const beneficiaryBytes = encodeType0AddressCbor(hashes);
  const precomputedVoucherDigest = voucherDigestWithAddress({
    claimId: args.claimId as HexString,
    policyId: args.policyId,
    beneficiaryAddressCbor: beneficiaryBytes,
    amountAda: args.amountAda,
    batchFairnessProofDigest: args.bfpDigest,
    issuedBlock: args.issuedBlock,
    expirySlotCardano: args.expirySlotCardano,
    materiosChainId: args.materiosChainId,
    networkMagic: args.networkMagic,
    aegisPolicyV1ScriptHash: args.aegisPolicyV1ScriptHash,
    settlementVersion: args.settlementVersion,
  });
  return {
    voucherBytes: args.voucherBytes,
    sigs: args.sigs,
    amountAda: args.amountAda,
    beneficiary: args.beneficiary,
    beneficiaryBytes,
    policyId: args.policyId,
    issuedBlock: args.issuedBlock,
    expirySlotCardano: args.expirySlotCardano,
    claimId: args.claimId,
    bfpDigest: args.bfpDigest,
    currentSlot: args.currentSlot,
    precomputedVoucherDigest,
  };
}

/**
 * Build a `RefundDeposit` redeemer payload for premium-collector. Structurally
 * identical to `RefundCredit` (both redeemers carry the same explicit voucher
 * fields); the Aiken split exists because the two validators enforce
 * different dwell / UTxO shape rules.
 */
export function buildRefundDeposit(
  args: Parameters<typeof buildRefundCredit>[0],
): ReturnType<typeof buildRefundCredit> {
  return buildRefundCredit(args);
}

// ---------------------------------------------------------------------------
// (4) validity_range strict equality
// ---------------------------------------------------------------------------

/**
 * Build a single-point Cardano validity range `[slot, slot]` matching the
 * round-2 strict-equality binding `current_slot == validity_range.upper_bound`.
 *
 * The keeper MUST use this for batch-tx submission; any wider range will be
 * rejected by the validator.
 */
export function buildSinglePointValidityRange(currentSlot: SlotNumber): ValidityRange {
  return { lowerBound: currentSlot, upperBound: currentSlot };
}

/**
 * Sanity-check that a validity range matches the strict-equality binding
 * for a given `currentSlot`. Returns `{ ok: true }` or an explanation.
 */
export function assertSinglePointValidityRange(
  range: ValidityRange,
  currentSlot: SlotNumber,
): { ok: true } | { ok: false; reason: string } {
  if (range.lowerBound !== range.upperBound) {
    return {
      ok: false,
      reason: `validity range is not a single point: [${range.lowerBound}, ${range.upperBound}]`,
    };
  }
  if (range.upperBound !== currentSlot) {
    return {
      ok: false,
      reason: `validity range upper bound ${range.upperBound} != current slot ${currentSlot}`,
    };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// (5) Mint extra_signatories — wallet signature collection
// ---------------------------------------------------------------------------

/**
 * Abstract wallet-signing interface. Keepers request the user's signature
 * over the Mint redeemer tx hash; the resulting VK + sig lands in
 * `tx.extra_signatories` for Aiken's beneficiary-authorization check.
 *
 * Implementations wrap:
 *   - Mesh `BrowserWallet.signTx` / `signData`
 *   - Lucid `lucid.wallet.signTx`
 *   - CIP-30 `enable().signTx`
 */
export interface ISignerWallet {
  /** Return the beneficiary's 28-byte payment-key hash (hex, 56 chars). */
  getPaymentKeyHash(): Promise<HexString>;
  /**
   * Sign the tx body and return the witness CBOR hex. The keeper's
   * tx-builder then appends this witness into the submitted tx.
   */
  signTxBody(txBodyCborHex: HexString): Promise<HexString>;
}

/**
 * Collect a beneficiary signature for an `AegisPolicyRedeemer::Mint` tx.
 * Round-2 addition: the mint path authorizes the beneficiary via
 * `tx.extra_signatories` membership (the beneficiary must personally sign so
 * an attacker cannot mint-for-you).
 *
 * Returns the 28-byte payment-key hash AND the tx-body signature witness
 * (both hex). The keeper appends the witness to the tx and includes the key
 * hash in `extra_signatories`.
 */
export async function collectMintSignatories(
  wallet: ISignerWallet,
  txBodyCborHex: HexString,
): Promise<{ paymentKeyHash: HexString; witnessCborHex: HexString }> {
  const paymentKeyHash = await wallet.getPaymentKeyHash();
  if (paymentKeyHash.length !== 58) {
    // 56 hex chars + 0x prefix
    throw new Error(
      `paymentKeyHash must be 28-byte hex (58 chars incl. 0x), got ${paymentKeyHash.length}`,
    );
  }
  const witnessCborHex = await wallet.signTxBody(txBodyCborHex);
  return { paymentKeyHash, witnessCborHex };
}

// ---------------------------------------------------------------------------
// (6) Voucher-body canonicalization (re-export for discoverability)
// ---------------------------------------------------------------------------

export { encodeType0AddressCbor, splitType0AddressBytes } from "./cardano-address.js";
export type { Type0AddressHashes } from "./cardano-address.js";
export { voucherDigestWithAddress } from "./hashing.js";

// A convenience alias — reviewers often search for `canonicalVoucherBody`.
/**
 * Canonical voucher body (196 bytes for type-0 addresses). Mirrors Aiken's
 * `canonical_voucher_body`:
 *
 *   claim_id(32) || policy_id(32) || beneficiary_cbor(80) ||
 *   amount_ada(u64 LE 8) || bfp_digest(32) || issued_block(u32 LE 4) ||
 *   expiry_slot_cardano(u64 LE 8)  = 196 bytes
 */
export function canonicalVoucherBody(args: {
  claimId: HexString;
  policyId: HexString;
  beneficiaryAddressCbor: Uint8Array;
  amountAda: AdaLovelace;
  batchFairnessProofDigest: HexString;
  issuedBlock: BlockNumber;
  expirySlotCardano: SlotNumber;
}): Uint8Array {
  // Construct the body bytes directly. Callers that want the post-hash digest
  // should call `voucherDigestWithAddress` (re-exported above) — we do NOT
  // hash here since this helper exists for tx-metadata / logging use cases.
  //
  // Width-encoders (`u64LE` / `u32LE`) are imported from `hashing.ts`, which
  // provides overflow checks (throws on negatives / out-of-range values)
  // instead of silently wrapping. See hashing.ts for the canonical
  // implementations.
  const hexToU8a = (s: string): Uint8Array => {
    const hex = s.startsWith("0x") ? s.slice(2) : s;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  };
  const claimId = hexToU8a(args.claimId);
  const policyId = hexToU8a(args.policyId);
  const bfpr = hexToU8a(args.batchFairnessProofDigest);
  const body = new Uint8Array(
    32 + 32 + args.beneficiaryAddressCbor.length + 8 + 32 + 4 + 8,
  );
  let o = 0;
  body.set(claimId, o);
  o += 32;
  body.set(policyId, o);
  o += 32;
  body.set(args.beneficiaryAddressCbor, o);
  o += args.beneficiaryAddressCbor.length;
  body.set(u64LE(args.amountAda), o);
  o += 8;
  body.set(bfpr, o);
  o += 32;
  body.set(u32LE(args.issuedBlock), o);
  o += 4;
  body.set(u64LE(args.expirySlotCardano), o);
  return body;
}

// Re-export the hex-util helper so callers can log raw body bytes.
export const toHex = u8aToHex;
