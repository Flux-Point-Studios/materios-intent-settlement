/**
 * Three-way cross-chain parity test (TypeScript side).
 *
 * Reads the pinned vector `voucher_digest_with_address` from
 * `docs/test-vectors.json`, reconstructs the canonical voucher pre-image via
 * the SDK's encoders, and asserts byte-equality with the pinned hex produced
 * by Aiken's `builtin.serialise_data(Address)` and
 * `domain_hash(tag_voucher, body)`.
 *
 * Sibling tests:
 *   - Aiken: aegis-parametric-insurance-dev/validators/aegis-policy-v1/lib/aegis/test_vectors.ak::vec_pinned_vchr_with_address
 *   - Rust:  pallets/intent-settlement/tests/parity_test.rs::voucher_digest_with_address_three_way_parity
 *
 * If this test fails, do NOT patch the TS side to match — the failure is a
 * signal that one of the three encoders drifted. Cross-check all three
 * before committing any fix.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { encodeType0AddressCbor } from "./cardano-address.js";
import { voucherDigestWithAddress } from "./hashing.js";
import type { HexString } from "./types.js";

function hexToU8a(s: string): Uint8Array {
  const hex = s.startsWith("0x") ? s.slice(2) : s;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Locate docs/test-vectors.json relative to this test file.
const TEST_VECTORS_PATH = resolve(
  __dirname,
  "..",
  "..",
  "docs",
  "test-vectors.json",
);

describe("voucher_digest_with_address three-way parity", () => {
  const raw = readFileSync(TEST_VECTORS_PATH, "utf8");
  const vectors = JSON.parse(raw);
  const v = vectors.voucher_digest_with_address;

  it("has the voucher_digest_with_address vector present", () => {
    expect(v).toBeDefined();
    expect(v.expected_hex).toBe(
      "ae73d78970eb486376fb9d5e4d00cba0a5b2a2200c935d942cc258b12a7f8405",
    );
  });

  it("reproduces the Aiken CBOR for the anchor address byte-for-byte", () => {
    const paymentHash = hexToU8a(v.payment_vk_hash_hex);
    const stakeHash = hexToU8a(v.stake_vk_hash_hex);
    const cbor = encodeType0AddressCbor({ paymentHash, stakeHash });
    expect(toHex(cbor)).toBe(v.beneficiary_address_cbor_hex);
    expect(cbor.length).toBe(80);
  });

  it("reproduces the pinned voucher digest (three-way cross-chain anchor)", () => {
    const paymentHash = hexToU8a(v.payment_vk_hash_hex);
    const stakeHash = hexToU8a(v.stake_vk_hash_hex);
    const cbor = encodeType0AddressCbor({ paymentHash, stakeHash });

    const digest = voucherDigestWithAddress({
      claimId: ("0x" + v.claim_id_hex) as HexString,
      policyId: ("0x" + v.policy_id_hex) as HexString,
      beneficiaryAddressCbor: cbor,
      amountAda: BigInt(v.amount_ada),
      batchFairnessProofDigest: ("0x" + v.bfpr_digest_hex) as HexString,
      issuedBlock: v.issued_block,
      expirySlotCardano: BigInt(v.expiry_slot_cardano),
    });
    expect(digest).toBe(("0x" + v.expected_hex) as HexString);
  });
});

describe("domain-tagged empty-body vectors (sanity anchors)", () => {
  const raw = readFileSync(TEST_VECTORS_PATH, "utf8");
  const vectors = JSON.parse(raw);

  it("intt_empty_body expected hex is preserved", () => {
    expect(vectors.intt_empty_body.expected_hex).toBe(
      "0baf44a136533f3a4f4425450b13cfb1e48d97ddcb2b64204b9f2f3ae14288aa",
    );
  });

  it("vchr_empty_body expected hex is preserved", () => {
    expect(vectors.vchr_empty_body.expected_hex).toBe(
      "25da1b71e4d650051ce3dbd3c41914b81067e1ce1c6f12d26591d285362d2b7c",
    );
  });

  it("bfpr_empty_body expected hex is preserved", () => {
    expect(vectors.bfpr_empty_body.expected_hex).toBe(
      "c03cbe26f35d0ad180c5840528ab78cf19354183a924833073af0aa8c623fd21",
    );
  });
});
