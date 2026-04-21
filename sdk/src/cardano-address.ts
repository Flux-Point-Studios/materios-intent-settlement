/**
 * Plutus V3 Data CBOR encoder for CIP-0019 type-0 Cardano addresses.
 *
 * # Why this file exists
 *
 * Team B's merged Aiken validator library (aegis-policy-v1) now includes a
 * voucher-body canonicalization that RAW-concatenates the beneficiary's
 * address as Plutus V3 Data CBOR (produced by `builtin.serialise_data`), NOT
 * the SCALE-length-prefixed raw bech32 bytes that the older
 * [`voucherDigest`](./hashing.ts) helper consumes.
 *
 * The three-way anchor (Aiken ↔ Rust ↔ TypeScript) is pinned in
 * `docs/test-vectors.json::voucher_digest_with_address` at
 * `ae73d78970eb486376fb9d5e4d00cba0a5b2a2200c935d942cc258b12a7f8405`.
 * Every side MUST emit byte-identical output for that vector, or vouchers
 * silently reject on Cardano.
 *
 * # Encoding layout
 *
 * A type-0 address (payment VK + stake VK inline) is encoded as:
 *
 *   d8 79 9f                       -- constr-0 indefinite (Address)
 *     d8 79 9f                     --   VerificationKey(payment)
 *       58 1c <28B payment hash>
 *     ff
 *     d8 79 9f                     --   Some(Inline(VerificationKey(stake)))
 *       d8 79 9f                   --     Inline(...)
 *         d8 79 9f                 --       VerificationKey(stake)
 *           58 1c <28B stake hash>
 *         ff
 *       ff
 *     ff
 *   ff
 *
 * Total: 80 bytes.
 *
 * # Lucid parity
 *
 * Lucid's `Data.to(addr, Address)` uses the same Plutus V3 Data encoder. The
 * `@anastasia-labs/cardano-multiplatform-lib` CBOR encoder also produces this
 * layout. We hand-roll here to avoid pulling Lucid into the SDK's surface
 * (the SDK is a thin client layer; the keeper owns the Cardano tx stack) and
 * to make the test deterministic with zero runtime dependencies.
 *
 * This encoder's output is verified byte-for-byte against the Aiken pinned
 * hex in `./cardano-address.test.ts` and against the three-way anchor in
 * `./hashing.test.ts::voucherDigestWithAddress three-way parity`.
 */

export interface Type0AddressHashes {
  /** 28-byte payment credential verification-key hash. */
  paymentHash: Uint8Array;
  /** 28-byte stake credential verification-key hash. */
  stakeHash: Uint8Array;
}

/**
 * Encode a CIP-0019 type-0 address as Plutus V3 Data CBOR, mirroring
 * Aiken's `builtin.serialise_data(Address)`.
 *
 * Returns exactly 80 bytes.
 */
export function encodeType0AddressCbor(addr: Type0AddressHashes): Uint8Array {
  if (addr.paymentHash.length !== 28) {
    throw new Error(
      `paymentHash must be 28 bytes, got ${addr.paymentHash.length}`,
    );
  }
  if (addr.stakeHash.length !== 28) {
    throw new Error(
      `stakeHash must be 28 bytes, got ${addr.stakeHash.length}`,
    );
  }
  const out = new Uint8Array(80);
  // outer Address constr-0 indef
  out[0] = 0xd8;
  out[1] = 0x79;
  out[2] = 0x9f;
  // payment credential: VerificationKey(hash28) constr-0 indef
  out[3] = 0xd8;
  out[4] = 0x79;
  out[5] = 0x9f;
  // bstr(28) = 0x58 0x1c <28 bytes>
  out[6] = 0x58;
  out[7] = 0x1c;
  out.set(addr.paymentHash, 8);
  out[36] = 0xff;
  // stake credential: Some(Inline(VerificationKey(hash28)))
  out[37] = 0xd8;
  out[38] = 0x79;
  out[39] = 0x9f; // Some
  out[40] = 0xd8;
  out[41] = 0x79;
  out[42] = 0x9f; // Inline
  out[43] = 0xd8;
  out[44] = 0x79;
  out[45] = 0x9f; // VK stake
  out[46] = 0x58;
  out[47] = 0x1c;
  out.set(addr.stakeHash, 48);
  out[76] = 0xff; // close VK(stake)
  out[77] = 0xff; // close Inline
  out[78] = 0xff; // close Some
  out[79] = 0xff; // close Address
  return out;
}

/**
 * Split a raw 57-byte CIP-0019 type-0 address buffer
 * (`0x01 || payment_hash(28) || stake_hash(28)`) into its two key hashes.
 */
export function splitType0AddressBytes(raw: Uint8Array): Type0AddressHashes {
  if (raw.length !== 57) {
    throw new Error(
      `type-0 address raw buffer must be 57 bytes, got ${raw.length}`,
    );
  }
  if (raw[0] !== 0x01) {
    throw new Error(
      `unsupported address header byte 0x${raw[0]!.toString(16)}; only type-0 (0x01) supported`,
    );
  }
  return {
    paymentHash: raw.slice(1, 29),
    stakeHash: raw.slice(29, 57),
  };
}
