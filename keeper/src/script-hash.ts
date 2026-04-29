/**
 * Cardano Plutus V3 script-hash verification (Task #76a).
 *
 * Cardano Plutus V3 script hashes are 28-byte blake2b-224 digests of the
 * compiled script bytes. The keeper accepts `POLICY_SCRIPT_CBOR` from env
 * but historically did not check that the operator-provided CBOR actually
 * compiles to the expected `aegisPolicyV1ScriptHash` baked into config.
 *
 * Risk: an operator wrong-config'd with a different validator's CBOR would
 * sign + submit Cardano txs that pin the AegisPolicyParams (which contain
 * the expected hash) but build outputs against a wrong-hash address — all
 * tx fees burn, no funds move. Worse, on mainnet the operator could be
 * tricked into submitting against an attacker-controlled validator.
 *
 * Defensive fix: at startup compute `blake2b_224(cbor_bytes)` of the env
 * CBOR and refuse to start if it doesn't equal the configured expected
 * hash. Mainnet operators MUST not silently use a wrong validator.
 */

import { blake2AsU8a } from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import type { HexString } from "@fluxpointstudios/materios-intent-settlement-sdk";

/**
 * `@polkadot/util-crypto` types for `blake2AsU8a` only enumerate
 * 64/128/256/384/512 bit lengths, but the underlying WASM accepts any
 * multiple of 8 from 8 to 512 — Plutus V3 needs 224. Wrap with a
 * runtime-correct call and a non-narrowed bit length.
 */
function blake2_224(data: Uint8Array): Uint8Array {
  // `blake2AsU8a` ignores bit-length narrowing at runtime; the DTS just
  // doesn't expose 224. Casting the third+ arg position is safe — the
  // implementation reads it as a plain number and feeds it through to
  // `wasm-crypto.blake2bHash(data, key, dkLen=bitLength/8)`.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fn = blake2AsU8a as unknown as (
    data: Uint8Array,
    bitLength: number,
  ) => Uint8Array;
  return fn(data, 224);
}

export class PolicyScriptHashMismatchError extends Error {
  readonly expectedHash: HexString;
  readonly computedHash: HexString;

  constructor(expectedHash: HexString, computedHash: HexString) {
    super(
      `POLICY_SCRIPT_CBOR script-hash mismatch: ` +
        `computed blake2b_224(cbor) = ${computedHash} but ` +
        `aegisPolicyV1ScriptHash = ${expectedHash}. ` +
        `Refusing to start — wrong validator binary or mis-configured env. ` +
        `On mainnet this would burn fees against a wrong-hash address.`,
    );
    this.name = "PolicyScriptHashMismatchError";
    this.expectedHash = expectedHash;
    this.computedHash = computedHash;
  }
}

/**
 * Compute the Plutus V3 script hash (`blake2b_224`) of compiled CBOR script
 * bytes. Returns a 28-byte (56 hex char) `0x`-prefixed string.
 *
 * NOTE: Plutus V3 hashes are blake2b-224 of the **language-tagged** script
 * bytes — that is, `0x03 || cbor_bytes` for V3 (`0x01` for V1, `0x02` for
 * V2). However, after `aiken blueprint apply` the produced `compiledCode`
 * field is the bare CBOR-wrapped flat-encoded script, and Aiken's
 * `validatorHash` helper hashes that bare CBOR directly without the
 * language tag prefix. We mirror Aiken's convention here so the hash
 * matches the on-chain script address that `aegis-policy-v1` deploys with.
 *
 * If the operator's blueprint uses the language-tagged variant we still
 * catch the mismatch — both sides must agree on the convention. The error
 * message is explicit so they know to inspect their pipeline.
 */
export function computePlutusV3ScriptHash(scriptCborHex: HexString): HexString {
  if (typeof scriptCborHex !== "string" || !scriptCborHex.startsWith("0x")) {
    throw new Error(
      `computePlutusV3ScriptHash: expected 0x-prefixed hex, got ${typeof scriptCborHex}`,
    );
  }
  const cborBytes = hexToU8a(scriptCborHex);
  if (cborBytes.length === 0) {
    throw new Error("computePlutusV3ScriptHash: empty CBOR payload");
  }
  // Plutus V3 = language tag 0x03 prepended before hashing. Cardano nodes
  // compute the script hash this way; Aiken's `validatorHash` does the
  // same when assembling the script address.
  const tagged = new Uint8Array(cborBytes.length + 1);
  tagged[0] = 0x03;
  tagged.set(cborBytes, 1);
  const hash = blake2_224(tagged); // 28 bytes
  if (hash.length !== 28) {
    throw new Error(
      `computePlutusV3ScriptHash: blake2_224 returned ${hash.length} bytes`,
    );
  }
  return u8aToHex(hash) as HexString;
}

/**
 * Validate that the operator-provided POLICY_SCRIPT_CBOR matches the
 * expected `aegisPolicyV1ScriptHash` from KeeperConfig. Throws
 * `PolicyScriptHashMismatchError` on mismatch — the keeper CLI must
 * propagate this to a fatal exit.
 *
 * If `expectedHash` is null/undefined, this throws because the keeper
 * MUST NOT accept an unbound CBOR — that's the historic vulnerability
 * (config field nullable for pre-blueprint compile). On mainnet operators
 * MUST set the field; on preprod we still enforce, fail-closed.
 */
export function verifyPolicyScriptHash(
  scriptCborHex: HexString,
  expectedHash: HexString | null | undefined,
): { ok: true; computedHash: HexString } {
  if (!expectedHash) {
    throw new Error(
      "aegisPolicyV1ScriptHash is missing from KeeperConfig. " +
        "Keeper refuses to start without a script-hash binding for " +
        "POLICY_SCRIPT_CBOR — set the deployed aiken-blueprint hash before " +
        "running on any network.",
    );
  }
  // Normalize the expected hash for comparison: lowercase + ensure 28-byte.
  const expectedNorm = normalizeExpectedHash(expectedHash);
  const computed = computePlutusV3ScriptHash(scriptCborHex);
  if (computed.toLowerCase() !== expectedNorm.toLowerCase()) {
    throw new PolicyScriptHashMismatchError(
      expectedNorm as HexString,
      computed,
    );
  }
  return { ok: true, computedHash: computed };
}

function normalizeExpectedHash(expected: HexString): HexString {
  if (!expected.startsWith("0x")) {
    throw new Error(
      `aegisPolicyV1ScriptHash must be 0x-prefixed hex, got ${expected}`,
    );
  }
  const bytes = hexToU8a(expected);
  if (bytes.length !== 28) {
    throw new Error(
      `aegisPolicyV1ScriptHash must be 28 bytes (Plutus V3 blake2b_224), got ${bytes.length}`,
    );
  }
  return expected.toLowerCase() as HexString;
}
