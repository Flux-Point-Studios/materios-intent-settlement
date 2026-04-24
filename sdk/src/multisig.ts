/**
 * M-of-N committee signature envelopes for `settle_claim` + `credit_deposit`.
 *
 * These helpers mirror the Rust payload builders in
 * `pallets/intent-settlement/src/lib.rs` (`settle_claim_payload`,
 * `credit_deposit_payload`) and must produce byte-identical digests — the
 * pallet verifies each sig via `sp_io::crypto::sr25519_verify(&sig, &msg, &pk)`
 * against the digest we emit here.
 *
 * Canonical shapes (spec-v1 §1.1 + pallet comments):
 *
 *   credit_deposit digest:
 *     blake2_256( b"CRDP" || target (32B) || amount_ada (LE u64) || cardano_tx_hash (32B) )
 *
 *   settle_claim digest:
 *     blake2_256( b"STCL" || claim_id (32B) || cardano_tx_hash (32B) || settled_direct (1B) )
 *
 * Bundle ordering + dedup semantics (match pallet `ensure_threshold_signatures`):
 *  - Caller's pubkey MUST appear in the bundle (origin-binding, anti-replay).
 *  - Duplicate signers are rejected by the pallet (`DuplicateSigner`), so we
 *    dedupe on the client side rather than submitting a doomed extrinsic.
 *  - Pallet order is insignificant; we emit caller-first, then remaining
 *    cosigners sorted by pubkey bytes, so verifiers see a deterministic
 *    bundle.
 */

import { blake2AsU8a } from "@polkadot/util-crypto";
import { Keyring } from "@polkadot/keyring";
import { hexToU8a, u8aConcat, u8aEq } from "@polkadot/util";
import type { HexString } from "./types.js";
import { u64LE } from "./hashing.js";

// ---------------------------------------------------------------------------
// Domain tags (Issue #7 — pallet lib.rs::TAG_CRDP, TAG_STCL).
// ---------------------------------------------------------------------------

/** `b"CRDP"` — 4-byte ASCII domain tag for credit_deposit payloads. */
export const TAG_CRDP: Uint8Array = new Uint8Array([0x43, 0x52, 0x44, 0x50]);
/** `b"STCL"` — 4-byte ASCII domain tag for settle_claim payloads. */
export const TAG_STCL: Uint8Array = new Uint8Array([0x53, 0x54, 0x43, 0x4c]);

// ---------------------------------------------------------------------------
// Payload builders (digests that committee members sign).
// ---------------------------------------------------------------------------

function require32(bytes: Uint8Array, field: string): void {
  if (bytes.length !== 32) {
    throw new Error(`${field}: expected 32 bytes, got ${bytes.length}`);
  }
}

/**
 * Byte-identical to Rust `settle_claim_payload(claim_id, tx_hash, settled_direct)`.
 *
 * Pre-image: `b"STCL" || claim_id (32B) || cardano_tx_hash (32B) || settled_direct (1B)`
 *
 * @returns 32-byte blake2_256 digest that committee members must sign.
 */
export function settleClaimPayload(args: {
  claimId: HexString;
  /** 32-byte Cardano transaction hash, hex-prefixed. */
  cardanoTxHash: HexString;
  settledDirect: boolean;
}): Uint8Array {
  const claimId = hexToU8a(args.claimId);
  const cardanoTxHash = hexToU8a(args.cardanoTxHash);
  require32(claimId, "claimId");
  require32(cardanoTxHash, "cardanoTxHash");
  const body = u8aConcat(
    claimId,
    cardanoTxHash,
    new Uint8Array([args.settledDirect ? 1 : 0]),
  );
  const digest = blake2AsU8a(u8aConcat(TAG_STCL, body), 256);
  // Safety net: `blake2AsU8a(…, 256)` is documented to return 32B. Guard
  // against a future breaking change in @polkadot/util-crypto.
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Byte-identical to Rust `credit_deposit_payload(target, amount_ada, tx_hash)`.
 *
 * Pre-image: `b"CRDP" || target (32B) || amount_ada (LE u64) || cardano_tx_hash (32B)`
 *
 * @param depositor 32-byte SS58 pubkey of the credited account (see spec §6).
 * @param amountAda Amount in lovelace (u64).
 * @param cardanoTxHash 32-byte Cardano deposit tx hash.
 * @returns 32-byte blake2_256 digest that committee members must sign.
 */
export function creditDepositPayload(args: {
  depositor: HexString;
  amountAda: bigint;
  cardanoTxHash: HexString;
}): Uint8Array {
  const depositor = hexToU8a(args.depositor);
  const cardanoTxHash = hexToU8a(args.cardanoTxHash);
  require32(depositor, "depositor");
  require32(cardanoTxHash, "cardanoTxHash");
  const body = u8aConcat(depositor, u64LE(args.amountAda), cardanoTxHash);
  const digest = blake2AsU8a(u8aConcat(TAG_CRDP, body), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

// ---------------------------------------------------------------------------
// Signing.
// ---------------------------------------------------------------------------

/**
 * sr25519-sign the given payload with the provided SURI (`//Alice`,
 * `//Alice///stash`, or a 12-/24-word mnemonic).
 *
 * IMPORTANT: `payload` MUST already be the 32-byte digest produced by
 * `settleClaimPayload` / `creditDepositPayload`. Do NOT pre-hash again — the
 * pallet verifies the raw digest, not `blake2(digest)`.
 */
export function signPayload(
  seed: string,
  payload: Uint8Array,
): { pubkey: Uint8Array; sig: Uint8Array } {
  const keyring = new Keyring({ type: "sr25519" });
  const pair = keyring.addFromUri(seed);
  const sig = pair.sign(payload);
  // sr25519 sigs are 64 bytes, pubkeys 32 bytes — guard against regressions.
  if (pair.publicKey.length !== 32) {
    throw new Error(`sr25519 public key length != 32 (got ${pair.publicKey.length})`);
  }
  if (sig.length !== 64) {
    throw new Error(`sr25519 signature length != 64 (got ${sig.length})`);
  }
  // Copy so callers can't accidentally mutate keyring-owned buffers.
  return { pubkey: Uint8Array.from(pair.publicKey), sig: Uint8Array.from(sig) };
}

// ---------------------------------------------------------------------------
// Bundle assembly.
// ---------------------------------------------------------------------------

type SignerEntry = { pubkey: Uint8Array; sig: Uint8Array };

/** Byte-lex comparator so deduplication + sort are deterministic. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    // After `noUncheckedIndexedAccess`, both reads may be `number | undefined`.
    // We've bounded i to min length so the fallback is unreachable, but keep
    // the coalesce so the type narrows to `number` for the subtraction.
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) return av - bv;
  }
  return a.length - b.length;
}

/**
 * Sign `payload` with every seed and return a deterministic `(pubkey, sig)`
 * bundle suitable for the pallet's M-of-N gate.
 *
 * Behaviour:
 *  - `callerSeed`'s signer is emitted FIRST (origin-binding convenience — the
 *    pallet only checks membership, not position, but this matches the
 *    convention used in the pallet tests).
 *  - Remaining cosigners are sorted by pubkey bytes so the bundle is
 *    byte-reproducible across invocations with identical inputs.
 *  - Duplicates (same seed appearing as caller + cosigner, or twice in the
 *    cosigner list, or different SURIs resolving to the same pubkey) are
 *    dropped silently — the pallet would reject with `DuplicateSigner` so we
 *    pre-empt that failure mode.
 */
export function buildSigBundle(args: {
  callerSeed: string;
  cosignerSeeds: string[];
  payload: Uint8Array;
}): SignerEntry[] {
  const caller = signPayload(args.callerSeed, args.payload);
  const seen: Uint8Array[] = [caller.pubkey];

  const cosignerEntries: SignerEntry[] = [];
  for (const seed of args.cosignerSeeds) {
    const entry = signPayload(seed, args.payload);
    if (seen.some((pk) => u8aEq(pk, entry.pubkey))) {
      continue; // dedupe (matches pallet `DuplicateSigner` semantics).
    }
    seen.push(entry.pubkey);
    cosignerEntries.push(entry);
  }

  cosignerEntries.sort((a, b) => compareBytes(a.pubkey, b.pubkey));
  return [caller, ...cosignerEntries];
}
