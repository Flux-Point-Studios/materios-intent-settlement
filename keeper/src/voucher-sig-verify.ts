/**
 * Local sr25519 verification of voucher committee sigs (Task #76b).
 *
 * Before paying real Cardano fees the keeper must independently verify
 * the (pubkey, sig) pairs attached to a Voucher. Historically the
 * `processBatch` path only checked `committeeSigs.length === 0` and a
 * 66-char digest length; never sr25519-verified. A malicious or buggy
 * committee daemon could ship a valid-looking voucher whose sigs don't
 * actually authenticate the digest, and the keeper would dutifully pay
 * the Cardano submit fee for it.
 *
 * This module provides a pure function `verifyVoucherSigs` that consumes
 * a Voucher + the committee membership snapshot and returns whether the
 * voucher is safe to submit. It does NOT mutate state — the caller decides
 * how to react (skip, log, increment a metric).
 */

import { hexToU8a } from "@polkadot/util";
import { sr25519Verify } from "@polkadot/util-crypto";
import {
  voucherDigest,
  voucherDigestWithAddress,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import type {
  CommitteePubkey,
  HexString,
  Voucher,
} from "@fluxpointstudios/materios-intent-settlement-sdk";

export type VoucherSigVerifyResult =
  | { ok: true; verifiedCount: number; threshold: number }
  | {
      ok: false;
      reason:
        | "no_signatures"
        | "digest_mismatch"
        | "insufficient_unique_valid_sigs"
        | "non_member_signer"
        | "duplicate_signer"
        | "bad_pubkey_format"
        | "bad_sig_format";
      detail?: string;
    };

export interface VerifyVoucherSigsOptions {
  /**
   * Live committee membership snapshot from chain state. Each entry is a
   * 0x-prefixed 32-byte sr25519 pubkey hex. Order is irrelevant.
   */
  committeeMembers: readonly CommitteePubkey[];
  /**
   * Minimum unique valid sigs required (M-of-N). The pallet's
   * MinSignerThreshold or DefaultMinSignerThreshold value. Pass the
   * `threshold` field from `getCommitteeState()`.
   */
  threshold: number;
  /**
   * Optional alternative digest function. When the voucher will be verified
   * against the Aiken validator on Cardano (which uses
   * `voucherDigestWithAddress` with CBOR beneficiary), pass that variant.
   * Default: SCALE-style `voucherDigest` (matches the pallet's compute path).
   */
  digestFn?: (voucher: Voucher) => HexString;
}

/**
 * Verify that `voucher.committeeSigs` contains AT LEAST `threshold` unique
 * sr25519 signatures from current committee members over the voucher's
 * canonical digest.
 *
 * This mirrors the pallet's `ensure_threshold_signatures` semantics so a
 * local rejection here predicts a chain-side rejection. We DO NOT submit
 * Cardano txs for vouchers we know will be rejected.
 */
export function verifyVoucherSigs(
  voucher: Voucher,
  opts: VerifyVoucherSigsOptions,
): VoucherSigVerifyResult {
  if (!voucher.committeeSigs || voucher.committeeSigs.length === 0) {
    return { ok: false, reason: "no_signatures" };
  }
  if (opts.threshold <= 0) {
    // Defensive: a zero threshold would auto-pass any sig set, including
    // an empty one. Treat as a hard misconfig.
    return {
      ok: false,
      reason: "insufficient_unique_valid_sigs",
      detail: `threshold must be >0, got ${opts.threshold}`,
    };
  }

  // Compute the canonical digest the committee should have signed.
  const digestFn = opts.digestFn ?? voucherDigest;
  let digestHex: HexString;
  try {
    digestHex = digestFn(voucher);
  } catch (err) {
    return {
      ok: false,
      reason: "digest_mismatch",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  if (
    typeof digestHex !== "string" ||
    !digestHex.startsWith("0x") ||
    digestHex.length !== 66
  ) {
    return {
      ok: false,
      reason: "digest_mismatch",
      detail: `bad digest hex: ${digestHex}`,
    };
  }
  const digestBytes = hexToU8a(digestHex);

  // Build a normalised set of committee member pubkeys for membership lookup.
  const memberSet = new Set<string>();
  for (const m of opts.committeeMembers) {
    if (typeof m !== "string" || !m.startsWith("0x")) continue;
    memberSet.add(m.toLowerCase());
  }

  const seenSigners = new Set<string>();
  let validCount = 0;

  for (const entry of voucher.committeeSigs) {
    if (
      typeof entry.pubkey !== "string" ||
      !entry.pubkey.startsWith("0x") ||
      entry.pubkey.length !== 66
    ) {
      return {
        ok: false,
        reason: "bad_pubkey_format",
        detail: entry.pubkey,
      };
    }
    if (
      typeof entry.sig !== "string" ||
      !entry.sig.startsWith("0x") ||
      entry.sig.length !== 130
    ) {
      return {
        ok: false,
        reason: "bad_sig_format",
        detail: entry.sig,
      };
    }
    const pkLower = entry.pubkey.toLowerCase();
    if (!memberSet.has(pkLower)) {
      // Pallet would reject with NotCommitteeMember; pre-empt before paying fees.
      return {
        ok: false,
        reason: "non_member_signer",
        detail: entry.pubkey,
      };
    }
    if (seenSigners.has(pkLower)) {
      // Pallet would reject with DuplicateSigner.
      return {
        ok: false,
        reason: "duplicate_signer",
        detail: entry.pubkey,
      };
    }
    seenSigners.add(pkLower);

    let pubkeyBytes: Uint8Array;
    let sigBytes: Uint8Array;
    try {
      pubkeyBytes = hexToU8a(entry.pubkey);
      sigBytes = hexToU8a(entry.sig);
    } catch (err) {
      return {
        ok: false,
        reason: "bad_sig_format",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    if (pubkeyBytes.length !== 32) {
      return { ok: false, reason: "bad_pubkey_format", detail: entry.pubkey };
    }
    if (sigBytes.length !== 64) {
      return { ok: false, reason: "bad_sig_format", detail: entry.sig };
    }

    let verified = false;
    try {
      verified = sr25519Verify(digestBytes, sigBytes, pubkeyBytes);
    } catch {
      verified = false;
    }
    if (verified) {
      validCount += 1;
    }
    // We DO NOT short-circuit on first invalid sig — keep iterating so we
    // can detect duplicate / non-member entries that come before the
    // invalid one. But we DO require the threshold of VALID sigs.
  }

  if (validCount < opts.threshold) {
    return {
      ok: false,
      reason: "insufficient_unique_valid_sigs",
      detail: `${validCount}/${opts.threshold} valid sigs`,
    };
  }
  return { ok: true, verifiedCount: validCount, threshold: opts.threshold };
}

export { voucherDigest, voucherDigestWithAddress };
