/**
 * Fairness-proof recomputation per spec §1.6.
 *
 * Given a sorted intent list, requested amounts, and pool balance, recompute:
 *   - pro_rata_scale_bps (capped at 10000 = 100%)
 *   - awarded_amounts_ada[i] = requested[i] * scale / 10000
 *
 * The E2E test uses this to INDEPENDENTLY verify the committee's anchored
 * BatchFairnessProof matches what the math says — catching any keeper /
 * committee disagreement with the pallet.
 *
 * Invariants enforced (spec §1.6):
 *   - sum(awarded) <= pool_balance
 *   - pro_rata_scale_bps <= 10000
 *   - awarded[i] == requested[i] * scale / 10000
 *   - sorted_intent_ids strictly ascending (FCFS by submitted_block, tiebreak IntentId bytes)
 */

import type { BatchFairnessProof, IntentId } from './types.js';
import { domainHash, fromHex } from './hashing.js';

export interface RecomputedProof {
  proRataScaleBps: number;
  awardedAmountsAda: bigint[];
  totalRequested: bigint;
  totalAwarded: bigint;
}

export const BPS_DENOMINATOR = 10_000;

/** Compute pro-rata scale (bps). 10_000 = full (no haircut). */
export function computeProRataScale(
  totalRequested: bigint,
  poolBalance: bigint,
): number {
  if (totalRequested < 0n || poolBalance < 0n) {
    throw new Error('amounts must be non-negative');
  }
  if (totalRequested === 0n) return BPS_DENOMINATOR;
  if (totalRequested <= poolBalance) return BPS_DENOMINATOR;
  // scale = pool * 10000 / requested, truncated (worst-case for users, safe for pool).
  const scale = (poolBalance * BigInt(BPS_DENOMINATOR)) / totalRequested;
  // Cap at BPS_DENOMINATOR just in case of rounding pathology.
  const bounded = scale > BigInt(BPS_DENOMINATOR) ? BigInt(BPS_DENOMINATOR) : scale;
  return Number(bounded);
}

/** Compute awarded amount for a single intent. */
export function computeAwarded(requested: bigint, proRataScaleBps: number): bigint {
  if (requested < 0n) throw new Error('requested must be non-negative');
  if (proRataScaleBps < 0 || proRataScaleBps > BPS_DENOMINATOR) {
    throw new Error(`proRataScaleBps out of range: ${proRataScaleBps}`);
  }
  return (requested * BigInt(proRataScaleBps)) / BigInt(BPS_DENOMINATOR);
}

/** End-to-end recomputation. */
export function recomputeFairnessProof(
  sortedIntentIds: IntentId[],
  requestedAmountsAda: bigint[],
  poolBalanceAda: bigint,
): RecomputedProof {
  if (sortedIntentIds.length !== requestedAmountsAda.length) {
    throw new Error(
      `parallel-array mismatch: ${sortedIntentIds.length} ids vs ${requestedAmountsAda.length} amounts`,
    );
  }
  assertStrictlyAscending(sortedIntentIds);

  let totalRequested = 0n;
  for (const r of requestedAmountsAda) totalRequested += r;

  const proRataScaleBps = computeProRataScale(totalRequested, poolBalanceAda);
  const awardedAmountsAda = requestedAmountsAda.map((r) =>
    computeAwarded(r, proRataScaleBps),
  );
  let totalAwarded = 0n;
  for (const a of awardedAmountsAda) totalAwarded += a;

  if (totalAwarded > poolBalanceAda) {
    // Defensive check — should be impossible given the scale formula.
    throw new Error(
      `pool-overcommit: awarded ${totalAwarded} > pool ${poolBalanceAda} (scale=${proRataScaleBps})`,
    );
  }
  return { proRataScaleBps, awardedAmountsAda, totalRequested, totalAwarded };
}

/** Verify an on-chain BFPR against a local recomputation. Throws on mismatch. */
export function assertFairnessProofMatches(
  proof: BatchFairnessProof,
  options: { poolBalanceAda?: bigint } = {},
): void {
  const poolBalance = options.poolBalanceAda ?? proof.poolBalanceAda;
  const recomputed = recomputeFairnessProof(
    proof.sortedIntentIds,
    proof.requestedAmountsAda,
    poolBalance,
  );
  if (recomputed.proRataScaleBps !== proof.proRataScaleBps) {
    throw new Error(
      `pro-rata-scale mismatch: local=${recomputed.proRataScaleBps} on-chain=${proof.proRataScaleBps}`,
    );
  }
  if (recomputed.awardedAmountsAda.length !== proof.awardedAmountsAda.length) {
    throw new Error(
      `awarded-length mismatch: local=${recomputed.awardedAmountsAda.length} on-chain=${proof.awardedAmountsAda.length}`,
    );
  }
  for (let i = 0; i < recomputed.awardedAmountsAda.length; i++) {
    const local = recomputed.awardedAmountsAda[i];
    const onChain = proof.awardedAmountsAda[i];
    if (local !== onChain) {
      throw new Error(
        `awarded[${i}] mismatch: local=${local} on-chain=${onChain} (intentId=${proof.sortedIntentIds[i]})`,
      );
    }
  }
}

/** Spec §1.6: sorted_intent_ids is strictly ascending. */
export function assertStrictlyAscending(ids: IntentId[]): void {
  for (let i = 1; i < ids.length; i++) {
    const prev = ids[i - 1]!;
    const curr = ids[i]!;
    if (compareHex(prev, curr) >= 0) {
      throw new Error(`sort-order violation at index ${i}: ${prev} >= ${curr}`);
    }
  }
}

/** Lexicographic compare of 0x-prefixed hex strings interpreted as byte arrays. */
export function compareHex(a: string, b: string): number {
  const aa = fromHex(a);
  const bb = fromHex(b);
  const n = Math.min(aa.length, bb.length);
  for (let i = 0; i < n; i++) {
    const av = aa[i]!;
    const bv = bb[i]!;
    if (av !== bv) return av - bv;
  }
  return aa.length - bb.length;
}

/** Spec §1.6 digest: domain_hash(b"BFPR", scale_encode(BatchFairnessProof)). */
export function fairnessProofDigestFromScaleBytes(scaleBytes: Uint8Array): string {
  return domainHash('BFPR', scaleBytes);
}
