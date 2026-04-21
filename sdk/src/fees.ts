/**
 * Keeper-fee math per spec §5.4.
 *
 *   keeper_fee_ada = min(
 *     2% * sum(awarded),
 *     500_000 (0.5 ADA base) + 5 * sum(awarded) / 1000 (50 bps),
 *   )
 *
 * Inputs and outputs are in lovelace (1 ADA = 1_000_000).
 * All math in bigint to avoid JS float drift.
 */

import type { AdaLovelace } from "./types.js";

/** Hard floor from v1 spec open-item Q2 proposal. */
export const KEEPER_FEE_FLOOR_LOVELACE = 500_000n; // 0.5 ADA

export function computeKeeperFeeLovelace(totalAwardedLovelace: AdaLovelace): AdaLovelace {
  if (totalAwardedLovelace < 0n) throw new Error("negative awarded");

  const twoPercentCap = (totalAwardedLovelace * 2n) / 100n;
  const bpsBased = 500_000n + (5n * totalAwardedLovelace) / 1000n;
  return twoPercentCap < bpsBased ? twoPercentCap : bpsBased;
}

/**
 * Whether the fee can cover tx-building cost. Below this the batch is
 * uneconomic; keeper should skip it (per §5.6 fee-spike + direct-path hints).
 */
export function isEconomic(
  totalAwardedLovelace: AdaLovelace,
  currentMinTxFeeLovelace: AdaLovelace,
): boolean {
  const fee = computeKeeperFeeLovelace(totalAwardedLovelace);
  return fee >= currentMinTxFeeLovelace;
}

/**
 * Return the lovelace output amount a keeper is allowed to claim.
 * Used when building a Cardano tx — this is the "fee output" value that the
 * Aiken validator verifies against `amount ≤ keeper_fee_ada`.
 */
export function feeOutputLovelace(totalAwardedLovelace: AdaLovelace): AdaLovelace {
  // Same as computeKeeperFeeLovelace today. Separate fn preserves intent
  // and lets the two drift if v1.5 changes the validator contract.
  return computeKeeperFeeLovelace(totalAwardedLovelace);
}
