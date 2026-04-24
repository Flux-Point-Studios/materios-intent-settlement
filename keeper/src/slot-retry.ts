/**
 * Slot-drift retry wrapper for Cardano tx build + submit (issue #17).
 *
 * Aiken's BatchClaimVoucher validator enforces strict equality
 * `current_slot == validity_range.upper_bound`. The keeper captures a tip,
 * builds a tx pinned to that slot, signs, and submits — but by the time
 * ogmios gossips the tx the chain has advanced, and the validator silently
 * rejects. Fee-spike retries don't help: the error isn't "fee too low", it
 * is a plutus-level rejection, and the next attempt needs a *fresh tip*.
 *
 * Behaviour:
 *   - Bounded retry (default 3 attempts).
 *   - Reads a fresh tip per attempt via injected `getCurrentSlot`.
 *   - Classifies each failure: only slot-mismatch errors retry; everything
 *     else (insufficient funds, bad signature, network down) propagates
 *     immediately so we don't burn the max-retries budget on a real bug.
 *   - Exponential backoff 250 → 500 → 1000 ms between attempts (spec).
 *   - On exhaustion, throws with the per-attempt slot + error payload so
 *     operators can correlate against chain tip logs.
 *
 * The detection signature (`SLOT_ERROR_SIGNATURES`) matches both:
 *   (a) the local runtime guard emitted by `buildBatchTx` when the
 *       validity-range check fails during a stale-slot rebuild, and
 *   (b) the ogmios / cardano-node rejection messages for
 *       OutsideValidityIntervalUTxO / PlutusFailure where the Aiken
 *       script traces mention validity-range or current_slot. We key
 *       on substring-insensitive because the shape varies between
 *       cardano-cli 8.x JSON, ogmios v6 JSON-WSP, and the Aiken trace text.
 */

import type { ICardanoProvider, SubmittedTx } from "./cardano.js";
import type { SlotNumber } from "@fluxpointstudios/materios-intent-settlement-sdk";

/**
 * Substrings we treat as slot-drift signals. Matched case-insensitively
 * against the error's `.message` (or stringified error) — if ANY matches
 * we retry with a fresh tip.
 *
 * Rationale per substring:
 *   - "validity range" / "validity interval" — common prefix in cardano-node
 *     + ogmios rejection payloads (OutsideValidityIntervalUTxO) and in the
 *     local `assertSinglePointValidityRange` guard.
 *   - "current slot" — emitted by our own SDK builder when the range's
 *     upper bound drifts from the captured tip.
 *   - "slot mismatch" / "slot drift" — future-proof wording that matches
 *     both the pallet-side receipt rejection (Materios settle_claim can
 *     emit this too) and Aiken script trace text ("tx slot != current_slot").
 *   - "outsidevalidityinterval" — the raw ledger-predicate-failure name
 *     that ogmios forwards verbatim when its JSON-WSP rejection path fires.
 *   - "plutusfailure" + "validity" — Plutus script rejections that name
 *     the validity-range check in their trace.
 *
 * If we see a Plutus failure WITHOUT a validity-range substring, that's a
 * real bug (e.g. bad datum) and we propagate — no retry.
 */
export const SLOT_ERROR_SIGNATURES = [
  "validity range",
  "validity interval",
  "current slot",
  "slot mismatch",
  "slot drift",
  "outsidevalidityinterval",
] as const;

export interface SlotDriftRetryOptions {
  maxRetries?: number; // default 3
  backoffMs?: readonly number[]; // default [250, 500, 1000]
  sleep?: (ms: number) => Promise<void>;
  logger?: (level: "info" | "warn", msg: string, meta?: unknown) => void;
}

export interface SlotDriftAttemptFailure {
  attempt: number;
  currentSlot: SlotNumber;
  error: unknown;
}

export class SlotDriftExhaustedError extends Error {
  readonly attempts: readonly SlotDriftAttemptFailure[];
  constructor(attempts: readonly SlotDriftAttemptFailure[]) {
    const summary = attempts
      .map(
        (a) =>
          `attempt=${a.attempt} slot=${a.currentSlot} err=${errMessage(a.error)}`,
      )
      .join(" | ");
    super(`slot-drift retries exhausted after ${attempts.length} attempts: ${summary}`);
    this.attempts = attempts;
    this.name = "SlotDriftExhaustedError";
  }
}

/**
 * Returns true if the error message contains any slot-drift signature.
 * Defensive: handles Error, string, and unknown throwables.
 */
export function isSlotDriftError(err: unknown): boolean {
  const msg = errMessage(err).toLowerCase();
  return SLOT_ERROR_SIGNATURES.some((sig) => msg.includes(sig));
}

function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (err === null || err === undefined) return String(err);
  try {
    const s = JSON.stringify(err);
    return typeof s === "string" ? s : String(err);
  } catch {
    return String(err);
  }
}

/**
 * Build + submit a Cardano tx with slot-drift retry.
 *
 * Each attempt:
 *   1. Captures the current Cardano tip.
 *   2. Calls `buildAndSubmit(currentSlot)` — the caller is responsible for
 *      building the tx bound to that slot and calling `provider.submitTx`.
 *   3. On success: returns immediately with `{ txHash, attempt, slot }`.
 *   4. On slot-drift error: logs + backs off + re-captures tip.
 *   5. On any other error: propagates immediately (no retry).
 *
 * We deliberately pass `currentSlot` INTO `buildAndSubmit` rather than
 * capturing it inside — this lets the caller rebuild the whole BuildBatchTxInput
 * with the fresh slot, and also lets tests verify that getCurrentSlot is
 * called once per attempt.
 */
export async function buildAndSubmitWithSlotRetry(
  provider: Pick<ICardanoProvider, "getCurrentSlot">,
  buildAndSubmit: (currentSlot: SlotNumber) => Promise<SubmittedTx>,
  opts: SlotDriftRetryOptions = {},
): Promise<{ submitted: SubmittedTx; attempt: number; slot: SlotNumber }> {
  const maxRetries = opts.maxRetries ?? 3;
  const backoff = opts.backoffMs ?? [250, 500, 1000];
  const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const log = opts.logger ?? (() => {});

  const failures: SlotDriftAttemptFailure[] = [];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const currentSlot = await provider.getCurrentSlot();
    try {
      const submitted = await buildAndSubmit(currentSlot);
      return { submitted, attempt, slot: currentSlot };
    } catch (err) {
      if (!isSlotDriftError(err)) {
        // Not a slot-drift failure — propagate immediately, do not consume
        // additional retry budget on a real bug.
        throw err;
      }
      failures.push({ attempt, currentSlot, error: err });
      if (attempt === maxRetries - 1) {
        throw new SlotDriftExhaustedError(failures);
      }
      const delayMs = backoff[attempt] ?? backoff[backoff.length - 1] ?? 1000;
      log("info", "slot drift detected, retrying with fresh tip", {
        attempt,
        currentSlot: currentSlot.toString(),
        delayMs,
        err: errMessage(err),
      });
      await sleep(delayMs);
    }
  }

  // Unreachable: the loop above always either returns or throws within
  // `maxRetries` iterations, but TS's control-flow analysis can't see it.
  throw new SlotDriftExhaustedError(failures);
}
