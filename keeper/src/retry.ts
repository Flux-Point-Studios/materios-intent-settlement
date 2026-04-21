/**
 * Retry utilities. Used for fee-spike bumping (§5.6) and generic RPC
 * backoff. All randomness is opt-in to keep tests deterministic.
 */

export interface RetryOptions {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  jitterFn?: () => number; // returns 0..1; default Math.random
  onAttempt?: (attemptIdx: number, delayMs: number) => void;
}

export async function retryWithBackoff<T>(
  op: (attempt: number) => Promise<T>,
  opts: RetryOptions,
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < opts.maxAttempts; attempt++) {
    try {
      return await op(attempt);
    } catch (err) {
      lastErr = err;
      if (attempt === opts.maxAttempts - 1) break;
      const exp = Math.min(opts.baseDelayMs * 2 ** attempt, opts.maxDelayMs);
      const jitter = opts.jitterFn ? opts.jitterFn() : Math.random();
      const delay = Math.floor(exp * (0.5 + jitter / 2));
      opts.onAttempt?.(attempt, delay);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

/**
 * Fee-bump retry policy for Cardano tx submission per spec §5.6. Returns the
 * bump factor to apply on each successive attempt.
 */
export function feeBumpFactor(attempt: number): number {
  // 1x, 1.5x, 2.25x, cap at 3x.
  return Math.min(3, 1 * 1.5 ** attempt);
}
