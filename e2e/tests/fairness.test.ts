import { describe, expect, it } from 'vitest';

import {
  BPS_DENOMINATOR,
  assertFairnessProofMatches,
  assertStrictlyAscending,
  compareHex,
  computeAwarded,
  computeProRataScale,
  fairnessProofDigestFromScaleBytes,
  recomputeFairnessProof,
} from '../src/fairness.js';
import type { BatchFairnessProof, IntentId } from '../src/types.js';

const ID = (byte: number): IntentId =>
  `0x${byte.toString(16).padStart(2, '0')}${'00'.repeat(31)}` as IntentId;

describe('fairness: computeProRataScale', () => {
  it('returns 10000 (full) when pool >= requested', () => {
    expect(computeProRataScale(100n, 200n)).toBe(10000);
    expect(computeProRataScale(100n, 100n)).toBe(10000);
  });

  it('returns 10000 when requested is 0 (no one asked for anything)', () => {
    expect(computeProRataScale(0n, 0n)).toBe(10000);
    expect(computeProRataScale(0n, 100n)).toBe(10000);
  });

  it('scales proportionally when pool < requested', () => {
    // requested 1000, pool 300 -> scale 3000 bps (30%)
    expect(computeProRataScale(1000n, 300n)).toBe(3000);
    // requested 1_000_000, pool 250_000 -> scale 2500 bps
    expect(computeProRataScale(1_000_000n, 250_000n)).toBe(2500);
  });

  it('truncates (rounds down) on division', () => {
    // requested 3, pool 1 -> 1*10000/3 = 3333
    expect(computeProRataScale(3n, 1n)).toBe(3333);
  });

  it('rejects negative amounts', () => {
    expect(() => computeProRataScale(-1n, 100n)).toThrow(/non-negative/);
    expect(() => computeProRataScale(100n, -1n)).toThrow(/non-negative/);
  });
});

describe('fairness: computeAwarded', () => {
  it('returns requested amount at full scale', () => {
    expect(computeAwarded(1000n, BPS_DENOMINATOR)).toBe(1000n);
  });
  it('returns 0 at zero scale', () => {
    expect(computeAwarded(1000n, 0)).toBe(0n);
  });
  it('computes partial awards', () => {
    expect(computeAwarded(1000n, 5000)).toBe(500n);
    expect(computeAwarded(1_000_000n, 2500)).toBe(250_000n);
  });
  it('rejects negative requested', () => {
    expect(() => computeAwarded(-1n, 5000)).toThrow(/non-negative/);
  });
  it('rejects out-of-range scale', () => {
    expect(() => computeAwarded(100n, -1)).toThrow(/out of range/);
    expect(() => computeAwarded(100n, 10_001)).toThrow(/out of range/);
  });
});

describe('fairness: recomputeFairnessProof', () => {
  it('happy path: enough pool, full awards', () => {
    const r = recomputeFairnessProof(
      [ID(0x01), ID(0x02), ID(0x03)],
      [100n, 200n, 300n],
      10_000n,
    );
    expect(r.proRataScaleBps).toBe(10000);
    expect(r.awardedAmountsAda).toEqual([100n, 200n, 300n]);
    expect(r.totalRequested).toBe(600n);
    expect(r.totalAwarded).toBe(600n);
  });

  it('haircut path: pool < requested', () => {
    const r = recomputeFairnessProof([ID(0x01), ID(0x02)], [1000n, 2000n], 1500n);
    // scale = 1500 * 10000 / 3000 = 5000 bps
    expect(r.proRataScaleBps).toBe(5000);
    expect(r.awardedAmountsAda).toEqual([500n, 1000n]);
    expect(r.totalAwarded).toBe(1500n);
  });

  it('rejects parallel-array length mismatch', () => {
    expect(() =>
      recomputeFairnessProof([ID(0x01), ID(0x02)], [100n], 100n),
    ).toThrow(/parallel-array mismatch/);
  });

  it('rejects unsorted intent ids', () => {
    expect(() =>
      recomputeFairnessProof([ID(0x02), ID(0x01)], [100n, 100n], 1000n),
    ).toThrow(/sort-order/);
  });
});

describe('fairness: compareHex + assertStrictlyAscending', () => {
  it('compares byte-lex', () => {
    expect(compareHex('0x00', '0x01')).toBeLessThan(0);
    expect(compareHex('0x01', '0x00')).toBeGreaterThan(0);
    expect(compareHex('0xab', '0xab')).toBe(0);
  });
  it('accepts strictly-ascending', () => {
    expect(() => assertStrictlyAscending([ID(0x01), ID(0x02), ID(0x03)])).not.toThrow();
  });
  it('rejects duplicates', () => {
    expect(() => assertStrictlyAscending([ID(0x01), ID(0x01)])).toThrow(/sort-order/);
  });
  it('rejects descending', () => {
    expect(() => assertStrictlyAscending([ID(0x02), ID(0x01)])).toThrow(/sort-order/);
  });
});

describe('fairness: assertFairnessProofMatches', () => {
  const baseProof = (): BatchFairnessProof => ({
    batchBlockRange: [100, 110],
    sortedIntentIds: [ID(0x01), ID(0x02)],
    requestedAmountsAda: [1000n, 2000n],
    poolBalanceAda: 1500n,
    proRataScaleBps: 5000,
    awardedAmountsAda: [500n, 1000n],
  });

  it('passes a correct proof', () => {
    expect(() => assertFairnessProofMatches(baseProof())).not.toThrow();
  });

  it('flags scale disagreement', () => {
    const p = baseProof();
    p.proRataScaleBps = 4000;
    expect(() => assertFairnessProofMatches(p)).toThrow(/pro-rata-scale mismatch/);
  });

  it('flags awarded-length disagreement', () => {
    const p = baseProof();
    p.awardedAmountsAda = [500n];
    expect(() => assertFairnessProofMatches(p)).toThrow(/awarded-length mismatch/);
  });

  it('flags per-index awarded disagreement', () => {
    const p = baseProof();
    p.awardedAmountsAda = [600n, 1000n];
    expect(() => assertFairnessProofMatches(p)).toThrow(/awarded\[0\] mismatch/);
  });

  it('uses override pool balance when supplied', () => {
    const p = baseProof();
    // Override: if we claim the pool had 3000 ADA, then scale should be 10000
    expect(() => assertFairnessProofMatches(p, { poolBalanceAda: 3000n })).toThrow(
      /pro-rata-scale mismatch/,
    );
  });
});

describe('fairness: digest helper', () => {
  it('produces a 32-byte domain-tagged hash', () => {
    const d = fairnessProofDigestFromScaleBytes(new Uint8Array([1, 2, 3]));
    expect(d).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    const bytes = new Uint8Array([9, 8, 7]);
    expect(fairnessProofDigestFromScaleBytes(bytes)).toBe(
      fairnessProofDigestFromScaleBytes(bytes),
    );
  });
});
