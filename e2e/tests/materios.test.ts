import { describe, expect, it } from 'vitest';

import {
  type ClaimQuerier,
  type IntentQuerier,
  makeClaimQuerier,
  makeIntentQuerier,
  realClock,
  waitForClaimStatus,
  waitForIntentStatus,
} from '../src/materios.js';
import { IntentStatus } from '../src/types.js';

/** Virtual clock so tests don't sleep. */
function fakeClock(initial = 0) {
  let t = initial;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
  };
}

describe('materios: waitForIntentStatus', () => {
  it('resolves immediately when status already at target', async () => {
    const q: IntentQuerier = { getIntentStatus: async () => IntentStatus.Attested };
    await expect(
      waitForIntentStatus(q, '0xaa', IntentStatus.Attested, { intervalMs: 1, timeoutMs: 10 }, fakeClock()),
    ).resolves.toBeUndefined();
  });

  it('resolves when status crosses target after a few polls', async () => {
    const sequence = [
      null,
      IntentStatus.Pending,
      IntentStatus.Pending,
      IntentStatus.Attested,
    ];
    let i = 0;
    const q: IntentQuerier = {
      getIntentStatus: async () => sequence[Math.min(i++, sequence.length - 1)] ?? null,
    };
    await expect(
      waitForIntentStatus(
        q,
        '0xbb',
        IntentStatus.Attested,
        { intervalMs: 1, timeoutMs: 1000 },
        fakeClock(),
      ),
    ).resolves.toBeUndefined();
  });

  it('accepts a higher status than target (forward-tolerant)', async () => {
    const q: IntentQuerier = { getIntentStatus: async () => IntentStatus.Settled };
    await expect(
      waitForIntentStatus(q, '0xcc', IntentStatus.Attested, { intervalMs: 1, timeoutMs: 10 }, fakeClock()),
    ).resolves.toBeUndefined();
  });

  it('throws on timeout when status never reaches target', async () => {
    const q: IntentQuerier = { getIntentStatus: async () => IntentStatus.Pending };
    await expect(
      waitForIntentStatus(q, '0xdd', IntentStatus.Attested, { intervalMs: 10, timeoutMs: 50 }, fakeClock()),
    ).rejects.toThrow(/timeout/);
  });

  it('calls the logger on status transitions', async () => {
    const logs: string[] = [];
    const sequence = [IntentStatus.Pending, IntentStatus.Attested];
    let i = 0;
    const q: IntentQuerier = {
      getIntentStatus: async () => sequence[Math.min(i++, sequence.length - 1)] ?? null,
    };
    await waitForIntentStatus(
      q,
      '0xee',
      IntentStatus.Attested,
      { intervalMs: 1, timeoutMs: 1000, log: (m) => logs.push(m) },
      fakeClock(),
    );
    expect(logs.some((l) => l.includes('reached status'))).toBe(true);
  });

  it('handles null (intent not found) gracefully without throwing', async () => {
    const q: IntentQuerier = { getIntentStatus: async () => null };
    await expect(
      waitForIntentStatus(q, '0xff', IntentStatus.Attested, { intervalMs: 1, timeoutMs: 30 }, fakeClock()),
    ).rejects.toThrow(/timeout/);
  });
});

describe('materios: realClock', () => {
  it('returns a real Date.now() + a setTimeout-backed sleep', async () => {
    const c = realClock();
    const start = c.now();
    expect(typeof start).toBe('number');
    await c.sleep(1);
    expect(c.now()).toBeGreaterThanOrEqual(start);
  });
});

describe('materios: makeIntentQuerier / makeClaimQuerier adapters', () => {
  // Build a stub ApiPromise-shaped object just enough to exercise the adapter.
  function stubApi(entry: unknown) {
    return {
      query: {
        intentSettlement: {
          intents: async () => entry,
          claims: async () => entry,
        },
      },
    } as unknown as Parameters<typeof makeIntentQuerier>[0];
  }

  it('intent querier returns null when entry is None', async () => {
    const q = makeIntentQuerier(stubApi({ isNone: true }));
    expect(await q.getIntentStatus('0xaa')).toBeNull();
  });

  it('intent querier unwraps and extracts numeric status', async () => {
    const entry = {
      isNone: false,
      unwrap: () => ({ status: { toNumber: () => IntentStatus.Attested } }),
    };
    const q = makeIntentQuerier(stubApi(entry));
    expect(await q.getIntentStatus('0xbb')).toBe(IntentStatus.Attested);
  });

  it('intent querier accepts plain numeric status (no .toNumber)', async () => {
    const entry = {
      isNone: false,
      unwrap: () => ({ status: IntentStatus.Settled }),
    };
    const q = makeIntentQuerier(stubApi(entry));
    expect(await q.getIntentStatus('0xcc')).toBe(IntentStatus.Settled);
  });

  it('claim querier returns null when entry is None', async () => {
    const q = makeClaimQuerier(stubApi({ isNone: true }));
    expect(await q.getClaimStatus('0x11')).toBeNull();
  });

  it('claim querier extracts numeric status', async () => {
    const entry = {
      isNone: false,
      unwrap: () => ({ status: { toNumber: () => IntentStatus.Vouchered } }),
    };
    const q = makeClaimQuerier(stubApi(entry));
    expect(await q.getClaimStatus('0x22')).toBe(IntentStatus.Vouchered);
  });

  it('intent querier returns null when status not numeric', async () => {
    const entry = {
      isNone: false,
      unwrap: () => ({ status: 'NotANumber' }),
    };
    const q = makeIntentQuerier(stubApi(entry));
    expect(await q.getIntentStatus('0xdd')).toBeNull();
  });
});

describe('materios: waitForClaimStatus', () => {
  it('resolves when claim reaches Settled', async () => {
    const sequence = [IntentStatus.Vouchered, IntentStatus.Settled];
    let i = 0;
    const q: ClaimQuerier = {
      getClaimStatus: async () => sequence[Math.min(i++, sequence.length - 1)] ?? null,
    };
    await expect(
      waitForClaimStatus(q, '0x11', IntentStatus.Settled, { intervalMs: 1, timeoutMs: 1000 }, fakeClock()),
    ).resolves.toBeUndefined();
  });

  it('times out when claim stuck in Vouchered', async () => {
    const q: ClaimQuerier = { getClaimStatus: async () => IntentStatus.Vouchered };
    await expect(
      waitForClaimStatus(q, '0x22', IntentStatus.Settled, { intervalMs: 5, timeoutMs: 40 }, fakeClock()),
    ).rejects.toThrow(/timeout/);
  });
});
