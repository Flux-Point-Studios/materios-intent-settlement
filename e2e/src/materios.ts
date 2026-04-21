/**
 * Materios-side orchestration helpers.
 *
 * Thin async wrappers around @polkadot/api used by the E2E test:
 *   - `connectMaterios` — open a WsProvider + ApiPromise
 *   - `waitForIntentAttested` — poll `Intents[intentId].status` until Attested or timeout
 *   - `waitForClaimSettled`  — poll `Claims[claimId].status` until Settled
 *   - `waitForEvent`         — reactive wrapper that resolves on a matching pallet event
 *
 * Keeps a narrow dependency on @polkadot/api (which the whole materios tool-chain
 * already uses) so that this module is unit-testable with a stub ApiPromise.
 *
 * IMPORTANT: the concrete storage key / runtime-API names are sourced from
 * Team A's spec §2.1 and §2.4. When Team A's PR lands the generated augment-api
 * types, those become the canonical shape; this module currently uses the
 * untyped `api.query.*.any` + `api.rpc.state.call` paths so it works against
 * any runtime that exposes the pallet.
 */

import type { ApiPromise } from '@polkadot/api';
import type { IntentId, ClaimId, IntentStatus } from './types.js';

/** Tunable poll loop. */
export interface PollOpts {
  intervalMs?: number;
  timeoutMs?: number;
  /** Optional logger for verbose mode. */
  log?: (msg: string) => void;
}

const DEFAULTS: Required<Omit<PollOpts, 'log'>> = {
  intervalMs: 2_000,
  timeoutMs: 120_000,
};

/** Abstract query interface — lets us inject a stub in unit tests. */
export interface IntentQuerier {
  getIntentStatus(intentId: IntentId): Promise<number | null>;
}
export interface ClaimQuerier {
  getClaimStatus(claimId: ClaimId): Promise<number | null>;
}

/** Production-path adapter over @polkadot/api. */
export function makeIntentQuerier(api: ApiPromise): IntentQuerier {
  return {
    async getIntentStatus(intentId) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const entry: any = await (api.query as any).intentSettlement?.intents?.(intentId);
      if (!entry || entry.isNone) return null;
      const inner = entry.unwrap?.() ?? entry;
      const status = inner.status?.toNumber?.() ?? inner.status;
      return typeof status === 'number' ? status : null;
    },
  };
}

export function makeClaimQuerier(api: ApiPromise): ClaimQuerier {
  return {
    async getClaimStatus(claimId) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const entry: any = await (api.query as any).intentSettlement?.claims?.(claimId);
      if (!entry || entry.isNone) return null;
      const inner = entry.unwrap?.() ?? entry;
      const status = inner.status?.toNumber?.() ?? inner.status;
      return typeof status === 'number' ? status : null;
    },
  };
}

export async function waitForIntentStatus(
  q: IntentQuerier,
  intentId: IntentId,
  target: IntentStatus,
  opts: PollOpts = {},
  clock: { now: () => number; sleep: (ms: number) => Promise<void> } = realClock(),
): Promise<void> {
  const intervalMs = opts.intervalMs ?? DEFAULTS.intervalMs;
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
  const start = clock.now();
  let lastSeen: number | null = null;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const current = await q.getIntentStatus(intentId);
    if (current !== null && current >= target) {
      opts.log?.(`intent ${intentId} reached status ${current} (target ${target})`);
      return;
    }
    if (current !== lastSeen) {
      opts.log?.(`intent ${intentId} status=${current} waiting-for=${target}`);
      lastSeen = current;
    }
    if (clock.now() - start >= timeoutMs) {
      throw new Error(
        `timeout waiting for intent ${intentId} to reach status ${target}; last seen: ${current}`,
      );
    }
    await clock.sleep(intervalMs);
  }
}

export async function waitForClaimStatus(
  q: ClaimQuerier,
  claimId: ClaimId,
  target: IntentStatus,
  opts: PollOpts = {},
  clock: { now: () => number; sleep: (ms: number) => Promise<void> } = realClock(),
): Promise<void> {
  const intervalMs = opts.intervalMs ?? DEFAULTS.intervalMs;
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
  const start = clock.now();
  let lastSeen: number | null = null;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const current = await q.getClaimStatus(claimId);
    if (current !== null && current >= target) {
      opts.log?.(`claim ${claimId} reached status ${current} (target ${target})`);
      return;
    }
    if (current !== lastSeen) {
      opts.log?.(`claim ${claimId} status=${current} waiting-for=${target}`);
      lastSeen = current;
    }
    if (clock.now() - start >= timeoutMs) {
      throw new Error(
        `timeout waiting for claim ${claimId} to reach status ${target}; last seen: ${current}`,
      );
    }
    await clock.sleep(intervalMs);
  }
}

export function realClock() {
  return {
    now: () => Date.now(),
    sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)),
  };
}

/**
 * Thin wrapper around api.connect(...).
 *
 * Separated into its own function so the E2E test can inject a mock
 * ApiPromise in unit tests without dragging in the full polkadot-api stack.
 */
/* v8 ignore start -- live-ws-only; exercised by scripts/full-demo.ts */
export async function connectMaterios(rpcWs: string): Promise<ApiPromise> {
  const { ApiPromise, WsProvider } = await import('@polkadot/api');
  const provider = new WsProvider(rpcWs);
  return ApiPromise.create({ provider });
}
/* v8 ignore stop */
