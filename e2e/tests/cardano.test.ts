import { describe, expect, it } from 'vitest';

import {
  buildCexplorerLink,
  type FetchFn,
  type KupoMatch,
  makeCardanoClient,
  pollCardanoUtxo,
} from '../src/cardano.js';

function fakeClock() {
  let t = 0;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
  };
}

function kupoMatch(override: Partial<KupoMatch> = {}): KupoMatch {
  return {
    transaction_id: 'aa'.repeat(32),
    output_index: 0,
    address: 'addr_test1q...',
    value: { coins: 2_000_000, assets: {} },
    datum_hash: null,
    datum_type: null,
    created_at: { slot_no: 1000, header_hash: 'hh' },
    spent_at: null,
    ...override,
  };
}

describe('cardano: buildCexplorerLink', () => {
  it('strips trailing slash from base', () => {
    expect(buildCexplorerLink('https://preprod.cexplorer.io/tx/', 'abcd')).toBe(
      'https://preprod.cexplorer.io/tx/abcd',
    );
  });
  it('strips 0x prefix from hash', () => {
    expect(buildCexplorerLink('https://preprod.cexplorer.io/tx', '0xabcd')).toBe(
      'https://preprod.cexplorer.io/tx/abcd',
    );
  });
  it('handles mainnet base equivalently', () => {
    expect(buildCexplorerLink('https://cexplorer.io/tx', 'deadbeef')).toBe(
      'https://cexplorer.io/tx/deadbeef',
    );
  });
});

describe('cardano: makeCardanoClient', () => {
  it('calls Kupo for list-utxos-at-address', async () => {
    const calls: string[] = [];
    const fetchFn: FetchFn = async (url) => {
      calls.push(url);
      return {
        ok: true,
        status: 200,
        json: async () => [kupoMatch()],
        text: async () => '',
      };
    };
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo:1442/',
      ogmiosUrl: 'http://ogmios:1337',
      fetch: fetchFn,
    });
    const utxos = await c.listUtxosAtAddress('addr_test1xyz');
    expect(calls[0]).toBe('http://kupo:1442/matches/addr_test1xyz?unspent');
    expect(utxos).toHaveLength(1);
  });

  it('throws on non-OK response', async () => {
    const fetchFn: FetchFn = async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
      text: async () => 'backend down',
    });
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios',
      fetch: fetchFn,
    });
    await expect(c.listUtxosAtAddress('addr')).rejects.toThrow(/kupo list-utxos 500/);
  });

  it('returns empty metadata on 404', async () => {
    const fetchFn: FetchFn = async () => ({
      ok: false,
      status: 404,
      json: async () => ({}),
      text: async () => 'not found',
    });
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios',
      fetch: fetchFn,
    });
    await expect(c.fetchTxMetadata('ffff')).resolves.toEqual({});
  });

  it('currentSlot hits ogmios base url and returns slot', async () => {
    const calls: string[] = [];
    const fetchFn: FetchFn = async (url) => {
      calls.push(url);
      return {
        ok: true,
        status: 200,
        json: async () => ({ result: { slot: 12345 } }),
        text: async () => '',
      };
    };
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios/',
      fetch: fetchFn,
    });
    expect(await c.currentSlot()).toBe(12345);
    expect(calls[0]).toBe('http://ogmios');
  });

  it('currentSlot returns 0 when ogmios omits slot', async () => {
    const fetchFn: FetchFn = async () => ({
      ok: true,
      status: 200,
      json: async () => ({}),
      text: async () => '',
    });
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios',
      fetch: fetchFn,
    });
    expect(await c.currentSlot()).toBe(0);
  });

  it('currentSlot throws on ogmios non-OK', async () => {
    const fetchFn: FetchFn = async () => ({
      ok: false,
      status: 502,
      json: async () => ({}),
      text: async () => 'gateway',
    });
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios',
      fetch: fetchFn,
    });
    await expect(c.currentSlot()).rejects.toThrow(/ogmios tip 502/);
  });

  it('throws on fetchTxMetadata non-404 error', async () => {
    const fetchFn: FetchFn = async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
      text: async () => 'broken',
    });
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios',
      fetch: fetchFn,
    });
    await expect(c.fetchTxMetadata('xx')).rejects.toThrow(/kupo metadata 500/);
  });

  it('returns metadata on 200', async () => {
    const body = { 8746: { p: 'materios', v: 2 } };
    const fetchFn: FetchFn = async () => ({
      ok: true,
      status: 200,
      json: async () => body,
      text: async () => JSON.stringify(body),
    });
    const c = makeCardanoClient({
      kupoUrl: 'http://kupo',
      ogmiosUrl: 'http://ogmios',
      fetch: fetchFn,
    });
    const md = await c.fetchTxMetadata('deadbeef');
    expect(md).toEqual(body);
  });
});

describe('cardano: pollCardanoUtxo', () => {
  it('resolves when predicate matches on first poll', async () => {
    const target = kupoMatch({ transaction_id: 'target' });
    let calls = 0;
    const client = {
      listUtxosAtAddress: async () => {
        calls++;
        return [target];
      },
      fetchTxMetadata: async () => ({}),
      currentSlot: async () => 1,
    };
    const found = await pollCardanoUtxo(
      client,
      'addr',
      (u) => u.transaction_id === 'target',
      { intervalMs: 1, timeoutMs: 1000 },
      fakeClock(),
    );
    expect(found).toBe(target);
    expect(calls).toBe(1);
  });

  it('polls multiple times until predicate matches', async () => {
    const target = kupoMatch({ transaction_id: 'target' });
    const series = [[], [kupoMatch({ transaction_id: 'other' })], [target]];
    let i = 0;
    const client = {
      listUtxosAtAddress: async () => series[Math.min(i++, series.length - 1)] ?? [],
      fetchTxMetadata: async () => ({}),
      currentSlot: async () => 1,
    };
    const found = await pollCardanoUtxo(
      client,
      'addr',
      (u) => u.transaction_id === 'target',
      { intervalMs: 1, timeoutMs: 1000 },
      fakeClock(),
    );
    expect(found.transaction_id).toBe('target');
  });

  it('throws on timeout when predicate never matches', async () => {
    const client = {
      listUtxosAtAddress: async () => [kupoMatch({ transaction_id: 'other' })],
      fetchTxMetadata: async () => ({}),
      currentSlot: async () => 1,
    };
    await expect(
      pollCardanoUtxo(
        client,
        'addr',
        (u) => u.transaction_id === 'missing',
        { intervalMs: 10, timeoutMs: 50 },
        fakeClock(),
      ),
    ).rejects.toThrow(/timeout polling/);
  });

  it('calls logger with a descriptive message', async () => {
    const logs: string[] = [];
    const target = kupoMatch({ transaction_id: 'target' });
    const client = {
      listUtxosAtAddress: async () => [target],
      fetchTxMetadata: async () => ({}),
      currentSlot: async () => 1,
    };
    await pollCardanoUtxo(
      client,
      'addr',
      () => true,
      { intervalMs: 1, timeoutMs: 1000, log: (m) => logs.push(m) },
      fakeClock(),
    );
    expect(logs.some((l) => l.includes('utxo found'))).toBe(true);
  });
});
