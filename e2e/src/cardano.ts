/**
 * Cardano-side orchestration helpers.
 *
 * Thin HTTP clients over Kupo + Ogmios used by the E2E test to:
 *   - `pollCardanoUtxo`  — wait until a given UTxO is produced at a script address
 *                          (confirms the Aiken validator accepted the keeper's batch voucher)
 *   - `fetchTxMetadata`  — fetch metadata at label 8746 / 2222 for a tx hash
 *   - `buildCexplorerLink` — deterministic URL builder for the demo-reel
 *
 * Uses `fetch` (built into Node 20) to keep this module framework-agnostic and
 * unit-testable with a stubbed fetch.
 */

export interface KupoMatch {
  transaction_id: string;
  output_index: number;
  address: string;
  value: { coins: number; assets: Record<string, number> };
  datum_hash: string | null;
  datum_type: 'hash' | 'inline' | null;
  created_at: { slot_no: number; header_hash: string };
  spent_at: { slot_no: number; header_hash: string } | null;
}

export interface FetchFn {
  (input: string, init?: { headers?: Record<string, string> }): Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
    text: () => Promise<string>;
  }>;
}

export interface CardanoClient {
  listUtxosAtAddress(address: string): Promise<KupoMatch[]>;
  fetchTxMetadata(txHash: string): Promise<Record<number, unknown>>;
  currentSlot(): Promise<number>;
}

export function makeCardanoClient(opts: {
  kupoUrl: string;
  ogmiosUrl: string;
  fetch?: FetchFn;
}): CardanoClient {
  const f: FetchFn = opts.fetch ?? (globalThis.fetch as unknown as FetchFn);
  const kupo = opts.kupoUrl.replace(/\/$/, '');
  const ogmios = opts.ogmiosUrl.replace(/\/$/, '');

  return {
    async listUtxosAtAddress(address) {
      const url = `${kupo}/matches/${encodeURIComponent(address)}?unspent`;
      const r = await f(url);
      if (!r.ok) throw new Error(`kupo list-utxos ${r.status}: ${await r.text()}`);
      const body = (await r.json()) as KupoMatch[];
      return body;
    },
    async fetchTxMetadata(txHash) {
      // Kupo does not expose metadata directly; use Blockfrost if available, else Ogmios query-ledger-state.
      // For demo we hit Kupo's /metadata/<tx> extension (Saturnswap kupo deployment exposes this).
      const url = `${kupo}/metadata/${txHash}`;
      const r = await f(url);
      if (!r.ok) {
        if (r.status === 404) return {};
        throw new Error(`kupo metadata ${r.status}: ${await r.text()}`);
      }
      const body = (await r.json()) as Record<number, unknown>;
      return body;
    },
    async currentSlot() {
      // Ogmios JSON-RPC: "queryNetwork/tip"
      const r = await f(`${ogmios}`, {
        headers: { 'content-type': 'application/json' },
      });
      if (!r.ok) throw new Error(`ogmios tip ${r.status}`);
      // Production call shape: POST body { jsonrpc:'2.0', method:'queryNetwork/tip' }.
      // Kept as a stub — E2E harness overrides this via opts.fetch to hit the right path.
      const body = (await r.json()) as { result?: { slot?: number } };
      return body.result?.slot ?? 0;
    },
  };
}

/** Poll until a UTxO appears at the given address matching the predicate (or timeout). */
export async function pollCardanoUtxo(
  client: CardanoClient,
  address: string,
  predicate: (utxo: KupoMatch) => boolean,
  opts: { intervalMs?: number; timeoutMs?: number; log?: (s: string) => void } = {},
  clock: { now: () => number; sleep: (ms: number) => Promise<void> } = {
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  },
): Promise<KupoMatch> {
  const intervalMs = opts.intervalMs ?? 5_000;
  const timeoutMs = opts.timeoutMs ?? 300_000;
  const start = clock.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const utxos = await client.listUtxosAtAddress(address);
    const match = utxos.find(predicate);
    if (match) {
      opts.log?.(`utxo found at ${address}: ${match.transaction_id}#${match.output_index}`);
      return match;
    }
    opts.log?.(`no match yet at ${address} (${utxos.length} utxos) — sleeping ${intervalMs}ms`);
    if (clock.now() - start >= timeoutMs) {
      throw new Error(
        `timeout polling ${address} for utxo after ${timeoutMs}ms (${utxos.length} visible)`,
      );
    }
    await clock.sleep(intervalMs);
  }
}

/** Build a https://preprod.cexplorer.io/tx/<hash> link. */
export function buildCexplorerLink(explorerTxBase: string, txHash: string): string {
  const base = explorerTxBase.replace(/\/$/, '');
  const clean = txHash.startsWith('0x') ? txHash.slice(2) : txHash;
  return `${base}/${clean}`;
}
