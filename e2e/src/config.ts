/**
 * Typed config loader.
 *
 * The E2E demo refuses to load mainnet config unless explicitly requested with
 * MATERIOS_E2E_ALLOW_MAINNET=1 — defense against copy-pasting the preprod
 * test script into a mainnet runner. Spec §6.6 also gates mainnet on committee
 * expansion, and the brief explicitly forbids mainnet txs.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { PreprodConfig } from './types.js';

export type Network = 'preprod' | 'mainnet';

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = join(HERE, '..', 'config');

export function loadConfig(network: Network = 'preprod'): PreprodConfig {
  if (network === 'mainnet' && process.env.MATERIOS_E2E_ALLOW_MAINNET !== '1') {
    throw new Error(
      'refusing to load mainnet config without MATERIOS_E2E_ALLOW_MAINNET=1 (see brief: preprod only)',
    );
  }
  const path = join(CONFIG_DIR, `${network}.json`);
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw) as PreprodConfig;
  validateConfig(parsed, network);
  return parsed;
}

export function validateConfig(cfg: PreprodConfig, network: Network): void {
  if (cfg.network !== network) {
    throw new Error(`config network mismatch: file has ${cfg.network}, expected ${network}`);
  }
  if (!cfg.materios?.rpcWs) {
    throw new Error('config: materios.rpcWs is required');
  }
  if (!cfg.cardano?.ogmiosUrl || !cfg.cardano?.kupoUrl) {
    throw new Error('config: cardano.ogmiosUrl and cardano.kupoUrl are required');
  }
  if (cfg.cardano.metadataLabels.batchAnchor !== 8746) {
    throw new Error(
      `config: batchAnchor label must be 8746 per spec §6.4, got ${cfg.cardano.metadataLabels.batchAnchor}`,
    );
  }
}

/** Check whether Team B's validator addresses have been populated. */
export function validatorsDeployed(cfg: PreprodConfig): boolean {
  return (
    !cfg.aegisValidators.aegisPolicyV1Address.startsWith('__') &&
    !cfg.aegisValidators.premiumCollectorAddress.startsWith('__') &&
    !cfg.aegisValidators.poolCustodyAddress.startsWith('__')
  );
}
