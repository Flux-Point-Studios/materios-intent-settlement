import { describe, expect, it } from 'vitest';

import { loadConfig, validateConfig, validatorsDeployed } from '../src/config.js';
import type { PreprodConfig } from '../src/types.js';

describe('config: loadConfig', () => {
  it('loads preprod.json', () => {
    const cfg = loadConfig('preprod');
    expect(cfg.network).toBe('preprod');
    expect(cfg.materios.rpcWs).toMatch(/^wss:\/\//);
    expect(cfg.cardano.metadataLabels.batchAnchor).toBe(8746);
    expect(cfg.cardano.metadataLabels.poiAnchor).toBe(2222);
  });

  it('refuses to load mainnet without explicit opt-in', () => {
    const prev = process.env.MATERIOS_E2E_ALLOW_MAINNET;
    delete process.env.MATERIOS_E2E_ALLOW_MAINNET;
    try {
      expect(() => loadConfig('mainnet')).toThrow(/MATERIOS_E2E_ALLOW_MAINNET/);
    } finally {
      if (prev !== undefined) process.env.MATERIOS_E2E_ALLOW_MAINNET = prev;
    }
  });
});

describe('config: validateConfig', () => {
  const base = (): PreprodConfig =>
    ({
      network: 'preprod',
      materios: {
        rpcWs: 'wss://example',
        genesisHash: '0x00',
        chainId: '00',
        blockTimeSec: 6,
      },
      cardano: {
        network: 'Preprod',
        ogmiosUrl: 'https://o',
        kupoUrl: 'https://k',
        blockfrostProjectId: 'x',
        explorerTxBase: 'https://ex/tx',
        explorerAddrBase: 'https://ex/a',
        metadataLabels: { batchAnchor: 8746, poiAnchor: 2222 },
      },
      aegisValidators: {
        aegisPolicyV1ScriptHash: '__TEAM_B__',
        aegisPolicyV1Address: '__TEAM_B__',
        premiumCollectorScriptHash: '__TEAM_B__',
        premiumCollectorAddress: '__TEAM_B__',
        poolCustodyScriptHash: '__TEAM_B__',
        poolCustodyAddress: '__TEAM_B__',
        deployedInTx: '__TEAM_B__',
      },
      testAccounts: { submitter: { materiosSs58: '5...', comment: '' } },
      committee: { threshold: 2, comment: '' },
      charli3: {
        preprodFeedPolicyId: '__OPEN__',
        preprodFeedAssetName: 'ADAUSD',
        stalenessBoundSlots: 300,
      },
    }) as PreprodConfig;

  it('accepts a well-formed preprod config', () => {
    expect(() => validateConfig(base(), 'preprod')).not.toThrow();
  });

  it('rejects network mismatch', () => {
    const c = base();
    (c as unknown as { network: string }).network = 'mainnet';
    expect(() => validateConfig(c, 'preprod')).toThrow(/network mismatch/);
  });

  it('rejects missing rpcWs', () => {
    const c = base();
    (c.materios as unknown as { rpcWs: string }).rpcWs = '';
    expect(() => validateConfig(c, 'preprod')).toThrow(/rpcWs/);
  });

  it('rejects wrong metadata label', () => {
    const c = base();
    c.cardano.metadataLabels.batchAnchor = 1234;
    expect(() => validateConfig(c, 'preprod')).toThrow(/8746/);
  });

  it('rejects missing Cardano endpoints', () => {
    const c = base();
    c.cardano.ogmiosUrl = '';
    expect(() => validateConfig(c, 'preprod')).toThrow(/ogmiosUrl/);
  });
});

describe('config: validatorsDeployed', () => {
  it('returns false when Team B placeholders still present', () => {
    const cfg = loadConfig('preprod');
    expect(validatorsDeployed(cfg)).toBe(false);
  });

  it('returns true once placeholders replaced', () => {
    const cfg = loadConfig('preprod');
    cfg.aegisValidators.aegisPolicyV1Address = 'addr_test1q_real';
    cfg.aegisValidators.premiumCollectorAddress = 'addr_test1q_real';
    cfg.aegisValidators.poolCustodyAddress = 'addr_test1q_real';
    expect(validatorsDeployed(cfg)).toBe(true);
  });
});
