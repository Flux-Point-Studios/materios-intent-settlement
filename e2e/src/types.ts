/**
 * TypeScript mirrors of the Rust types in spec §1.
 *
 * Scaffolded from spec alone — Team A's SDK (`sdk/` package) will export canonical
 * codecs; this module is purely the Team D view for orchestration assertions.
 * When Team A's SDK lands, this file should re-export from `@materios/sdk`
 * and delete the local structural types.
 */

export type Hex = `0x${string}`;

/** 32-byte Blake2b-256 hash as 0x-prefixed hex. */
export type H256 = Hex;

/** SS58 public key as 0x-prefixed hex (32 bytes). */
export type AccountIdHex = Hex;

/** Spec §1.3: IntentId / PolicyId / ClaimId are all H256 (Blake2b-256 with domain tag). */
export type IntentId = H256;
export type PolicyId = H256;
export type ClaimId = H256;

/** Spec §1.1: domain separation tags. */
export const DOMAIN_TAGS = {
  INTENT: 'INTT',
  POLICY: 'POLY',
  CLAIM: 'CLAM',
  VOUCHER: 'VCHR',
  FAIRNESS: 'BFPR',
  COMMITTEE: 'CMTT',
} as const;

export type DomainTag = (typeof DOMAIN_TAGS)[keyof typeof DOMAIN_TAGS];

/** Spec §1.4: IntentStatus discriminants. */
export enum IntentStatus {
  Pending = 0,
  Attested = 1,
  Vouchered = 2,
  Settled = 3,
  Expired = 4,
  Refunded = 5,
}

export type IntentKind =
  | {
      type: 'BuyPolicy';
      productId: H256;
      strike: bigint;
      termSlots: number;
      premiumAda: bigint;
      beneficiaryCardanoAddr: Uint8Array;
    }
  | {
      type: 'RequestPayout';
      policyId: PolicyId;
      oracleEvidence: Uint8Array;
    }
  | {
      type: 'RefundCredit';
      amountAda: bigint;
    };

export interface Intent {
  submitter: AccountIdHex;
  nonce: bigint;
  kind: IntentKind;
  submittedBlock: number;
  ttlBlock: number;
  status: IntentStatus;
}

/** Spec §1.6. */
export interface BatchFairnessProof {
  batchBlockRange: [number, number];
  sortedIntentIds: IntentId[];
  requestedAmountsAda: bigint[];
  poolBalanceAda: bigint;
  proRataScaleBps: number;
  awardedAmountsAda: bigint[];
}

/** Spec §1.7. */
export interface Voucher {
  claimId: ClaimId;
  policyId: PolicyId;
  beneficiaryCardanoAddr: Uint8Array;
  amountAda: bigint;
  batchFairnessProofDigest: H256;
  issuedBlock: number;
  expirySlotCardano: bigint;
  committeeSigs: Array<{ pubkey: Uint8Array; signature: Uint8Array }>;
}

export interface PreprodConfig {
  network: 'preprod';
  materios: {
    rpcWs: string;
    genesisHash: string;
    chainId: string;
    blockTimeSec: number;
  };
  cardano: {
    network: 'Preprod';
    ogmiosUrl: string;
    kupoUrl: string;
    blockfrostProjectId: string;
    explorerTxBase: string;
    explorerAddrBase: string;
    metadataLabels: { batchAnchor: number; poiAnchor: number };
  };
  aegisValidators: {
    aegisPolicyV1ScriptHash: string;
    aegisPolicyV1Address: string;
    premiumCollectorScriptHash: string;
    premiumCollectorAddress: string;
    poolCustodyScriptHash: string;
    poolCustodyAddress: string;
    deployedInTx: string;
  };
  testAccounts: {
    submitter: { materiosSs58: string; comment: string };
  };
  committee: { threshold: number; comment: string };
  charli3: {
    preprodFeedPolicyId: string;
    preprodFeedAssetName: string;
    stalenessBoundSlots: number;
  };
}
