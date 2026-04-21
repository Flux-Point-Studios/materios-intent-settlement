/**
 * Types mirroring pallet_intent_settlement + pallet_committee_governance
 * (materios-intent-settlement-spec-v1.md §1).
 *
 * These are TypeScript representations of the canonical SCALE types.
 * Byte-level equivalence is tested via the hashing helpers in ./hashing.ts.
 */

export type HexString = `0x${string}`;

/** 32-byte Blake2b-256 output, hex-encoded with 0x prefix. */
export type IntentId = HexString;
export type PolicyId = HexString;
export type ClaimId = HexString;

export type BlockNumber = number; // u32
export type Nonce = bigint; // u64
export type AdaLovelace = bigint; // u64 (1 ADA = 1_000_000 lovelace)
export type SlotNumber = bigint; // u64
export type MotraBalance = bigint; // u128

/** Raw ed25519 pubkey (32 bytes) and signature (64 bytes), hex. */
export type CommitteePubkey = HexString;
export type CommitteeSig = HexString;

export enum IntentStatus {
  Pending = 0,
  Attested = 1,
  Vouchered = 2,
  Settled = 3,
  Expired = 4,
  Refunded = 5,
}

export enum ExpiryReason {
  TTL = 0,
  VoucherExpired = 1,
}

/** §1.4 — IntentKind discriminated union. Ordinals match SCALE enum. */
export type IntentKind =
  | {
      tag: "BuyPolicy";
      productId: HexString; // H256
      strike: bigint; // u64 (product-defined units, e.g. ADA/USD * 1e6)
      termSlots: number; // u32
      premiumAda: AdaLovelace;
      beneficiaryCardanoAddr: Uint8Array; // bech32 bytes, up to 114
    }
  | {
      tag: "RequestPayout";
      policyId: PolicyId;
      oracleEvidence: Uint8Array; // up to 512 bytes
    }
  | {
      tag: "RefundCredit";
      amountAda: AdaLovelace;
    };

export interface Intent {
  submitter: HexString; // 32-byte SS58 pubkey
  nonce: Nonce;
  kind: IntentKind;
  submittedBlock: BlockNumber;
  ttlBlock: BlockNumber;
  status: IntentStatus;
}

/** §1.6 */
export interface BatchFairnessProof {
  batchBlockRange: [BlockNumber, BlockNumber];
  sortedIntentIds: IntentId[];
  requestedAmountsAda: AdaLovelace[];
  poolBalanceAda: AdaLovelace;
  proRataScaleBps: number; // u32, 10000 = 100%
  awardedAmountsAda: AdaLovelace[];
}

/** §1.7 */
export interface Voucher {
  claimId: ClaimId;
  policyId: PolicyId;
  beneficiaryCardanoAddr: Uint8Array;
  amountAda: AdaLovelace;
  batchFairnessProofDigest: HexString; // 32-byte hex
  issuedBlock: BlockNumber;
  expirySlotCardano: SlotNumber;
  committeeSigs: Array<{ pubkey: CommitteePubkey; sig: CommitteeSig }>;
}

/** §2.4 BatchPayload returned by runtime API. */
export interface BatchPayload {
  intent: Intent;
  intentId: IntentId;
  attestationSigs: Array<{ pubkey: CommitteePubkey; sig: CommitteeSig }>;
}

export interface CommitteeState {
  members: CommitteePubkey[];
  threshold: number;
  lastMirror: {
    committeeSetDigest: HexString;
    cardanoTxHash: HexString;
    mirroredAtBlock: BlockNumber;
  } | null;
}

/** Keeper-side state tracked per voucher (§5.6 idempotency). */
export interface KeeperSubmission {
  claimId: ClaimId;
  cardanoTxHash: HexString | null;
  attempts: number;
  firstSeenBlock: BlockNumber;
  state: "observed" | "submitting" | "submitted" | "confirmed" | "failed" | "expired";
  feeBumpCount: number;
  lastError?: string;
}

/** Config knobs for the keeper. */
export interface KeeperConfig {
  materiosRpcUrl: string;
  cardanoOgmiosUrl: string;
  cardanoKupoUrl: string;
  keeperMnemonic: string;
  network: "preprod" | "mainnet";
  confirmationDepthSlots: number; // k = 2160 default
  feeSpikeMaxAttempts: number; // default 3
  feeSpikeBackoffMs: number; // base backoff
  pollIntervalMs: number; // default 6000 (one block)
  maxBatchSize: number; // default 32
  dryRun: boolean;
}

/** Committee daemon config. */
export interface CommitteeDaemonConfig {
  materiosRpcUrl: string;
  cardanoOgmiosUrl: string;
  sr25519Uri: string; // mnemonic or dev uri like //Alice
  ed25519Uri: string; // separate ed25519 key for Cardano-verifiable voucher sigs (//aegis derivation)
  blobGatewayUrl?: string;
  daemonStatePath: string;
  haltDetectSeconds: number; // 60 per v2 Q5
  haltRecoverBlocks: number; // 3 per v2 Q5
  haltExtensionThresholdSeconds: number; // 86400 (24h) per v2 Q5
  pollIntervalMs: number;
}

/** §4.1 AegisPolicyRedeemer::Claim — direct-path from SDK perspective. */
export interface DirectClaimParams {
  policyId: PolicyId;
  oracleUtxoRef: { txHash: HexString; outputIndex: number };
  cardanoProviderUrl: string;
  beneficiaryAddr: string;
}

export interface DaemonState {
  // Last Materios block we processed. Persisted for crash recovery.
  lastProcessedBlock: BlockNumber;
  cardanoHalt: {
    inHalt: boolean;
    haltStartedAt: number | null; // epoch seconds
    haltCumulativeSeconds: number;
    lastCardanoBlockAt: number | null;
    consecutiveRecoveryBlocks: number;
    extensionPublishedForHaltId?: string;
  };
  attestedIntents: Record<IntentId, { attestedAtBlock: BlockNumber }>;
}
