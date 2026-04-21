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
  /**
   * Team B round-2 addition: the deployed `aegis_policy_v1` script hash
   * (post `aiken blueprint apply`). Nullable until the blueprint lands on
   * preprod / mainnet; when set, the keeper stamps it into every
   * AegisPolicyParams it builds and rejects tx submission if the
   * subsidiary scripts were compiled with a different hash.
   */
  aegisPolicyV1ScriptHash?: HexString | null;
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

// ---------------------------------------------------------------------------
// Team B merged Aiken schema (aegis-policy-v1 on aegis-parametric-insurance-dev main).
// These types mirror `validators/aegis-policy-v1/lib/aegis/types.ak`.
// ---------------------------------------------------------------------------

/**
 * Cardano script hash (Blake2b-224), 28 bytes hex-encoded. Written as a
 * `HexString` to keep compile-time homogeneity with other hashes; callers
 * should ensure the payload is 56 hex chars (28 bytes).
 */
export type ScriptHash = HexString;

/**
 * Compile-time parameters baked into `aegis_policy_v1`. Mirrors Aiken's
 * `AegisPolicyParams`. The `aegisPolicyV1ScriptHash` field is the new B-4/B-5
 * /B-7 fix added in Team B round 2 and MUST be set before deploy; pre-blueprint
 * it's nullable so tests and stub harnesses compile.
 */
export interface AegisPolicyParams {
  committeePubkeySet: HexString[]; // list of 32-byte ed25519 pubkeys
  committeeThreshold: number;
  minFairnessProofSigCount: number;
  charli3OracleRef: { txHash: HexString; outputIndex: number };
  charli3FeedPolicyId: HexString;
  charli3FeedAssetName: HexString;
  materiosChainId: HexString; // 32-byte genesis hash
  poolCustodyScriptHash: ScriptHash;
  premiumCollectorScriptHash: ScriptHash;
  /**
   * B-4/B-5/B-7 fix: the deployed `aegis_policy_v1` script hash, used by
   * subsidiary validators to bind tx-level authorization. Nullable until
   * `aiken blueprint apply` produces the real hash.
   */
  aegisPolicyV1ScriptHash: ScriptHash | null;
  settlementVersion: number;
  oracleFreshnessSlots: number;
}

/**
 * Datum on the premium-collector UTxO (§4.2). The `depositorCardanoAddr` and
 * `amountAda` fields are the B-8 fix added in Team B round 2 — refunds MUST
 * return to the address that funded the deposit, and the validator checks
 * `amount_ada <= datum.amount_ada`.
 *
 * `depositorCardanoAddr` is the raw 57-byte CIP-0019 type-0 address buffer
 * (header || payment_hash || stake_hash); the validator CBOR-encodes it for
 * voucher-pre-image binding.
 */
export interface PremiumDepositDatum {
  depositorMateriosAccount: HexString; // 32-byte SS58 pubkey
  /**
   * B-8 fix: the Cardano address that funded the deposit. Raw 57-byte
   * CIP-0019 type-0 address buffer. Refund flows pin this as the
   * authorizative destination.
   */
  depositorCardanoAddr: Uint8Array;
  depositedAtSlot: bigint;
  depositId: HexString; // blake2b_256(tx_hash || output_index)
  /**
   * B-8 fix: amount (lovelace) this deposit UTxO is denominated at. Enables
   * `amount_ada <= datum.amount_ada` enforcement on refund paths.
   */
  amountAda: AdaLovelace;
  productId: HexString;
}

/**
 * Common explicit fields shared by both `RefundCredit` (aegis-policy-v1) and
 * `RefundDeposit` (premium-collector) redeemers. Mirrors the B-8 fix that
 * adds `beneficiary_bytes` + `policy_id` to the explicit fields.
 */
export interface RefundRedeemerFields {
  /** SCALE-encoded voucher bytes (opaque to Aiken). */
  voucherBytes: Uint8Array;
  /** List of (pubkey, sig) committee signatures over the voucher digest. */
  sigs: Array<{ pubkey: CommitteePubkey; sig: CommitteeSig }>;
  amountAda: AdaLovelace;
  /** Raw 57-byte CIP-0019 type-0 beneficiary address. */
  beneficiary: Uint8Array;
  /**
   * B-8 fix: Plutus V3 Data CBOR of `beneficiary` — MUST equal
   * `encodeType0AddressCbor(splitType0AddressBytes(beneficiary))`. The Aiken
   * validator reconstructs the voucher body from this field.
   */
  beneficiaryBytes: Uint8Array;
  /** B-8 fix: policy_id bound into the voucher pre-image. */
  policyId: PolicyId;
  issuedBlock: BlockNumber;
  expirySlotCardano: SlotNumber;
  claimId: ClaimId;
  bfpDigest: HexString;
  currentSlot: SlotNumber;
}

/**
 * A Cardano slot range. When used with the strict-equality binding
 * (Team B round-2 addition), `lower === upper === currentSlot` — see
 * `buildSinglePointValidityRange`.
 */
export interface ValidityRange {
  lowerBound: SlotNumber;
  upperBound: SlotNumber;
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
