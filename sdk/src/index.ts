/**
 * @fluxpointstudios/materios-intent-settlement-sdk
 *
 * Client SDK for the Materios intent-settlement layer.
 *
 * @example
 * ```ts
 * import { IntentSettlementClient, IntentStatus } from "@fluxpointstudios/materios-intent-settlement-sdk";
 *
 * const client = new IntentSettlementClient({
 *   materiosRpcUrl: "wss://materios.fluxpointstudios.com/preprod-rpc",
 *   signerUri: process.env.MATERIOS_MNEMONIC,
 * });
 *
 * const { intentId, txHash } = await client.submitIntent({
 *   tag: "BuyPolicy",
 *   productId: "0x" + "00".repeat(32) as `0x${string}`,
 *   strike: 500_000n,
 *   termSlots: 86400,
 *   premiumAda: 1_000_000n,
 *   beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1...")
 * });
 *
 * const snap = await client.pollIntentStatus(intentId, [IntentStatus.Settled, IntentStatus.Expired]);
 * ```
 */

export { IntentSettlementClient } from "./client.js";
export type {
  IntentSettlementClientConfig,
  SubmitIntentResult,
  IntentStatusSnapshot,
} from "./client.js";

export {
  submitIntent,
  submitCreditRefund,
  submitSettleClaim,
  MateriosRpcClient,
} from "./rpc.js";
export type { MateriosRpcClientOptions, SettleClaimArgs } from "./rpc.js";

export {
  intentId,
  intentIdPreimage,
  encodeIntentKind,
  voucherDigestWithAddress,
  fairnessProofDigest,
  validateFairnessProof,
  domainHash,
  domainHashHex,
  DomainTag,
  u64LE,
  u32LE,
  compactCompactLen,
} from "./hashing.js";

export {
  encodeType0AddressCbor,
  splitType0AddressBytes,
} from "./cardano-address.js";
export type { Type0AddressHashes } from "./cardano-address.js";

export {
  buildAegisPolicyParams,
  buildPremiumDepositDatum,
  buildRefundCredit,
  buildRefundDeposit,
  buildSinglePointValidityRange,
  assertSinglePointValidityRange,
  collectMintSignatories,
  canonicalVoucherBody,
} from "./builders.js";
export type { ISignerWallet } from "./builders.js";

export {
  computeKeeperFeeLovelace,
  feeOutputLovelace,
  isEconomic,
  KEEPER_FEE_FLOOR_LOVELACE,
} from "./fees.js";

export {
  IntentStatus,
  ExpiryReason,
} from "./types.js";

export {
  settleClaimPayload,
  creditDepositPayload,
  requestVoucherPayload,
  attestBatchIntentsPayload,
  requestBatchVouchersPayload,
  submitBatchIntentsPayload,
  signPayload,
  buildSigBundle,
  TAG_CRDP,
  TAG_STCL,
  TAG_RVCH,
  TAG_ABIN,
  TAG_RVBN,
  TAG_SBIN,
} from "./multisig.js";

export type {
  HexString,
  IntentId,
  PolicyId,
  ClaimId,
  BlockNumber,
  Nonce,
  AdaLovelace,
  SlotNumber,
  MotraBalance,
  CommitteePubkey,
  CommitteeSig,
  Intent,
  IntentKind,
  Voucher,
  BatchPayload,
  BatchFairnessProof,
  CommitteeState,
  KeeperSubmission,
  KeeperConfig,
  CommitteeDaemonConfig,
  DaemonState,
  DirectClaimParams,
  // Team B merged Aiken schema (round-2 additions)
  ScriptHash,
  AegisPolicyParams,
  PremiumDepositDatum,
  RefundRedeemerFields,
  ValidityRange,
} from "./types.js";
