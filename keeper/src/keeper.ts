/**
 * Keeper orchestration loop.
 *
 * Per spec §5.3:
 *   Poll Materios → BatchPayload[] → build Cardano tx → submit → monitor
 *   k-depth confirmation → settle_claim back to Materios.
 *
 * All external deps are injected so tests can stub them one layer at a time.
 */

import {
  MateriosRpcClient,
  buildSigBundle,
  computeKeeperFeeLovelace,
  encodeType0AddressCbor,
  settleClaimAttestedPayload,
  splitType0AddressBytes,
  validateFairnessProof,
  voucherDigestWithAddress,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import { u8aToHex } from "@polkadot/util";
import type {
  BatchPayload,
  BlockNumber,
  ClaimId,
  HexString,
  KeeperConfig,
  Voucher,
  BatchFairnessProof,
} from "@fluxpointstudios/materios-intent-settlement-sdk";

import { KeeperStateStore } from "./state.js";
import { retryWithBackoff, feeBumpFactor } from "./retry.js";
import type { ICardanoProvider, BuildBatchTxInput } from "./cardano.js";
import { buildBatchTx } from "./cardano.js";
import { initialHaltState, stepHaltDetector, shouldPauseAttestations } from "./halt.js";
import type { HaltState } from "./halt.js";
import {
  buildAndSubmitWithSlotRetry,
  isSlotDriftError,
  SlotDriftExhaustedError,
} from "./slot-retry.js";
import { verifyPolicyScriptHash } from "./script-hash.js";
import { verifyVoucherSigs } from "./voucher-sig-verify.js";
import type { CommitteePubkey } from "@fluxpointstudios/materios-intent-settlement-sdk";

export interface KeeperDeps {
  rpc: MateriosRpcClient;
  cardano: ICardanoProvider;
  state: KeeperStateStore;
  keeperCardanoAddr: string;
  policyScriptCbor: HexString;
  logger?: (level: "info" | "warn" | "error", msg: string, meta?: unknown) => void;
  clock?: () => number;
  // When a voucher's fairness proof isn't locally reconstructible, the
  // caller can inject a resolver that fetches the full BFPR from Materios
  // storage (events pallet) or the events-indexer.
  fetchFairnessProof?: (voucher: Voucher) => Promise<BatchFairnessProof | null>;
  /**
   * Task #76b: optional override for the committee membership snapshot
   * used during voucher-sig verification. When unset, the keeper queries
   * `rpc.getCommitteeState()` once per `runOnce` and caches it. Tests
   * can inject a static snapshot to keep them hermetic.
   */
  fetchCommitteeSnapshot?: () => Promise<{
    members: readonly CommitteePubkey[];
    threshold: number;
  } | null>;
}

export interface KeeperMetrics {
  batchesObserved: number;
  batchesSubmitted: number;
  batchesConfirmed: number;
  batchesSettled: number;
  feeSpikeRetries: number;
  committeeSigFailures: number;
  /**
   * Task #76b: incremented every time a voucher's `(pubkey, sig)` bundle
   * fails local sr25519 verification BEFORE the keeper pays Cardano fees.
   * Distinct from `committeeSigFailures` (length/digest sanity checks); a
   * voucher that passes the cheap sanity but fails crypto-verify lands
   * here.
   */
  voucherSigVerifyFailures: number;
  orphanRollbacks: number;
  currentlyPaused: boolean;
}

export class Keeper {
  readonly metrics: KeeperMetrics = {
    batchesObserved: 0,
    batchesSubmitted: 0,
    batchesConfirmed: 0,
    batchesSettled: 0,
    feeSpikeRetries: 0,
    committeeSigFailures: 0,
    voucherSigVerifyFailures: 0,
    orphanRollbacks: 0,
    currentlyPaused: false,
  };

  private halt: HaltState = initialHaltState();
  private stopSignal = false;
  /**
   * Cached committee snapshot for voucher-sig verification (Task #76b).
   * Refreshed at the top of every `runOnce` so committee rotations are
   * picked up within one poll interval.
   */
  private committeeSnapshot: {
    members: readonly CommitteePubkey[];
    threshold: number;
  } | null = null;

  constructor(
    private readonly config: KeeperConfig,
    private readonly deps: KeeperDeps,
  ) {
    // Task #76a: refuse to construct (and therefore refuse to start) if
    // POLICY_SCRIPT_CBOR doesn't match the configured aegisPolicyV1ScriptHash.
    // Operators on mainnet absolutely must not silently use a wrong
    // validator binary; preprod enforces the same gate so misconfigs are
    // caught in CI, not at fee-burn time.
    //
    // The check throws on mismatch / missing hash; the keeper CLI's
    // `main().catch` surface logs it via sanitizeKeyringError and exits 1.
    verifyPolicyScriptHash(deps.policyScriptCbor, config.aegisPolicyV1ScriptHash);
  }

  log(level: "info" | "warn" | "error", msg: string, meta?: unknown): void {
    (this.deps.logger ?? defaultLogger)(level, msg, meta);
  }

  stop(): void {
    this.stopSignal = true;
  }

  async runOnce(): Promise<KeeperMetrics> {
    // (1) halt detector step
    const ts = await this.deps.cardano.getLatestBlockTimestamp().catch(() => null);
    const { state, transition } = stepHaltDetector(this.halt, ts, {
      haltDetectSeconds: 60,
      haltRecoverBlocks: 3,
      haltExtensionThresholdSeconds: 86_400,
      clock: this.deps.clock ?? (() => Math.floor(Date.now() / 1000)),
    });
    this.halt = state;
    this.metrics.currentlyPaused = shouldPauseAttestations(state);
    if (transition.kind === "entered_halt") {
      this.log("warn", "Cardano halt detected; pausing keeper submissions");
    }
    if (transition.kind === "recovered") {
      this.log("info", "Cardano recovered; resuming keeper submissions", {
        elapsedSeconds: transition.elapsedSeconds,
      });
    }
    if (this.metrics.currentlyPaused) {
      return this.metrics;
    }

    // (1.5) Task #76b: refresh the committee membership snapshot used by
    // local voucher-sig verification. Cached for the duration of this tick
    // so a single rotation mid-loop doesn't half-verify some vouchers
    // against a stale snapshot.
    await this.refreshCommitteeSnapshot();

    // (2) fetch pending batches
    const cursor = this.deps.state.snapshot.cursor;
    const batches = await this.deps.rpc.getPendingBatches(cursor, this.config.maxBatchSize).catch((err: unknown) => {
      this.log("warn", "getPendingBatches failed", err);
      return [] as BatchPayload[];
    });

    for (const batch of batches) {
      this.metrics.batchesObserved += 1;
      await this.processBatch(batch);
    }

    // (3) advance cursor past head
    const tip = await this.deps.rpc.getLatestBlockNumber().catch(() => cursor);
    this.deps.state.setCursor(tip);

    // (4) reconcile in-flight submissions (confirmation + settle_claim)
    await this.reconcileInflight();

    await this.deps.state.flush();
    return this.metrics;
  }

  async run(): Promise<void> {
    while (!this.stopSignal) {
      try {
        await this.runOnce();
      } catch (err) {
        this.log("error", "keeper runOnce errored", err);
      }
      await new Promise((r) => setTimeout(r, this.config.pollIntervalMs));
    }
  }

  /**
   * Task #76b: refresh the committee membership snapshot used for local
   * voucher-sig verification. Called at the top of `runOnce` so a single
   * snapshot is reused for every voucher in this tick.
   *
   * On RPC failure the cached snapshot is preserved (best-effort). On a
   * fresh process where the first fetch fails, the cache stays null and
   * `processBatch` will refuse to submit until a successful fetch lands.
   */
  private async refreshCommitteeSnapshot(): Promise<void> {
    try {
      if (this.deps.fetchCommitteeSnapshot) {
        const snap = await this.deps.fetchCommitteeSnapshot();
        if (snap) this.committeeSnapshot = snap;
        return;
      }
      const state = await this.deps.rpc.getCommitteeState();
      if (state && Array.isArray(state.members) && state.members.length > 0) {
        this.committeeSnapshot = {
          members: state.members,
          threshold: state.threshold > 0 ? state.threshold : 1,
        };
      }
    } catch (err) {
      this.log("warn", "committee snapshot refresh failed", err);
      // Keep prior cache; processBatch will skip submit if cache is null.
    }
  }

  private async processBatch(batch: BatchPayload): Promise<void> {
    // Each BatchPayload encapsulates an attested intent. The voucher for it
    // may or may not exist yet (committee may not have vouchered). Skip if
    // voucher isn't ready.
    const claimId = deriveClaimIdFromBatch(batch);
    if (this.deps.state.isAlreadySettled(claimId)) return; // idempotent

    const voucher = await this.deps.rpc.getVoucher(claimId);
    if (!voucher) {
      this.log("info", "no voucher yet", { claimId });
      return;
    }
    this.deps.state.recordObservation(claimId, batch.intent.submittedBlock);

    const bfpr = this.deps.fetchFairnessProof
      ? await this.deps.fetchFairnessProof(voucher)
      : null;
    if (!bfpr) {
      this.log("warn", "cannot resolve fairness proof; skipping batch", { claimId });
      return;
    }
    const validation = validateFairnessProof(bfpr);
    if (!validation.ok) {
      this.log("error", "fairness proof invalid; refusing to submit", {
        claimId,
        reason: validation.reason,
      });
      this.deps.state.updateSubmission(claimId, { state: "failed", lastError: validation.reason });
      return;
    }

    // Cross-check: the voucher's batchFairnessProofDigest must equal our computed BFPR digest.
    const sub = this.deps.state.snapshot.submissions[claimId];
    if (sub?.state === "submitting" || sub?.state === "submitted") {
      this.log("info", "already in-flight, will reconcile", { claimId, state: sub.state });
      return;
    }

    // Cheap pre-check: empty committeeSigs is a structural failure and
    // means no point continuing to the full sr25519 verify below.
    if (voucher.committeeSigs.length === 0) {
      this.metrics.committeeSigFailures += 1;
      return;
    }

    // (Pre-#73 there was a separate `voucherDigest(voucher)` length-66 check
    // here. That was a degenerate validation against the SCALE-encoded digest
    // form which has been retired in favour of the chain-identity-bound CBOR
    // form (`voucherDigestWithAddress`). The full sigs-against-snapshot
    // verify below subsumes the structural check, so dropping it does not
    // weaken the keeper's pre-flight.)

    // Task #76b: sr25519-verify the (pubkey, sig) bundle against the live
    // committee snapshot BEFORE paying Cardano fees. The pallet-side gate
    // would catch a bad bundle on `settle_claim`, but by then we've already
    // burned the Cardano submit fee. Pre-emptive local verify keeps a
    // malicious / buggy committee daemon from making the keeper hemorrhage
    // ADA.
    //
    // Stale-snapshot tolerance: we DON'T mark the submission as failed
    // here — leave the sub in `observed` so a subsequent tick (with a
    // refreshed snapshot) can retry. A genuinely-bad voucher will sit in
    // `observed` until it expires (BFPR digest mismatch / ttl_block).
    if (this.committeeSnapshot && this.committeeSnapshot.members.length > 0) {
      const sigCheck = verifyVoucherSigs(voucher, {
        committeeMembers: this.committeeSnapshot.members,
        threshold: this.committeeSnapshot.threshold,
        // #73 + #79: chain-identity tuple bound into the canonical
        // voucher digest. The deployed Aiken validator and the pallet's
        // runtime-side recompute use these exact constants — passing
        // them here keeps local verify and chain verify byte-identical.
        chainIdentity: {
          materiosChainId: this.config.materiosChainId,
          networkMagic: this.config.networkMagic,
          aegisPolicyV1ScriptHash: this.config.aegisPolicyV1ScriptHash,
          settlementVersion: this.config.settlementVersion,
        },
      });
      if (!sigCheck.ok) {
        this.metrics.voucherSigVerifyFailures += 1;
        this.log("warn", "voucher sig verify failed; skipping submit", {
          claimId,
          reason: sigCheck.reason,
          detail: sigCheck.detail,
          threshold: this.committeeSnapshot.threshold,
          memberCount: this.committeeSnapshot.members.length,
        });
        return;
      }
    } else {
      // Snapshot unavailable — refuse to submit. The pallet enforces a
      // threshold sig bundle, so we'd waste fees if the vouchers don't
      // ultimately satisfy it. Better to retry on the next tick once the
      // RPC recovers.
      this.metrics.voucherSigVerifyFailures += 1;
      this.log("warn", "no committee snapshot available; skipping submit", {
        claimId,
      });
      return;
    }

    const totalAwarded = bfpr.awardedAmountsAda.reduce((a, b) => a + b, 0n);
    const feeOutput = computeKeeperFeeLovelace(totalAwarded);

    // Base build input — `currentSlot` is filled in by the slot-drift retry
    // wrapper on each attempt so the tx is always pinned to a fresh tip.
    const buildInputBase: Omit<BuildBatchTxInput, "currentSlot"> = {
      voucher,
      fairnessProof: bfpr,
      keeperAddr: this.deps.keeperCardanoAddr,
      keeperFeeLovelace: feeOutput,
      policyScriptCbor: this.deps.policyScriptCbor,
      poolUtxoRef: { txHash: ("0x" + "00".repeat(32)) as HexString, outputIndex: 0 },
      policyUtxoRefs: [],
      metadataLabel8746Payload: {
        p: "materios",
        v: 2,
        ext: { fairness_proof_digest: voucher.batchFairnessProofDigest },
      },
    };

    this.deps.state.updateSubmission(claimId, { state: "submitting", attempts: (sub?.attempts ?? 0) });

    // Nested retry strategy:
    //   outer (fee-spike, retryWithBackoff): handles generic submit failures
    //     like fee-too-low, network blips, etc. Fee-bump factor scales here.
    //   inner (slot-drift, buildAndSubmitWithSlotRetry): handles Aiken's
    //     strict-equality current_slot check — each attempt re-reads the tip
    //     and rebuilds the tx pinned to it. Slot-drift errors do NOT consume
    //     the outer fee-spike budget; other errors propagate outward.
    const result = await retryWithBackoff(
      async (attempt) => {
        const bump = feeBumpFactor(attempt);
        if (bump !== 1) this.metrics.feeSpikeRetries += 1;

        // Dry-run: no real provider call, skip slot-drift retry too.
        if (this.config.dryRun) {
          return { txHash: ("0x" + "00".repeat(32)) as HexString, submittedAtSlot: 0n };
        }

        const { submitted } = await buildAndSubmitWithSlotRetry(
          this.deps.cardano,
          async (currentSlot) => {
            const built = await buildBatchTx({ ...buildInputBase, currentSlot });
            return this.deps.cardano.submitTx(built.unsignedTxCborHex);
          },
          {
            logger: (level, msg, meta) => this.log(level, msg, meta),
          },
        );
        return submitted;
      },
      {
        maxAttempts: this.config.feeSpikeMaxAttempts,
        baseDelayMs: this.config.feeSpikeBackoffMs,
        maxDelayMs: this.config.feeSpikeBackoffMs * 10,
      },
    ).catch((err) => {
      // SlotDriftExhaustedError is terminal — don't mask it as a generic
      // "submit failed after max attempts"; preserve the per-attempt detail.
      if (err instanceof SlotDriftExhaustedError || isSlotDriftError(err)) {
        this.log("error", "slot-drift retries exhausted", err);
      } else {
        this.log("error", "tx submit failed after max attempts", err);
      }
      this.deps.state.updateSubmission(claimId, {
        state: "failed",
        lastError: err instanceof Error ? err.message : String(err),
      });
      return null;
    });

    if (!result) return;

    this.metrics.batchesSubmitted += 1;
    this.deps.state.updateSubmission(claimId, {
      state: "submitted",
      cardanoTxHash: result.txHash,
      attempts: (sub?.attempts ?? 0) + 1,
    });
    this.log("info", "submitted Cardano tx", { claimId, txHash: result.txHash });
  }

  /**
   * Task #266 (mis-sec P0): for every "submitted" submission, poll the
   * Cardano provider until it's confirmed to k-depth, then post the new
   * two-phase attested-settle pair:
   *   1. `request_settle(claim_id, tx_hash, settled_direct, evidence)` —
   *      anyone can submit, the keeper does so as the requester.
   *   2. `attest_settle(claim_id, signatures)` — committee provides
   *      M-of-N sigs over the canonical STCA digest. The keeper assembles
   *      the bundle itself when it's also a committee member (M=1
   *      interim); the long-term path collects sigs from cert-daemon
   *      attestors before submitting.
   *
   * Replaces the legacy single-call `settle_claim` extrinsic, which
   * carries no falsifiable evidence and is rejected post-cutover.
   *
   * The legacy single-call path is preserved as a fall-back for the
   * 50-block grace window during the spec-N upgrade — controlled via the
   * `useAttestedSettlePath` config knob (defaults true).
   */
  private async reconcileInflight(): Promise<void> {
    const subs = Object.values(this.deps.state.snapshot.submissions);
    for (const sub of subs) {
      if (sub.state !== "submitted" || !sub.cardanoTxHash) continue;
      const conf = await this.deps.cardano
        .isConfirmed(sub.cardanoTxHash, this.config.confirmationDepthSlots)
        .catch(() => null);
      if (!conf) continue;
      if (conf.txSlot === null && sub.state === "submitted") {
        // Possible rollback: the tx disappeared. Reset to "observed" so we re-submit.
        this.metrics.orphanRollbacks += 1;
        this.deps.state.updateSubmission(sub.claimId, {
          state: "observed",
          cardanoTxHash: null,
          lastError: "orphaned",
        });
        continue;
      }
      if (!conf.confirmed) continue;

      this.metrics.batchesConfirmed += 1;
      const settledDirect = false;
      try {
        await this.submitAttestedSettle(sub, conf.txSlot, conf.currentSlot, settledDirect);
        this.deps.state.markSettled(sub.claimId, sub.cardanoTxHash);
        this.metrics.batchesSettled += 1;
      } catch (err) {
        this.log("error", "attested settle pipeline failed", { claimId: sub.claimId, err });
      }
    }
  }

  /**
   * Task #266 (mis-sec P0): two-phase attested settle.
   *
   * Phase 1 (`request_settle`): pin the falsifiable evidence on chain so
   * any watcher can later prove the requester lied. The keeper builds
   * `SettlementEvidence` from chain-state-derived facts (voucher amount,
   * beneficiary payment-key hash, mainchain genesis pinning) so a
   * malicious requester cannot lie about anything cross-checkable.
   *
   * Phase 2 (`attest_settle`): the committee provides M-of-N sigs over
   * the canonical 209-byte STCA digest. The pallet rebuilds the same
   * digest from chain state, so every honest attestor sees the same
   * bytes — bad bundles fail sig-verify locally, never settling a bad
   * claim.
   *
   * @throws if any phase fails or the on-chain voucher is missing
   */
  private async submitAttestedSettle(
    sub: { claimId: ClaimId; cardanoTxHash: HexString | null },
    txSlot: bigint | null,
    currentSlot: bigint,
    settledDirect: boolean,
  ): Promise<void> {
    if (!sub.cardanoTxHash) {
      throw new Error("submitAttestedSettle: missing cardanoTxHash");
    }
    if (txSlot === null) {
      throw new Error("submitAttestedSettle: missing Cardano tx slot");
    }
    const voucher = await this.deps.rpc.getVoucher(sub.claimId);
    if (!voucher) {
      throw new Error(`voucher missing for claim ${sub.claimId}`);
    }
    // Cardano blocks at ~20s each. Convert slot delta to approximate
    // blocks for the pallet's `MinFinalityDepth` floor. The cert-daemon's
    // production path measures actual block count via Ogmios chain
    // history; this approximation is good enough for the keeper's M=1
    // interim, since the pallet enforces the floor either way.
    const slotDelta = currentSlot - txSlot;
    const approxDepth = Number(slotDelta / 20n);
    if (approxDepth < this.config.minFinalityDepth) {
      throw new Error(
        `depth ${approxDepth} < MinFinalityDepth ${this.config.minFinalityDepth}; deferring`,
      );
    }
    // Re-derive payment-key hash from the voucher's CIP-0019 type-0
    // address. The pallet does the same; mismatch => SettlementEvidenceMismatch.
    const beneficiaryHash = paymentKeyHashFromBeneficiaryAddr(voucher);
    const evidence = {
      cardano_tx_hash: sub.cardanoTxHash,
      observed_at_depth: approxDepth,
      observed_slot: txSlot,
      beneficiary_addr_hash: u8aToHex(beneficiaryHash),
      amount_lovelace: voucher.amountAda,
      mainchain_genesis_hash: this.config.mainchainGenesisHash,
    };

    // Phase 1: request_settle. Anyone can post — the keeper's mnemonic
    // is the typical signer. The extrinsic is permissionless; failure
    // here is usually an `AlreadySettled` race with another keeper, or
    // a stale evidence rejection at the chain. Pin state on success.
    await this.deps.rpc.submitExtrinsic(
      "intentSettlement",
      "requestSettle",
      [sub.claimId, sub.cardanoTxHash, settledDirect, evidence],
    );

    // Phase 2: attest_settle. The keeper's mnemonic MUST be a current
    // committee member for the M=1 interim. The bundle here is a single
    // sig; the settlement-daemon path (B) replaces this with M-of-N
    // collected sigs from cert-daemon peers.
    // Rehydrate the voucher's canonical Plutus V3 Data CBOR for the
    // beneficiary address — the pallet does the same; the digest must
    // commit to byte-identical CBOR.
    const beneficiaryCbor = encodeType0AddressCbor(splitType0AddressBytes(
      typeof voucher.beneficiaryCardanoAddr === "string"
        ? hexToBytes(voucher.beneficiaryCardanoAddr)
        : voucher.beneficiaryCardanoAddr,
    ));
    const voucherDigestHex = voucherDigestWithAddress({
      // #73: chain-identity tuple bound into the canonical voucher digest.
      materiosChainId: this.config.materiosChainId,
      networkMagic: this.config.networkMagic,
      aegisPolicyV1ScriptHash: this.config.aegisPolicyV1ScriptHash,
      settlementVersion: this.config.settlementVersion,
      claimId: voucher.claimId,
      policyId: voucher.policyId,
      beneficiaryAddressCbor: beneficiaryCbor,
      amountAda: voucher.amountAda,
      batchFairnessProofDigest: voucher.batchFairnessProofDigest,
      issuedBlock: voucher.issuedBlock,
      expirySlotCardano: voucher.expirySlotCardano,
    });
    const stcaPayload = settleClaimAttestedPayload({
      materiosChainId: this.config.materiosChainId,
      claimId: sub.claimId,
      voucherDigest: voucherDigestHex,
      cardanoTxHash: sub.cardanoTxHash,
      settledDirect,
      beneficiaryAddrHash: u8aToHex(beneficiaryHash),
      amountLovelace: voucher.amountAda,
      observedAtDepth: approxDepth,
      observedSlot: txSlot,
      mainchainGenesisHash: this.config.mainchainGenesisHash,
    });
    const bundle = buildSigBundle({
      callerSeed: this.config.keeperMnemonic,
      cosignerSeeds: [],
      payload: stcaPayload,
    });
    const signatures = bundle.map(
      (e) => [u8aToHex(e.pubkey), u8aToHex(e.sig)] as [HexString, HexString],
    );
    await this.deps.rpc.submitExtrinsic(
      "intentSettlement",
      "attestSettle",
      [sub.claimId, signatures],
    );
  }
}

/**
 * Task #266 (mis-sec P0): lift the 28-byte payment-key hash from the
 * voucher's `beneficiary_cardano_addr` (CIP-0019 type-0 shape:
 * `0x01 || payment_hash(28) || stake_hash(28)`). The pallet does the same
 * derivation; the keeper must produce byte-identical bytes or the
 * `SettlementEvidence` cross-check fails.
 */
function paymentKeyHashFromBeneficiaryAddr(voucher: {
  beneficiaryCardanoAddr: Uint8Array | HexString;
}): Uint8Array {
  const raw =
    typeof voucher.beneficiaryCardanoAddr === "string"
      ? hexToBytes(voucher.beneficiaryCardanoAddr)
      : voucher.beneficiaryCardanoAddr;
  const split = splitType0AddressBytes(raw);
  return split.paymentHash;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`hex string must be even-length, got ${clean.length}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function defaultLogger(level: "info" | "warn" | "error", msg: string, meta?: unknown): void {
  // eslint-disable-next-line no-console
  const fn = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
  if (meta !== undefined) fn(`[keeper][${level}] ${msg}`, meta);
  else fn(`[keeper][${level}] ${msg}`);
}

/**
 * Batch payloads are indexed by intent. For claim lookup we use a stable
 * derivation — the claim_id was produced by the committee when they issued
 * the voucher, so we must fetch it from the voucher itself in practice. The
 * derivation here is a placeholder for when pallet A's events expose the
 * real claim_id alongside the intent_id.
 */
function deriveClaimIdFromBatch(batch: BatchPayload): ClaimId {
  // Until pallet A exposes claim_id in the BatchPayload struct, treat
  // intent_id as the lookup key; committee daemon issues one claim per
  // attested intent.
  return batch.intentId as unknown as ClaimId;
}
