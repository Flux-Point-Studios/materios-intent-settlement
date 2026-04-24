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
  settleClaimPayload,
  validateFairnessProof,
  voucherDigest,
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
}

export interface KeeperMetrics {
  batchesObserved: number;
  batchesSubmitted: number;
  batchesConfirmed: number;
  batchesSettled: number;
  feeSpikeRetries: number;
  committeeSigFailures: number;
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
    orphanRollbacks: 0,
    currentlyPaused: false,
  };

  private halt: HaltState = initialHaltState();
  private stopSignal = false;

  constructor(
    private readonly config: KeeperConfig,
    private readonly deps: KeeperDeps,
  ) {}

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

    // Sanity: recompute voucher digest and make sure it matches what committee signed.
    // Any committee sig failure here is a hard stop — don't waste tx fees.
    if (voucher.committeeSigs.length === 0) {
      this.metrics.committeeSigFailures += 1;
      return;
    }
    const digest = voucherDigest(voucher);
    if (!digest || digest.length !== 66) {
      this.metrics.committeeSigFailures += 1;
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
   * For every "submitted" submission, poll the Cardano provider until it's
   * confirmed to k-depth, then call `settle_claim` on Materios.
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
      // Settle on Materios. Idempotent per §2.2 #5.
      //
      // Wave 2 W2.1 (Option C interim): pallet's settle_claim now requires an
      // M-of-N committee sig bundle (issue #7, PR #23). Keeper ships as M=1 —
      // signs with its own KEEPER_MNEMONIC which MUST be a current committee
      // member. Settlement-daemon (B) that collects sigs from multiple
      // committee peers is a follow-up once the pallet is live on a runtime.
      const settledDirect = false;
      const payload = settleClaimPayload({
        claimId: sub.claimId,
        cardanoTxHash: sub.cardanoTxHash,
        settledDirect,
      });
      const bundle = buildSigBundle({
        callerSeed: this.config.keeperMnemonic,
        cosignerSeeds: [],
        payload,
      });
      const signatures = bundle.map(
        (e) => [u8aToHex(e.pubkey), u8aToHex(e.sig)] as [HexString, HexString],
      );
      try {
        await this.deps.rpc.submitExtrinsic("intentSettlement", "settleClaim", [
          sub.claimId,
          sub.cardanoTxHash,
          settledDirect,
          signatures,
        ]);
        this.deps.state.markSettled(sub.claimId, sub.cardanoTxHash);
        this.metrics.batchesSettled += 1;
      } catch (err) {
        this.log("error", "settle_claim extrinsic failed", { claimId: sub.claimId, err });
      }
    }
  }
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
