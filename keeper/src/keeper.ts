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
