/**
 * Cardano tx building + submission glue via mesh-js.
 *
 * This module is intentionally thin: it wraps @meshsdk/core (KupmiosProvider +
 * MeshWallet + MeshTxBuilder) so the keeper logic in ./keeper.ts can stay
 * provider-agnostic, and so tests can inject a fake provider.
 *
 * Network targets (per spec §6.6):
 *   preprod:  wss://ogmios.saturnswap.io + https://kupo.saturnswap.io
 *   mainnet:  same endpoints (Saturnswap runs both)
 *
 * We DO NOT submit any mainnet tx during development — the keeper refuses
 * unless `cardanoNetwork === "mainnet"` AND `enableMainnet === true`.
 */

import type {
  AdaLovelace,
  HexString,
  SlotNumber,
  Voucher,
  BatchFairnessProof,
  ValidityRange,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import {
  assertSinglePointValidityRange,
  buildSinglePointValidityRange,
  feeOutputLovelace,
} from "@fluxpointstudios/materios-intent-settlement-sdk";

export interface CardanoProviderOptions {
  network: "preprod" | "mainnet";
  ogmiosUrl: string;
  kupoUrl: string;
  enableMainnet?: boolean;
}

export interface BuildBatchTxInput {
  voucher: Voucher;
  fairnessProof: BatchFairnessProof;
  keeperAddr: string;
  keeperFeeLovelace: AdaLovelace;
  policyScriptCbor: HexString; // compiled aegis-policy-v1 (Team B output)
  poolUtxoRef: { txHash: HexString; outputIndex: number };
  policyUtxoRefs: Array<{ txHash: HexString; outputIndex: number }>;
  metadataLabel8746Payload: unknown;
  /**
   * Cardano slot captured immediately before tx building. The resulting tx
   * MUST declare `validity_range = [currentSlot, currentSlot]` to satisfy
   * Team B's round-2 strict-equality binding `current_slot ==
   * validity_range.upper_bound`. Construct via
   * `buildSinglePointValidityRange(currentSlot)`.
   *
   * REQUIRED as of issue #16: a missing slot produces a tx with no
   * validity-range binding, which Aiken's strict-equality check rejects
   * silently. Callers MUST capture the tip via `cardano.getCurrentSlot()`
   * immediately before this call. Slot drift between capture and submit
   * is handled by the retry wrapper in `keeper.ts` (issue #17).
   */
  currentSlot: SlotNumber;
  /** Optional pre-built range. If provided, must be `[currentSlot, currentSlot]`. */
  validityRange?: ValidityRange;
}

export interface BuildBatchTxResult {
  unsignedTxCborHex: HexString;
  feeLovelace: AdaLovelace;
}

export interface SubmittedTx {
  txHash: HexString;
  submittedAtSlot: SlotNumber;
}

export interface ICardanoProvider {
  submitTx(txCborHex: HexString): Promise<SubmittedTx>;
  isConfirmed(
    txHash: HexString,
    confirmationDepthSlots: number,
  ): Promise<{ confirmed: boolean; currentSlot: SlotNumber; txSlot: SlotNumber | null }>;
  getCurrentSlot(): Promise<SlotNumber>;
  /** Heartbeat — polls latest block metadata, used by the halt detector. */
  getLatestBlockTimestamp(): Promise<number>;
}

/**
 * Kupmios-backed provider. Thin wrapper around @meshsdk/core's provider.
 * Kept as a factory so tests can swap it out for FakeCardanoProvider without
 * needing mesh-sdk at all.
 */
export async function createMeshCardanoProvider(
  opts: CardanoProviderOptions,
): Promise<ICardanoProvider> {
  if (opts.network === "mainnet" && !opts.enableMainnet) {
    throw new Error(
      "refusing to connect to mainnet without enableMainnet:true (safety flag)",
    );
  }

  // Lazy-import mesh-js so tests that stub the provider don't need mesh-js
  // installed. Mesh exports differ slightly across versions; we adapt.
  const mesh = (await import("@meshsdk/core").catch(() => null)) as any;

  if (!mesh) {
    throw new Error(
      "@meshsdk/core not available at runtime; install it or pass a custom provider",
    );
  }

  const KupmiosProvider = mesh.KupmiosProvider ?? mesh.BlockfrostProvider;
  if (!KupmiosProvider) {
    throw new Error(
      "mesh-js version does not export KupmiosProvider; install @meshsdk/core >=1.8",
    );
  }
  const provider = new KupmiosProvider(opts.kupoUrl, opts.ogmiosUrl);

  async function getCurrentSlot(): Promise<bigint> {
    const tip = await provider.fetchProtocolTip?.();
    if (tip?.slot !== undefined) return BigInt(tip.slot);
    return 0n;
  }

  async function getLatestBlockTimestamp(): Promise<number> {
    const tip = await provider.fetchProtocolTip?.();
    return tip?.time
      ? Math.floor(new Date(tip.time).getTime() / 1000)
      : Math.floor(Date.now() / 1000);
  }

  const impl: ICardanoProvider = {
    async submitTx(txCborHex) {
      const txHash = (await provider.submitTx(txCborHex)) as HexString;
      const slot = await getCurrentSlot();
      return { txHash, submittedAtSlot: slot };
    },
    async isConfirmed(txHash, depth) {
      const current = await getCurrentSlot();
      try {
        const utxos = await provider.fetchUTxOs(txHash);
        if (!utxos || utxos.length === 0) {
          return { confirmed: false, currentSlot: current, txSlot: null };
        }
        const first = utxos[0];
        const txSlot = BigInt(first?.output?.slotNo ?? first?.slot ?? 0);
        const confirmed = current - txSlot >= BigInt(depth);
        return { confirmed, currentSlot: current, txSlot };
      } catch {
        return { confirmed: false, currentSlot: current, txSlot: null };
      }
    },
    getCurrentSlot,
    getLatestBlockTimestamp,
  };
  return impl;
}

/**
 * Build (but do not submit) a Cardano tx for a single voucher. Callers
 * typically chain this with `provider.submitTx`.
 *
 * v1 scope: this is a PLACEHOLDER-READY implementation — the actual script
 * address + Plutus datum construction is filled in once Team B's Aiken
 * artifact is published. Until then, `build()` returns a deterministic fake
 * CBOR so keeper pipelines can exercise the submit/poll/settle logic
 * end-to-end with stubbed providers in integration tests.
 */
export async function buildBatchTx(input: BuildBatchTxInput): Promise<BuildBatchTxResult> {
  // Fee sanity check BEFORE attempting build.
  const totalAwarded = input.fairnessProof.awardedAmountsAda.reduce(
    (a, b) => a + b,
    0n,
  );
  const expected = feeOutputLovelace(totalAwarded);
  if (input.keeperFeeLovelace !== expected) {
    throw new Error(
      `keeper fee ${input.keeperFeeLovelace} != expected ${expected} (spec §5.4)`,
    );
  }

  // Team B round-2: enforce strict-equality validity range
  // `current_slot == validity_range.upper_bound`. The slot is REQUIRED
  // (issue #16) — a missing slot previously produced a tx with no validity
  // range that Aiken silently rejected. Runtime guard catches permissive
  // `as any` / JS callers that bypass the TypeScript requirement.
  if (input.currentSlot === undefined || input.currentSlot === null) {
    throw new Error(
      "buildBatchTx: currentSlot is required (see issue #16); capture via cardano.getCurrentSlot() immediately before calling",
    );
  }
  const range =
    input.validityRange ?? buildSinglePointValidityRange(input.currentSlot);
  const ok = assertSinglePointValidityRange(range, input.currentSlot);
  if (!ok.ok) {
    throw new Error(`validity range check failed: ${ok.reason}`);
  }

  // Placeholder body: deterministic hash of voucher + fairness_proof_digest,
  // so the keeper's orphan-recovery test can compute a stable "txCbor" for
  // fake providers. Real implementation uses MeshTxBuilder.
  const placeholderCbor =
    "0x" +
    input.voucher.claimId.slice(2) +
    input.voucher.batchFairnessProofDigest.slice(2);
  return {
    unsignedTxCborHex: placeholderCbor as HexString,
    feeLovelace: input.keeperFeeLovelace,
  };
}
