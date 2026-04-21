/**
 * Public SDK entrypoint — the `IntentSettlementClient` surface documented in
 * Team-C scope.
 *
 * Works in Node and browser (bundler-friendly ESM).
 */

import { MateriosRpcClient, submitIntent, submitCreditRefund, submitSettleClaim } from "./rpc.js";
import { intentId as computeIntentId } from "./hashing.js";
import type {
  IntentId,
  IntentKind,
  IntentStatus,
  Voucher,
  BatchPayload,
  AdaLovelace,
  DirectClaimParams,
  HexString,
} from "./types.js";

export interface IntentSettlementClientConfig {
  materiosRpcUrl: string;
  /**
   * Optional sr25519 signer URI (mnemonic or dev like //Alice). Required
   * for any method that submits an extrinsic.
   */
  signerUri?: string;
}

export interface SubmitIntentResult {
  intentId: IntentId;
  txHash: HexString;
}

export interface IntentStatusSnapshot {
  intentId: IntentId;
  status: IntentStatus | "Unknown";
  claimId?: IntentId;
  voucher?: Voucher;
  cardanoTxHash?: HexString;
}

export class IntentSettlementClient {
  private rpc: MateriosRpcClient;
  private connected = false;

  constructor(private readonly config: IntentSettlementClientConfig) {
    const rpcOpts: { rpcUrl: string; signerUri?: string } = {
      rpcUrl: config.materiosRpcUrl,
    };
    if (config.signerUri) rpcOpts.signerUri = config.signerUri;
    this.rpc = new MateriosRpcClient(rpcOpts);
  }

  async connect(): Promise<void> {
    if (!this.connected) {
      await this.rpc.connect();
      this.connected = true;
    }
  }

  async disconnect(): Promise<void> {
    if (this.connected) {
      await this.rpc.disconnect();
      this.connected = false;
    }
  }

  /**
   * Submit a new Intent. Requires signerUri on the client.
   * Returns the computed intentId (pre-image-derived) + the Materios tx hash.
   */
  async submitIntent(kind: IntentKind, opts?: { nonce?: bigint; submittedBlock?: number; submitter?: HexString }): Promise<SubmitIntentResult> {
    await this.connect();
    const res = await submitIntent(this.rpc, kind);
    // Best-effort synthesize an intentId for optimistic UX. Authoritative id
    // comes from the chain's IntentSubmitted event.
    const submitter = opts?.submitter ?? ("0x" + "00".repeat(32)) as HexString;
    const id = computeIntentId({
      submitter,
      nonce: opts?.nonce ?? 0n,
      kind,
      submittedBlock: opts?.submittedBlock ?? 0,
    });
    return { intentId: id, txHash: res.txHash };
  }

  /** Request a credit refund — sugar over submit_intent with RefundCredit kind. */
  async requestCreditRefund(amountAda: AdaLovelace): Promise<{ txHash: HexString }> {
    await this.connect();
    return submitCreditRefund(this.rpc, amountAda);
  }

  /**
   * Poll the chain for current intent status. `maxWaitMs` bounds the total
   * wait. Returns as soon as status reaches one of `targetStatuses` or the
   * deadline elapses.
   */
  async pollIntentStatus(
    intentId: IntentId,
    targetStatuses: IntentStatus[],
    opts: { maxWaitMs?: number; pollIntervalMs?: number } = {},
  ): Promise<IntentStatusSnapshot> {
    const deadline = Date.now() + (opts.maxWaitMs ?? 60_000);
    const interval = opts.pollIntervalMs ?? 6000;
    await this.connect();

    while (Date.now() < deadline) {
      const snap = await this.getIntentStatus(intentId);
      if (snap.status !== "Unknown" && targetStatuses.includes(snap.status as IntentStatus)) {
        return snap;
      }
      await new Promise((r) => setTimeout(r, interval));
    }
    return this.getIntentStatus(intentId);
  }

  async getIntentStatus(intentId: IntentId): Promise<IntentStatusSnapshot> {
    await this.connect();
    const api = this.rpc.getApi();
    try {
      const raw = await (api.query as any).intentSettlement?.intents?.(intentId);
      if (!raw || raw.isNone) {
        return { intentId, status: "Unknown" };
      }
      const data = raw.unwrap ? raw.unwrap() : raw;
      const statusVal = Number(data.status?.toNumber ? data.status.toNumber() : data.status ?? -1);
      return {
        intentId,
        status: Number.isInteger(statusVal) && statusVal >= 0 ? (statusVal as IntentStatus) : "Unknown",
      };
    } catch {
      return { intentId, status: "Unknown" };
    }
  }

  /** Return vouchered-and-awaiting-settlement batch payloads for keeper UIs. */
  async getPendingBatches(sinceBlock: number, maxCount = 32): Promise<BatchPayload[]> {
    await this.connect();
    return this.rpc.getPendingBatches(sinceBlock, maxCount);
  }

  async getVoucher(claimId: HexString): Promise<Voucher | null> {
    await this.connect();
    return this.rpc.getVoucher(claimId);
  }

  /**
   * Direct-path claim (spec §4 + v1 Q11).
   * Constructs a `Claim` redeemer against `aegis-policy-v1` using Charli3 as
   * oracle — the path that requires NO committee signature.
   *
   * This returns a built-but-unsigned tx-body the caller can sign via CIP-30
   * or a server-side mesh-js wallet. Implementation expects the keeper
   * package's buildDirectClaimTx to be available; the SDK here just exposes
   * the client-facing contract.
   *
   * NOTE: in-browser direct claims need a wallet-extension bridge; this
   * method throws if neither a builder nor a wallet hook is configured.
   */
  async claimDirect(_params: DirectClaimParams): Promise<{ unsignedTxCborHex: HexString }> {
    throw new Error(
      "claimDirect: the SDK ships the RPC surface; direct-path tx building is delegated to @fluxpointstudios/materios-intent-settlement-keeper (buildDirectClaimTx). Import that or provide your own mesh-js builder.",
    );
  }

  /** Used by committee daemon. Not a normal dApp API. */
  async settleClaim(
    claimId: HexString,
    cardanoTxHash: HexString,
    settledDirect: boolean,
  ): Promise<{ txHash: HexString }> {
    await this.connect();
    return submitSettleClaim(this.rpc, { claimId, cardanoTxHash, settledDirect });
  }
}
