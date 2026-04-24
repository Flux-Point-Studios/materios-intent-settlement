/**
 * Thin wrapper around @polkadot/api so keeper + committee daemon + SDK share
 * one connection lifecycle. Kept small and mockable for unit tests.
 */

import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import type { KeyringPair } from "@polkadot/keyring/types";
import type {
  BatchPayload,
  CommitteeState,
  Voucher,
  IntentId,
  ClaimId,
  HexString,
  Intent,
  IntentKind,
  AdaLovelace,
  BlockNumber,
} from "./types.js";

export interface MateriosRpcClientOptions {
  rpcUrl: string;
  signerUri?: string; // optional; only needed for signed extrinsics
}

export class MateriosRpcClient {
  private api?: ApiPromise;
  private signer?: KeyringPair;
  private readonly rpcUrl: string;
  private readonly signerUri?: string;
  private provider?: WsProvider;

  constructor(opts: MateriosRpcClientOptions) {
    this.rpcUrl = opts.rpcUrl;
    this.signerUri = opts.signerUri;
  }

  async connect(): Promise<void> {
    if (this.api?.isConnected) return;
    this.provider = new WsProvider(this.rpcUrl, false);
    await this.provider.connect();
    this.api = await ApiPromise.create({ provider: this.provider, throwOnConnect: true });
    if (this.signerUri) {
      const keyring = new Keyring({ type: "sr25519" });
      try {
        this.signer = keyring.addFromUri(this.signerUri);
      } catch (err: unknown) {
        // @polkadot/keyring throws Error messages that may echo the offending
        // suri fragment. Never let the raw error propagate — callers that
        // log err.message or err would otherwise leak a mnemonic. Throw a
        // scrubbed error with a stable tag so CLIs can surface a safe reason.
        const name = err instanceof Error ? err.name || "Error" : "Error";
        throw new Error(`Invalid signerUri (${name}) — raw keyring error suppressed`);
      }
    }
  }

  async disconnect(): Promise<void> {
    if (this.api?.isConnected) await this.api.disconnect();
    this.api = undefined;
    this.provider = undefined;
  }

  getApi(): ApiPromise {
    if (!this.api) throw new Error("MateriosRpcClient not connected");
    return this.api;
  }

  getSigner(): KeyringPair {
    if (!this.signer) throw new Error("no signer configured");
    return this.signer;
  }

  /**
   * §2.4 runtime-API call. Team A will expose this as a state_call. Until
   * that pallet PR lands, the keeper can stub this via an injected
   * {@link MateriosRpcClient['getPendingBatchesFn']} override in tests.
   */
  async getPendingBatches(sinceBlock: BlockNumber, maxCount: number): Promise<BatchPayload[]> {
    const api = this.getApi();
    if ((api.call as any).intentSettlementRuntimeApi?.getPendingBatches) {
      const res = await (api.call as any).intentSettlementRuntimeApi.getPendingBatches(
        sinceBlock,
        maxCount,
      );
      return this.decodeBatchPayloads(res);
    }
    // Graceful degradation: pallet not yet deployed.
    return [];
  }

  async getCommitteeState(): Promise<CommitteeState> {
    const api = this.getApi();
    if ((api.call as any).intentSettlementRuntimeApi?.getCommitteeState) {
      const res = await (api.call as any).intentSettlementRuntimeApi.getCommitteeState();
      return this.decodeCommitteeState(res);
    }
    return { members: [], threshold: 0, lastMirror: null };
  }

  async getVoucher(claimId: ClaimId): Promise<Voucher | null> {
    const api = this.getApi();
    if ((api.call as any).intentSettlementRuntimeApi?.getVoucher) {
      const res = await (api.call as any).intentSettlementRuntimeApi.getVoucher(claimId);
      return this.decodeVoucher(res);
    }
    return null;
  }

  async submitExtrinsic(
    section: string,
    method: string,
    args: unknown[],
  ): Promise<{ txHash: HexString; blockHash: HexString | null }> {
    const api = this.getApi();
    const signer = this.getSigner();
    const ext = (api.tx as any)[section][method](...args);
    return new Promise((resolve, reject) => {
      let unsub: (() => void) | null = null;
      ext
        .signAndSend(signer, (result: any) => {
          if (result.status.isInBlock) {
            const blockHash = result.status.asInBlock.toHex() as HexString;
            const txHash = ext.hash.toHex() as HexString;
            unsub?.();
            resolve({ txHash, blockHash });
          } else if (result.isError) {
            unsub?.();
            reject(new Error(`extrinsic ${section}.${method} errored`));
          }
        })
        .then((u: () => void) => {
          unsub = u;
        })
        .catch(reject);
    });
  }

  /** Dry-run a call for fee estimation and syntactic validation. */
  async paymentInfo(
    section: string,
    method: string,
    args: unknown[],
  ): Promise<{ partialFee: bigint; weightRefTime: bigint }> {
    const api = this.getApi();
    const signer = this.getSigner();
    const ext = (api.tx as any)[section][method](...args);
    const info = await ext.paymentInfo(signer);
    return {
      partialFee: BigInt(info.partialFee.toString()),
      weightRefTime: BigInt(info.weight.refTime.toString()),
    };
  }

  // -- decoders (hand-rolled; tolerant of shape drift while Team A's PR is in-flight)

  private decodeBatchPayloads(raw: unknown): BatchPayload[] {
    if (!raw) return [];
    const anyRaw = raw as any;
    const list = typeof anyRaw.toJSON === "function" ? anyRaw.toJSON() : anyRaw;
    if (!Array.isArray(list)) return [];
    return list.map((item: any) => ({
      intent: this.decodeIntent(item.intent),
      intentId: item.intentId as HexString,
      attestationSigs: (item.attestationSigs ?? []).map((p: any) => ({
        pubkey: p.pubkey as HexString,
        sig: p.sig as HexString,
      })),
    }));
  }

  private decodeIntent(raw: any): Intent {
    return {
      submitter: raw.submitter as HexString,
      nonce: BigInt(raw.nonce ?? 0),
      kind: raw.kind as IntentKind,
      submittedBlock: Number(raw.submittedBlock ?? 0),
      ttlBlock: Number(raw.ttlBlock ?? 0),
      status: raw.status,
    };
  }

  private decodeVoucher(raw: any): Voucher | null {
    if (!raw || raw.isNone) return null;
    const v = raw.unwrap ? raw.unwrap() : raw;
    return {
      claimId: v.claimId as HexString,
      policyId: v.policyId as HexString,
      beneficiaryCardanoAddr: new Uint8Array(v.beneficiaryCardanoAddr ?? []),
      amountAda: BigInt(v.amountAda ?? 0),
      batchFairnessProofDigest: v.batchFairnessProofDigest as HexString,
      issuedBlock: Number(v.issuedBlock ?? 0),
      expirySlotCardano: BigInt(v.expirySlotCardano ?? 0),
      committeeSigs: (v.committeeSigs ?? []).map((p: any) => ({
        pubkey: p.pubkey as HexString,
        sig: p.sig as HexString,
      })),
    };
  }

  private decodeCommitteeState(raw: any): CommitteeState {
    return {
      members: raw.members ?? [],
      threshold: Number(raw.threshold ?? 0),
      lastMirror: raw.lastMirror
        ? {
            committeeSetDigest: raw.lastMirror.committeeSetDigest,
            cardanoTxHash: raw.lastMirror.cardanoTxHash,
            mirroredAtBlock: Number(raw.lastMirror.mirroredAtBlock),
          }
        : null,
    };
  }

  /** Current finalized block number, used as keeper cursor. */
  async getLatestBlockNumber(): Promise<BlockNumber> {
    const api = this.getApi();
    const header = await api.rpc.chain.getHeader();
    return Number(header.number.toBigInt());
  }
}

export interface SettleClaimArgs {
  claimId: ClaimId;
  cardanoTxHash: HexString;
  settledDirect: boolean;
}

export async function submitSettleClaim(
  client: MateriosRpcClient,
  args: SettleClaimArgs,
): Promise<{ txHash: HexString }> {
  const res = await client.submitExtrinsic("intentSettlement", "settleClaim", [
    args.claimId,
    args.cardanoTxHash,
    args.settledDirect,
  ]);
  return { txHash: res.txHash };
}

export async function submitIntent(
  client: MateriosRpcClient,
  kind: IntentKind,
): Promise<{ txHash: HexString }> {
  const res = await client.submitExtrinsic("intentSettlement", "submitIntent", [kind]);
  return { txHash: res.txHash };
}

export async function submitCreditRefund(
  client: MateriosRpcClient,
  amount: AdaLovelace,
): Promise<{ txHash: HexString }> {
  const res = await client.submitExtrinsic("intentSettlement", "requestCreditRefund", [amount]);
  return { txHash: res.txHash };
}
