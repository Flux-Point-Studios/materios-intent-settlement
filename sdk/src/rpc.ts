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
  AttestedBond,
  SettlementConstants,
  SettlementRequestView,
} from "./types.js";

/**
 * The extrinsic was included in a block, but its dispatch failed. `pallet`
 * and `error` name a module error (`intentSettlement`,
 * `SettlementRequestAlreadyExists`); other dispatch errors have a null
 * pallet and their variant as `error` (`BadOrigin`, `Token.FundsUnavailable`).
 */
export class DispatchFailedError extends Error {
  constructor(
    readonly call: string,
    readonly pallet: string | null,
    readonly error: string,
    readonly blockHash: HexString,
  ) {
    super(`${call} failed in block ${blockHash}: ${pallet ? `${pallet}.` : ""}${error}`);
    this.name = "DispatchFailedError";
  }
}

function describeDispatchError(api: ApiPromise, dispatchError: any): { pallet: string | null; error: string } {
  if (dispatchError.isModule) {
    const meta = api.registry.findMetaError(dispatchError.asModule);
    return { pallet: meta.section, error: meta.name };
  }
  const variant = String(dispatchError.type);
  const inner = dispatchError[`as${variant}`];
  return { pallet: null, error: inner?.type ? `${variant}.${inner.type}` : variant };
}

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
  /**
   * Task #77: per-signer nonce gate. Serialises `accountNextIndex →
   * signAndSend RPC accept` so concurrent callers under the same signer
   * cannot both read the same on-chain nonce and collide in the mempool.
   *
   * The chain advances when each `signAndSend` resolves the local
   * Promise<unsub>; the next caller awaits that resolution before reading
   * `accountNextIndex` again. Inclusion (in-block) waits happen OUTSIDE
   * the gate so we don't bottleneck on block production.
   *
   * Reset to a fresh resolved Promise on `disconnect()` so a future
   * re-connect doesn't inherit a never-resolving gate.
   *
   * Mirrors the production fix shipped in receipt-submitter.mjs
   * (feedback_polkadot_nonce_race_on_burst.md, 2026-04-24).
   */
  private nonceChain: Promise<void> = Promise.resolve();

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
    // Reset the nonce chain on every fresh connect so a stalled prior gate
    // doesn't permanently wedge new submits.
    this.nonceChain = Promise.resolve();
  }

  async disconnect(): Promise<void> {
    if (this.api?.isConnected) await this.api.disconnect();
    this.api = undefined;
    this.provider = undefined;
    // Reset the nonce-gate chain — any never-resolving promise from the
    // pre-disconnect signAndSend can permanently wedge new submissions.
    this.nonceChain = Promise.resolve();
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

    // Task #77: nonce-gate guards the (accountNextIndex → signAndSend RPC)
    // window. Concurrent callers (e.g. keeper.reconcileInflight running
    // settle_claim for many vouchers in a `for…of`) would otherwise all
    // read the same on-chain nonce and the second tx would land with
    // `1014: Priority is too low`, silently dropping the claim.
    //
    // The gate releases as soon as the RPC accepts the tx into the pool
    // (the signAndSend promise resolves with an unsub fn). Inclusion-wait
    // happens AFTER the gate releases.
    //
    // Mirrors receipt-submitter.mjs (2026-04-24) — battle-tested under
    // burst submits.
    return new Promise((resolve, reject) => {
      const prev = this.nonceChain;
      let releaseGate: (() => void) | undefined;
      this.nonceChain = new Promise<void>((r) => {
        releaseGate = r;
      });
      const release = (): void => {
        if (releaseGate) {
          releaseGate();
          releaseGate = undefined;
        }
      };

      prev
        .then(async () => {
          let nonce: number;
          try {
            const next = await api.rpc.system.accountNextIndex(signer.address);
            // `Index` (a.k.a. AccountNonce) is a u32 in the runtime; toNumber()
            // is safe for any account that hasn't sent ~4B txs.
            nonce = (next as any).toNumber
              ? (next as any).toNumber()
              : Number(next.toString());
          } catch (err) {
            // accountNextIndex itself failed — release the gate to keep
            // queued callers moving and surface the error.
            release();
            reject(err instanceof Error ? err : new Error(String(err)));
            return;
          }

          let unsub: (() => void) | null = null;
          let settled = false;
          const done = (
            value: { txHash: HexString; blockHash: HexString | null } | null,
            err: Error | null,
          ): void => {
            if (settled) return;
            settled = true;
            if (unsub) unsub();
            release();
            if (err) reject(err);
            else if (value) resolve(value);
          };

          try {
            const unsubPromise = ext.signAndSend(
              signer,
              { nonce },
              (result: any) => {
                if (result?.status?.isInBlock) {
                  const blockHash = result.status.asInBlock.toHex() as HexString;
                  if (result.dispatchError) {
                    const { pallet, error } = describeDispatchError(api, result.dispatchError);
                    done(null, new DispatchFailedError(`${section}.${method}`, pallet, error, blockHash));
                    return;
                  }
                  const txHash = ext.hash.toHex() as HexString;
                  done({ txHash, blockHash }, null);
                } else if (result?.isError) {
                  done(
                    null,
                    new Error(
                      `extrinsic ${section}.${method} errored (nonce=${nonce})`,
                    ),
                  );
                }
              },
            );
            unsubPromise
              .then((u: () => void) => {
                unsub = u;
                // The RPC accepted the tx into the pool; subsequent
                // accountNextIndex queries will now return nonce+1. Release
                // the gate so the next queued caller can claim its nonce.
                release();
              })
              .catch((e: unknown) => {
                done(null, e instanceof Error ? e : new Error(String(e)));
              });
          } catch (e) {
            done(null, e instanceof Error ? e : new Error(String(e)));
          }
        })
        .catch((e) => {
          release();
          reject(e instanceof Error ? e : new Error(String(e)));
        });
    });
  }

  /** The pending settlement request for a claim, if any. */
  async getSettlementRequest(claimId: ClaimId): Promise<SettlementRequestView | null> {
    const stored: any = await (this.getApi().query as any).intentSettlement.claimSettlementRequests(claimId);
    if (!stored.isSome) return null;
    const request = stored.unwrap();
    const evidence = request.evidence;
    return {
      requester: request.requester.toHex() as HexString,
      submittedBlock: request.submittedBlock.toNumber(),
      settledDirect: request.settledDirect.isTrue,
      bondAmount: BigInt(request.bondAmount.toString()),
      evidence: {
        cardano_tx_hash: evidence.cardanoTxHash.toHex() as HexString,
        observed_at_depth: evidence.observedAtDepth.toNumber(),
        observed_slot: BigInt(evidence.observedSlot.toString()),
        beneficiary_addr_hash: evidence.beneficiaryAddrHash.toHex() as HexString,
        amount_lovelace: BigInt(evidence.amountLovelace.toString()),
        mainchain_genesis_hash: evidence.mainchainGenesisHash.toHex() as HexString,
      },
    };
  }

  /** Whether the claim is settled on Materios. */
  async isClaimSettled(claimId: ClaimId): Promise<boolean> {
    const stored: any = await (this.getApi().query as any).intentSettlement.claims(claimId);
    return stored.isSome && stored.unwrap().settled.isTrue;
  }

  /** The bond held after attestation until its release, if any. */
  async getAttestedBond(claimId: ClaimId): Promise<AttestedBond | null> {
    const query: any = (this.getApi().query as any).intentSettlement;
    const [holder, attestedAt]: any[] = await Promise.all([
      query.bondedClaimRequester(claimId),
      query.bondedClaimAttestedAt(claimId),
    ]);
    if (!holder.isSome || !attestedAt.isSome) return null;
    const [requester, amount] = holder.unwrap();
    return {
      requester: requester.toHex() as HexString,
      amount: BigInt(amount.toString()),
      attestedAt: attestedAt.unwrap().toNumber(),
    };
  }

  /** Settlement constants from the connected runtime's metadata. */
  getSettlementConstants(): SettlementConstants {
    const consts: any = (this.getApi().consts as any).intentSettlement ?? {};
    const read = (name: string): any => {
      const value = consts[name];
      if (value === undefined) throw new Error(`runtime lacks intentSettlement.${name}`);
      return value;
    };
    return {
      minSettlementBond: BigInt(read("minSettlementBond").toString()),
      settlementRequestTtl: read("settlementRequestTtl").toNumber(),
      bondReleaseDelayBlocks: read("bondReleaseDelayBlocks").toNumber(),
      maxObservedDepth: read("maxObservedDepth").toNumber(),
    };
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

/**
 * Wrapper around the legacy `intentSettlement.settleClaim` extrinsic.
 *
 * @deprecated Task #266 (mis-sec P0): the legacy `settle_claim` path is
 * retired at `STCA_CUTOVER_BLOCK = upgrade_block + 50` and post-cutover
 * the runtime rejects with `Error::DeprecatedExtrinsic`. New code MUST
 * call `intentSettlement.requestSettle` + `intentSettlement.attestSettle`
 * (see the keeper's `submitAttestedSettle` reference) so each committee
 * signature commits to a falsifiable Cardano-record fact.
 *
 * This helper is retained for the 50-block grace window and for tooling
 * that needs to drive both paths during rollout.
 */
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
