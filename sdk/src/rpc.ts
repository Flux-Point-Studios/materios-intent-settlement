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

/**
 * The extrinsic's outcome could not be established: it was not included
 * within the timeout, or it was included but its events could not be read or
 * attributed to it. The caller must read chain state to learn what happened.
 */
export class ExtrinsicOutcomeUnknownError extends Error {
  constructor(readonly call: string, detail: string) {
    super(`${call}: outcome unknown (${detail})`);
    this.name = "ExtrinsicOutcomeUnknownError";
  }
}

/** The node refused the transaction before inclusion, e.g. `1010` for an unpaid fee. */
export class TransactionRejectedError extends Error {
  constructor(
    readonly call: string,
    readonly code: number,
    readonly reason: string,
  ) {
    super(`${call} rejected by the pool: ${code}: ${reason}`);
    this.name = "TransactionRejectedError";
  }
}

function describeDispatchError(dispatchError: any): { pallet: string | null; error: string } {
  if (dispatchError.isModule) {
    try {
      const meta = dispatchError.registry.findMetaError(dispatchError.asModule);
      return { pallet: meta.section, error: meta.name };
    } catch {
      return { pallet: null, error: dispatchError.toString() };
    }
  }
  const variant = String(dispatchError.type);
  const inner = dispatchError[`as${variant}`];
  return { pallet: null, error: inner?.type ? `${variant}.${inner.type}` : variant };
}

/**
 * The dispatch error behind a failed inclusion: the extrinsic's own, or one
 * reported by a wrapper (utility batch, sudo, proxy) whose inner call failed.
 */
function failedDispatch(result: any): unknown | null {
  if (result.dispatchError) return result.dispatchError;
  for (const { event } of result.events ?? []) {
    if (event.section === "utility" && (event.method === "BatchInterrupted" || event.method === "ItemFailed")) {
      return event.data[event.data.length - 1];
    }
    const innerResult = (event.data ?? []).find((value: any) => value?.isErr === true);
    if (innerResult) return innerResult.asErr;
  }
  return null;
}

function succeeded(result: any): boolean {
  return (result.events ?? []).some(
    ({ event }: any) => event.section === "system" && event.method === "ExtrinsicSuccess",
  );
}

function asRejection(call: string, error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  const pool = /^(\d{4}): (.*)$/s.exec(message);
  if (pool) return new TransactionRejectedError(call, Number(pool[1]), pool[2]!);
  return error instanceof Error ? error : new Error(message);
}

export interface MateriosRpcClientOptions {
  rpcUrl: string;
  signerUri?: string; // optional; only needed for signed extrinsics
  /** How long submitExtrinsic waits for inclusion before giving up. Default 120 s. */
  inclusionTimeoutMs?: number;
}

export class MateriosRpcClient {
  private api?: ApiPromise;
  private signer?: KeyringPair;
  private readonly rpcUrl: string;
  private readonly signerUri?: string;
  private readonly inclusionTimeoutMs: number;
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
    this.inclusionTimeoutMs = opts.inclusionTimeoutMs ?? 120_000;
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

          const call = `${section}.${method}`;
          let unsub: (() => void) | null = null;
          let settled = false;
          const done = (
            value: { txHash: HexString; blockHash: HexString | null } | null,
            err: Error | null,
          ): void => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            if (unsub) unsub();
            release();
            if (err) reject(err);
            else if (value) resolve(value);
          };
          const timeout = setTimeout(
            () => done(null, new ExtrinsicOutcomeUnknownError(call, `not included within ${this.inclusionTimeoutMs} ms`)),
            this.inclusionTimeoutMs,
          );

          const onStatus = (result: any): void => {
            if (result?.status?.isInBlock) {
              const blockHash = result.status.asInBlock.toHex() as HexString;
              if (result.internalError) {
                done(null, new ExtrinsicOutcomeUnknownError(call, `events unreadable in ${blockHash}`));
                return;
              }
              const failure = failedDispatch(result);
              if (failure) {
                const { pallet, error } = describeDispatchError(failure);
                done(null, new DispatchFailedError(call, pallet, error, blockHash));
                return;
              }
              if (!succeeded(result)) {
                done(null, new ExtrinsicOutcomeUnknownError(call, `no ExtrinsicSuccess in ${blockHash}`));
                return;
              }
              done({ txHash: ext.hash.toHex() as HexString, blockHash }, null);
            } else if (result?.isError) {
              done(null, new Error(`extrinsic ${call} errored (nonce=${nonce})`));
            }
          };

          try {
            const unsubPromise = ext.signAndSend(signer, { nonce }, (result: any) => {
              try {
                onStatus(result);
              } catch (e) {
                done(null, e instanceof Error ? e : new Error(String(e)));
              }
            });
            unsubPromise
              .then((u: () => void) => {
                unsub = u;
                // The RPC accepted the tx into the pool; subsequent
                // accountNextIndex queries will now return nonce+1. Release
                // the gate so the next queued caller can claim its nonce.
                release();
              })
              .catch((e: unknown) => {
                done(null, asRejection(call, e));
              });
          } catch (e) {
            done(null, asRejection(call, e));
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

  /** Whether the claim is settled at the best block and at the finalized head. */
  async claimSettlement(claimId: ClaimId): Promise<{ best: boolean; finalized: boolean }> {
    const api = this.getApi();
    const settledIn = async (query: any): Promise<boolean> => {
      const stored: any = await query.intentSettlement.claims(claimId);
      return stored.isSome && stored.unwrap().settled.isTrue;
    };
    const finalizedHead = await api.rpc.chain.getFinalizedHead();
    const [best, finalized] = await Promise.all([
      settledIn(api.query),
      api.at(finalizedHead).then((at) => settledIn(at.query)),
    ]);
    return { best, finalized };
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
      minFinalityDepth: read("minFinalityDepth").toNumber(),
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

  /** Current best block number, used as keeper cursor and for TTL arithmetic. */
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
