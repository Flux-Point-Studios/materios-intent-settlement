/**
 * In-memory model of the settlement pallet's request, attest, supersede and
 * bond-release calls, for keeper tests. Failed dispatches reject with the
 * SDK's DispatchFailedError, as an included-but-failed extrinsic does, and
 * leave state untouched. Bonds move between free and reserved balances.
 */

import { signatureVerify } from "@polkadot/util-crypto";
import { DispatchFailedError, TransactionRejectedError } from "@fluxpointstudios/materios-intent-settlement-sdk";
import type {
  AttestedBond,
  ClaimId,
  HexString,
  SettlementConstants,
  SettlementEvidence,
  SettlementRequestView,
} from "@fluxpointstudios/materios-intent-settlement-sdk";

export type StcaPayload = (
  claimId: ClaimId,
  evidence: SettlementEvidence,
  settledDirect: boolean,
) => Uint8Array;

type Signatures = Array<[HexString, HexString]>;

export class FakeSettlementChain {
  block = 200;
  threshold = 1;
  constants: SettlementConstants = {
    minSettlementBond: 500n,
    settlementRequestTtl: 2400,
    bondReleaseDelayBlocks: 30,
    maxObservedDepth: 2160,
    minFinalityDepth: 15,
  };
  /** Blocks between inclusion and finality. */
  finalityLag = 0;
  /** Runs before each submission; may throw to fail it or record a side effect. */
  beforeSubmit: (method: string) => void = () => {};
  /** Runs after a submission was included; may throw to lose its outcome. */
  afterInclusion: (method: string) => void = () => {};
  readonly committee = new Set<HexString>();
  readonly settled = new Set<ClaimId>();
  private readonly settledAt = new Map<ClaimId, number>();
  readonly requests = new Map<ClaimId, SettlementRequestView>();
  readonly attested = new Map<ClaimId, AttestedBond>();
  readonly calls: Array<{ method: string; args: unknown[]; failure?: string }> = [];
  private readonly free = new Map<HexString, bigint>();
  private readonly reserved = new Map<HexString, bigint>();
  private current = "";

  constructor(
    readonly signer: HexString,
    private readonly stcaPayload: StcaPayload,
  ) {
    this.committee.add(signer);
    this.free.set(signer, 10_000n);
  }

  fund(account: HexString, amount: bigint): void {
    this.free.set(account, (this.free.get(account) ?? 0n) + amount);
  }

  freeBalance(account: HexString): bigint {
    return this.free.get(account) ?? 0n;
  }

  reservedBalance(account: HexString): bigint {
    return this.reserved.get(account) ?? 0n;
  }

  /** Files a request on behalf of another account, as an attacker would. */
  fileRequest(requester: HexString, claimId: ClaimId, evidence: SettlementEvidence, bond: bigint): void {
    this.reserve(requester, bond);
    this.requests.set(claimId, {
      requester,
      submittedBlock: this.block,
      settledDirect: false,
      bondAmount: bond,
      evidence,
    });
  }

  /** Settles a pending request as an M-of-N committee attestation would. */
  attestAsCommittee(claimId: ClaimId): void {
    const request = this.requests.get(claimId)!;
    if (request.bondAmount > 0n) {
      this.attested.set(claimId, { requester: request.requester, amount: request.bondAmount, attestedAt: this.block });
    }
    this.requests.delete(claimId);
    this.settle(claimId);
  }

  /** The RPC surface the keeper uses, minus batch and voucher lookups. */
  rpc() {
    return {
      getLatestBlockNumber: async () => this.block,
      getSettlementRequest: async (claimId: ClaimId) => this.requests.get(claimId) ?? null,
      claimSettlement: async (claimId: ClaimId) => ({
        best: this.settled.has(claimId),
        finalized: this.settled.has(claimId) && this.settledAt.get(claimId)! <= this.block - this.finalityLag,
      }),
      getAttestedBond: async (claimId: ClaimId) => this.attested.get(claimId) ?? null,
      getSettlementConstants: () => this.constants,
      getApi: () => ({ consts: { intentSettlement: { minSettlementBond: this.constants.minSettlementBond } } }),
      getSigner: () => ({ publicKey: hexToBytes(this.signer) }),
      submitExtrinsic: async (section: string, method: string, args: unknown[]) => {
        try {
          this.beforeSubmit(method);
          this.dispatch(method, args);
          this.calls.push({ method, args });
        } catch (failure) {
          if (failure instanceof DispatchFailedError || failure instanceof TransactionRejectedError) {
            this.calls.push({ method, args, failure: failure instanceof DispatchFailedError ? failure.error : `Rejected:${failure.code}` });
          }
          throw failure;
        }
        this.afterInclusion(method);
        return { txHash: ("0x" + "aa".repeat(32)) as HexString, blockHash: ("0x" + "bb".repeat(32)) as HexString };
      },
    };
  }

  private dispatch(method: string, args: unknown[]): void {
    this.current = method;
    switch (method) {
      case "requestSettle": {
        const [claimId, , settledDirect, evidence, bond] = args as [ClaimId, HexString, boolean, SettlementEvidence, bigint];
        this.ensure(!this.settled.has(claimId), "AlreadySettled");
        this.ensure(evidence.observed_at_depth <= this.constants.maxObservedDepth, "FinalityDepthAboveMaximum");
        this.ensure(bond > 0n && bond >= this.constants.minSettlementBond, "BondBelowMinimum");
        const prior = this.requests.get(claimId);
        this.ensure(!prior || this.expired(prior), "SettlementRequestAlreadyExists");
        const refund = prior && prior.requester === this.signer ? prior.bondAmount : 0n;
        if (this.freeBalance(this.signer) + refund < bond) {
          throw new DispatchFailedError(`intentSettlement.${method}`, "balances", "InsufficientBalance", this.blockHash());
        }
        if (prior) this.unreserve(prior.requester, prior.bondAmount);
        this.fileRequest(this.signer, claimId, evidence, bond);
        this.requests.get(claimId)!.settledDirect = settledDirect;
        return;
      }
      case "attestSettle": {
        const [claimId, signatures] = args as [ClaimId, Signatures];
        this.ensureCommittee(signatures);
        const request = this.requests.get(claimId);
        this.ensure(request !== undefined, "SettlementRequestMissing");
        this.ensure(!this.expired(request!), "SettlementRequestExpired");
        this.ensure(!this.settled.has(claimId), "AlreadySettled");
        this.ensureSigned(claimId, request!.evidence, request!.settledDirect, signatures);
        if (request!.bondAmount > 0n) {
          this.attested.set(claimId, {
            requester: request!.requester,
            amount: request!.bondAmount,
            attestedAt: this.block,
          });
        }
        this.requests.delete(claimId);
        this.settle(claimId);
        return;
      }
      case "supersedeSettlementRequest": {
        const [claimId, settledDirect, evidence, signatures] = args as [ClaimId, boolean, SettlementEvidence, Signatures];
        this.ensureCommittee(signatures);
        this.ensure(evidence.observed_at_depth <= this.constants.maxObservedDepth, "FinalityDepthAboveMaximum");
        this.ensure(!this.settled.has(claimId), "AlreadySettled");
        const request = this.requests.get(claimId);
        this.ensure(request !== undefined, "SettlementRequestMissing");
        this.ensure(
          JSON.stringify(request!.evidence, bigints) !== JSON.stringify(evidence, bigints) ||
            request!.settledDirect !== settledDirect,
          "SupersedeMatchesRequest",
        );
        this.ensureSigned(claimId, evidence, settledDirect, signatures);
        this.unreserve(request!.requester, request!.bondAmount);
        this.requests.delete(claimId);
        this.settle(claimId);
        return;
      }
      case "releaseSettlementBond": {
        const [claimId] = args as [ClaimId];
        const held = this.attested.get(claimId);
        if (held) {
          this.ensure(this.block >= held.attestedAt + this.constants.bondReleaseDelayBlocks, "BondReleaseTooEarly");
          this.unreserve(held.requester, held.amount);
          this.attested.delete(claimId);
          return;
        }
        const request = this.requests.get(claimId);
        this.ensure(request !== undefined && request.bondAmount > 0n, "BondNotReserved");
        this.ensure(this.expired(request!), "BondReleaseTooEarly");
        this.unreserve(request!.requester, request!.bondAmount);
        this.requests.delete(claimId);
        return;
      }
      default:
        throw new Error(`fake chain has no ${method}`);
    }
  }

  /** Records `claimId` settled at the current block, as any settling call does. */
  settle(claimId: ClaimId): void {
    this.settled.add(claimId);
    this.settledAt.set(claimId, this.block);
  }

  private expired(request: SettlementRequestView): boolean {
    return this.block - request.submittedBlock > this.constants.settlementRequestTtl;
  }

  private ensureCommittee(signatures: Signatures): void {
    this.ensure(this.committee.has(this.signer), "NotCommitteeMember");
    this.ensure(signatures.length >= this.threshold, "InsufficientSignatures");
  }

  private ensureSigned(
    claimId: ClaimId,
    evidence: SettlementEvidence,
    settledDirect: boolean,
    signatures: Signatures,
  ): void {
    const payload = this.stcaPayload(claimId, evidence, settledDirect);
    for (const [pubkey, sig] of signatures) {
      this.ensure(this.committee.has(pubkey), "SignerNotCommitteeMember");
      this.ensure(signatureVerify(payload, sig, pubkey).isValid, "InvalidSignature");
    }
  }

  private ensure(condition: boolean, error: string): void {
    if (!condition) {
      throw new DispatchFailedError(`intentSettlement.${this.current}`, "intentSettlement", error, this.blockHash());
    }
  }

  private reserve(account: HexString, amount: bigint): void {
    this.free.set(account, this.freeBalance(account) - amount);
    this.reserved.set(account, this.reservedBalance(account) + amount);
  }

  private unreserve(account: HexString, amount: bigint): void {
    this.reserved.set(account, this.reservedBalance(account) - amount);
    this.free.set(account, this.freeBalance(account) + amount);
  }

  private blockHash(): HexString {
    return ("0x" + this.block.toString(16).padStart(64, "0")) as HexString;
  }
}

function bigints(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString() : value;
}

function hexToBytes(hex: HexString): Uint8Array {
  const clean = hex.slice(2);
  return Uint8Array.from({ length: clean.length / 2 }, (_, i) => parseInt(clean.slice(i * 2, i * 2 + 2), 16));
}
