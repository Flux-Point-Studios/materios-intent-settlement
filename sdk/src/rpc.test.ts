import { describe, it, expect, vi } from "vitest";
import {
  DispatchFailedError,
  ExtrinsicOutcomeUnknownError,
  MateriosRpcClient,
  TransactionRejectedError,
  submitIntent,
  submitCreditRefund,
  submitSettleClaim,
} from "./rpc.js";

/**
 * Unit tests for RPC wrapper decoders + extrinsic submission helpers. Full
 * WS connection flow is covered by tests/integration/preprod.test.ts.
 */

describe("MateriosRpcClient", () => {
  it("throws if getApi called before connect", () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    expect(() => client.getApi()).toThrow(/not connected/);
  });

  it("throws if getSigner called before connect", () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    expect(() => client.getSigner()).toThrow(/no signer/);
  });

  it("getPendingBatches returns [] when runtime API not present", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    // @ts-expect-error private assignment for test
    client["api"] = { call: {} } as any;
    const res = await client.getPendingBatches(0, 10);
    expect(res).toEqual([]);
  });

  it("getCommitteeState returns default when runtime API missing", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    // @ts-expect-error
    client["api"] = { call: {} } as any;
    const res = await client.getCommitteeState();
    expect(res).toEqual({ members: [], threshold: 0, lastMirror: null });
  });

  it("getVoucher returns null when runtime API missing", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    // @ts-expect-error
    client["api"] = { call: {} } as any;
    const res = await client.getVoucher("0x00");
    expect(res).toBeNull();
  });

  it("getLatestBlockNumber decodes header bigint", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    const api = {
      rpc: { chain: { getHeader: vi.fn().mockResolvedValue({ number: { toBigInt: () => 42n } }) } },
    };
    // @ts-expect-error
    client["api"] = api as any;
    const n = await client.getLatestBlockNumber();
    expect(n).toBe(42);
  });

  it("getPendingBatches decodes shape when runtime API exposed", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    const raw = {
      toJSON: () => [
        {
          intent: {
            submitter: "0x" + "aa".repeat(32),
            nonce: 7,
            kind: { tag: "RefundCredit", amountAda: 1 },
            submittedBlock: 10,
            ttlBlock: 20,
            status: 1,
          },
          intentId: "0x" + "bb".repeat(32),
          attestationSigs: [{ pubkey: "0x" + "cc".repeat(32), sig: "0x" + "dd".repeat(64) }],
        },
      ],
    };
    const api = {
      call: {
        intentSettlementRuntimeApi: {
          getPendingBatches: vi.fn().mockResolvedValue(raw),
        },
      },
    };
    // @ts-expect-error
    client["api"] = api as any;
    const batches = await client.getPendingBatches(0, 10);
    expect(batches.length).toBe(1);
    expect(batches[0]!.intent.nonce).toBe(7n);
    expect(batches[0]!.attestationSigs.length).toBe(1);
  });

  it("submitExtrinsic resolves in-block", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub", signerUri: "//Alice" });
    const unsub = vi.fn();
    const ext = {
      hash: { toHex: () => "0x" + "ff".repeat(32) },
      // Task #77 changed signAndSend signature to (signer, {nonce}, cb).
      signAndSend: vi.fn().mockImplementation((_signer, _opts, cb) => {
        // Simulate in-block callback
        setTimeout(
          () =>
            cb({
              status: {
                isInBlock: true,
                asInBlock: { toHex: () => "0x" + "11".repeat(32) },
              },
              isError: false,
              events: [SUCCESS],
            }),
          10,
        );
        return Promise.resolve(unsub);
      }),
    };
    const api = {
      tx: { intentSettlement: { settleClaim: () => ext } },
      rpc: {
        system: {
          accountNextIndex: vi.fn().mockResolvedValue({ toNumber: () => 7 }),
        },
      },
    };
    // @ts-expect-error
    client["api"] = api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;
    const res = await client.submitExtrinsic("intentSettlement", "settleClaim", [
      "0x" + "00".repeat(32),
      "0x" + "00".repeat(32),
      false,
    ]);
    expect(res.txHash).toBe("0x" + "ff".repeat(32));
    expect(res.blockHash).toBe("0x" + "11".repeat(32));
    // Task #77: nonce was passed explicitly to signAndSend.
    expect(ext.signAndSend).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ nonce: 7 }),
      expect.any(Function),
    );
    expect(api.rpc.system.accountNextIndex).toHaveBeenCalledWith("5GrwvaEF");
  });

  it("submitExtrinsic rejects on error result", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub", signerUri: "//Alice" });
    const unsub = vi.fn();
    const ext = {
      hash: { toHex: () => "0x" + "ff".repeat(32) },
      signAndSend: vi.fn().mockImplementation((_signer, _opts, cb) => {
        setTimeout(() => cb({ status: {}, isError: true }), 10);
        return Promise.resolve(unsub);
      }),
    };
    const api = {
      tx: { intentSettlement: { settleClaim: () => ext } },
      rpc: {
        system: {
          accountNextIndex: vi.fn().mockResolvedValue({ toNumber: () => 0 }),
        },
      },
    };
    // @ts-expect-error
    client["api"] = api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;
    await expect(
      client.submitExtrinsic("intentSettlement", "settleClaim", []),
    ).rejects.toThrow();
  });
});

const SUCCESS = { event: { section: "system", method: "ExtrinsicSuccess", data: [] } };
const BLOCK = "0x" + "11".repeat(32);

function moduleError(name: string) {
  return {
    isModule: true,
    asModule: { index: 2, error: 45 },
    registry: { findMetaError: () => ({ section: "intentSettlement", name }) },
    toString: () => `{"module":{"index":2,"error":45}}`,
  };
}

/** A client whose signAndSend reports `outcome` (or nothing) once the tx is in a block. */
function submittingClient(
  outcome: Record<string, unknown> | null,
  options: { send?: () => Promise<unknown>; inclusionTimeoutMs?: number } = {},
): MateriosRpcClient {
  const client = new MateriosRpcClient({
    rpcUrl: "ws://stub",
    signerUri: "//Alice",
    inclusionTimeoutMs: options.inclusionTimeoutMs ?? 5_000,
  });
  const ext = {
    hash: { toHex: () => "0x" + "ff".repeat(32) },
    signAndSend: vi.fn().mockImplementation((_signer, _opts, cb) => {
      if (outcome) {
        setTimeout(() => cb({ status: { isInBlock: true, asInBlock: { toHex: () => BLOCK } }, isError: false, events: [], ...outcome }), 1);
      }
      return options.send ? options.send() : Promise.resolve(vi.fn());
    }),
  };
  const api = {
    tx: { intentSettlement: { requestSettle: () => ext } },
    rpc: { system: { accountNextIndex: vi.fn().mockResolvedValue({ toNumber: () => 3 }) } },
  };
  // @ts-expect-error
  client["api"] = api as any;
  // @ts-expect-error
  client["signer"] = { address: "5GrwvaEF" } as any;
  return client;
}

describe("dispatch failures", () => {
  const submit = (client: MateriosRpcClient) =>
    client.submitExtrinsic("intentSettlement", "requestSettle", []).catch((error: unknown) => error);

  it("rejects an included extrinsic whose dispatch failed, naming the module error", async () => {
    const failure = await submit(submittingClient({ dispatchError: moduleError("SettlementRequestAlreadyExists") }));
    expect(failure).toBeInstanceOf(DispatchFailedError);
    expect(failure).toMatchObject({
      call: "intentSettlement.requestSettle",
      pallet: "intentSettlement",
      error: "SettlementRequestAlreadyExists",
      blockHash: BLOCK,
    });
  });

  it("names non-module dispatch errors by their variant", async () => {
    const failure = await submit(
      submittingClient({ dispatchError: { isModule: false, type: "Token", asToken: { type: "FundsUnavailable" } } }),
    );
    expect(failure).toMatchObject({ pallet: null, error: "Token.FundsUnavailable" });
  });

  it("still rejects when the dispatch error cannot be decoded", async () => {
    const undecodable = {
      ...moduleError("unused"),
      registry: {
        findMetaError: () => {
          throw new Error("unknown module error");
        },
      },
    };
    const failure = await submit(submittingClient({ dispatchError: undecodable }));
    expect(failure).toBeInstanceOf(DispatchFailedError);
    expect(failure).toMatchObject({ pallet: null, error: `{"module":{"index":2,"error":45}}` });
  });

  it("rejects a wrapper call whose inner dispatch failed", async () => {
    const interrupted = {
      events: [SUCCESS, { event: { section: "utility", method: "BatchInterrupted", data: [{}, moduleError("AlreadySettled")] } }],
    };
    expect(await submit(submittingClient(interrupted))).toMatchObject({ error: "AlreadySettled" });
    const sudid = {
      events: [SUCCESS, { event: { section: "sudo", method: "Sudid", data: [{ isErr: true, asErr: moduleError("BondNotReserved") }] } }],
    };
    expect(await submit(submittingClient(sudid))).toMatchObject({ error: "BondNotReserved" });
  });

  it("treats an inclusion it cannot attribute to success as an unknown outcome", async () => {
    const unreadable = await submit(submittingClient({ internalError: new Error("events unavailable") }));
    expect(unreadable).toBeInstanceOf(ExtrinsicOutcomeUnknownError);
    const unattributed = await submit(submittingClient({ events: [] }));
    expect(unattributed).toBeInstanceOf(ExtrinsicOutcomeUnknownError);
  });

  it("gives up on a submission that is never included", async () => {
    const failure = await submit(submittingClient(null, { inclusionTimeoutMs: 20 }));
    expect(failure).toBeInstanceOf(ExtrinsicOutcomeUnknownError);
  });

  it("names a transaction the pool rejected, such as an unpaid fee", async () => {
    const failure = await submit(
      submittingClient(null, {
        send: () =>
          Promise.reject(new Error("1010: Invalid Transaction: Inability to pay some fees , e.g. account balance too low")),
      }),
    );
    expect(failure).toBeInstanceOf(TransactionRejectedError);
    expect(failure).toMatchObject({ code: 1010, reason: "Invalid Transaction: Inability to pay some fees , e.g. account balance too low" });
  });
});

describe("settlement reads", () => {
  function readClient(
    query: Record<string, unknown>,
    consts: Record<string, unknown> = {},
    finalizedQuery: Record<string, unknown> = query,
  ): MateriosRpcClient {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub" });
    const finalizedHead = "0x" + "fe".repeat(32);
    // @ts-expect-error
    client["api"] = {
      query: { intentSettlement: query },
      consts: { intentSettlement: consts },
      rpc: { chain: { getFinalizedHead: vi.fn().mockResolvedValue(finalizedHead) } },
      at: vi.fn().mockImplementation(async (hash: string) => {
        expect(hash).toBe(finalizedHead);
        return { query: { intentSettlement: finalizedQuery } };
      }),
    } as any;
    return client;
  }
  const codec = (value: unknown) => ({ toString: () => String(value), toNumber: () => Number(value), toHex: () => value });
  const some = (value: unknown) => ({ isSome: true, isNone: false, unwrap: () => value });
  const none = { isSome: false, isNone: true };

  it("decodes a pending settlement request with its requester as a public key", async () => {
    const client = readClient({
      claimSettlementRequests: vi.fn().mockResolvedValue(
        some({
          requester: codec("0x" + "ab".repeat(32)),
          submittedBlock: codec(7),
          settledDirect: { isTrue: false },
          bondAmount: codec(500),
          evidence: {
            cardanoTxHash: codec("0x" + "cd".repeat(32)),
            observedAtDepth: codec(15),
            observedSlot: codec(123),
            beneficiaryAddrHash: codec("0x" + "22".repeat(28)),
            amountLovelace: codec(1000),
            mainchainGenesisHash: codec("0x" + "65".repeat(32)),
          },
        }),
      ),
    });
    await expect(client.getSettlementRequest(("0x" + "01".repeat(32)) as `0x${string}`)).resolves.toEqual({
      requester: "0x" + "ab".repeat(32),
      submittedBlock: 7,
      settledDirect: false,
      bondAmount: 500n,
      evidence: {
        cardano_tx_hash: "0x" + "cd".repeat(32),
        observed_at_depth: 15,
        observed_slot: 123n,
        beneficiary_addr_hash: "0x" + "22".repeat(28),
        amount_lovelace: 1000n,
        mainchain_genesis_hash: "0x" + "65".repeat(32),
      },
    });
  });

  it("reports absent requests, unsettled claims and unbonded claims", async () => {
    const client = readClient({
      claimSettlementRequests: vi.fn().mockResolvedValue(none),
      claims: vi.fn().mockResolvedValue(none),
      bondedClaimRequester: vi.fn().mockResolvedValue(none),
      bondedClaimAttestedAt: vi.fn().mockResolvedValue(none),
    });
    const claim = ("0x" + "01".repeat(32)) as `0x${string}`;
    await expect(client.getSettlementRequest(claim)).resolves.toBeNull();
    await expect(client.claimSettlement(claim)).resolves.toEqual({ best: false, finalized: false });
    await expect(client.getAttestedBond(claim)).resolves.toBeNull();
  });

  it("reads settled claims and attested bonds", async () => {
    const client = readClient({
      claims: vi.fn().mockResolvedValue(some({ settled: { isTrue: true } })),
      bondedClaimRequester: vi.fn().mockResolvedValue(some([codec("0x" + "ab".repeat(32)), codec(500)])),
      bondedClaimAttestedAt: vi.fn().mockResolvedValue(some(codec(90))),
    });
    const claim = ("0x" + "01".repeat(32)) as `0x${string}`;
    await expect(client.claimSettlement(claim)).resolves.toEqual({ best: true, finalized: true });
    await expect(client.getAttestedBond(claim)).resolves.toEqual({
      requester: "0x" + "ab".repeat(32),
      amount: 500n,
      attestedAt: 90,
    });
  });

  it("reads settlement at the best block and at the finalized head separately", async () => {
    const settled = { claims: vi.fn().mockResolvedValue(some({ settled: { isTrue: true } })) };
    const unsettled = { claims: vi.fn().mockResolvedValue(none) };
    const client = readClient(settled, {}, unsettled);
    await expect(client.claimSettlement(("0x" + "01".repeat(32)) as `0x${string}`)).resolves.toEqual({
      best: true,
      finalized: false,
    });
  });

  it("reads the settlement constants and refuses a runtime that lacks one", () => {
    const complete = {
      minSettlementBond: codec(0),
      settlementRequestTtl: codec(2400),
      bondReleaseDelayBlocks: codec(30),
      maxObservedDepth: codec(2160),
      minFinalityDepth: codec(15),
    };
    expect(readClient({}, complete).getSettlementConstants()).toEqual({
      minSettlementBond: 0n,
      settlementRequestTtl: 2400,
      bondReleaseDelayBlocks: 30,
      maxObservedDepth: 2160,
      minFinalityDepth: 15,
    });
    const { maxObservedDepth: _, ...missing } = complete;
    expect(() => readClient({}, missing).getSettlementConstants()).toThrow(/maxObservedDepth/);
  });
});

describe("extrinsic helpers", () => {
  function stubClient(): MateriosRpcClient {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub", signerUri: "//Alice" });
    // @ts-expect-error
    client.submitExtrinsic = vi.fn().mockResolvedValue({ txHash: "0xabc", blockHash: null });
    return client;
  }

  it("submitIntent calls submitExtrinsic with intentSettlement.submitIntent", async () => {
    const client = stubClient();
    const res = await submitIntent(client, { tag: "RefundCredit", amountAda: 1n });
    expect(res.txHash).toBe("0xabc");
    // @ts-expect-error
    expect(client.submitExtrinsic).toHaveBeenCalledWith(
      "intentSettlement",
      "submitIntent",
      expect.any(Array),
    );
  });

  it("submitCreditRefund calls requestCreditRefund", async () => {
    const client = stubClient();
    await submitCreditRefund(client, 42n);
    // @ts-expect-error
    expect(client.submitExtrinsic).toHaveBeenCalledWith(
      "intentSettlement",
      "requestCreditRefund",
      [42n],
    );
  });

  it("submitSettleClaim passes (claimId, txHash, settledDirect) tuple", async () => {
    const client = stubClient();
    await submitSettleClaim(client, {
      claimId: ("0x" + "aa".repeat(32)) as `0x${string}`,
      cardanoTxHash: ("0x" + "bb".repeat(32)) as `0x${string}`,
      settledDirect: true,
    });
    // @ts-expect-error
    const call = (client.submitExtrinsic as any).mock.calls[0];
    expect(call[0]).toBe("intentSettlement");
    expect(call[1]).toBe("settleClaim");
    expect(call[2][2]).toBe(true);
  });
});
