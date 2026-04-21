import { describe, it, expect, vi } from "vitest";
import { MateriosRpcClient, submitIntent, submitCreditRefund, submitSettleClaim } from "./rpc.js";

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
      signAndSend: vi.fn().mockImplementation((_signer, cb) => {
        // Simulate in-block callback
        setTimeout(
          () =>
            cb({
              status: {
                isInBlock: true,
                asInBlock: { toHex: () => "0x" + "11".repeat(32) },
              },
              isError: false,
            }),
          10,
        );
        return Promise.resolve(unsub);
      }),
    };
    const api = {
      tx: { intentSettlement: { settleClaim: () => ext } },
    };
    // @ts-expect-error
    client["api"] = api as any;
    // @ts-expect-error
    client["signer"] = {} as any;
    const res = await client.submitExtrinsic("intentSettlement", "settleClaim", [
      "0x" + "00".repeat(32),
      "0x" + "00".repeat(32),
      false,
    ]);
    expect(res.txHash).toBe("0x" + "ff".repeat(32));
    expect(res.blockHash).toBe("0x" + "11".repeat(32));
  });

  it("submitExtrinsic rejects on error result", async () => {
    const client = new MateriosRpcClient({ rpcUrl: "ws://stub", signerUri: "//Alice" });
    const unsub = vi.fn();
    const ext = {
      hash: { toHex: () => "0x" + "ff".repeat(32) },
      signAndSend: vi.fn().mockImplementation((_signer, cb) => {
        setTimeout(() => cb({ status: {}, isError: true }), 10);
        return Promise.resolve(unsub);
      }),
    };
    const api = { tx: { intentSettlement: { settleClaim: () => ext } } };
    // @ts-expect-error
    client["api"] = api as any;
    // @ts-expect-error
    client["signer"] = {} as any;
    await expect(
      client.submitExtrinsic("intentSettlement", "settleClaim", []),
    ).rejects.toThrow();
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
