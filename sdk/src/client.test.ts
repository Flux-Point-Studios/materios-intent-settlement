import { describe, it, expect, vi } from "vitest";
import { IntentSettlementClient } from "./client.js";
import { IntentStatus } from "./types.js";

/**
 * Client tests. These stub only the @polkadot/api layer (ONE layer deep,
 * per Team-C TDD rule). Logic under test is the SDK's status-polling and
 * entrypoint wiring.
 */

function stubApi(overrides: Record<string, any> = {}) {
  return {
    isConnected: true,
    query: {
      intentSettlement: {
        intents: vi.fn().mockResolvedValue({
          isNone: false,
          unwrap: () => ({
            status: { toNumber: () => IntentStatus.Pending },
          }),
        }),
      },
    },
    rpc: {
      chain: { getHeader: vi.fn().mockResolvedValue({ number: { toBigInt: () => 1n } }) },
    },
    tx: {},
    call: {},
    disconnect: vi.fn(),
    ...overrides,
  };
}

describe("IntentSettlementClient", () => {
  it("rejects claimDirect until caller wires mesh builder", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://localhost:9944" });
    // @ts-expect-error private
    client["rpc"].connect = vi.fn();
    // @ts-expect-error private
    client["rpc"].getApi = () => stubApi();
    await expect(
      client.claimDirect({
        policyId: ("0x" + "01".repeat(32)) as `0x${string}`,
        oracleUtxoRef: { txHash: ("0x" + "00".repeat(32)) as `0x${string}`, outputIndex: 0 },
        cardanoProviderUrl: "",
        beneficiaryAddr: "",
      }),
    ).rejects.toThrow(/claimDirect/);
  });

  it("getIntentStatus returns Unknown when pallet not yet on-chain", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://localhost:9944" });
    // @ts-expect-error private
    client["rpc"].connect = vi.fn();
    // @ts-expect-error private
    client["connected"] = true;
    const apiNoPallet = {
      isConnected: true,
      query: {}, // no intentSettlement
      rpc: { chain: { getHeader: vi.fn() } },
      tx: {},
      call: {},
    };
    // @ts-expect-error private
    client["rpc"].getApi = () => apiNoPallet;
    const snap = await client.getIntentStatus(("0x" + "aa".repeat(32)) as `0x${string}`);
    expect(snap.status).toBe("Unknown");
  });

  it("getIntentStatus returns decoded status when pallet is live", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://localhost:9944" });
    // @ts-expect-error private
    client["rpc"].connect = vi.fn();
    // @ts-expect-error private
    client["connected"] = true;
    // @ts-expect-error private
    client["rpc"].getApi = () => stubApi();
    const snap = await client.getIntentStatus(("0x" + "aa".repeat(32)) as `0x${string}`);
    expect(snap.status).toBe(IntentStatus.Pending);
  });

  it("submitIntent computes a non-empty intentId and returns tx hash", async () => {
    const client = new IntentSettlementClient({
      materiosRpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error private
    client["rpc"].connect = vi.fn();
    // @ts-expect-error private
    client["connected"] = true;
    // @ts-expect-error private
    client["rpc"].submitExtrinsic = vi.fn().mockResolvedValue({
      txHash: ("0x" + "aa".repeat(32)) as `0x${string}`,
      blockHash: null,
    });
    const res = await client.submitIntent({ tag: "RefundCredit", amountAda: 5n });
    expect(res.intentId.length).toBe(66);
    expect(res.txHash).toBe("0x" + "aa".repeat(32));
  });

  it("requestCreditRefund delegates to submitCreditRefund", async () => {
    const client = new IntentSettlementClient({
      materiosRpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error private
    client["rpc"].connect = vi.fn();
    // @ts-expect-error private
    client["connected"] = true;
    const spy = vi.fn().mockResolvedValue({
      txHash: ("0x" + "bb".repeat(32)) as `0x${string}`,
      blockHash: null,
    });
    // @ts-expect-error private
    client["rpc"].submitExtrinsic = spy;
    await client.requestCreditRefund(100n);
    expect(spy).toHaveBeenCalledWith("intentSettlement", "requestCreditRefund", [100n]);
  });

  it("getPendingBatches proxies to rpc client", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://stub" });
    // @ts-expect-error
    client["rpc"].connect = vi.fn();
    // @ts-expect-error
    client["connected"] = true;
    // @ts-expect-error
    client["rpc"].getPendingBatches = vi.fn().mockResolvedValue([]);
    const r = await client.getPendingBatches(0);
    expect(r).toEqual([]);
  });

  it("getVoucher proxies to rpc client", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://stub" });
    // @ts-expect-error
    client["rpc"].connect = vi.fn();
    // @ts-expect-error
    client["connected"] = true;
    // @ts-expect-error
    client["rpc"].getVoucher = vi.fn().mockResolvedValue(null);
    const v = await client.getVoucher(("0x" + "00".repeat(32)) as `0x${string}`);
    expect(v).toBeNull();
  });

  it("settleClaim delegates to submitSettleClaim helper", async () => {
    const client = new IntentSettlementClient({
      materiosRpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error
    client["rpc"].connect = vi.fn();
    // @ts-expect-error
    client["connected"] = true;
    // @ts-expect-error
    client["rpc"].submitExtrinsic = vi.fn().mockResolvedValue({
      txHash: ("0x" + "cc".repeat(32)) as `0x${string}`,
      blockHash: null,
    });
    const res = await client.settleClaim(
      ("0x" + "11".repeat(32)) as `0x${string}`,
      ("0x" + "22".repeat(32)) as `0x${string}`,
      true,
    );
    expect(res.txHash).toBe("0x" + "cc".repeat(32));
  });

  it("disconnect is idempotent when not connected", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://stub" });
    await client.disconnect();
    await client.disconnect();
  });

  it("pollIntentStatus returns early when target is reached", async () => {
    const client = new IntentSettlementClient({ materiosRpcUrl: "ws://localhost:9944" });
    // @ts-expect-error private
    client["rpc"].connect = vi.fn();
    // @ts-expect-error private
    client["connected"] = true;
    const statuses = [IntentStatus.Pending, IntentStatus.Settled];
    let call = 0;
    const api = stubApi({
      query: {
        intentSettlement: {
          intents: vi.fn().mockImplementation(async () => ({
            isNone: false,
            unwrap: () => ({ status: { toNumber: () => statuses[Math.min(call++, statuses.length - 1)] } }),
          })),
        },
      },
    });
    // @ts-expect-error private
    client["rpc"].getApi = () => api;
    const snap = await client.pollIntentStatus(("0x" + "bb".repeat(32)) as `0x${string}`, [IntentStatus.Settled], {
      maxWaitMs: 1000,
      pollIntervalMs: 10,
    });
    expect(snap.status).toBe(IntentStatus.Settled);
  });
});
