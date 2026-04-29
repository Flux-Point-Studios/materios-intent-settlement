/**
 * Task #77 — submitExtrinsic nonce race regression test.
 *
 * Reproduces the failure mode that prompted the fix:
 *   keeper.reconcileInflight() calls submitExtrinsic in a `for…of` loop;
 *   without an explicit nonce + per-signer mutex, two consecutive
 *   submits read the same accountNextIndex and the second tx lands as
 *   `1014: Priority is too low` in the mempool, silently dropping the
 *   claim.
 *
 * Asserts that N concurrent submitExtrinsic calls:
 *   - all complete (no priority-cap drops)
 *   - get DISTINCT, MONOTONICALLY INCREASING nonces
 *   - serialise the (accountNextIndex → signAndSend RPC) window so the
 *     N-th call doesn't claim its nonce until the (N-1)-th has been
 *     accepted into the pool.
 *
 * The mock is deliberately stateful: accountNextIndex returns the
 * "current" nonce (incremented by signAndSend's pool-accept callback),
 * and signAndSend records the nonce it was given.
 */

import { describe, it, expect, vi } from "vitest";
import { MateriosRpcClient } from "./rpc.js";

interface CapturedTx {
  nonce: number;
  acceptedAt: number;
}

/**
 * Build an api stub that simulates a running chain's nonce + pool.
 * `signAcceptDelayMs` controls how long signAndSend takes between
 * being called and resolving the unsub Promise — large values amplify
 * the race window so a buggy implementation reliably produces a
 * collision.
 */
function makeChainSim(opts: { signAcceptDelayMs: number }) {
  let onChainNonce = 0;
  const captured: CapturedTx[] = [];

  const accountNextIndex = vi.fn().mockImplementation(async () => {
    return { toNumber: () => onChainNonce };
  });

  const signAndSend = vi
    .fn()
    .mockImplementation(
      (_signer: unknown, opts: { nonce: number }, cb: (r: any) => void) => {
        const claimed = opts.nonce;
        const acceptedAt = Date.now();
        // Asynchronously resolve the unsub promise — between when
        // signAndSend is called and when its Promise resolves, the next
        // queued submitExtrinsic MUST NOT be allowed to read
        // accountNextIndex (otherwise it'll see the stale nonce).
        return new Promise<() => void>((resolve) => {
          setTimeout(() => {
            captured.push({ nonce: claimed, acceptedAt });
            // Pool accepted — bump the on-chain "next index" so the next
            // call sees nonce+1.
            onChainNonce = claimed + 1;
            resolve(() => {});
            // Drive the in-block resolution asynchronously — settles the
            // outer submitExtrinsic Promise so the test's `Promise.all`
            // resolves.
            setTimeout(
              () =>
                cb({
                  status: {
                    isInBlock: true,
                    asInBlock: { toHex: () => "0x" + "11".repeat(32) },
                  },
                  isError: false,
                }),
              5,
            );
          }, opts.signAcceptDelayMs);
        });
      },
    );

  const ext = {
    hash: { toHex: () => "0x" + "ff".repeat(32) },
    signAndSend,
  };
  const api = {
    tx: { intentSettlement: { settleClaim: () => ext } },
    rpc: { system: { accountNextIndex } },
  };
  return { api, captured, signAndSend, accountNextIndex };
}

describe("submitExtrinsic nonce race fix (Task #77)", () => {
  it("N concurrent submits get distinct, monotonically increasing nonces", async () => {
    const N = 10;
    const sim = makeChainSim({ signAcceptDelayMs: 5 });
    const client = new MateriosRpcClient({
      rpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error patch internal api/signer
    client["api"] = sim.api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;

    const promises: Promise<unknown>[] = [];
    for (let i = 0; i < N; i++) {
      promises.push(
        client.submitExtrinsic("intentSettlement", "settleClaim", []),
      );
    }
    const results = await Promise.all(promises);
    expect(results).toHaveLength(N);

    // All N nonces were used, each distinct.
    expect(sim.captured).toHaveLength(N);
    const nonces = sim.captured.map((c) => c.nonce);
    expect(new Set(nonces).size).toBe(N);

    // Monotonically increasing 0..N-1 in submission order — the gate
    // serialises so each caller claims the next available nonce.
    for (let i = 0; i < N; i++) {
      expect(nonces[i]).toBe(i);
    }
  });

  it("serialises accountNextIndex calls — no two submits read the same nonce", async () => {
    // Larger delay amplifies the race window. Without the gate, the
    // second submit would call accountNextIndex BEFORE the first one's
    // signAndSend pool-accept lands; both would receive nonce=0 and
    // collide.
    const sim = makeChainSim({ signAcceptDelayMs: 30 });
    const client = new MateriosRpcClient({
      rpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error
    client["api"] = sim.api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;

    const N = 5;
    const startTimes: number[] = [];
    const submits: Promise<unknown>[] = [];
    for (let i = 0; i < N; i++) {
      startTimes.push(Date.now());
      submits.push(
        client.submitExtrinsic("intentSettlement", "settleClaim", []),
      );
    }
    await Promise.all(submits);

    // accountNextIndex must have been called N times (once per submit).
    expect(sim.accountNextIndex).toHaveBeenCalledTimes(N);

    // The nonces captured in pool-accept order must be 0..N-1 in
    // strict sequence — proves the gate held while each submit's
    // signAndSend got accepted.
    const nonces = sim.captured.map((c) => c.nonce);
    for (let i = 0; i < N; i++) {
      expect(nonces[i]).toBe(i);
    }
  });

  it("releases the gate even when signAndSend rejects", async () => {
    const accountNextIndex = vi
      .fn()
      .mockResolvedValueOnce({ toNumber: () => 0 })
      .mockResolvedValueOnce({ toNumber: () => 1 });

    let firstCall = true;
    const signAndSend = vi
      .fn()
      .mockImplementation(
        (_s: unknown, opts: { nonce: number }, cb: (r: any) => void) => {
          if (firstCall) {
            firstCall = false;
            // Simulate the RPC rejecting the tx outright (e.g. the
            // signer was banned). The gate MUST release so the next
            // queued submit can proceed.
            return Promise.reject(new Error("RPC rejected"));
          }
          // Second call: succeed normally.
          return new Promise<() => void>((resolve) => {
            setTimeout(() => {
              resolve(() => {});
              setTimeout(
                () =>
                  cb({
                    status: {
                      isInBlock: true,
                      asInBlock: { toHex: () => "0x" + "11".repeat(32) },
                    },
                    isError: false,
                  }),
                5,
              );
            }, 5);
          });
        },
      );

    const ext = {
      hash: { toHex: () => "0x" + "ff".repeat(32) },
      signAndSend,
    };
    const api = {
      tx: { intentSettlement: { settleClaim: () => ext } },
      rpc: { system: { accountNextIndex } },
    };
    const client = new MateriosRpcClient({
      rpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error
    client["api"] = api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;

    // First submit fails; second submit must NOT hang waiting on a
    // never-released gate.
    const r1 = client
      .submitExtrinsic("intentSettlement", "settleClaim", [])
      .catch((e) => ({ failed: true, msg: (e as Error).message }));
    const r2 = client.submitExtrinsic(
      "intentSettlement",
      "settleClaim",
      [],
    );

    const [out1, out2] = await Promise.all([r1, r2]);
    expect(out1).toEqual({ failed: true, msg: "RPC rejected" });
    expect(out2).toBeTruthy();
  });

  it("disconnect() resets the nonce gate so a re-connect doesn't inherit a wedged state", async () => {
    const sim = makeChainSim({ signAcceptDelayMs: 5 });
    const client = new MateriosRpcClient({
      rpcUrl: "ws://stub",
      signerUri: "//Alice",
    });
    // @ts-expect-error
    client["api"] = sim.api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;
    // @ts-expect-error — preset a wedged gate
    client["nonceChain"] = new Promise<void>(() => {
      // never resolves
    });
    await client.disconnect();
    // After disconnect the gate must be a fresh resolved Promise.
    // We re-instate api+signer to drive a final submit which would have
    // hung on the wedged gate.
    // @ts-expect-error
    client["api"] = sim.api as any;
    // @ts-expect-error
    client["signer"] = { address: "5GrwvaEF" } as any;
    const result = await client.submitExtrinsic(
      "intentSettlement",
      "settleClaim",
      [],
    );
    expect(result).toBeTruthy();
  });
});
