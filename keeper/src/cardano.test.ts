import { describe, it, expect } from "vitest";
import { buildBatchTx, createMeshCardanoProvider } from "./cardano.js";
import type { Voucher, BatchFairnessProof, HexString } from "@fluxpointstudios/materios-intent-settlement-sdk";
import { computeKeeperFeeLovelace } from "@fluxpointstudios/materios-intent-settlement-sdk";

const sampleVoucher: Voucher = {
  claimId: ("0x" + "aa".repeat(32)) as HexString,
  policyId: ("0x" + "bb".repeat(32)) as HexString,
  beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1xyz"),
  amountAda: 10_000_000n,
  batchFairnessProofDigest: ("0x" + "cc".repeat(32)) as HexString,
  issuedBlock: 1000,
  expirySlotCardano: 5_000_000n,
  committeeSigs: [],
};

const sampleBfpr: BatchFairnessProof = {
  batchBlockRange: [990, 1000],
  sortedIntentIds: [("0x" + "dd".repeat(32)) as HexString],
  requestedAmountsAda: [20_000_000n],
  poolBalanceAda: 100_000_000n,
  proRataScaleBps: 5000,
  awardedAmountsAda: [10_000_000n],
};

describe("buildBatchTx", () => {
  it("rejects incorrect keeper fee (prevents mis-specified fee output)", async () => {
    await expect(
      buildBatchTx({
        voucher: sampleVoucher,
        fairnessProof: sampleBfpr,
        keeperAddr: "addr_test1keeper",
        keeperFeeLovelace: 1n, // wrong
        policyScriptCbor: "0x00" as HexString,
        poolUtxoRef: { txHash: ("0x" + "00".repeat(32)) as HexString, outputIndex: 0 },
        policyUtxoRefs: [],
        metadataLabel8746Payload: {},
      }),
    ).rejects.toThrow(/spec §5.4/);
  });

  it("returns deterministic placeholder cbor when fee matches", async () => {
    const totalAwarded = sampleBfpr.awardedAmountsAda.reduce((a, b) => a + b, 0n);
    const fee = computeKeeperFeeLovelace(totalAwarded);

    const res = await buildBatchTx({
      voucher: sampleVoucher,
      fairnessProof: sampleBfpr,
      keeperAddr: "addr_test1keeper",
      keeperFeeLovelace: fee,
      policyScriptCbor: "0x00" as HexString,
      poolUtxoRef: { txHash: ("0x" + "00".repeat(32)) as HexString, outputIndex: 0 },
      policyUtxoRefs: [],
      metadataLabel8746Payload: {},
    });

    expect(res.feeLovelace).toBe(fee);
    expect(res.unsignedTxCborHex.length).toBeGreaterThan(4);
    // Deterministic: re-run produces same cbor.
    const res2 = await buildBatchTx({
      voucher: sampleVoucher,
      fairnessProof: sampleBfpr,
      keeperAddr: "addr_test1keeper",
      keeperFeeLovelace: fee,
      policyScriptCbor: "0x00" as HexString,
      poolUtxoRef: { txHash: ("0x" + "00".repeat(32)) as HexString, outputIndex: 0 },
      policyUtxoRefs: [],
      metadataLabel8746Payload: {},
    });
    expect(res.unsignedTxCborHex).toBe(res2.unsignedTxCborHex);
  });
});

describe("createMeshCardanoProvider safety", () => {
  it("refuses mainnet without explicit enableMainnet flag", async () => {
    await expect(
      createMeshCardanoProvider({
        network: "mainnet",
        ogmiosUrl: "wss://ogmios.saturnswap.io",
        kupoUrl: "https://kupo.saturnswap.io",
      }),
    ).rejects.toThrow(/enableMainnet/);
  });
});
