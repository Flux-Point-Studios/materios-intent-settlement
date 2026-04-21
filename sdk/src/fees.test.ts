import { describe, it, expect } from "vitest";
import {
  computeKeeperFeeLovelace,
  feeOutputLovelace,
  isEconomic,
  KEEPER_FEE_FLOOR_LOVELACE,
} from "./fees.js";

describe("computeKeeperFeeLovelace (spec §5.4)", () => {
  it("zero batch → 2% cap wins (0 < 0.5 ADA)", () => {
    expect(computeKeeperFeeLovelace(0n)).toBe(0n);
  });

  it("small batch: 2% cap is lower than 0.5+50bps for small values", () => {
    // At 10 ADA awarded (10_000_000 lovelace):
    //   2% cap    = 200_000 (0.2 ADA)
    //   bps-based = 500_000 + 50_000 = 550_000
    //   min = 200_000
    expect(computeKeeperFeeLovelace(10_000_000n)).toBe(200_000n);
  });

  it("break-even: at 25 ADA, 2% cap = 500_000 matches floor", () => {
    // 2% of 25 ADA = 0.5 ADA = 500_000
    expect(computeKeeperFeeLovelace(25_000_000n)).toBe(500_000n);
  });

  it("large batch: bps-based undercuts 2%", () => {
    // At 10_000 ADA awarded:
    //   2% cap    = 200_000_000 (200 ADA)
    //   bps-based = 500_000 + 50_000_000 = 50_500_000 (~50.5 ADA)
    //   min = 50_500_000
    expect(computeKeeperFeeLovelace(10_000_000_000n)).toBe(50_500_000n);
  });

  it("rejects negative input", () => {
    expect(() => computeKeeperFeeLovelace(-1n)).toThrow();
  });

  it("feeOutputLovelace matches computeKeeperFeeLovelace in v1", () => {
    expect(feeOutputLovelace(100_000_000n)).toBe(
      computeKeeperFeeLovelace(100_000_000n),
    );
  });

  it("fee floor constant is 0.5 ADA", () => {
    expect(KEEPER_FEE_FLOOR_LOVELACE).toBe(500_000n);
  });
});

describe("isEconomic", () => {
  it("tiny batch + min-fee 0.3 ADA → economic at small batch 2% of 20 ADA = 0.4 ADA", () => {
    // awarded = 20 ADA → 2% cap = 400_000; bps = 500_000 + 100_000 = 600_000; fee = 400_000
    // minTxFee = 300_000 → economic.
    expect(isEconomic(20_000_000n, 300_000n)).toBe(true);
  });

  it("tiny batch + high min-fee → NOT economic", () => {
    // awarded = 1 ADA → fee = 20_000; minTxFee = 200_000 → not economic
    expect(isEconomic(1_000_000n, 200_000n)).toBe(false);
  });
});
