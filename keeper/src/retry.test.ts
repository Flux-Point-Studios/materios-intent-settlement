import { describe, it, expect, vi } from "vitest";
import { retryWithBackoff, feeBumpFactor } from "./retry.js";

describe("retryWithBackoff", () => {
  it("returns on first success", async () => {
    const op = vi.fn().mockResolvedValue("ok");
    const res = await retryWithBackoff(op, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 10 });
    expect(res).toBe("ok");
    expect(op).toHaveBeenCalledTimes(1);
  });

  it("retries on failure and eventually resolves", async () => {
    const op = vi.fn()
      .mockRejectedValueOnce(new Error("boom"))
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValue("ok");
    const res = await retryWithBackoff(op, {
      maxAttempts: 3,
      baseDelayMs: 1,
      maxDelayMs: 10,
      jitterFn: () => 0,
    });
    expect(res).toBe("ok");
    expect(op).toHaveBeenCalledTimes(3);
  });

  it("throws after maxAttempts failures", async () => {
    const op = vi.fn().mockRejectedValue(new Error("nope"));
    await expect(
      retryWithBackoff(op, {
        maxAttempts: 2,
        baseDelayMs: 1,
        maxDelayMs: 2,
        jitterFn: () => 0,
      }),
    ).rejects.toThrow("nope");
    expect(op).toHaveBeenCalledTimes(2);
  });

  it("calls onAttempt with attempt + delay", async () => {
    const onAttempt = vi.fn();
    const op = vi.fn().mockRejectedValueOnce(new Error("x")).mockResolvedValue("ok");
    await retryWithBackoff(op, {
      maxAttempts: 2,
      baseDelayMs: 10,
      maxDelayMs: 100,
      jitterFn: () => 0.5,
      onAttempt,
    });
    expect(onAttempt).toHaveBeenCalledTimes(1);
    expect(onAttempt.mock.calls[0][0]).toBe(0);
    expect(onAttempt.mock.calls[0][1]).toBeGreaterThanOrEqual(5); // 10 * (0.5 + 0.25)
  });
});

describe("feeBumpFactor", () => {
  it("returns 1 for attempt 0", () => {
    expect(feeBumpFactor(0)).toBe(1);
  });

  it("is monotonically nondecreasing and capped at 3x", () => {
    let prev = 0;
    for (let a = 0; a < 20; a++) {
      const f = feeBumpFactor(a);
      expect(f).toBeGreaterThanOrEqual(prev);
      expect(f).toBeLessThanOrEqual(3);
      prev = f;
    }
  });
});
