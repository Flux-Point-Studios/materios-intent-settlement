import { describe, it, expect } from "vitest";
import {
  initialHaltState,
  stepHaltDetector,
  shouldPauseAttestations,
  shouldPublishExtension,
} from "./halt.js";

const cfg = (overrides: Partial<Parameters<typeof stepHaltDetector>[2]> = {}) => ({
  haltDetectSeconds: 60,
  haltRecoverBlocks: 3,
  haltExtensionThresholdSeconds: 86_400,
  ...overrides,
});

describe("stepHaltDetector", () => {
  it("transitions none → entered_halt after 60s gap", () => {
    let now = 1000;
    const clock = () => now;
    let s = initialHaltState();

    // First heartbeat: fresh block at t=1000.
    ({ state: s } = stepHaltDetector(s, 1000, cfg({ clock })));
    expect(s.inHalt).toBe(false);

    // Jump 30s: still healthy.
    now = 1030;
    ({ state: s } = stepHaltDetector(s, 1000, cfg({ clock })));
    expect(s.inHalt).toBe(false);

    // Jump past 60s: halt triggered.
    now = 1061;
    const step = stepHaltDetector(s, 1000, cfg({ clock }));
    s = step.state;
    expect(s.inHalt).toBe(true);
    expect(step.transition.kind).toBe("entered_halt");
  });

  it("stays halted until 3 consecutive recovery blocks", () => {
    let now = 1000;
    const clock = () => now;
    let s = initialHaltState();
    s.inHalt = true;
    s.haltStartedAt = 900;
    s.lastCardanoBlockAt = 900;

    // Fresh block #1
    now = 1010;
    ({ state: s } = stepHaltDetector(s, 910, cfg({ clock })));
    expect(s.inHalt).toBe(true);
    expect(s.consecutiveRecoveryBlocks).toBe(1);

    // Fresh block #2
    now = 1020;
    ({ state: s } = stepHaltDetector(s, 920, cfg({ clock })));
    expect(s.inHalt).toBe(true);
    expect(s.consecutiveRecoveryBlocks).toBe(2);

    // Fresh block #3 triggers recovery
    now = 1030;
    const step = stepHaltDetector(s, 930, cfg({ clock }));
    s = step.state;
    expect(s.inHalt).toBe(false);
    expect(step.transition.kind).toBe("recovered");
    if (step.transition.kind === "recovered") {
      expect(step.transition.exceededExtensionThreshold).toBe(false);
    }
  });

  it("tags long halt (>24h) as requiring DegradationExtension", () => {
    let now = 900 + 25 * 3600;
    const clock = () => now;
    let s = initialHaltState();
    s.inHalt = true;
    s.haltStartedAt = 900;
    s.lastCardanoBlockAt = 900;

    // 3 recovery blocks in quick succession.
    for (let i = 1; i <= 3; i++) {
      const stepRes = stepHaltDetector(s, 900 + i, cfg({ clock }));
      s = stepRes.state;
      if (i === 3) {
        expect(stepRes.transition.kind).toBe("recovered");
        if (stepRes.transition.kind === "recovered") {
          expect(stepRes.transition.exceededExtensionThreshold).toBe(true);
          expect(shouldPublishExtension(stepRes.transition)).toBe(true);
        }
      }
    }
  });

  it("resets recovery counter when no fresh block in a tick", () => {
    let now = 1000;
    const clock = () => now;
    let s = initialHaltState();
    s.inHalt = true;
    s.haltStartedAt = 900;
    s.lastCardanoBlockAt = 900;

    // Progress #1
    now = 1010;
    ({ state: s } = stepHaltDetector(s, 910, cfg({ clock })));
    expect(s.consecutiveRecoveryBlocks).toBe(1);

    // Stall (no new block)
    now = 1020;
    ({ state: s } = stepHaltDetector(s, 910, cfg({ clock })));
    expect(s.consecutiveRecoveryBlocks).toBe(0);
    expect(s.inHalt).toBe(true);
  });

  it("shouldPauseAttestations mirrors inHalt", () => {
    const s = initialHaltState();
    expect(shouldPauseAttestations(s)).toBe(false);
    expect(shouldPauseAttestations({ ...s, inHalt: true })).toBe(true);
  });
});
