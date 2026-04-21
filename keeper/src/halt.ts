/**
 * Cardano-halt circuit breaker per aegis v2 Q5.
 *
 * Two state machines:
 *   - Committee-daemon side: pauses signing while Cardano is degraded.
 *   - Keeper side: refuses to submit batches while degraded (and retries).
 *
 * Both share one detector. Source of truth is time-since-last-Cardano-block.
 */

export interface HaltDetectorConfig {
  haltDetectSeconds: number; // 60
  haltRecoverBlocks: number; // 3
  haltExtensionThresholdSeconds: number; // 86400
  clock?: () => number; // unix seconds; default Date.now()/1000
}

export interface HaltState {
  inHalt: boolean;
  haltStartedAt: number | null;
  haltCumulativeSeconds: number;
  lastCardanoBlockAt: number | null;
  consecutiveRecoveryBlocks: number;
  extensionPublishedForHaltId?: string;
}

export function initialHaltState(): HaltState {
  return {
    inHalt: false,
    haltStartedAt: null,
    haltCumulativeSeconds: 0,
    lastCardanoBlockAt: null,
    consecutiveRecoveryBlocks: 0,
  };
}

export type HaltTransition =
  | { kind: "none"; inHalt: boolean }
  | { kind: "entered_halt"; at: number; inHalt: boolean }
  | { kind: "recovered"; at: number; elapsedSeconds: number; exceededExtensionThreshold: boolean; inHalt: boolean };

/**
 * Feed the detector two signals: (a) the current wall-clock time, (b) the
 * timestamp of the latest Cardano block (0 if unknown). Returns the state
 * transition (if any) and an updated state.
 */
export function stepHaltDetector(
  prev: HaltState,
  latestCardanoBlockTimestamp: number | null,
  config: HaltDetectorConfig,
): { state: HaltState; transition: HaltTransition } {
  const now = config.clock ? config.clock() : Math.floor(Date.now() / 1000);
  const next: HaltState = { ...prev };
  next.lastCardanoBlockAt = latestCardanoBlockTimestamp ?? prev.lastCardanoBlockAt;
  let transition: HaltTransition = { kind: "none", inHalt: prev.inHalt };

  const lastBlockAt = next.lastCardanoBlockAt;
  if (lastBlockAt === null) {
    // Never seen a block; nothing to compare. Keep state.
    return { state: next, transition };
  }

  const delta = now - lastBlockAt;

  if (!prev.inHalt) {
    if (delta >= config.haltDetectSeconds) {
      next.inHalt = true;
      next.haltStartedAt = now;
      next.consecutiveRecoveryBlocks = 0;
      transition = { kind: "entered_halt", at: now, inHalt: true };
    }
  } else {
    // We are in halt. Check if a fresh block landed this tick.
    const sawFreshBlock =
      prev.lastCardanoBlockAt !== null &&
      latestCardanoBlockTimestamp !== null &&
      latestCardanoBlockTimestamp > prev.lastCardanoBlockAt;
    if (sawFreshBlock) {
      next.consecutiveRecoveryBlocks = prev.consecutiveRecoveryBlocks + 1;
      if (next.consecutiveRecoveryBlocks >= config.haltRecoverBlocks) {
        const startedAt = prev.haltStartedAt ?? now;
        const elapsed = now - startedAt;
        next.haltCumulativeSeconds = prev.haltCumulativeSeconds + elapsed;
        next.inHalt = false;
        next.haltStartedAt = null;
        next.consecutiveRecoveryBlocks = 0;
        transition = {
          kind: "recovered",
          at: now,
          elapsedSeconds: elapsed,
          exceededExtensionThreshold: elapsed >= config.haltExtensionThresholdSeconds,
          inHalt: false,
        };
      }
    } else {
      // No fresh block; stay in halt.
      next.consecutiveRecoveryBlocks = 0;
    }
  }

  transition.inHalt = next.inHalt;
  return { state: next, transition };
}

/**
 * Helper to compute "should we pause attestations?" from state.
 */
export function shouldPauseAttestations(state: HaltState): boolean {
  return state.inHalt;
}

/**
 * Should the committee publish a DegradationExtension attestation for this
 * recovery event?
 */
export function shouldPublishExtension(transition: HaltTransition): boolean {
  return transition.kind === "recovered" && transition.exceededExtensionThreshold;
}
