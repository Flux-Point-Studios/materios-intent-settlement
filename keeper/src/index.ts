/**
 * @fluxpointstudios/materios-intent-settlement-keeper
 *
 * Public module entry. Exports both the keeper primitives and the committee
 * daemon.
 */

export { Keeper } from "./keeper.js";
export type { KeeperDeps, KeeperMetrics } from "./keeper.js";

export { KeeperStateStore } from "./state.js";
export type { KeeperPersistedState } from "./state.js";

export {
  buildBatchTx,
  createMeshCardanoProvider,
} from "./cardano.js";
export type {
  ICardanoProvider,
  CardanoProviderOptions,
  BuildBatchTxInput,
  BuildBatchTxResult,
  SubmittedTx,
} from "./cardano.js";

export {
  initialHaltState,
  stepHaltDetector,
  shouldPauseAttestations,
  shouldPublishExtension,
} from "./halt.js";
export type { HaltState, HaltTransition, HaltDetectorConfig } from "./halt.js";

export { retryWithBackoff, feeBumpFactor } from "./retry.js";

export { CommitteeDaemon } from "./daemon/index.js";
export type {
  CommitteeDaemonDeps,
  AttestationOutput,
  DegradationExtensionPayload,
} from "./daemon/index.js";
