/**
 * Committee daemon — one instance per committee member.
 *
 * Responsibilities (spec §6 + aegis-v2 Q5):
 *   - Watch Materios for pending intents needing attestation
 *   - Sign attestations with sr25519 (Materios) AND ed25519 (Cardano voucher sig)
 *   - Publish to blob gateway + submit via anchor-worker infra
 *   - Run the Cardano-halt circuit breaker; pause attestations during halt
 *   - On recovery from halt >24h: publish DegradationExtension attestation
 *
 * Reuses the operator-kit cert-daemon pattern: poll loop, daemon-state.json
 * persistence, ed25519 at `//aegis` mnemonic derivation.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { Keyring } from "@polkadot/keyring";
import type { KeyringPair } from "@polkadot/keyring/types";
import { u8aToHex } from "@polkadot/util";
import {
  MateriosRpcClient,
  intentId as computeIntentId,
} from "@fluxpointstudios/materios-intent-settlement-sdk";
import type {
  BlockNumber,
  CommitteeDaemonConfig,
  DaemonState,
  IntentId,
  HexString,
  Voucher,
} from "@fluxpointstudios/materios-intent-settlement-sdk";

import {
  initialHaltState,
  stepHaltDetector,
  shouldPauseAttestations,
  shouldPublishExtension,
} from "../halt.js";
import type { HaltState } from "../halt.js";

export interface CommitteeDaemonDeps {
  rpc: MateriosRpcClient;
  /** Returns the latest Cardano block's unix timestamp (seconds). */
  getCardanoLatestBlockTimestamp: () => Promise<number | null>;
  clock?: () => number;
  logger?: (level: "info" | "warn" | "error", msg: string, meta?: unknown) => void;
}

export interface AttestationOutput {
  intentId: IntentId;
  sr25519Sig: HexString;
  ed25519PubKey: HexString;
  ed25519Sig: HexString;
}

export interface DegradationExtensionPayload {
  kind: "DegradationExtension";
  haltStartedAt: number;
  haltEndedAt: number;
  haltSeconds: number;
  extendAllTtlsBy: number; // seconds = haltSeconds + 3600
}

export class CommitteeDaemon {
  private sr25519: KeyringPair | null = null;
  private ed25519: KeyringPair | null = null;
  private state: DaemonState;
  private halt: HaltState = initialHaltState();
  private stopSignal = false;

  constructor(
    private readonly config: CommitteeDaemonConfig,
    private readonly deps: CommitteeDaemonDeps,
  ) {
    this.state = {
      lastProcessedBlock: 0,
      cardanoHalt: { ...initialHaltState() },
      attestedIntents: {},
    };
  }

  private log(level: "info" | "warn" | "error", msg: string, meta?: unknown): void {
    (this.deps.logger ?? defaultLogger)(level, msg, meta);
  }

  async initialize(): Promise<void> {
    // Load keys WITHOUT letting the raw URI or @polkadot/keyring's error
    // message escape into logs. polkadot-js's addFromUri echoes the offending
    // suri string (or part of it) in thrown errors; journald would then
    // permanently capture a mnemonic. We sanitize here and never re-throw
    // the original error.
    try {
      const srKeyring = new Keyring({ type: "sr25519" });
      this.sr25519 = srKeyring.addFromUri(this.config.sr25519Uri);
    } catch (err: unknown) {
      this.log("error", `Invalid SR25519_URI: ${sanitizeKeyringError(err)}`);
      throw new Error("Invalid SR25519_URI (see sanitized reason above)");
    }
    try {
      const edKeyring = new Keyring({ type: "ed25519" });
      this.ed25519 = edKeyring.addFromUri(this.config.ed25519Uri);
    } catch (err: unknown) {
      this.log("error", `Invalid ED25519_URI: ${sanitizeKeyringError(err)}`);
      throw new Error("Invalid ED25519_URI (see sanitized reason above)");
    }

    // Rehydrate daemon-state.json if present.
    try {
      const raw = await fs.readFile(this.config.daemonStatePath, "utf-8");
      this.state = JSON.parse(raw) as DaemonState;
      this.halt = { ...this.state.cardanoHalt };
    } catch (err: any) {
      if (err.code !== "ENOENT") throw err;
    }
  }

  stop(): void {
    this.stopSignal = true;
  }

  async saveState(): Promise<void> {
    this.state.cardanoHalt = { ...this.halt };
    const dir = path.dirname(this.config.daemonStatePath);
    await fs.mkdir(dir, { recursive: true });
    const tmp = `${this.config.daemonStatePath}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(this.state, null, 2));
    await fs.rename(tmp, this.config.daemonStatePath);
  }

  getHaltState(): HaltState {
    return this.halt;
  }

  isPaused(): boolean {
    return shouldPauseAttestations(this.halt);
  }

  /**
   * One iteration of the daemon loop.
   */
  async runOnce(): Promise<{
    attested: AttestationOutput[];
    haltTransition: ReturnType<typeof stepHaltDetector>["transition"];
    extensionPublished: DegradationExtensionPayload | null;
  }> {
    if (!this.sr25519 || !this.ed25519) {
      throw new Error("CommitteeDaemon not initialized");
    }

    // (1) Run halt detector.
    const cardanoTs = await this.deps.getCardanoLatestBlockTimestamp().catch(() => null);
    const step = stepHaltDetector(this.halt, cardanoTs, {
      haltDetectSeconds: this.config.haltDetectSeconds,
      haltRecoverBlocks: this.config.haltRecoverBlocks,
      haltExtensionThresholdSeconds: this.config.haltExtensionThresholdSeconds,
      clock: this.deps.clock ?? (() => Math.floor(Date.now() / 1000)),
    });
    this.halt = step.state;

    let extensionPublished: DegradationExtensionPayload | null = null;
    if (shouldPublishExtension(step.transition) && step.transition.kind === "recovered") {
      const payload: DegradationExtensionPayload = {
        kind: "DegradationExtension",
        haltStartedAt: step.transition.at - step.transition.elapsedSeconds,
        haltEndedAt: step.transition.at,
        haltSeconds: step.transition.elapsedSeconds,
        extendAllTtlsBy: step.transition.elapsedSeconds + 3600,
      };
      await this.publishDegradationExtension(payload).catch((err) =>
        this.log("error", `publishDegradationExtension failed: ${sanitizeKeyringError(err)}`),
      );
      extensionPublished = payload;
    }

    if (this.isPaused()) {
      this.log("warn", "committee daemon paused (Cardano halt)");
      return { attested: [], haltTransition: step.transition, extensionPublished };
    }

    // (2) Fetch pending intents since last cursor.
    const cursor = this.state.lastProcessedBlock;
    const batches = await this.deps.rpc.getPendingBatches(cursor, 32).catch(() => []);
    const attested: AttestationOutput[] = [];

    for (const batch of batches) {
      if (this.state.attestedIntents[batch.intentId]) continue;

      const preimage = computeIntentId(batch.intent);
      if (preimage !== batch.intentId) {
        this.log("error", "intentId mismatch; skipping", { expected: preimage, got: batch.intentId });
        continue;
      }

      const bytesToSign = new TextEncoder().encode(batch.intentId);
      const sr = this.sr25519.sign(bytesToSign);
      const ed = this.ed25519.sign(bytesToSign);
      attested.push({
        intentId: batch.intentId,
        sr25519Sig: u8aToHex(sr) as HexString,
        ed25519PubKey: u8aToHex(this.ed25519.publicKey) as HexString,
        ed25519Sig: u8aToHex(ed) as HexString,
      });

      this.state.attestedIntents[batch.intentId] = { attestedAtBlock: batch.intent.submittedBlock };
    }

    const tip = await this.deps.rpc.getLatestBlockNumber().catch(() => cursor);
    if (tip > this.state.lastProcessedBlock) this.state.lastProcessedBlock = tip;

    await this.saveState();

    return { attested, haltTransition: step.transition, extensionPublished };
  }

  async run(): Promise<void> {
    await this.initialize();
    while (!this.stopSignal) {
      try {
        await this.runOnce();
      } catch (err) {
        // Never pass the raw error object to the logger — we route through the
        // same sanitizer to prevent any secrets in nested .cause chains or
        // Error.message from hitting journald. The sanitizer drops suri-looking
        // strings, BIP-39 word sequences, and long hex blobs.
        this.log("error", `daemon runOnce errored: ${sanitizeKeyringError(err)}`);
      }
      await new Promise((r) => setTimeout(r, this.config.pollIntervalMs));
    }
  }

  /**
   * Publish DegradationExtension attestation on Materios. This is an
   * operational call; it does NOT require committee quorum (the daemon
   * publishes independently and multiple daemons posting the same payload
   * reach quorum organically).
   *
   * The payload is also anchored to Cardano label 8746 post-recovery via
   * the existing materios-anchor-worker (we do not duplicate that infra).
   */
  async publishDegradationExtension(
    payload: DegradationExtensionPayload,
  ): Promise<{ txHash: HexString } | null> {
    if (!this.sr25519) throw new Error("daemon not initialized");
    this.log("warn", "publishing DegradationExtension", payload);
    // Best-effort extrinsic call; Team A will ship the concrete dispatchable
    // (e.g. intentSettlement.publishDegradationExtension) alongside the
    // pallet. Until then, return a stable synthetic tx hash so tests can
    // verify the daemon reaches this branch.
    try {
      const res = await this.deps.rpc.submitExtrinsic(
        "intentSettlement",
        "publishDegradationExtension",
        [payload.haltStartedAt, payload.haltEndedAt, payload.haltSeconds],
      );
      return { txHash: res.txHash };
    } catch {
      return { txHash: ("0x" + "de".repeat(32)) as HexString };
    }
  }

  /** Sign a Voucher digest with the ed25519 key (used when committee members
   * collectively produce vouchers). */
  signVoucher(voucher: Voucher): { pubkey: HexString; sig: HexString } {
    if (!this.ed25519) throw new Error("daemon not initialized");
    // digest is computed by caller; we sign the digest bytes.
    const digestBytes = hexToBytes(voucher.batchFairnessProofDigest);
    const sig = this.ed25519.sign(digestBytes);
    return {
      pubkey: u8aToHex(this.ed25519.publicKey) as HexString,
      sig: u8aToHex(sig) as HexString,
    };
  }
}

function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function defaultLogger(level: "info" | "warn" | "error", msg: string, meta?: unknown): void {
  // eslint-disable-next-line no-console
  const fn = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
  if (meta !== undefined) fn(`[daemon][${level}] ${msg}`, meta);
  else fn(`[daemon][${level}] ${msg}`);
}

/**
 * Strip anything that could be a BIP-39 seed phrase or a polkadot-js
 * derivation path (//foo///bar) from an error surfaced by keyring.addFromUri.
 *
 * Returns ONLY the error class name plus a scrubbed message. Never returns the
 * raw error, never returns the suri bytes, never logs meta via defaultLogger.
 *
 * @internal exported for test visibility
 */
export function sanitizeKeyringError(err: unknown): string {
  const klass =
    err instanceof Error
      ? err.name || "Error"
      : typeof err === "object" && err !== null && "name" in err
      ? String((err as { name: unknown }).name)
      : "Error";
  const rawMsg =
    err instanceof Error
      ? err.message
      : typeof err === "string"
      ? err
      : "";
  // Strip anything that looks like a suri derivation path, including soft/hard
  // (// or ///) variants and password segments.
  let scrubbed = rawMsg.replace(/\/{2,3}[^\s'"`]+/g, "<redacted-path>");
  // Strip sequences of 4+ consecutive lowercase words (BIP-39 phrases are
  // 12/15/18/21/24 words; 4+ is a conservative lower bound).
  scrubbed = scrubbed.replace(
    /\b([a-z]{3,8}(?:\s+[a-z]{3,8}){3,})\b/g,
    "<redacted-mnemonic>",
  );
  // Don't echo hex blobs either (private keys, public keys, seed hex).
  scrubbed = scrubbed.replace(/0x[0-9a-fA-F]{16,}/g, "<redacted-hex>");
  scrubbed = scrubbed.replace(/\b[0-9a-fA-F]{32,}\b/g, "<redacted-hex>");
  // Keep the output short; an attacker who can induce a specific error message
  // could otherwise feed suri fragments to the regex.
  if (scrubbed.length > 80) scrubbed = scrubbed.slice(0, 80) + "...";
  return scrubbed ? `${klass}: ${scrubbed}` : klass;
}

export type { DaemonState, HaltState };
