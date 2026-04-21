/**
 * Keeper persistent state. JSON on disk, same shape as the committee daemon's
 * daemon-state.json (see operator-kit@cdc35c2). Designed for crash-recovery:
 * any in-flight submission can be resumed.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import type { KeeperSubmission, ClaimId, BlockNumber, HexString } from "@fluxpointstudios/materios-intent-settlement-sdk";

export interface KeeperPersistedState {
  cursor: BlockNumber;
  submissions: Record<ClaimId, KeeperSubmission>;
  // Dedup per §5.6: (claim_id, cardano_tx_hash) idempotency key.
  settledClaims: Record<ClaimId, HexString>;
  lastSeenCardanoSlot: bigint | null;
  updatedAt: string;
}

function emptyState(): KeeperPersistedState {
  return {
    cursor: 0,
    submissions: {},
    settledClaims: {},
    lastSeenCardanoSlot: null,
    updatedAt: new Date().toISOString(),
  };
}

export class KeeperStateStore {
  private state: KeeperPersistedState;
  private readonly filepath: string;
  private writePending: Promise<void> | null = null;

  constructor(filepath: string, initial?: KeeperPersistedState) {
    this.filepath = filepath;
    this.state = initial ?? emptyState();
  }

  static async load(filepath: string): Promise<KeeperStateStore> {
    try {
      const raw = await fs.readFile(filepath, "utf-8");
      const parsed = JSON.parse(raw, (key, value) => {
        if (key === "lastSeenCardanoSlot" && typeof value === "string") {
          return BigInt(value);
        }
        return value;
      }) as KeeperPersistedState;
      return new KeeperStateStore(filepath, parsed);
    } catch (err: any) {
      if (err.code === "ENOENT") {
        return new KeeperStateStore(filepath);
      }
      throw err;
    }
  }

  get snapshot(): KeeperPersistedState {
    return this.state;
  }

  async save(): Promise<void> {
    this.state.updatedAt = new Date().toISOString();
    const data = JSON.stringify(this.state, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2);
    // Write atomically — write to .tmp and rename.
    const dir = path.dirname(this.filepath);
    await fs.mkdir(dir, { recursive: true });
    const tmp = `${this.filepath}.tmp`;
    await fs.writeFile(tmp, data);
    await fs.rename(tmp, this.filepath);
  }

  /** Queue a write; coalesces concurrent callers. */
  async flush(): Promise<void> {
    if (this.writePending) return this.writePending;
    this.writePending = this.save().finally(() => {
      this.writePending = null;
    });
    return this.writePending;
  }

  recordObservation(claimId: ClaimId, atBlock: BlockNumber): KeeperSubmission {
    const existing = this.state.submissions[claimId];
    if (existing) return existing;
    const fresh: KeeperSubmission = {
      claimId,
      cardanoTxHash: null,
      attempts: 0,
      firstSeenBlock: atBlock,
      state: "observed",
      feeBumpCount: 0,
    };
    this.state.submissions[claimId] = fresh;
    return fresh;
  }

  updateSubmission(claimId: ClaimId, patch: Partial<KeeperSubmission>): KeeperSubmission {
    const cur = this.state.submissions[claimId];
    if (!cur) throw new Error(`no submission for ${claimId}`);
    const next = { ...cur, ...patch };
    this.state.submissions[claimId] = next;
    return next;
  }

  markSettled(claimId: ClaimId, cardanoTxHash: HexString): void {
    this.state.settledClaims[claimId] = cardanoTxHash;
    if (this.state.submissions[claimId]) {
      this.state.submissions[claimId]!.state = "confirmed";
      this.state.submissions[claimId]!.cardanoTxHash = cardanoTxHash;
    }
  }

  isAlreadySettled(claimId: ClaimId): HexString | null {
    return this.state.settledClaims[claimId] ?? null;
  }

  setCursor(block: BlockNumber): void {
    if (block > this.state.cursor) this.state.cursor = block;
  }

  setLastSeenCardanoSlot(slot: bigint): void {
    this.state.lastSeenCardanoSlot = slot;
  }
}
