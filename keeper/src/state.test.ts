import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { KeeperStateStore } from "./state.js";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

describe("KeeperStateStore", () => {
  let dir: string;
  let file: string;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "keeper-state-"));
    file = path.join(dir, "state.json");
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("loads empty state if file missing", async () => {
    const store = await KeeperStateStore.load(file);
    expect(store.snapshot.cursor).toBe(0);
    expect(Object.keys(store.snapshot.submissions)).toEqual([]);
  });

  it("recordObservation is idempotent per claim", () => {
    const store = new KeeperStateStore(file);
    const a = store.recordObservation("0xaaa" as `0x${string}`, 10);
    const b = store.recordObservation("0xaaa" as `0x${string}`, 20);
    expect(a).toEqual(b);
    expect(a.firstSeenBlock).toBe(10);
  });

  it("updateSubmission throws for unknown claim", () => {
    const store = new KeeperStateStore(file);
    expect(() => store.updateSubmission("0xzzz" as `0x${string}`, { state: "failed" })).toThrow();
  });

  it("markSettled + isAlreadySettled", () => {
    const store = new KeeperStateStore(file);
    store.recordObservation("0xaaa" as `0x${string}`, 1);
    store.markSettled("0xaaa" as `0x${string}`, ("0x" + "bb".repeat(32)) as `0x${string}`);
    expect(store.isAlreadySettled("0xaaa" as `0x${string}`)).toBe(
      "0x" + "bb".repeat(32),
    );
    expect(store.isAlreadySettled("0xccc" as `0x${string}`)).toBeNull();
  });

  it("setCursor only advances", () => {
    const store = new KeeperStateStore(file);
    store.setCursor(5);
    store.setCursor(3);
    expect(store.snapshot.cursor).toBe(5);
    store.setCursor(10);
    expect(store.snapshot.cursor).toBe(10);
  });

  it("round-trips through save/load", async () => {
    const store = new KeeperStateStore(file);
    store.recordObservation("0xaaa" as `0x${string}`, 1);
    store.setLastSeenCardanoSlot(12345n);
    await store.flush();

    const loaded = await KeeperStateStore.load(file);
    expect(loaded.snapshot.submissions["0xaaa"]?.firstSeenBlock).toBe(1);
    expect(loaded.snapshot.lastSeenCardanoSlot).toBe(12345n);
  });
});
