/**
 * URI-leak regression tests (issue #9).
 *
 * @polkadot/keyring's addFromUri() throws errors whose `.message` can echo the
 * offending suri — if that message ever reaches console.error / stderr /
 * journald, a mnemonic is leaked permanently. This file is a
 * defense-in-depth regression net that proves:
 *
 *   1. Invalid SIGNER_URI does not end up in stderr when the daemon
 *      initialize() path runs.
 *   2. A thrown error whose message contains suri-looking substrings is
 *      fully sanitized by sanitizeKeyringError before being logged.
 *   3. The error re-thrown by initialize() does NOT contain the suri.
 *
 * The sanitizer is the single chokepoint; both CLI entrypoints and the
 * daemon's runOnce catch route their logging through it.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { CommitteeDaemon, sanitizeKeyringError } from "../index.js";

// A plausible-looking-but-invalid suri. We intentionally use 11 lowercase
// words so the BIP-39 word-sequence regex catches it, and a `//hard`
// derivation suffix so the suri-path regex catches that too.
const GARBAGE_SURI =
  "garbage mnemonic phrase here totally invalid keys noway noway noway noway noway//hard///pw";

describe("URI leak prevention (issue #9)", () => {
  beforeAll(async () => {
    await cryptoWaitReady();
  });

  it("test_invalid_signer_uri_does_not_leak_to_stderr: daemon initialize() with garbage SR25519_URI does NOT echo the URI anywhere", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "urileak-"));
    const logs: { level: string; msg: string; meta?: unknown }[] = [];
    const daemon = new CommitteeDaemon(
      {
        materiosRpcUrl: "ws://stub",
        cardanoOgmiosUrl: "wss://stub",
        sr25519Uri: GARBAGE_SURI,
        ed25519Uri: "//Alice//aegis",
        daemonStatePath: path.join(tmpDir, "ds.json"),
        haltDetectSeconds: 60,
        haltRecoverBlocks: 3,
        haltExtensionThresholdSeconds: 86400,
        pollIntervalMs: 10,
      },
      {
        rpc: {} as any,
        getCardanoLatestBlockTimestamp: async () => 0,
        logger: (level, msg, meta) => logs.push({ level, msg, meta }),
      },
    );

    let caught: Error | null = null;
    try {
      await daemon.initialize();
    } catch (e) {
      caught = e as Error;
    }

    // Must have thrown — garbage suri can't derive a valid key.
    expect(caught).not.toBeNull();

    // The re-thrown error message must NOT contain the URI.
    expect(caught?.message ?? "").not.toContain("garbage");
    expect(caught?.message ?? "").not.toContain("mnemonic");
    expect(caught?.message ?? "").not.toContain("//hard");
    expect(caught?.message ?? "").not.toContain("///pw");

    // Every captured log line must be URI-free.
    for (const entry of logs) {
      const line = `${entry.msg} ${JSON.stringify(entry.meta ?? null)}`;
      expect(line).not.toContain("garbage mnemonic phrase");
      expect(line).not.toContain("noway noway");
      expect(line).not.toContain("//hard");
      expect(line).not.toContain("///pw");
    }

    // And — crucially — the sanitized log MUST have been emitted, proving
    // we took the safe path (instead of silently swallowing the error).
    const errLogs = logs.filter((l) => l.level === "error");
    expect(errLogs.length).toBeGreaterThanOrEqual(1);
    expect(errLogs[0]!.msg).toMatch(/Invalid SR25519_URI:/);

    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("test_thrown_error_message_sanitized: sanitizeKeyringError strips suri fragments", () => {
    const err = new Error(
      'Invalid suri "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima//0///mypw"',
    );
    err.name = "SyntaxError";
    const out = sanitizeKeyringError(err);
    expect(out).toContain("SyntaxError");
    expect(out).not.toContain("alpha bravo charlie");
    expect(out).not.toContain("//0");
    expect(out).not.toContain("///mypw");
  });

  it("sanitizeKeyringError redacts BIP-39 word runs", () => {
    const err = new Error(
      "derivation failed for abandon ability able about above absent absorb abstract absurd abuse",
    );
    const out = sanitizeKeyringError(err);
    expect(out).not.toContain("abandon ability able about");
    expect(out).toContain("redacted-mnemonic");
  });

  it("sanitizeKeyringError redacts //derivation paths even without word runs", () => {
    const err = new Error("Unable to decode suri //foo//bar///password123");
    const out = sanitizeKeyringError(err);
    expect(out).not.toContain("//foo");
    expect(out).not.toContain("///password123");
    expect(out).toContain("redacted-path");
  });

  it("sanitizeKeyringError redacts long hex blobs (private keys, seed hex)", () => {
    const err = new Error(
      "bad seed: 0xdeadbeefcafebabe0011223344556677889900aabbccddeeff0011223344",
    );
    const out = sanitizeKeyringError(err);
    expect(out).not.toContain("0xdeadbeefcafebabe");
    expect(out).toContain("redacted-hex");
  });

  it("sanitizeKeyringError handles non-Error inputs safely", () => {
    expect(sanitizeKeyringError(undefined)).toBe("Error");
    expect(sanitizeKeyringError(null)).toBe("Error");
    expect(sanitizeKeyringError("plain string")).toContain("Error");
    // Bare-object "Error-like"
    expect(sanitizeKeyringError({ name: "Weird", message: "hello" })).toContain("Weird");
  });

  it("sanitizeKeyringError truncates overlong messages", () => {
    const err = new Error("x".repeat(500));
    const out = sanitizeKeyringError(err);
    // class + ": " + <=80 chars + "..."
    expect(out.length).toBeLessThanOrEqual(100);
    expect(out).toContain("...");
  });

  it("test_invalid_signer_uri_does_not_leak_to_stderr (stderr capture variant): nothing suri-like hits process.stderr", async () => {
    // Capture real stderr writes during initialize.
    const originalWrite = process.stderr.write.bind(process.stderr);
    const captured: string[] = [];
    (process.stderr as any).write = (chunk: any, ...rest: any[]) => {
      captured.push(String(chunk));
      return originalWrite(chunk, ...rest);
    };

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "urileak2-"));
    const daemon = new CommitteeDaemon(
      {
        materiosRpcUrl: "ws://stub",
        cardanoOgmiosUrl: "wss://stub",
        sr25519Uri: "//Alice",
        ed25519Uri: GARBAGE_SURI, // this one fails now
        daemonStatePath: path.join(tmpDir, "ds.json"),
        haltDetectSeconds: 60,
        haltRecoverBlocks: 3,
        haltExtensionThresholdSeconds: 86400,
        pollIntervalMs: 10,
      },
      {
        rpc: {} as any,
        getCardanoLatestBlockTimestamp: async () => 0,
        // Intentionally NOT passing a custom logger — we want the
        // defaultLogger (which writes to console.error -> stderr) to run so
        // the leakage test is realistic.
      },
    );
    try {
      await daemon.initialize();
    } catch {
      // expected
    } finally {
      (process.stderr as any).write = originalWrite;
    }

    const joined = captured.join("");
    expect(joined).not.toContain("garbage mnemonic phrase");
    expect(joined).not.toContain("noway noway");
    expect(joined).not.toContain("//hard");
    expect(joined).not.toContain("///pw");

    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});
