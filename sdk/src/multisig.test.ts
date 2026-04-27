import { describe, it, expect } from "vitest";
import { cryptoWaitReady, sr25519Verify } from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import {
  settleClaimPayload,
  creditDepositPayload,
  requestVoucherPayload,
  signPayload,
  buildSigBundle,
  TAG_CRDP,
  TAG_STCL,
  TAG_RVCH,
} from "./multisig.js";
import type { HexString } from "./types.js";

// Bring up WASM-backed sr25519 once per file. Every test in this module needs
// a real sr25519 keypair so the verifier can round-trip the bundle.
await cryptoWaitReady();

// ---------------------------------------------------------------------------
// Domain-tag sanity (matches pallet constants TAG_CRDP / TAG_STCL).
// ---------------------------------------------------------------------------

describe("multisig domain tags", () => {
  it("TAG_CRDP is ASCII `CRDP`", () => {
    expect(Array.from(TAG_CRDP)).toEqual([0x43, 0x52, 0x44, 0x50]);
  });

  it("TAG_STCL is ASCII `STCL`", () => {
    expect(Array.from(TAG_STCL)).toEqual([0x53, 0x54, 0x43, 0x4c]);
  });

  it("TAG_RVCH is ASCII `RVCH` (Task #174)", () => {
    expect(Array.from(TAG_RVCH)).toEqual([0x52, 0x56, 0x43, 0x48]);
  });
});

// ---------------------------------------------------------------------------
// Payload parity tests.
//
// Expected hex digests below were computed from the canonical Rust payload
// builders (`pallets/intent-settlement/src/lib.rs::credit_deposit_payload` /
// `settle_claim_payload`) using the same sp_core::hashing::blake2_256 that
// pallet uses at runtime. See PR description for the generator program and
// the companion fixture added to `pallets/intent-settlement/src/tests.rs`.
// ---------------------------------------------------------------------------

describe("creditDepositPayload — Rust parity", () => {
  it("matches Rust fixture A (all-0x07 target, amount=1000, all-0x01 tx)", () => {
    const digest = creditDepositPayload({
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    expect(u8aToHex(digest)).toBe(
      "0xd61b0438a19adc712cd0d01b4fee1174f5a8eb5df931918dac9ae0e2f32d51db",
    );
  });

  it("matches Rust fixture B (structured target/tx, amount=2_000_000)", () => {
    // target_b[i] = (i*7 + 3) mod 256
    const target_b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) target_b[i] = ((i * 7 + 3) & 0xff) as number;
    // tx_b[i] = ((i ^ 0xAB) + 1) mod 256
    const tx_b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) tx_b[i] = (((i ^ 0xab) + 1) & 0xff) as number;

    const digest = creditDepositPayload({
      depositor: u8aToHex(target_b) as HexString,
      amountAda: 2_000_000n,
      cardanoTxHash: u8aToHex(tx_b) as HexString,
    });
    expect(u8aToHex(digest)).toBe(
      "0x56e006017231f0f62d48ed5739446e31fbfaab94ad3e68117ca57393b3db8c4f",
    );
  });

  it("returns a 32-byte digest", () => {
    const digest = creditDepositPayload({
      depositor: ("0x" + "00".repeat(32)) as HexString,
      amountAda: 0n,
      cardanoTxHash: ("0x" + "00".repeat(32)) as HexString,
    });
    expect(digest.length).toBe(32);
  });

  it("is sensitive to amount (u64 LE encoding)", () => {
    const a = creditDepositPayload({
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    const b = creditDepositPayload({
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_001n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(b));
  });

  it("rejects non-32-byte depositor", () => {
    expect(() =>
      creditDepositPayload({
        depositor: ("0x" + "07".repeat(16)) as HexString,
        amountAda: 1n,
        cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      }),
    ).toThrow();
  });

  it("rejects non-32-byte cardanoTxHash", () => {
    expect(() =>
      creditDepositPayload({
        depositor: ("0x" + "07".repeat(32)) as HexString,
        amountAda: 1n,
        cardanoTxHash: ("0x" + "01".repeat(16)) as HexString,
      }),
    ).toThrow();
  });
});

describe("settleClaimPayload — Rust parity", () => {
  it("matches Rust fixture C (all-0x07 claim, all-0x01 tx, direct=false)", () => {
    const digest = settleClaimPayload({
      claimId: ("0x" + "07".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      settledDirect: false,
    });
    expect(u8aToHex(digest)).toBe(
      "0x59be22f98eb07437195ca49bda86e1ff6ba495c8d19a0ac11d207e20d2dff285",
    );
  });

  it("matches Rust fixture D (same inputs but direct=true — must differ)", () => {
    const digest = settleClaimPayload({
      claimId: ("0x" + "07".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      settledDirect: true,
    });
    expect(u8aToHex(digest)).toBe(
      "0xae3761839a7a605a75d9643427e2b768436316e2cdda877e9f4c508ec6374b08",
    );
  });

  it("matches Rust fixture E (structured claim/tx) for both direct flags", () => {
    // claim_e[i] = ((i * 5) ^ 0x5A) mod 256
    const claim_e = new Uint8Array(32);
    for (let i = 0; i < 32; i++) claim_e[i] = (((i * 5) ^ 0x5a) & 0xff) as number;
    // tx_e[i] = ((i ^ 0xCC) + 1) mod 256
    const tx_e = new Uint8Array(32);
    for (let i = 0; i < 32; i++) tx_e[i] = (((i ^ 0xcc) + 1) & 0xff) as number;

    const falseDigest = settleClaimPayload({
      claimId: u8aToHex(claim_e) as HexString,
      cardanoTxHash: u8aToHex(tx_e) as HexString,
      settledDirect: false,
    });
    const trueDigest = settleClaimPayload({
      claimId: u8aToHex(claim_e) as HexString,
      cardanoTxHash: u8aToHex(tx_e) as HexString,
      settledDirect: true,
    });

    expect(u8aToHex(falseDigest)).toBe(
      "0x7493705c88435cdf3faf46b1f5031281b777c6320ec3b71375ca06bb5b427e4a",
    );
    expect(u8aToHex(trueDigest)).toBe(
      "0x94b4d41f29528f1b00cf3de7df4f5bd22f27521d769f04547bb69f3b459862d6",
    );
  });

  it("returns a 32-byte digest", () => {
    const digest = settleClaimPayload({
      claimId: ("0x" + "00".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "00".repeat(32)) as HexString,
      settledDirect: false,
    });
    expect(digest.length).toBe(32);
  });

  it("domain-separated from creditDepositPayload", () => {
    // Same 32B bytes as "claim" vs "depositor" — digests must still differ
    // because of the 4-byte domain tag at the front.
    const sd = settleClaimPayload({
      claimId: ("0x" + "42".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "99".repeat(32)) as HexString,
      settledDirect: false,
    });
    const cd = creditDepositPayload({
      depositor: ("0x" + "42".repeat(32)) as HexString,
      amountAda: 0n, // zero body tail won't salvage equal digests
      cardanoTxHash: ("0x" + "99".repeat(32)) as HexString,
    });
    expect(u8aToHex(sd)).not.toBe(u8aToHex(cd));
  });
});

// ---------------------------------------------------------------------------
// signPayload — well-known //Alice sr25519 pubkey check + sig verification.
// ---------------------------------------------------------------------------

describe("signPayload", () => {
  const ALICE_PUBKEY_HEX =
    "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

  it("//Alice sr25519 pubkey matches the well-known value", () => {
    const payload = new Uint8Array(32); // arbitrary 32B — pubkey is seed-derived
    const { pubkey } = signPayload("//Alice", payload);
    expect(u8aToHex(pubkey)).toBe(ALICE_PUBKEY_HEX);
  });

  it("signatures verify against the signer's pubkey + payload", () => {
    const payload = settleClaimPayload({
      claimId: ("0x" + "aa".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "bb".repeat(32)) as HexString,
      settledDirect: false,
    });
    const { pubkey, sig } = signPayload("//Alice", payload);
    expect(sr25519Verify(payload, sig, pubkey)).toBe(true);
  });

  it("signatures do NOT verify against a different pubkey", () => {
    const payload = new Uint8Array(32);
    const { sig } = signPayload("//Alice", payload);
    const bobPubkey = hexToU8a(
      "0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48",
    );
    expect(sr25519Verify(payload, sig, bobPubkey)).toBe(false);
  });

  it("signatures do NOT verify against a different payload", () => {
    const payloadA = new Uint8Array(32).fill(0x01);
    const payloadB = new Uint8Array(32).fill(0x02);
    const { pubkey, sig } = signPayload("//Alice", payloadA);
    expect(sr25519Verify(payloadB, sig, pubkey)).toBe(false);
  });

  it("returns a 32-byte pubkey + 64-byte sig", () => {
    const payload = new Uint8Array(32);
    const { pubkey, sig } = signPayload("//Bob", payload);
    expect(pubkey.length).toBe(32);
    expect(sig.length).toBe(64);
  });
});

// ---------------------------------------------------------------------------
// buildSigBundle — ordering, dedup, round-trip verification.
// ---------------------------------------------------------------------------

describe("buildSigBundle", () => {
  const samplePayload = (): Uint8Array =>
    settleClaimPayload({
      claimId: ("0x" + "aa".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "bb".repeat(32)) as HexString,
      settledDirect: false,
    });

  const ALICE_PK =
    "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
  const BOB_PK =
    "0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48";

  it("caller appears first, produces 2 entries for //Alice + //Bob", () => {
    const payload = samplePayload();
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Bob"],
      payload,
    });
    expect(bundle.length).toBe(2);
    expect(u8aToHex(bundle[0]!.pubkey)).toBe(ALICE_PK);
    expect(u8aToHex(bundle[1]!.pubkey)).toBe(BOB_PK);
  });

  it("every signature verifies under its pubkey + the shared payload", () => {
    const payload = samplePayload();
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Bob", "//Charlie"],
      payload,
    });
    expect(bundle.length).toBe(3);
    for (const entry of bundle) {
      expect(sr25519Verify(payload, entry.sig, entry.pubkey)).toBe(true);
    }
  });

  it("cosigners after the caller are sorted stably by pubkey bytes", () => {
    // Charlie=0x90b5ab… Bob=0x8eaf04… Dave=0x306721…
    // Sorted byte-lex: Dave (0x30…) < Bob (0x8e…) < Charlie (0x90…).
    const payload = samplePayload();
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Charlie", "//Bob", "//Dave"],
      payload,
    });
    expect(bundle.length).toBe(4);
    expect(u8aToHex(bundle[0]!.pubkey)).toBe(ALICE_PK);
    expect(u8aToHex(bundle[1]!.pubkey)).toBe(
      "0x306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20",
    );
    expect(u8aToHex(bundle[2]!.pubkey)).toBe(BOB_PK);
    expect(u8aToHex(bundle[3]!.pubkey)).toBe(
      "0x90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22",
    );
  });

  it("deduplicates a cosigner that matches the caller (pallet DuplicateSigner semantics)", () => {
    const payload = samplePayload();
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Alice", "//Bob"],
      payload,
    });
    // //Alice appears once (as caller), //Bob once as cosigner.
    expect(bundle.length).toBe(2);
    expect(u8aToHex(bundle[0]!.pubkey)).toBe(ALICE_PK);
    expect(u8aToHex(bundle[1]!.pubkey)).toBe(BOB_PK);
  });

  it("deduplicates repeated seeds inside the cosigner list", () => {
    const payload = samplePayload();
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Bob", "//Bob"],
      payload,
    });
    expect(bundle.length).toBe(2);
    expect(u8aToHex(bundle[0]!.pubkey)).toBe(ALICE_PK);
    expect(u8aToHex(bundle[1]!.pubkey)).toBe(BOB_PK);
  });

  it("single-signer bundles are still valid (caller-only, threshold check is pallet-side)", () => {
    const payload = samplePayload();
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: [],
      payload,
    });
    expect(bundle.length).toBe(1);
    expect(u8aToHex(bundle[0]!.pubkey)).toBe(ALICE_PK);
    expect(sr25519Verify(payload, bundle[0]!.sig, bundle[0]!.pubkey)).toBe(true);
  });

  it("round-trips with the real creditDepositPayload shape", () => {
    const payload = creditDepositPayload({
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 5_000_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Bob"],
      payload,
    });
    for (const entry of bundle) {
      expect(sr25519Verify(payload, entry.sig, entry.pubkey)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Task #174 — `requestVoucherPayload` parity with Rust + helper sanity.
//
// The Rust counterpart is `request_voucher_payload(claim_id, intent_id,
// voucher_digest, bfpr_digest)` in `pallets/intent-settlement/src/lib.rs`.
// Fixture F's expected hex is pinned in
// `pallets/intent-settlement/src/tests.rs::TASK_174_FIXTURE_F_HEX` and
// matches the value asserted below — any drift fails loudly in both Rust
// and TS CI.
// ---------------------------------------------------------------------------

describe("requestVoucherPayload — Rust parity (Task #174)", () => {
  it("matches Rust fixture F (claim=0x07.., intent=0x11.., voucher_digest=0x22.., bfpr_digest=0x33..)", () => {
    const digest = requestVoucherPayload({
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    expect(u8aToHex(digest)).toBe(
      "0xb3a165c261b9a5b76ec4d22779d0ae2fb56ef0bd8f3da3fcb48a40f1e8b1fdd4",
    );
  });

  it("returns a 32-byte digest", () => {
    const digest = requestVoucherPayload({
      claimId: ("0x" + "00".repeat(32)) as HexString,
      intentId: ("0x" + "00".repeat(32)) as HexString,
      voucherDigest: ("0x" + "00".repeat(32)) as HexString,
      bfprDigest: ("0x" + "00".repeat(32)) as HexString,
    });
    expect(digest.length).toBe(32);
  });

  it("is sensitive to claimId", () => {
    const a = requestVoucherPayload({
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    const b = requestVoucherPayload({
      claimId: ("0x" + "08".repeat(32)) as HexString, // <- single byte flip
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(b));
  });

  it("voucherDigest and bfprDigest are NOT interchangeable", () => {
    // Field-position attack: if the pre-image swallowed the two digests in
    // a position-insensitive way (e.g. XOR), an attacker could pre-compute
    // a sig for the swapped pair. The pallet's pre-image is positional, so
    // the SDK helper must mirror that sensitivity.
    const a = requestVoucherPayload({
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    const swapped = requestVoucherPayload({
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "33".repeat(32)) as HexString, // <- swapped
      bfprDigest: ("0x" + "22".repeat(32)) as HexString, // <- swapped
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(swapped));
  });

  it("domain-separated from settleClaimPayload + creditDepositPayload", () => {
    // Same 32B chunks fed to all three should still produce three distinct
    // digests because of the 4-byte domain tag prefix.
    const rv = requestVoucherPayload({
      claimId: ("0x" + "42".repeat(32)) as HexString,
      intentId: ("0x" + "42".repeat(32)) as HexString,
      voucherDigest: ("0x" + "42".repeat(32)) as HexString,
      bfprDigest: ("0x" + "42".repeat(32)) as HexString,
    });
    const sd = settleClaimPayload({
      claimId: ("0x" + "42".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "42".repeat(32)) as HexString,
      settledDirect: false,
    });
    const cd = creditDepositPayload({
      depositor: ("0x" + "42".repeat(32)) as HexString,
      amountAda: 0n,
      cardanoTxHash: ("0x" + "42".repeat(32)) as HexString,
    });
    expect(u8aToHex(rv)).not.toBe(u8aToHex(sd));
    expect(u8aToHex(rv)).not.toBe(u8aToHex(cd));
    expect(u8aToHex(sd)).not.toBe(u8aToHex(cd));
  });

  it("rejects non-32-byte inputs", () => {
    const ok32 = ("0x" + "07".repeat(32)) as HexString;
    const short16 = ("0x" + "07".repeat(16)) as HexString;
    expect(() =>
      requestVoucherPayload({
        claimId: short16,
        intentId: ok32,
        voucherDigest: ok32,
        bfprDigest: ok32,
      }),
    ).toThrow();
    expect(() =>
      requestVoucherPayload({
        claimId: ok32,
        intentId: short16,
        voucherDigest: ok32,
        bfprDigest: ok32,
      }),
    ).toThrow();
    expect(() =>
      requestVoucherPayload({
        claimId: ok32,
        intentId: ok32,
        voucherDigest: short16,
        bfprDigest: ok32,
      }),
    ).toThrow();
    expect(() =>
      requestVoucherPayload({
        claimId: ok32,
        intentId: ok32,
        voucherDigest: ok32,
        bfprDigest: short16,
      }),
    ).toThrow();
  });
});

describe("requestVoucherPayload + buildSigBundle round-trip (Task #174)", () => {
  it("each sig in the bundle verifies under the request_voucher digest", () => {
    // T10 from the brief: the SDK helper that constructs the sig envelope
    // must produce the SAME bytes as a hand-rolled blake2b + sr25519 — and
    // those bytes must verify back. This is the regression test that
    // catches helper drift before any chain submit is attempted.
    const payload = requestVoucherPayload({
      claimId: ("0x" + "aa".repeat(32)) as HexString,
      intentId: ("0x" + "bb".repeat(32)) as HexString,
      voucherDigest: ("0x" + "cc".repeat(32)) as HexString,
      bfprDigest: ("0x" + "dd".repeat(32)) as HexString,
    });
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: ["//Bob"],
      payload,
    });
    expect(bundle.length).toBe(2);
    for (const entry of bundle) {
      expect(sr25519Verify(payload, entry.sig, entry.pubkey)).toBe(true);
    }
  });

  it("hand-rolled signature over the same digest matches the helper bundle entry", () => {
    // Belt-and-braces: signPayload (low-level) and buildSigBundle (caller-
    // first ordering) must agree on what //Alice signs over the request_-
    // voucher digest. If they ever drift, this fails before bundle hits
    // the chain.
    const payload = requestVoucherPayload({
      claimId: ("0x" + "01".repeat(32)) as HexString,
      intentId: ("0x" + "02".repeat(32)) as HexString,
      voucherDigest: ("0x" + "03".repeat(32)) as HexString,
      bfprDigest: ("0x" + "04".repeat(32)) as HexString,
    });
    const handRolled = signPayload("//Alice", payload);
    const bundle = buildSigBundle({
      callerSeed: "//Alice",
      cosignerSeeds: [],
      payload,
    });
    expect(u8aToHex(bundle[0]!.pubkey)).toBe(u8aToHex(handRolled.pubkey));
    // sr25519 sigs are randomized per call (Schnorrkel adds nonce entropy)
    // so we can't byte-compare. But both sigs must verify under the same
    // pubkey + payload — that's the cross-check that protects against
    // helper-vs-low-level drift.
    expect(sr25519Verify(payload, bundle[0]!.sig, bundle[0]!.pubkey)).toBe(true);
    expect(sr25519Verify(payload, handRolled.sig, handRolled.pubkey)).toBe(true);
  });
});
