import { describe, it, expect } from "vitest";
import { cryptoWaitReady, sr25519Verify } from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import {
  settleClaimPayload,
  creditDepositPayload,
  requestVoucherPayload,
  attestBatchIntentsPayload,
  requestBatchVouchersPayload,
  submitBatchIntentsPayload,
  signPayload,
  buildSigBundle,
  TAG_CRDP,
  TAG_STCL,
  TAG_RVCH,
  TAG_ABIN,
  TAG_RVBN,
  TAG_SBIN,
} from "./multisig.js";
import type { HexString } from "./types.js";

// Bring up WASM-backed sr25519 once per file. Every test in this module needs
// a real sr25519 keypair so the verifier can round-trip the bundle.
await cryptoWaitReady();

// #73: chain-identity fixture pinned across the SDK + Rust pallet test
// suite. 32 × 0x73. Production runtimes plumb the actual genesis hash.
const TEST_CHAIN_ID = ("0x" + "73".repeat(32)) as HexString;

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

  it("TAG_ABIN is ASCII `ABIN` (Task #211)", () => {
    expect(Array.from(TAG_ABIN)).toEqual([0x41, 0x42, 0x49, 0x4e]);
  });

  it("TAG_RVBN is ASCII `RVBN` (Task #212)", () => {
    expect(Array.from(TAG_RVBN)).toEqual([0x52, 0x56, 0x42, 0x4e]);
  });

  it("TAG_SBIN is ASCII `SBIN` (Task #210)", () => {
    expect(Array.from(TAG_SBIN)).toEqual([0x53, 0x42, 0x49, 0x4e]);
  });
});

// ---------------------------------------------------------------------------
// Payload parity tests.
//
// Expected hex digests below were computed from the canonical Rust payload
// builders with chain_id = 32×0x73 (#73). See `tests.rs::FIXTURE_*_HEX`.
// ---------------------------------------------------------------------------

describe("creditDepositPayload — Rust parity", () => {
  it("matches Rust fixture A (all-0x07 target, amount=1000, all-0x01 tx)", () => {
    const digest = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    expect(u8aToHex(digest)).toBe(
      "0x80ca7ca008d0fe64f934c66fc079ecc9f1ef09bc4a217d183e68f2f9792030b4",
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
      materiosChainId: TEST_CHAIN_ID,
      depositor: u8aToHex(target_b) as HexString,
      amountAda: 2_000_000n,
      cardanoTxHash: u8aToHex(tx_b) as HexString,
    });
    expect(u8aToHex(digest)).toBe(
      "0xf569b8ae2bcd6b03bfbb48b7c936573c50ac3825c328ef7bc3edf5eece6b691c",
    );
  });

  it("returns a 32-byte digest", () => {
    const digest = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
      depositor: ("0x" + "00".repeat(32)) as HexString,
      amountAda: 0n,
      cardanoTxHash: ("0x" + "00".repeat(32)) as HexString,
    });
    expect(digest.length).toBe(32);
  });

  it("is sensitive to amount (u64 LE encoding)", () => {
    const a = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    const b = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_001n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(b));
  });

  it("#73: is sensitive to materiosChainId — preprod vs mainnet", () => {
    const onPreprod = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    const onMainnet = creditDepositPayload({
      materiosChainId: ("0x" + "99".repeat(32)) as HexString,
      depositor: ("0x" + "07".repeat(32)) as HexString,
      amountAda: 1_000n,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
    });
    expect(u8aToHex(onPreprod)).not.toBe(u8aToHex(onMainnet));
  });

  it("rejects non-32-byte depositor", () => {
    expect(() =>
      creditDepositPayload({
        materiosChainId: TEST_CHAIN_ID,
        depositor: ("0x" + "07".repeat(16)) as HexString,
        amountAda: 1n,
        cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      }),
    ).toThrow();
  });

  it("rejects non-32-byte cardanoTxHash", () => {
    expect(() =>
      creditDepositPayload({
        materiosChainId: TEST_CHAIN_ID,
        depositor: ("0x" + "07".repeat(32)) as HexString,
        amountAda: 1n,
        cardanoTxHash: ("0x" + "01".repeat(16)) as HexString,
      }),
    ).toThrow();
  });

  it("rejects non-32-byte materiosChainId (#73)", () => {
    expect(() =>
      creditDepositPayload({
        materiosChainId: ("0x" + "07".repeat(16)) as HexString,
        depositor: ("0x" + "07".repeat(32)) as HexString,
        amountAda: 1n,
        cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      }),
    ).toThrow();
  });
});

describe("settleClaimPayload — Rust parity", () => {
  it("matches Rust fixture C (all-0x07 claim, all-0x01 tx, direct=false)", () => {
    const digest = settleClaimPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "07".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      settledDirect: false,
    });
    expect(u8aToHex(digest)).toBe(
      "0xb0a3133f8e2508ea0c3ed8f78d9444c55cc88c1593a984ecfadc90906a1d0b6f",
    );
  });

  it("matches Rust fixture D (same inputs but direct=true — must differ)", () => {
    const digest = settleClaimPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "07".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "01".repeat(32)) as HexString,
      settledDirect: true,
    });
    expect(u8aToHex(digest)).toBe(
      "0x211464d3b3e199c5caea322a7959e565929a45fdcb5e44ff99403e350c88f584",
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
      materiosChainId: TEST_CHAIN_ID,
      claimId: u8aToHex(claim_e) as HexString,
      cardanoTxHash: u8aToHex(tx_e) as HexString,
      settledDirect: false,
    });
    const trueDigest = settleClaimPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: u8aToHex(claim_e) as HexString,
      cardanoTxHash: u8aToHex(tx_e) as HexString,
      settledDirect: true,
    });

    expect(u8aToHex(falseDigest)).toBe(
      "0xfcb8b391f750b12693b119e5b4a54800fa1ef84ccf8914a7fc18169e7bb7b088",
    );
    expect(u8aToHex(trueDigest)).toBe(
      "0xe77d47efed4f6529b1556d7406d38fd97e541ee744296da11521776ef382afbd",
    );
  });

  it("returns a 32-byte digest", () => {
    const digest = settleClaimPayload({
      materiosChainId: TEST_CHAIN_ID,
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
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "42".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "99".repeat(32)) as HexString,
      settledDirect: false,
    });
    const cd = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
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
      materiosChainId: TEST_CHAIN_ID,
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
      materiosChainId: TEST_CHAIN_ID,
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
      materiosChainId: TEST_CHAIN_ID,
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
// Fixture F's expected hex is pinned in
// `pallets/intent-settlement/src/tests.rs::FIXTURE_RVCH_F_HEX`.
// ---------------------------------------------------------------------------

describe("requestVoucherPayload — Rust parity (Task #174)", () => {
  it("matches Rust fixture F (claim=0x07.., intent=0x11.., voucher_digest=0x22.., bfpr_digest=0x33..)", () => {
    const digest = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    expect(u8aToHex(digest)).toBe(
      "0x61d097786f93582b10784bec0d9f3d3136f65d11e54648226e0df53ec13e5e7d",
    );
  });

  it("returns a 32-byte digest", () => {
    const digest = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "00".repeat(32)) as HexString,
      intentId: ("0x" + "00".repeat(32)) as HexString,
      voucherDigest: ("0x" + "00".repeat(32)) as HexString,
      bfprDigest: ("0x" + "00".repeat(32)) as HexString,
    });
    expect(digest.length).toBe(32);
  });

  it("is sensitive to claimId", () => {
    const a = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    const b = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
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
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "07".repeat(32)) as HexString,
      intentId: ("0x" + "11".repeat(32)) as HexString,
      voucherDigest: ("0x" + "22".repeat(32)) as HexString,
      bfprDigest: ("0x" + "33".repeat(32)) as HexString,
    });
    const swapped = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
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
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "42".repeat(32)) as HexString,
      intentId: ("0x" + "42".repeat(32)) as HexString,
      voucherDigest: ("0x" + "42".repeat(32)) as HexString,
      bfprDigest: ("0x" + "42".repeat(32)) as HexString,
    });
    const sd = settleClaimPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "42".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "42".repeat(32)) as HexString,
      settledDirect: false,
    });
    const cd = creditDepositPayload({
      materiosChainId: TEST_CHAIN_ID,
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
        materiosChainId: TEST_CHAIN_ID,
        claimId: short16,
        intentId: ok32,
        voucherDigest: ok32,
        bfprDigest: ok32,
      }),
    ).toThrow();
    expect(() =>
      requestVoucherPayload({
        materiosChainId: TEST_CHAIN_ID,
        claimId: ok32,
        intentId: short16,
        voucherDigest: ok32,
        bfprDigest: ok32,
      }),
    ).toThrow();
    expect(() =>
      requestVoucherPayload({
        materiosChainId: TEST_CHAIN_ID,
        claimId: ok32,
        intentId: ok32,
        voucherDigest: short16,
        bfprDigest: ok32,
      }),
    ).toThrow();
    expect(() =>
      requestVoucherPayload({
        materiosChainId: TEST_CHAIN_ID,
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
    const payload = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
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
    const payload = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
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
    expect(sr25519Verify(payload, bundle[0]!.sig, bundle[0]!.pubkey)).toBe(true);
    expect(sr25519Verify(payload, handRolled.sig, handRolled.pubkey)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task #211 — `attestBatchIntentsPayload` parity with Rust pallet.
// ---------------------------------------------------------------------------

describe("attestBatchIntentsPayload — Rust parity (Task #211)", () => {
  it("matches Rust fixture H (3 intent_ids 0x07*32 / 0x11*32 / 0x22*32)", () => {
    const digest = attestBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      intentIds: [
        ("0x" + "07".repeat(32)) as HexString,
        ("0x" + "11".repeat(32)) as HexString,
        ("0x" + "22".repeat(32)) as HexString,
      ],
    });
    expect(u8aToHex(digest)).toBe(
      "0x357d464882c4cc9e8af6c41dcd10f52ba689c1e3a1b7b6424297abea573d47dc",
    );
  });

  it("returns a 32-byte digest and is sensitive to ordering", () => {
    const a = attestBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      intentIds: [
        ("0x" + "07".repeat(32)) as HexString,
        ("0x" + "11".repeat(32)) as HexString,
      ],
    });
    expect(a.length).toBe(32);
    const reversed = attestBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      intentIds: [
        ("0x" + "11".repeat(32)) as HexString,
        ("0x" + "07".repeat(32)) as HexString,
      ],
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(reversed));
  });

  it("includes N prefix — empty batch hashes to a deterministic non-zero digest", () => {
    const empty = attestBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      intentIds: [],
    });
    expect(empty.length).toBe(32);
    const one = attestBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      intentIds: [("0x" + "07".repeat(32)) as HexString],
    });
    expect(u8aToHex(empty)).not.toBe(u8aToHex(one));
  });

  it("rejects non-32-byte intent_ids", () => {
    expect(() =>
      attestBatchIntentsPayload({
        materiosChainId: TEST_CHAIN_ID,
        intentIds: [("0x" + "07".repeat(16)) as HexString],
      }),
    ).toThrow();
  });

  it("domain-separated from settleClaimPayload (STCL)", () => {
    const ab = attestBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      intentIds: [("0x" + "42".repeat(32)) as HexString],
    });
    const sc = settleClaimPayload({
      materiosChainId: TEST_CHAIN_ID,
      claimId: ("0x" + "42".repeat(32)) as HexString,
      cardanoTxHash: ("0x" + "00".repeat(32)) as HexString,
      settledDirect: false,
    });
    expect(u8aToHex(ab)).not.toBe(u8aToHex(sc));
  });
});

// ---------------------------------------------------------------------------
// Task #212 — `requestBatchVouchersPayload` parity with Rust pallet.
// ---------------------------------------------------------------------------

describe("requestBatchVouchersPayload — Rust parity (Task #212)", () => {
  it("matches Rust fixture I (2 entries with structured tuple bytes)", () => {
    const digest = requestBatchVouchersPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          claimId: ("0x" + "07".repeat(32)) as HexString,
          intentId: ("0x" + "11".repeat(32)) as HexString,
          voucherDigest: ("0x" + "22".repeat(32)) as HexString,
          bfprDigest: ("0x" + "33".repeat(32)) as HexString,
        },
        {
          claimId: ("0x" + "44".repeat(32)) as HexString,
          intentId: ("0x" + "55".repeat(32)) as HexString,
          voucherDigest: ("0x" + "66".repeat(32)) as HexString,
          bfprDigest: ("0x" + "77".repeat(32)) as HexString,
        },
      ],
    });
    expect(u8aToHex(digest)).toBe(
      "0x363ba6b0c2d91cc0b7c01dd8c35a3505b619d5ea7eff3c9479b3a4ff4e3aa2ab",
    );
  });

  it("returns 32 bytes and is sensitive to ordering", () => {
    const a = requestBatchVouchersPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          claimId: ("0x" + "07".repeat(32)) as HexString,
          intentId: ("0x" + "11".repeat(32)) as HexString,
          voucherDigest: ("0x" + "22".repeat(32)) as HexString,
          bfprDigest: ("0x" + "33".repeat(32)) as HexString,
        },
        {
          claimId: ("0x" + "44".repeat(32)) as HexString,
          intentId: ("0x" + "55".repeat(32)) as HexString,
          voucherDigest: ("0x" + "66".repeat(32)) as HexString,
          bfprDigest: ("0x" + "77".repeat(32)) as HexString,
        },
      ],
    });
    expect(a.length).toBe(32);
    const reversed = requestBatchVouchersPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          claimId: ("0x" + "44".repeat(32)) as HexString,
          intentId: ("0x" + "55".repeat(32)) as HexString,
          voucherDigest: ("0x" + "66".repeat(32)) as HexString,
          bfprDigest: ("0x" + "77".repeat(32)) as HexString,
        },
        {
          claimId: ("0x" + "07".repeat(32)) as HexString,
          intentId: ("0x" + "11".repeat(32)) as HexString,
          voucherDigest: ("0x" + "22".repeat(32)) as HexString,
          bfprDigest: ("0x" + "33".repeat(32)) as HexString,
        },
      ],
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(reversed));
  });

  it("rejects non-32-byte entry fields", () => {
    expect(() =>
      requestBatchVouchersPayload({
        materiosChainId: TEST_CHAIN_ID,
        entries: [
          {
            claimId: ("0x" + "07".repeat(16)) as HexString, // SHORT
            intentId: ("0x" + "11".repeat(32)) as HexString,
            voucherDigest: ("0x" + "22".repeat(32)) as HexString,
            bfprDigest: ("0x" + "33".repeat(32)) as HexString,
          },
        ],
      }),
    ).toThrow();
  });

  it("domain-separated from requestVoucherPayload (RVCH)", () => {
    // Single-entry RVBN must not collide with RVCH digest computed over
    // the same 4-tuple. Same body bytes, different domain tags.
    const single: { claimId: HexString; intentId: HexString; voucherDigest: HexString; bfprDigest: HexString } = {
      claimId: ("0x" + "11".repeat(32)) as HexString,
      intentId: ("0x" + "22".repeat(32)) as HexString,
      voucherDigest: ("0x" + "33".repeat(32)) as HexString,
      bfprDigest: ("0x" + "44".repeat(32)) as HexString,
    };
    const rvch = requestVoucherPayload({
      materiosChainId: TEST_CHAIN_ID,
      ...single,
    });
    const rvbn = requestBatchVouchersPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [single],
    });
    expect(u8aToHex(rvch)).not.toBe(u8aToHex(rvbn));
  });
});

// ---------------------------------------------------------------------------
// Task #210 — `submitBatchIntentsPayload` parity with Rust pallet.
// ---------------------------------------------------------------------------

describe("submitBatchIntentsPayload — Rust parity (Task #210)", () => {
  it("matches Rust fixture G (3 RequestPayout entries, ascending policy ids)", () => {
    const evidence = new Uint8Array(4);
    const digest = submitBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "07".repeat(32)) as HexString,
            oracleEvidence: evidence,
          },
        },
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "11".repeat(32)) as HexString,
            oracleEvidence: evidence,
          },
        },
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "22".repeat(32)) as HexString,
            oracleEvidence: evidence,
          },
        },
      ],
    });
    expect(u8aToHex(digest)).toBe(
      "0x5e5a531a065e50077dcccb1f8ad03ba5f070be8235417a0291d138f72b3deaa8",
    );
  });

  it("returns a 32-byte digest and is sensitive to entry ordering", () => {
    const ev = new Uint8Array(4);
    const a = submitBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "07".repeat(32)) as HexString,
            oracleEvidence: ev,
          },
        },
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "11".repeat(32)) as HexString,
            oracleEvidence: ev,
          },
        },
      ],
    });
    expect(a.length).toBe(32);
    const reversed = submitBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "11".repeat(32)) as HexString,
            oracleEvidence: ev,
          },
        },
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "07".repeat(32)) as HexString,
            oracleEvidence: ev,
          },
        },
      ],
    });
    expect(u8aToHex(a)).not.toBe(u8aToHex(reversed));
  });

  it("includes N prefix — empty batch hashes to a deterministic non-zero digest", () => {
    const empty = submitBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [],
    });
    expect(empty.length).toBe(32);
    const one = submitBatchIntentsPayload({
      materiosChainId: TEST_CHAIN_ID,
      entries: [
        {
          kind: {
            tag: "RequestPayout",
            policyId: ("0x" + "00".repeat(32)) as HexString,
            oracleEvidence: new Uint8Array(0),
          },
        },
      ],
    });
    expect(u8aToHex(empty)).not.toBe(u8aToHex(one));
  });
});
