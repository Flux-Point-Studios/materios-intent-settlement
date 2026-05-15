/**
 * M-of-N committee signature envelopes for `settle_claim` + `credit_deposit`.
 *
 * These helpers mirror the Rust payload builders in
 * `pallets/intent-settlement/src/lib.rs` (`settle_claim_payload`,
 * `credit_deposit_payload`) and must produce byte-identical digests — the
 * pallet verifies each sig via `sp_io::crypto::sr25519_verify(&sig, &msg, &pk)`
 * against the digest we emit here.
 *
 * Canonical shapes (spec-v1 §1.1 + pallet comments):
 *
 *   credit_deposit digest:
 *     blake2_256( b"CRDP" || target (32B) || amount_ada (LE u64) || cardano_tx_hash (32B) )
 *
 *   settle_claim digest:
 *     blake2_256( b"STCL" || claim_id (32B) || cardano_tx_hash (32B) || settled_direct (1B) )
 *
 * Bundle ordering + dedup semantics (match pallet `ensure_threshold_signatures`):
 *  - Caller's pubkey MUST appear in the bundle (origin-binding, anti-replay).
 *  - Duplicate signers are rejected by the pallet (`DuplicateSigner`), so we
 *    dedupe on the client side rather than submitting a doomed extrinsic.
 *  - Pallet order is insignificant; we emit caller-first, then remaining
 *    cosigners sorted by pubkey bytes, so verifiers see a deterministic
 *    bundle.
 */

import { blake2AsU8a } from "@polkadot/util-crypto";
import { Keyring } from "@polkadot/keyring";
import { hexToU8a, u8aConcat, u8aEq } from "@polkadot/util";
import type { HexString, IntentKind } from "./types.js";
import { encodeIntentKind, u32LE, u64LE } from "./hashing.js";

// ---------------------------------------------------------------------------
// Domain tags (Issue #7 — pallet lib.rs::TAG_CRDP, TAG_STCL; Task #174 —
// TAG_RVCH).
// ---------------------------------------------------------------------------

/** `b"CRDP"` — 4-byte ASCII domain tag for credit_deposit payloads. */
export const TAG_CRDP: Uint8Array = new Uint8Array([0x43, 0x52, 0x44, 0x50]);
/**
 * `b"STCL"` — 4-byte ASCII domain tag for the legacy settle_claim payload.
 *
 * @deprecated Task #266 (mis-sec P0): the legacy `settle_claim` extrinsic
 * is retired at `STCA_CUTOVER_BLOCK = upgrade_block + 50`. New code MUST
 * use `TAG_STCA` + `settleClaimAttestedPayload` so committee sigs commit
 * to the FAT Cardano observation (cardano_tx + slot + depth + beneficiary
 * + amount + voucher_digest + mainchain_genesis_hash) rather than a
 * vacuous hash.
 */
export const TAG_STCL: Uint8Array = new Uint8Array([0x53, 0x54, 0x43, 0x4c]);
/**
 * `b"STCA"` — 4-byte ASCII domain tag for the **attested** settle_claim
 * payload (Task #266, mis-sec P0). The new split-extrinsic pipeline
 * (`request_settle` + `attest_settle`) signs over a 209-byte body that
 * commits to seven verifiable Cardano facts:
 *   - cardano_tx_hash
 *   - settled_direct flag
 *   - beneficiary_addr_hash (28-byte payment-key hash from the voucher)
 *   - amount_lovelace (from the voucher)
 *   - observed_at_depth (>= MinFinalityDepth)
 *   - observed_slot (Cardano slot of the settling tx)
 *   - mainchain_genesis_hash (pins preprod vs mainnet)
 *
 * Plus the chain-state-derived `voucher_digest` so a colluding M cannot
 * reuse one legitimate Cardano payment to close multiple Materios claims
 * (attack A5 in design memo §1.2).
 *
 * Domain-separated from `STCL` so a stale STCL bundle cannot replay onto
 * the new STCA path.
 */
export const TAG_STCA: Uint8Array = new Uint8Array([0x53, 0x54, 0x43, 0x41]);
/**
 * `b"BSTA"` — 4-byte ASCII domain tag for the **batch** attested-settle
 * payload (Task #266, mis-sec P0). The committee signs ONE digest over
 * N STCA-shaped per-entry bodies for `attest_batch_settle`. Mirrors the
 * spec-207 batching win for the new path. Domain-separated from `STBA`
 * (the legacy `settle_batch_atomic` tag) so pre-fix batch sigs cannot
 * replay onto the attested-batch path.
 */
export const TAG_BSTA: Uint8Array = new Uint8Array([0x42, 0x53, 0x54, 0x41]);
/**
 * `b"RVCH"` — 4-byte ASCII domain tag for `request_voucher` payloads
 * (Task #174). Closes the M-of-N gap on the voucher-mint stage of the
 * intent pipeline so a single committee member can no longer unilaterally
 * mint a voucher with an attestation bundle they posted earlier.
 */
export const TAG_RVCH: Uint8Array = new Uint8Array([0x52, 0x56, 0x43, 0x48]);
/**
 * `b"ABIN"` — 4-byte ASCII domain tag for `attest_batch_intents` payloads
 * (Task #211). One M-of-N committee signature bundle authorises the entire
 * batch's `Pending -> Attested` transition. Pre-spec-207 a 3-of-3 committee
 * posted M*N `attest_intent` extrinsics per epoch — at N=256 that's 768
 * sig-verify rounds. Post-spec-207 it's ONE sig-verify per batch.
 */
export const TAG_ABIN: Uint8Array = new Uint8Array([0x41, 0x42, 0x49, 0x4e]);
/**
 * `b"RVBN"` — 4-byte ASCII domain tag for `request_batch_vouchers`
 * payloads (Task #212). One M-of-N committee signature bundle authorises
 * N voucher mints. Pre-spec-207 each voucher mint required its own M-of-N
 * round (per PR #26's RVCH gate); post-spec-207 N mints collapse to one
 * sig-verify.
 */
export const TAG_RVBN: Uint8Array = new Uint8Array([0x52, 0x56, 0x42, 0x4e]);
/**
 * `b"SBIN"` — 4-byte ASCII domain tag for the `submit_batch_intents` event
 * digest (Task #210). NOT a sig pre-image (the user-side burst stage has
 * no M-of-N gate; the user origin IS the authority). Indexers read this
 * digest off the `BatchIntentsSubmitted` event so they can correlate the
 * on-chain landing with the keeper's observed batch object.
 */
export const TAG_SBIN: Uint8Array = new Uint8Array([0x53, 0x42, 0x49, 0x4e]);

// ---------------------------------------------------------------------------
// Payload builders (digests that committee members sign).
// ---------------------------------------------------------------------------

function require32(bytes: Uint8Array, field: string): void {
  if (bytes.length !== 32) {
    throw new Error(`${field}: expected 32 bytes, got ${bytes.length}`);
  }
}

/**
 * Byte-identical to Rust `settle_claim_payload(materios_chain_id, claim_id,
 * tx_hash, settled_direct)`.
 *
 * Pre-image (#73): `b"STCL" || materios_chain_id (32B) || claim_id (32B)
 *                   || cardano_tx_hash (32B) || settled_direct (1B)`
 *
 * @returns 32-byte blake2_256 digest that committee members must sign.
 *
 * @deprecated Task #266 (mis-sec P0): the legacy `settle_claim` extrinsic
 * is retired at `STCA_CUTOVER_BLOCK = upgrade_block + 50`. New code MUST
 * use `settleClaimAttestedPayload` which commits each signature to the
 * FAT Cardano observation (cardano_tx + slot + depth + beneficiary +
 * amount + voucher_digest + mainchain_genesis_hash). The vacuous-hash
 * design here let any colluding M close a claim against a non-existent
 * Cardano payment (attack A1 in the design memo).
 */
export function settleClaimPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  claimId: HexString;
  /** 32-byte Cardano transaction hash, hex-prefixed. */
  cardanoTxHash: HexString;
  settledDirect: boolean;
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  const claimId = hexToU8a(args.claimId);
  const cardanoTxHash = hexToU8a(args.cardanoTxHash);
  require32(chainId, "materiosChainId");
  require32(claimId, "claimId");
  require32(cardanoTxHash, "cardanoTxHash");
  const body = u8aConcat(
    chainId,
    claimId,
    cardanoTxHash,
    new Uint8Array([args.settledDirect ? 1 : 0]),
  );
  const digest = blake2AsU8a(u8aConcat(TAG_STCL, body), 256);
  // Safety net: `blake2AsU8a(…, 256)` is documented to return 32B. Guard
  // against a future breaking change in @polkadot/util-crypto.
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

function require28(bytes: Uint8Array, field: string): void {
  if (bytes.length !== 28) {
    throw new Error(`${field}: expected 28 bytes, got ${bytes.length}`);
  }
}

/**
 * Byte-identical to Rust `settle_claim_attested_payload(...)` (Task #266,
 * mis-sec P0).
 *
 * Pre-image (209 bytes):
 *
 *     b"STCA"                                 (4B  domain tag)
 *  || materios_chain_id                       (32B chain identity, #73)
 *  || claim_id                                (32B)
 *  || voucher_digest                          (32B chain-state-derived)
 *  || cardano_tx_hash                         (32B)
 *  || settled_direct                          (1B  0x00 / 0x01)
 *  || beneficiary_addr_hash                   (28B 28-byte payment-key hash)
 *  || amount_lovelace                         (8B  LE u64)
 *  || observed_at_depth                       (4B  LE u32)
 *  || observed_slot                           (8B  LE u64)
 *  || mainchain_genesis_hash                  (32B preprod vs mainnet pin)
 *
 * Total body length = 209 bytes (4 blake2 blocks). The legacy STCL body
 * was 97 bytes (2 blocks); this digest costs one extra blake2 round per
 * signer (~300 ns) for the safety win of binding each committee
 * signature to a falsifiable Cardano-record fact.
 *
 * `voucherDigest` here is the chain-state-derived value the pallet looks
 * up from `Vouchers[claim_id]` at `attest_settle` time — compute via the
 * SDK's `voucherDigestWithAddress` helper using the SAME chain-identity
 * inputs the runtime uses (otherwise the digest diverges and
 * `InvalidSignature` fires on-chain).
 *
 * @returns 32-byte blake2_256 digest that committee members must sign.
 */
export function settleClaimAttestedPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  /** 32-byte claim id (H256), hex-prefixed. */
  claimId: HexString;
  /**
   * 32-byte canonical voucher digest from on-chain `Vouchers[claim_id]`.
   * Compute via `voucherDigestWithAddress` with the same chain-identity
   * inputs the runtime uses, or hand back the value the chain exposes
   * via the runtime API.
   */
  voucherDigest: HexString;
  /** 32-byte Cardano transaction hash claimed to have settled this claim. */
  cardanoTxHash: HexString;
  /** Whether this is the 10-minute direct-path fallback (true) vs the keeper-batch path (false). */
  settledDirect: boolean;
  /**
   * 28-byte payment-key hash, lifted from positions [1..29] of the CIP-0019
   * type-0 address in the on-chain voucher.
   */
  beneficiaryAddrHash: HexString;
  /** Lovelace amount paid by the settling Cardano tx. Must equal `claim.amount_ada`. */
  amountLovelace: bigint;
  /** Cardano depth at which the attestor observed the tx. Must be >= MinFinalityDepth. */
  observedAtDepth: number;
  /** Cardano slot of the settling tx. */
  observedSlot: bigint;
  /** 32-byte Cardano genesis hash (preprod vs mainnet pin). */
  mainchainGenesisHash: HexString;
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  const claimId = hexToU8a(args.claimId);
  const voucherDigest = hexToU8a(args.voucherDigest);
  const cardanoTxHash = hexToU8a(args.cardanoTxHash);
  const beneficiary = hexToU8a(args.beneficiaryAddrHash);
  const mcGenesis = hexToU8a(args.mainchainGenesisHash);
  require32(chainId, "materiosChainId");
  require32(claimId, "claimId");
  require32(voucherDigest, "voucherDigest");
  require32(cardanoTxHash, "cardanoTxHash");
  require28(beneficiary, "beneficiaryAddrHash");
  require32(mcGenesis, "mainchainGenesisHash");
  const body = u8aConcat(
    chainId,
    claimId,
    voucherDigest,
    cardanoTxHash,
    new Uint8Array([args.settledDirect ? 1 : 0]),
    beneficiary,
    u64LE(args.amountLovelace),
    u32LE(args.observedAtDepth),
    u64LE(args.observedSlot),
    mcGenesis,
  );
  // Sanity: body must be exactly 209 bytes per the locked design memo §3.2.
  // 32+32+32+32+1+28+8+4+8+32 = 209.
  if (body.length !== 209) {
    throw new Error(
      `STCA body length must be 209 bytes (got ${body.length}); see design memo §3.2`,
    );
  }
  const digest = blake2AsU8a(u8aConcat(TAG_STCA, body), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Per-entry view of an `attest_batch_settle` payload's body. The pallet
 * reconstructs the same struct from chain state at attest time; the SDK
 * helper here exists so keepers can pre-compute the batch digest before
 * gathering committee sigs.
 */
export interface BatchAttestSettleEntry {
  /** 32-byte claim id, hex-prefixed. */
  claimId: HexString;
  /** 32-byte canonical voucher digest. */
  voucherDigest: HexString;
  /** 32-byte Cardano tx hash. */
  cardanoTxHash: HexString;
  /** Direct-path flag (10-minute fallback vs keeper-batch). */
  settledDirect: boolean;
  /** 28-byte payment-key hash from the voucher's CIP-0019 type-0 address. */
  beneficiaryAddrHash: HexString;
  /** Lovelace amount paid by the settling Cardano tx. */
  amountLovelace: bigint;
  /** Cardano observation depth (>= MinFinalityDepth). */
  observedAtDepth: number;
  /** Cardano slot of the settling tx. */
  observedSlot: bigint;
  /** 32-byte Cardano genesis hash. */
  mainchainGenesisHash: HexString;
}

/**
 * Byte-identical to Rust `attest_batch_settle_payload(entries)` (Task #266,
 * mis-sec P0).
 *
 * Pre-image:
 *
 *     b"BSTA"
 *  || materios_chain_id (32B)
 *  || u32_le(N)
 *  || N x (claim_id (32B) || voucher_digest (32B) || cardano_tx_hash (32B)
 *          || settled_direct (1B) || beneficiary_addr_hash (28B)
 *          || amount_lovelace (LE u64, 8B) || observed_at_depth (LE u32, 4B)
 *          || observed_slot (LE u64, 8B) || mainchain_genesis_hash (32B))
 *
 * Each per-entry body is identical in shape to the single-call STCA body.
 * Flat byte stream — NOT SCALE-encoded — so the digest is independent of
 * substrate-interface BoundedVec wrapping quirks.
 */
export function attestBatchSettlePayload(args: {
  materiosChainId: HexString;
  entries: BatchAttestSettleEntry[];
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  require32(chainId, "materiosChainId");
  const n = args.entries.length;
  const parts: Uint8Array[] = [TAG_BSTA, chainId, u32LE(n)];
  for (const e of args.entries) {
    const cid = hexToU8a(e.claimId);
    const vd = hexToU8a(e.voucherDigest);
    const tx = hexToU8a(e.cardanoTxHash);
    const ben = hexToU8a(e.beneficiaryAddrHash);
    const mc = hexToU8a(e.mainchainGenesisHash);
    require32(cid, "entries[].claimId");
    require32(vd, "entries[].voucherDigest");
    require32(tx, "entries[].cardanoTxHash");
    require28(ben, "entries[].beneficiaryAddrHash");
    require32(mc, "entries[].mainchainGenesisHash");
    parts.push(
      cid,
      vd,
      tx,
      new Uint8Array([e.settledDirect ? 1 : 0]),
      ben,
      u64LE(e.amountLovelace),
      u32LE(e.observedAtDepth),
      u64LE(e.observedSlot),
      mc,
    );
  }
  const digest = blake2AsU8a(u8aConcat(...parts), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Byte-identical to Rust `credit_deposit_payload(materios_chain_id, target,
 * amount_ada, tx_hash)`.
 *
 * Pre-image (#73): `b"CRDP" || materios_chain_id (32B) || target (32B)
 *                   || amount_ada (LE u64) || cardano_tx_hash (32B)`
 *
 * @returns 32-byte blake2_256 digest that committee members must sign.
 */
export function creditDepositPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  /** 32-byte SS58 pubkey of the credited account (see spec §6). */
  depositor: HexString;
  /** Amount in lovelace (u64). */
  amountAda: bigint;
  /** 32-byte Cardano deposit tx hash. */
  cardanoTxHash: HexString;
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  const depositor = hexToU8a(args.depositor);
  const cardanoTxHash = hexToU8a(args.cardanoTxHash);
  require32(chainId, "materiosChainId");
  require32(depositor, "depositor");
  require32(cardanoTxHash, "cardanoTxHash");
  const body = u8aConcat(
    chainId,
    depositor,
    u64LE(args.amountAda),
    cardanoTxHash,
  );
  const digest = blake2AsU8a(u8aConcat(TAG_CRDP, body), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Byte-identical to Rust
 * `request_voucher_payload(claim_id, intent_id, voucher_digest, bfpr_digest)`
 * (Task #174).
 *
 * Pre-image:
 * `b"RVCH" || claim_id (32B) || intent_id (32B) || voucher_digest (32B) || bfpr_digest (32B)`
 *
 * All four 32-byte inputs are deterministic functions of state visible to
 * every honest operator at the moment of voucher mint:
 *   - `claimId`, `intentId`: chosen by the keeper, included verbatim in the
 *     dispatch.
 *   - `voucherDigest`: `compute_voucher_digest(voucher)` per the SDK's
 *     `hashing.ts::voucherDigest` helper. Pure function of the voucher
 *     struct (which the pallet stores as-is).
 *   - `bfprDigest`: `compute_fairness_proof_digest(proof)` per the SDK's
 *     `hashing.ts::fairnessProofDigest`. The pallet rejects with
 *     `FairnessDigestMismatch` unless `voucher.batch_fairness_proof_digest`
 *     equals this value, so the two digests cross-check.
 *
 * Per `feedback_mofn_hash_determinism.md` no operator-local state (wall
 * clock, Cardano epoch, locally-computed verification level) appears in
 * the pre-image. Replay-across-epoch protection comes from the live
 * committee-membership check in the pallet's `ensure_threshold_signatures`:
 * rotated-out members can no longer pass `is_member`, so old bundles can't
 * be replayed after a committee rotation.
 *
 * @returns 32-byte blake2_256 digest that committee members must sign.
 */
export function requestVoucherPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  /** 32-byte claim id (H256), hex-prefixed. */
  claimId: HexString;
  /** 32-byte intent id (H256), hex-prefixed. */
  intentId: HexString;
  /**
   * 32-byte digest of the `Voucher` struct. Compute via
   * `hashing.ts::voucherDigestWithAddress` (the chain-identity-bound CBOR
   * form) and hand the same bytes here.
   */
  voucherDigest: HexString;
  /**
   * 32-byte digest of the `BatchFairnessProof` struct. Compute via
   * `hashing.ts::fairnessProofDigest`. MUST equal
   * `voucher.batch_fairness_proof_digest`.
   */
  bfprDigest: HexString;
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  const claimId = hexToU8a(args.claimId);
  const intentId = hexToU8a(args.intentId);
  const voucherDigest = hexToU8a(args.voucherDigest);
  const bfprDigest = hexToU8a(args.bfprDigest);
  require32(chainId, "materiosChainId");
  require32(claimId, "claimId");
  require32(intentId, "intentId");
  require32(voucherDigest, "voucherDigest");
  require32(bfprDigest, "bfprDigest");
  const body = u8aConcat(chainId, claimId, intentId, voucherDigest, bfprDigest);
  const digest = blake2AsU8a(u8aConcat(TAG_RVCH, body), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Byte-identical to Rust `attest_batch_intents_payload(intent_ids)` (Task #211).
 *
 * Pre-image:
 *   `b"ABIN" || u32_le(N) || N x intent_id (32B each)`
 *
 * Flat byte stream — NOT SCALE-encoded BoundedVec — so the digest is
 * independent of the substrate-interface BoundedVec wrapping quirk
 * (`feedback_substrate_interface_boundedvec_wrap.md`). The Aiken / Rust
 * pallet mirrors reconstruct the same byte stream from raw bytes.
 *
 * Per `feedback_mofn_hash_determinism.md`: only chain-derived intent_ids
 * appear in the pre-image (no operator-local state). All committee
 * members independently compute the same digest from the keeper's
 * announced intent_ids list.
 *
 * Pinned cross-layer fixture H (`intent_ids = [0x07*32, 0x11*32, 0x22*32]`)
 * hashes to
 * `13d4c95e1e392553a6b6462eb0f5a24244007ec2410242b6de8297097a17b613`.
 *
 * @returns 32-byte blake2_256 digest committee members must sign.
 */
export function attestBatchIntentsPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  /** List of 32-byte intent IDs (H256), hex-prefixed. */
  intentIds: HexString[];
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  require32(chainId, "materiosChainId");
  const n = args.intentIds.length;
  const parts: Uint8Array[] = [TAG_ABIN, chainId, u32LE(n)];
  for (const id of args.intentIds) {
    const idBytes = hexToU8a(id);
    if (idBytes.length !== 32) {
      throw new Error(`intentId: expected 32 bytes, got ${idBytes.length}`);
    }
    parts.push(idBytes);
  }
  const digest = blake2AsU8a(u8aConcat(...parts), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Byte-identical to Rust `request_batch_vouchers_payload(entries)`
 * (Task #212).
 *
 * Pre-image:
 *   `b"RVBN" || u32_le(N) || N x (claim_id || intent_id
 *                                || voucher_digest || bfpr_digest)`
 *
 * Each per-entry tuple is identical in shape to the spec-206
 * `requestVoucherPayload` body — the batch path concatenates N of them
 * after a 4-byte length prefix and re-tags with RVBN.
 *
 * The pallet computes `voucher_digest` + `bfpr_digest` deterministically
 * from each entry's `voucher` + `fairness_proof` (canonical SCALE) BEFORE
 * verifying the signature, so the keeper and committee always see the
 * same pre-image. Compute the per-entry digests here via the SDK helpers
 * `voucherDigest` (in `hashing.ts`) and `fairnessProofDigest`.
 *
 * Pinned cross-layer fixture I:
 *   entries = [
 *     (claim=0x07*32, intent=0x11*32, vd=0x22*32, bd=0x33*32),
 *     (claim=0x44*32, intent=0x55*32, vd=0x66*32, bd=0x77*32),
 *   ]
 *   digest = `f82d8e395614d905f0a12f78adf5e6562f6493247327bcbac42f5aeba3f34873`
 *
 * @returns 32-byte blake2_256 digest committee members must sign.
 */
export function requestBatchVouchersPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  entries: {
    claimId: HexString;
    intentId: HexString;
    voucherDigest: HexString;
    bfprDigest: HexString;
  }[];
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  require32(chainId, "materiosChainId");
  const n = args.entries.length;
  const parts: Uint8Array[] = [TAG_RVBN, chainId, u32LE(n)];
  for (const e of args.entries) {
    const cid = hexToU8a(e.claimId);
    const iid = hexToU8a(e.intentId);
    const vd = hexToU8a(e.voucherDigest);
    const bd = hexToU8a(e.bfprDigest);
    if (cid.length !== 32) {
      throw new Error(`claimId: expected 32 bytes, got ${cid.length}`);
    }
    if (iid.length !== 32) {
      throw new Error(`intentId: expected 32 bytes, got ${iid.length}`);
    }
    if (vd.length !== 32) {
      throw new Error(`voucherDigest: expected 32 bytes, got ${vd.length}`);
    }
    if (bd.length !== 32) {
      throw new Error(`bfprDigest: expected 32 bytes, got ${bd.length}`);
    }
    parts.push(cid, iid, vd, bd);
  }
  const digest = blake2AsU8a(u8aConcat(...parts), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

/**
 * Byte-identical to Rust `submit_batch_intents_payload(entries)` (Task #210).
 *
 * Pre-image:
 *   `b"SBIN" || u32_le(N) || N×scale(IntentKind)`
 *
 * NOT a sig pre-image. The user-side burst stage has no M-of-N gate (the
 * user origin IS the authority). This digest is emitted in the
 * `BatchIntentsSubmitted` event so off-chain observers can correlate the
 * on-chain landing with the keeper's observed batch object. The included
 * N prefix prevents trivial digest collision between two batches that
 * share an IntentKind list of different lengths.
 *
 * Pinned cross-layer fixture G (3-entry RequestPayout list with
 * policy_ids 0x07*32 / 0x11*32 / 0x22*32 and 4-byte zero oracle_evidence
 * each) hashes to
 * `a6644ed7143c4460cb5d0b1fab0fd1de6badee4e663b1a6d11d1c223404afb0a`.
 *
 * @returns 32-byte blake2_256 digest matching the Rust pallet emission.
 */
export function submitBatchIntentsPayload(args: {
  /** #73: 32-byte Materios genesis hash. */
  materiosChainId: HexString;
  entries: { kind: IntentKind }[];
}): Uint8Array {
  const chainId = hexToU8a(args.materiosChainId);
  require32(chainId, "materiosChainId");
  const n = args.entries.length;
  const parts: Uint8Array[] = [TAG_SBIN, chainId, u32LE(n)];
  for (const e of args.entries) {
    parts.push(encodeIntentKind(e.kind));
  }
  const digest = blake2AsU8a(u8aConcat(...parts), 256);
  if (digest.length !== 32) {
    throw new Error(`blake2_256 digest length != 32 (got ${digest.length})`);
  }
  return digest;
}

// ---------------------------------------------------------------------------
// Signing.
// ---------------------------------------------------------------------------

/**
 * sr25519-sign the given payload with the provided SURI (`//Alice`,
 * `//Alice///stash`, or a 12-/24-word mnemonic).
 *
 * IMPORTANT: `payload` MUST already be the 32-byte digest produced by
 * `settleClaimPayload` / `creditDepositPayload`. Do NOT pre-hash again — the
 * pallet verifies the raw digest, not `blake2(digest)`.
 */
export function signPayload(
  seed: string,
  payload: Uint8Array,
): { pubkey: Uint8Array; sig: Uint8Array } {
  const keyring = new Keyring({ type: "sr25519" });
  const pair = keyring.addFromUri(seed);
  const sig = pair.sign(payload);
  // sr25519 sigs are 64 bytes, pubkeys 32 bytes — guard against regressions.
  if (pair.publicKey.length !== 32) {
    throw new Error(`sr25519 public key length != 32 (got ${pair.publicKey.length})`);
  }
  if (sig.length !== 64) {
    throw new Error(`sr25519 signature length != 64 (got ${sig.length})`);
  }
  // Copy so callers can't accidentally mutate keyring-owned buffers.
  return { pubkey: Uint8Array.from(pair.publicKey), sig: Uint8Array.from(sig) };
}

// ---------------------------------------------------------------------------
// Bundle assembly.
// ---------------------------------------------------------------------------

type SignerEntry = { pubkey: Uint8Array; sig: Uint8Array };

/** Byte-lex comparator so deduplication + sort are deterministic. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    // After `noUncheckedIndexedAccess`, both reads may be `number | undefined`.
    // We've bounded i to min length so the fallback is unreachable, but keep
    // the coalesce so the type narrows to `number` for the subtraction.
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) return av - bv;
  }
  return a.length - b.length;
}

/**
 * Sign `payload` with every seed and return a deterministic `(pubkey, sig)`
 * bundle suitable for the pallet's M-of-N gate.
 *
 * Behaviour:
 *  - `callerSeed`'s signer is emitted FIRST (origin-binding convenience — the
 *    pallet only checks membership, not position, but this matches the
 *    convention used in the pallet tests).
 *  - Remaining cosigners are sorted by pubkey bytes so the bundle is
 *    byte-reproducible across invocations with identical inputs.
 *  - Duplicates (same seed appearing as caller + cosigner, or twice in the
 *    cosigner list, or different SURIs resolving to the same pubkey) are
 *    dropped silently — the pallet would reject with `DuplicateSigner` so we
 *    pre-empt that failure mode.
 */
export function buildSigBundle(args: {
  callerSeed: string;
  cosignerSeeds: string[];
  payload: Uint8Array;
}): SignerEntry[] {
  const caller = signPayload(args.callerSeed, args.payload);
  const seen: Uint8Array[] = [caller.pubkey];

  const cosignerEntries: SignerEntry[] = [];
  for (const seed of args.cosignerSeeds) {
    const entry = signPayload(seed, args.payload);
    if (seen.some((pk) => u8aEq(pk, entry.pubkey))) {
      continue; // dedupe (matches pallet `DuplicateSigner` semantics).
    }
    seen.push(entry.pubkey);
    cosignerEntries.push(entry);
  }

  cosignerEntries.sort((a, b) => compareBytes(a.pubkey, b.pubkey));
  return [caller, ...cosignerEntries];
}
