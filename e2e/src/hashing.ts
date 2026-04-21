/**
 * Domain-tagged Blake2b-256 hashing per spec §1.1.
 *
 * Reference implementation the E2E test uses to RECOMPUTE IntentId, VoucherDigest,
 * FairnessProofDigest values from raw bytes and assert them equal to what the
 * pallet / keeper produced. If Team A's SDK disagrees with this module,
 * we surface the drift loudly (that is the point of this file).
 *
 * Team A's canonical SDK MUST produce byte-identical output for the same input;
 * see `tests/hashing.test.ts` for the vector-based cross-check.
 */

import blake2b from 'blake2b';
import type { DomainTag, H256 } from './types.js';

/** Spec §1.1: pre-image = 4-byte ASCII tag || body. */
export function domainHash(tag: DomainTag, body: Uint8Array): H256 {
  if (tag.length !== 4) {
    throw new Error(`domain tag must be 4 ASCII bytes, got ${tag.length}: ${tag}`);
  }
  const tagBytes = new TextEncoder().encode(tag);
  if (tagBytes.length !== 4) {
    throw new Error(`domain tag must encode to 4 bytes (ASCII only), got ${tagBytes.length}`);
  }
  const buf = new Uint8Array(4 + body.length);
  buf.set(tagBytes, 0);
  buf.set(body, 4);
  const out = blake2b(32).update(buf).digest();
  return toHex(out);
}

/** Little-endian u32 encoder (SCALE convention). */
export function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xff_ff_ff_ff) {
    throw new Error(`u32le out of range: ${n}`);
  }
  const buf = new Uint8Array(4);
  buf[0] = n & 0xff;
  buf[1] = (n >>> 8) & 0xff;
  buf[2] = (n >>> 16) & 0xff;
  buf[3] = (n >>> 24) & 0xff;
  return buf;
}

/** Little-endian u64 encoder (SCALE convention). */
export function u64le(n: bigint): Uint8Array {
  if (n < 0n || n > 0xff_ff_ff_ff_ff_ff_ff_ffn) {
    throw new Error(`u64le out of range: ${n}`);
  }
  const buf = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    buf[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  }
  return buf;
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error(`odd-length hex: ${hex}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex: ${hex}`);
    out[i] = byte;
  }
  return out;
}

export function toHex(bytes: Uint8Array): H256 {
  let s = '0x';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s as H256;
}
