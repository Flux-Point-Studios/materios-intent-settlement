import { describe, it, expect } from "vitest";
import {
  encodeType0AddressCbor,
  splitType0AddressBytes,
} from "./cardano-address.js";

// The pinned anchor address from docs/test-vectors.json::voucher_digest_with_address.
// Bech32: addr1qx2h3pcsp6l9lxc0nujfdrczrmmstvju024xxvjcu2ywptslud3z94x5tgw8p0aefdjm8wxwrt0j49y384nuxgsjd9xq89stdk
const PINNED_PAYMENT = new Uint8Array([
  0x95, 0x78, 0x87, 0x10, 0x0e, 0xbe, 0x5f, 0x9b, 0x0f, 0x9f, 0x24, 0x96, 0x8f, 0x02,
  0x1e, 0xf7, 0x05, 0xb2, 0x5c, 0x7a, 0xaa, 0x63, 0x32, 0x58, 0xe2, 0x88, 0xe0, 0xae,
]);
const PINNED_STAKE = new Uint8Array([
  0x1f, 0xe3, 0x62, 0x22, 0xd4, 0xd4, 0x5a, 0x1c, 0x70, 0xbf, 0xb9, 0x4b, 0x65, 0xb3,
  0xb8, 0xce, 0x1a, 0xdf, 0x2a, 0x94, 0x91, 0x3d, 0x67, 0xc3, 0x22, 0x12, 0x69, 0x4c,
]);

/** Pinned Aiken output for the anchor address — from test_vectors.ak::vec_vchr_address_cbor_pinned. */
const PINNED_CBOR_HEX =
  "d8799fd8799f581c957887100ebe5f9b0f9f24968f021ef705b25c7aaa633258e288e0aeffd8799fd8799fd8799f581c1fe36222d4d45a1c70bfb94b65b3b8ce1adf2a94913d67c32212694cffffffff";

function toHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("encodeType0AddressCbor", () => {
  it("emits exactly 80 bytes for a type-0 address", () => {
    const cbor = encodeType0AddressCbor({
      paymentHash: PINNED_PAYMENT,
      stakeHash: PINNED_STAKE,
    });
    expect(cbor.length).toBe(80);
  });

  it("matches the Aiken pinned CBOR for the anchor address (three-way parity)", () => {
    const cbor = encodeType0AddressCbor({
      paymentHash: PINNED_PAYMENT,
      stakeHash: PINNED_STAKE,
    });
    expect(toHex(cbor)).toBe(PINNED_CBOR_HEX);
  });

  it("emits correct outer markers (d8 79 9f ... ff)", () => {
    const cbor = encodeType0AddressCbor({
      paymentHash: PINNED_PAYMENT,
      stakeHash: PINNED_STAKE,
    });
    expect(cbor[0]).toBe(0xd8);
    expect(cbor[1]).toBe(0x79);
    expect(cbor[2]).toBe(0x9f);
    expect(cbor[79]).toBe(0xff);
    // bstr(28) prefix
    expect(cbor[6]).toBe(0x58);
    expect(cbor[7]).toBe(0x1c);
    expect(cbor[46]).toBe(0x58);
    expect(cbor[47]).toBe(0x1c);
  });

  it("rejects non-28-byte payment hash", () => {
    expect(() =>
      encodeType0AddressCbor({
        paymentHash: new Uint8Array(27),
        stakeHash: PINNED_STAKE,
      }),
    ).toThrow();
  });

  it("rejects non-28-byte stake hash", () => {
    expect(() =>
      encodeType0AddressCbor({
        paymentHash: PINNED_PAYMENT,
        stakeHash: new Uint8Array(29),
      }),
    ).toThrow();
  });

  it("distinct addresses produce distinct CBOR", () => {
    const a = encodeType0AddressCbor({
      paymentHash: PINNED_PAYMENT,
      stakeHash: PINNED_STAKE,
    });
    const b = encodeType0AddressCbor({
      paymentHash: new Uint8Array(28), // zeros
      stakeHash: new Uint8Array(28),
    });
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe("splitType0AddressBytes", () => {
  it("round-trips the pinned anchor address", () => {
    const raw = new Uint8Array(57);
    raw[0] = 0x01;
    raw.set(PINNED_PAYMENT, 1);
    raw.set(PINNED_STAKE, 29);
    const { paymentHash, stakeHash } = splitType0AddressBytes(raw);
    expect(toHex(paymentHash)).toBe(toHex(PINNED_PAYMENT));
    expect(toHex(stakeHash)).toBe(toHex(PINNED_STAKE));
  });

  it("rejects wrong-length input", () => {
    expect(() => splitType0AddressBytes(new Uint8Array(10))).toThrow();
  });

  it("rejects non-type-0 header byte", () => {
    const raw = new Uint8Array(57);
    raw[0] = 0x02;
    expect(() => splitType0AddressBytes(raw)).toThrow(/type-0/);
  });
});
