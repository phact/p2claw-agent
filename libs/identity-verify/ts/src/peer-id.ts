// z-base-32 codec for p2claw peer ids.
//
// peer_id is the box's Ed25519 public key (32 bytes) encoded as
// 52 z-base-32 characters. The alphabet is the canonical Zooko form:
// human-readable, no easy-to-confuse pairs (no 0/O, 1/l/I, etc.).
//
// Reference: http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt

const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

const DECODE_TABLE: Record<string, number> = (() => {
  const t: Record<string, number> = {};
  for (let i = 0; i < ALPHABET.length; i++) {
    t[ALPHABET[i]!] = i;
  }
  return t;
})();

/**
 * Decode a 52-char z-base-32 string into the 32-byte Ed25519 public
 * key it encodes. Throws on any input that isn't exactly 52 chars of
 * the z-base-32 alphabet.
 */
export function decodePeerId(peerId: string): Uint8Array {
  if (peerId.length !== 52) {
    throw new Error(
      `peer_id length must be 52 z-base-32 characters, got ${peerId.length}`,
    );
  }
  // 52 chars × 5 bits = 260 bits; we want the leading 256 bits = 32
  // bytes. The trailing 4 bits are padding and must be zero.
  const out = new Uint8Array(32);
  let buffer = 0;
  let bitsHeld = 0;
  let outIdx = 0;
  for (let i = 0; i < peerId.length; i++) {
    const ch = peerId[i]!;
    const v = DECODE_TABLE[ch];
    if (v === undefined) {
      throw new Error(`peer_id contains non-z-base-32 character at index ${i}`);
    }
    buffer = (buffer << 5) | v;
    bitsHeld += 5;
    if (bitsHeld >= 8) {
      bitsHeld -= 8;
      out[outIdx++] = (buffer >> bitsHeld) & 0xff;
    }
  }
  // Any leftover bits must be zero — anything else is a corrupted
  // peer_id (real encoders zero-pad on the right).
  if (bitsHeld > 0 && (buffer & ((1 << bitsHeld) - 1)) !== 0) {
    throw new Error("peer_id has non-zero trailing bits");
  }
  return out;
}

/**
 * Encode a 32-byte Ed25519 public key into its 52-char z-base-32
 * peer_id form. Used by the placeholder vector generator; not part
 * of the public verify API.
 */
export function encodePeerId(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) {
    throw new Error(`pubkey must be 32 bytes, got ${pubkey.length}`);
  }
  let buffer = 0;
  let bitsHeld = 0;
  let out = "";
  for (let i = 0; i < pubkey.length; i++) {
    buffer = (buffer << 8) | pubkey[i]!;
    bitsHeld += 8;
    while (bitsHeld >= 5) {
      bitsHeld -= 5;
      out += ALPHABET[(buffer >> bitsHeld) & 0x1f];
    }
  }
  if (bitsHeld > 0) {
    out += ALPHABET[(buffer << (5 - bitsHeld)) & 0x1f];
  }
  return out;
}
