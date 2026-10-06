"""z-base-32 codec for p2claw peer ids.

peer_id is the box's Ed25519 public key (32 bytes) encoded as 52
z-base-32 characters. The alphabet is the canonical Zooko form:
human-readable, no easy-to-confuse pairs.

Reference: http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
"""

from __future__ import annotations

_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
_DECODE_TABLE: dict[str, int] = {ch: i for i, ch in enumerate(_ALPHABET)}


def decode_peer_id(peer_id: str) -> bytes:
    """Decode a 52-char z-base-32 string into a 32-byte Ed25519 pubkey.

    Raises:
        ValueError: if the input isn't 52 characters of the z-base-32
            alphabet, or has non-zero trailing pad bits.
    """
    if len(peer_id) != 52:
        raise ValueError(
            f"peer_id length must be 52 z-base-32 characters, got {len(peer_id)}"
        )
    out = bytearray(32)
    buffer = 0
    bits_held = 0
    out_idx = 0
    for i, ch in enumerate(peer_id):
        v = _DECODE_TABLE.get(ch)
        if v is None:
            raise ValueError(
                f"peer_id contains non-z-base-32 character at index {i}"
            )
        buffer = (buffer << 5) | v
        bits_held += 5
        if bits_held >= 8:
            bits_held -= 8
            out[out_idx] = (buffer >> bits_held) & 0xFF
            out_idx += 1
    if bits_held > 0 and (buffer & ((1 << bits_held) - 1)) != 0:
        raise ValueError("peer_id has non-zero trailing bits")
    return bytes(out)


def encode_peer_id(pubkey: bytes) -> str:
    """Encode a 32-byte Ed25519 pubkey into its 52-char z-base-32 form.

    Used by the placeholder vector generator; not part of the public
    verify API.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
    buffer = 0
    bits_held = 0
    out: list[str] = []
    for byte in pubkey:
        buffer = (buffer << 8) | byte
        bits_held += 8
        while bits_held >= 5:
            bits_held -= 5
            out.append(_ALPHABET[(buffer >> bits_held) & 0x1F])
    if bits_held > 0:
        out.append(_ALPHABET[(buffer << (5 - bits_held)) & 0x1F])
    return "".join(out)
