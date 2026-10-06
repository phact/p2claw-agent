//! z-base-32 encoding used for canonical `PeerId` strings and DNS
//! labels. Alphabet:
//!
//! ```text
//! ybndrfg8ejkmcpqxot1uwisza345h769
//! ```
//!
//! Omits visually confusable characters (`0`/`O`, `1`/`l`/`I`) and is
//! fully lowercase. No padding. Every 5 input bits map to one output
//! character; 32-byte inputs produce 52 characters (256 bits → 260
//! output bits, trailing 4 bits are padding and MUST decode to zero).

use crate::error::IdentityError;

pub const Z32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Reverse lookup: `DECODE[byte] == 0xFF` means "not in alphabet".
const DECODE: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0u8;
    while i < 32 {
        let c = Z32_ALPHABET[i as usize];
        t[c as usize] = i;
        i += 1;
    }
    t
};

/// Encode bytes to z-base-32. Output length is `ceil(input_len * 8 / 5)`.
pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let out_len = input.len().saturating_mul(8).div_ceil(5);
    let mut out = String::with_capacity(out_len);

    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(Z32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        // Left-shift the remaining bits so they occupy the top of a
        // 5-bit group; implicit zero padding at the bottom.
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(Z32_ALPHABET[idx] as char);
    }
    out
}

/// Decode z-base-32. `expected_bytes` tells the decoder the exact
/// output length; the function validates that any trailing padding
/// bits are zero.
pub fn decode(s: &str, expected_bytes: usize) -> Result<Vec<u8>, IdentityError> {
    let expected_chars = expected_bytes.saturating_mul(8).div_ceil(5);
    if s.len() != expected_chars {
        return Err(IdentityError::Z32WrongLength {
            got: s.len(),
            expected: expected_chars,
        });
    }

    let mut out = Vec::with_capacity(expected_bytes);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v = DECODE[c as usize];
        if v == 0xFF {
            return Err(IdentityError::Z32InvalidChar(c));
        }
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = ((buf >> bits) & 0xFF) as u8;
            out.push(byte);
        }
    }

    if out.len() != expected_bytes {
        return Err(IdentityError::Z32WrongLength {
            got: out.len(),
            expected: expected_bytes,
        });
    }

    // Any bits left in the buffer are padding and must be zero.
    if bits > 0 {
        let padding_mask = (1u32 << bits) - 1;
        if (buf & padding_mask) != 0 {
            return Err(IdentityError::Z32NonZeroPadding);
        }
    }

    Ok(out)
}
