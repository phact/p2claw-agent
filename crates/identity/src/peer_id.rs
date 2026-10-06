use std::fmt;

use crate::error::IdentityError;
use crate::zbase32;

/// Length of the canonical z-base-32 encoding of a 32-byte pubkey.
pub const PEER_ID_Z32_LEN: usize = 52;

/// Minimum alias length: first 12 z-base-32 chars of `peer_id_z32`.
/// Aliases are always at least this long.
pub const ALIAS_BASE_LEN: usize = 12;

/// Maximum alias length. Coord extends one z-base-32 char at a time
/// on prefix collision up to this cap (~80 bits, ~2⁻⁴⁰ collision
/// rate per pair); beyond it registration is rejected.
pub const ALIAS_MAX_LEN: usize = 16;

/// A peer identifier: the raw Ed25519 public key bytes, no hash, no
/// truncation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Canonical z-base-32 string, lowercase, 52 characters.
    pub fn to_z32(&self) -> String {
        zbase32::encode(&self.0)
    }

    /// Parse the 52-char z-base-32 form.
    pub fn from_z32(s: &str) -> Result<Self, IdentityError> {
        let v = zbase32::decode(s, 32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(Self(arr))
    }

    /// First 12 characters of the canonical z-base-32 string — the
    /// `alias_base` used as the default alias.
    pub fn alias_base(&self) -> String {
        let s = self.to_z32();
        s[..ALIAS_BASE_LEN].to_string()
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.to_z32())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_z32())
    }
}
