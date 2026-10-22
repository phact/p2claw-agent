//! The coordination root key the agent trusts.
//!
//! Coord's root key is its iroh node ID for the control connection and
//! the key that signs alias bindings. Registration and `/v1/coord-self`
//! deliver it over HTTPS, so on their own they trust any certificate
//! authority that can issue for the coordination host. The production
//! key is compiled in instead. Other deployments configure theirs
//! (`--coord-root-pubkey`), or trust the key from first registration;
//! either way a key that differs from the expected one is refused,
//! never adopted.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine as _;
use p2claw_identity::PeerId;

/// Coordination FQDN the compiled-in root key belongs to.
pub const DEFAULT_COORD_DOMAIN: &str = "coord.p2claw.com";

/// Root key of [`DEFAULT_COORD_DOMAIN`]. Forks pointing the default at
/// their own coordination service set `P2CLAW_DEFAULT_COORD_ROOT_PUBKEY`
/// (base64url) at build time.
pub fn default_root() -> Result<PeerId, String> {
    match option_env!("P2CLAW_DEFAULT_COORD_ROOT_PUBKEY") {
        Some(b64) => decode(b64),
        None => Ok(p2claw_identity::p2claw_coord_root()),
    }
}

/// Decode a base64url (no padding) 32-byte root key.
pub fn decode(b64: &str) -> Result<PeerId, String> {
    let raw = B64_URL.decode(b64).map_err(|e| format!("base64: {e}"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", raw.len()))?;
    Ok(PeerId::from_bytes(bytes))
}

/// The root key pinned for `coord_domain`: the configured one, else the
/// compiled-in key when `coord_domain` is the default. `None` means no
/// pin, and the key from first registration is trusted.
pub fn pinned(coord_domain: &str, configured: Option<&str>) -> Result<Option<PeerId>, String> {
    match configured.filter(|s| !s.is_empty()) {
        Some(b64) => decode(b64).map(Some),
        None if coord_domain == DEFAULT_COORD_DOMAIN => default_root().map(Some),
        None => Ok(None),
    }
}

/// The key a registration response must carry: the pin, else the key
/// already on record. The all-zeros placeholder for an undecodable key
/// counts as no record.
pub fn expected(pin: Option<PeerId>, recorded: Option<&PeerId>) -> Option<PeerId> {
    pin.or_else(|| recorded.filter(|k| k.as_bytes() != &[0u8; 32]).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_domain_pins_compiled_in_key() {
        let pin = pinned(DEFAULT_COORD_DOMAIN, None).unwrap();
        assert_eq!(pin, Some(default_root().unwrap()));
    }

    #[test]
    fn built_in_key_is_the_production_root() {
        if option_env!("P2CLAW_DEFAULT_COORD_ROOT_PUBKEY").is_none() {
            let b64 = B64_URL.encode(default_root().unwrap().as_bytes());
            assert_eq!(b64, "SS7zAo5r6_W2IOX1WMpt0Y6hhMdxgDZKsWrhHQoCCTg");
        }
    }

    #[test]
    fn configured_key_wins() {
        let k = B64_URL.encode([7u8; 32]);
        let pin = pinned(DEFAULT_COORD_DOMAIN, Some(&k)).unwrap();
        assert_eq!(pin, Some(PeerId::from_bytes([7u8; 32])));
        let pin = pinned("coord.example.net", Some(&k)).unwrap();
        assert_eq!(pin, Some(PeerId::from_bytes([7u8; 32])));
    }

    #[test]
    fn other_domain_without_config_is_unpinned() {
        assert_eq!(pinned("coord.example.net", None).unwrap(), None);
        assert_eq!(pinned("coord.example.net", Some("")).unwrap(), None);
    }

    #[test]
    fn bad_configured_key_is_an_error() {
        assert!(pinned(DEFAULT_COORD_DOMAIN, Some("not-a-key")).is_err());
        assert!(pinned(DEFAULT_COORD_DOMAIN, Some(&B64_URL.encode([1u8; 31]))).is_err());
    }

    #[test]
    fn expected_prefers_pin_then_record() {
        let pin = PeerId::from_bytes([1u8; 32]);
        let rec = PeerId::from_bytes([2u8; 32]);
        let zero = PeerId::from_bytes([0u8; 32]);
        assert_eq!(expected(Some(pin), Some(&rec)), Some(pin));
        assert_eq!(expected(None, Some(&rec)), Some(rec));
        assert_eq!(expected(None, Some(&zero)), None);
        assert_eq!(expected(None, None), None);
    }
}
