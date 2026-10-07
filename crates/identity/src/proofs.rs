//! Domain-separated signed payloads: registration proof and DTLS
//! fingerprint binding. Exact byte layouts are pinned by the
//! `build_*_payload` helpers below.

use ed25519_dalek::Signature;

use crate::error::IdentityError;
use crate::keypair::{SigningKey, VerifyingKey};
use crate::peer_id::PeerId;

/// Domain separator for registration-proof signatures.
pub const REGISTRATION_DOMAIN_SEP: &[u8] = b"p2claw-register-v1";

/// Domain separator for DTLS-fingerprint signatures.
pub const DTLS_FP_DOMAIN_SEP: &[u8] = b"p2claw-dtls-fp-v1";

/// Domain separator for the coord-signed alias→peer_id binding.
pub const ALIAS_BINDING_DOMAIN_SEP: &[u8] = b"p2claw-binding-v1";

/// Domain separator for the peer-signed vanity-upgrade request.
pub const ALIAS_UPGRADE_DOMAIN_SEP: &[u8] = b"p2claw-alias-upgrade-v1";

/// Maximum accepted clock skew for registration timestamps, in seconds.
pub const REGISTRATION_MAX_SKEW_SECS: u64 = 60;

/// Maximum accepted clock skew for vanity-upgrade timestamps, in seconds.
pub const ALIAS_UPGRADE_MAX_SKEW_SECS: u64 = 60;

/// Domain separator for HTTP requests a box signs with its identity key.
pub const BOX_REQUEST_DOMAIN_SEP: &[u8] = b"p2claw-box-request-v1";

/// Maximum accepted clock skew for signed box requests, in seconds.
pub const BOX_REQUEST_MAX_SKEW_SECS: u64 = 60;

/// Headers carrying a signed box request: the signer's peer id (z-base-32),
/// the Unix timestamp the signature covers, and the signature
/// (base64url, no padding).
pub const BOX_REQUEST_PEER_HEADER: &str = "x-p2claw-peer";
pub const BOX_REQUEST_TIMESTAMP_HEADER: &str = "x-p2claw-timestamp";
pub const BOX_REQUEST_SIGNATURE_HEADER: &str = "x-p2claw-signature";

/// Build the canonical payload for a registration-proof signature:
///
/// ```text
///   "p2claw-register-v1" || 0x0A || pubkey || u16_be(len(coord_domain))
///       || coord_domain || u64_be(timestamp)
/// ```
pub fn build_registration_payload(
    pubkey: &[u8; 32],
    coord_domain: &str,
    timestamp_secs: u64,
) -> Result<Vec<u8>, IdentityError> {
    let domain = coord_domain.as_bytes();
    if domain.len() > u16::MAX as usize {
        return Err(IdentityError::CoordDomainTooLong);
    }
    let mut out = Vec::with_capacity(REGISTRATION_DOMAIN_SEP.len() + 1 + 32 + 2 + domain.len() + 8);
    out.extend_from_slice(REGISTRATION_DOMAIN_SEP);
    out.push(0x0A);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&timestamp_secs.to_be_bytes());
    Ok(out)
}

/// Sign a registration proof. Caller supplies the clock.
pub fn sign_registration(
    sk: &SigningKey,
    coord_domain: &str,
    timestamp_secs: u64,
) -> Result<Signature, IdentityError> {
    let pubkey = sk.peer_id();
    let payload = build_registration_payload(pubkey.as_bytes(), coord_domain, timestamp_secs)?;
    Ok(sk.sign(&payload))
}

/// Verify a registration proof and clock skew.
///
/// `now_secs` is the verifier's current time; `timestamp_secs` is the
/// timestamp the signer claimed. They must be within
/// [`REGISTRATION_MAX_SKEW_SECS`].
pub fn verify_registration(
    peer_id: &PeerId,
    coord_domain: &str,
    timestamp_secs: u64,
    sig: &Signature,
    now_secs: u64,
) -> Result<(), IdentityError> {
    let skew = now_secs.abs_diff(timestamp_secs);
    if skew > REGISTRATION_MAX_SKEW_SECS {
        return Err(IdentityError::ClockSkew {
            skew,
            max: REGISTRATION_MAX_SKEW_SECS,
        });
    }
    let payload = build_registration_payload(peer_id.as_bytes(), coord_domain, timestamp_secs)?;
    let vk = VerifyingKey::from_peer_id(peer_id)?;
    vk.verify(&payload, sig)
}

/// Build the canonical payload for a DTLS-fingerprint signature:
///
/// ```text
///   "p2claw-dtls-fp-v1" || 0x0A || pubkey || u16_be(len(session_id))
///       || session_id || u8(fp_alg) || fp
/// ```
pub fn build_dtls_fp_payload(
    pubkey: &[u8; 32],
    session_id: &str,
    fp_alg: u8,
    fp: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let sid = session_id.as_bytes();
    if sid.len() > u16::MAX as usize {
        return Err(IdentityError::SessionIdTooLong);
    }
    let mut out =
        Vec::with_capacity(DTLS_FP_DOMAIN_SEP.len() + 1 + 32 + 2 + sid.len() + 1 + fp.len());
    out.extend_from_slice(DTLS_FP_DOMAIN_SEP);
    out.push(0x0A);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&(sid.len() as u16).to_be_bytes());
    out.extend_from_slice(sid);
    out.push(fp_alg);
    out.extend_from_slice(fp);
    Ok(out)
}

pub fn sign_dtls_fp(
    sk: &SigningKey,
    session_id: &str,
    fp_alg: u8,
    fp: &[u8],
) -> Result<Signature, IdentityError> {
    let pubkey = sk.peer_id();
    let payload = build_dtls_fp_payload(pubkey.as_bytes(), session_id, fp_alg, fp)?;
    Ok(sk.sign(&payload))
}

pub fn verify_dtls_fp(
    peer_id: &PeerId,
    session_id: &str,
    fp_alg: u8,
    fp: &[u8],
    sig: &Signature,
) -> Result<(), IdentityError> {
    let payload = build_dtls_fp_payload(peer_id.as_bytes(), session_id, fp_alg, fp)?;
    let vk = VerifyingKey::from_peer_id(peer_id)?;
    vk.verify(&payload, sig)
}

/// Build the canonical payload for a coord-signed alias→peer_id
/// binding:
///
/// ```text
///   "p2claw-binding-v1" || 0x0A
///       || u16_be(len(alias)) || alias
///       || 0x00
///       || pubkey (32 bytes)
///       || u64_be(issued_at)
/// ```
///
/// The inner `0x00` separator between the length-prefixed alias and
/// the pubkey keeps the layout self-delimiting so a future field
/// insertion (e.g. `kind`) can be added without retroactively
/// changing older signatures.
pub fn build_alias_binding_payload(
    alias: &str,
    pubkey: &[u8; 32],
    issued_at: u64,
) -> Result<Vec<u8>, IdentityError> {
    let alias_bytes = alias.as_bytes();
    if alias_bytes.len() > u16::MAX as usize {
        return Err(IdentityError::AliasTooLong);
    }
    let mut out =
        Vec::with_capacity(ALIAS_BINDING_DOMAIN_SEP.len() + 1 + 2 + alias_bytes.len() + 1 + 32 + 8);
    out.extend_from_slice(ALIAS_BINDING_DOMAIN_SEP);
    out.push(0x0A);
    out.extend_from_slice(&(alias_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(alias_bytes);
    out.push(0x00);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&issued_at.to_be_bytes());
    Ok(out)
}

/// Sign an alias binding with the coord root key.
pub fn sign_alias_binding(
    root_sk: &SigningKey,
    alias: &str,
    peer_id: &PeerId,
    issued_at: u64,
) -> Result<Signature, IdentityError> {
    let payload = build_alias_binding_payload(alias, peer_id.as_bytes(), issued_at)?;
    Ok(root_sk.sign(&payload))
}

/// Verify an alias binding against the coord's root public key.
/// Used by the bootstrap (with a pinned root pubkey) to check the
/// edge-injected binding metadata.
pub fn verify_alias_binding(
    root_vk: &VerifyingKey,
    alias: &str,
    peer_id: &PeerId,
    issued_at: u64,
    sig: &Signature,
) -> Result<(), IdentityError> {
    let payload = build_alias_binding_payload(alias, peer_id.as_bytes(), issued_at)?;
    root_vk.verify(&payload, sig)
}

/// Build the canonical payload for a peer-signed vanity-upgrade
/// request:
///
/// ```text
///   "p2claw-alias-upgrade-v1" || 0x0A
///       || pubkey (32 bytes)
///       || u16_be(len(requested_alias)) || requested_alias
///       || u16_be(len(coord_domain)) || coord_domain
///       || u64_be(timestamp)
/// ```
pub fn build_alias_upgrade_payload(
    pubkey: &[u8; 32],
    requested_alias: &str,
    coord_domain: &str,
    timestamp_secs: u64,
) -> Result<Vec<u8>, IdentityError> {
    let alias_bytes = requested_alias.as_bytes();
    if alias_bytes.len() > u16::MAX as usize {
        return Err(IdentityError::AliasTooLong);
    }
    let domain = coord_domain.as_bytes();
    if domain.len() > u16::MAX as usize {
        return Err(IdentityError::CoordDomainTooLong);
    }
    let mut out = Vec::with_capacity(
        ALIAS_UPGRADE_DOMAIN_SEP.len() + 1 + 32 + 2 + alias_bytes.len() + 2 + domain.len() + 8,
    );
    out.extend_from_slice(ALIAS_UPGRADE_DOMAIN_SEP);
    out.push(0x0A);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&(alias_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(alias_bytes);
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&timestamp_secs.to_be_bytes());
    Ok(out)
}

/// Sign a vanity-upgrade request with the peer's identity key.
pub fn sign_alias_upgrade(
    sk: &SigningKey,
    requested_alias: &str,
    coord_domain: &str,
    timestamp_secs: u64,
) -> Result<Signature, IdentityError> {
    let pubkey = sk.peer_id();
    let payload = build_alias_upgrade_payload(
        pubkey.as_bytes(),
        requested_alias,
        coord_domain,
        timestamp_secs,
    )?;
    Ok(sk.sign(&payload))
}

/// Verify a vanity-upgrade request against the peer's identity key
/// and the server's clock skew window.
pub fn verify_alias_upgrade(
    peer_id: &PeerId,
    requested_alias: &str,
    coord_domain: &str,
    timestamp_secs: u64,
    sig: &Signature,
    now_secs: u64,
) -> Result<(), IdentityError> {
    let skew = now_secs.abs_diff(timestamp_secs);
    if skew > ALIAS_UPGRADE_MAX_SKEW_SECS {
        return Err(IdentityError::ClockSkew {
            skew,
            max: ALIAS_UPGRADE_MAX_SKEW_SECS,
        });
    }
    let payload = build_alias_upgrade_payload(
        peer_id.as_bytes(),
        requested_alias,
        coord_domain,
        timestamp_secs,
    )?;
    let vk = VerifyingKey::from_peer_id(peer_id)?;
    vk.verify(&payload, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_binding_payload_shape() {
        let pubkey = [7u8; 32];
        let payload =
            build_alias_binding_payload("blue-otter-7392", &pubkey, 0x1122_3344_5566_7788).unwrap();
        assert!(payload.starts_with(b"p2claw-binding-v1\n"));
        // After domain separator + 0x0A comes u16_be alias length.
        let off = ALIAS_BINDING_DOMAIN_SEP.len() + 1;
        let alias_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
        assert_eq!(alias_len, "blue-otter-7392".len());
        // Alias bytes, then the 0x00 separator, then the 32-byte pubkey.
        let alias_start = off + 2;
        let alias_end = alias_start + alias_len;
        assert_eq!(&payload[alias_start..alias_end], b"blue-otter-7392");
        assert_eq!(payload[alias_end], 0x00);
        let pk_start = alias_end + 1;
        assert_eq!(&payload[pk_start..pk_start + 32], &pubkey[..]);
        // Timestamp trails as u64_be.
        assert_eq!(
            &payload[pk_start + 32..],
            &0x1122_3344_5566_7788u64.to_be_bytes()
        );
    }

    #[test]
    fn alias_binding_roundtrip() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let sig = sign_alias_binding(&root, "blue-otter-7392", &peer, 1_767_400_000).unwrap();
        verify_alias_binding(
            &root.verifying_key(),
            "blue-otter-7392",
            &peer,
            1_767_400_000,
            &sig,
        )
        .expect("binding should verify");
        // Tampered alias → BadSignature.
        let err = verify_alias_binding(
            &root.verifying_key(),
            "blue-otter-7393",
            &peer,
            1_767_400_000,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::BadSignature));
    }

    #[test]
    fn alias_binding_domain_separator_collision_protection() {
        // A registration-signed blob must not verify as a binding,
        // even if the low-level bytes happen to align.
        let sk = SigningKey::generate();
        let peer = sk.peer_id();
        let reg_sig = sign_registration(&sk, "coord.p2claw.com", 1_767_400_000).unwrap();
        let err = verify_alias_binding(
            &sk.verifying_key(),
            "blue-otter-7392",
            &peer,
            1_767_400_000,
            &reg_sig,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::BadSignature));
    }

    #[test]
    fn alias_upgrade_payload_shape() {
        let pubkey = [9u8; 32];
        let payload = build_alias_upgrade_payload(
            &pubkey,
            "swift-falcon-0001",
            "coord.p2claw.com",
            1_767_400_000,
        )
        .unwrap();
        assert!(payload.starts_with(b"p2claw-alias-upgrade-v1\n"));
    }

    #[test]
    fn alias_upgrade_roundtrip() {
        let sk = SigningKey::generate();
        let peer = sk.peer_id();
        let now = 1_767_400_000;
        let sig = sign_alias_upgrade(&sk, "swift-falcon-0001", "coord.p2claw.com", now).unwrap();
        verify_alias_upgrade(
            &peer,
            "swift-falcon-0001",
            "coord.p2claw.com",
            now,
            &sig,
            now,
        )
        .expect("upgrade sig should verify");
        // Beyond the skew window → ClockSkew.
        let err = verify_alias_upgrade(
            &peer,
            "swift-falcon-0001",
            "coord.p2claw.com",
            now,
            &sig,
            now + ALIAS_UPGRADE_MAX_SKEW_SECS + 1,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::ClockSkew { .. }));
    }

    #[test]
    fn alias_upgrade_rejects_other_peer() {
        let sk = SigningKey::generate();
        let other = SigningKey::generate().peer_id();
        let now = 1_767_400_000;
        let sig = sign_alias_upgrade(&sk, "swift-falcon-0001", "coord.p2claw.com", now).unwrap();
        let err = verify_alias_upgrade(
            &other,
            "swift-falcon-0001",
            "coord.p2claw.com",
            now,
            &sig,
            now,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::BadSignature));
    }
}

/// Build the canonical payload for a signed box request:
///
/// ```text
///   "p2claw-box-request-v1" || 0x0A || pubkey
///       || u16_be(len(host)) || host || u16_be(len(method)) || method
///       || u16_be(len(path)) || path || u64_be(timestamp) || sha256(body)
/// ```
///
/// `host` is the authority the request is sent to, so a signature for one
/// service can't be replayed at another; `path` includes the query string.
pub fn build_box_request_payload(
    pubkey: &[u8; 32],
    host: &str,
    method: &str,
    path: &str,
    timestamp_secs: u64,
    body_sha256: &[u8; 32],
) -> Result<Vec<u8>, IdentityError> {
    let mut out = Vec::with_capacity(
        BOX_REQUEST_DOMAIN_SEP.len() + 1 + 32 + 6 + host.len() + method.len() + path.len() + 8 + 32,
    );
    out.extend_from_slice(BOX_REQUEST_DOMAIN_SEP);
    out.push(0x0A);
    out.extend_from_slice(pubkey);
    for field in [host, method, path] {
        let bytes = field.as_bytes();
        if bytes.len() > u16::MAX as usize {
            return Err(IdentityError::FieldTooLong);
        }
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(&timestamp_secs.to_be_bytes());
    out.extend_from_slice(body_sha256);
    Ok(out)
}

/// Sign an HTTP request as this box. Caller supplies the clock and the
/// body's SHA-256.
pub fn sign_box_request(
    sk: &SigningKey,
    host: &str,
    method: &str,
    path: &str,
    timestamp_secs: u64,
    body_sha256: &[u8; 32],
) -> Result<Signature, IdentityError> {
    let payload = build_box_request_payload(
        sk.peer_id().as_bytes(),
        host,
        method,
        path,
        timestamp_secs,
        body_sha256,
    )?;
    Ok(sk.sign(&payload))
}

/// Verify a signed box request and its clock skew
/// ([`BOX_REQUEST_MAX_SKEW_SECS`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_box_request(
    peer_id: &PeerId,
    host: &str,
    method: &str,
    path: &str,
    timestamp_secs: u64,
    body_sha256: &[u8; 32],
    sig: &Signature,
    now_secs: u64,
) -> Result<(), IdentityError> {
    let skew = now_secs.abs_diff(timestamp_secs);
    if skew > BOX_REQUEST_MAX_SKEW_SECS {
        return Err(IdentityError::ClockSkew {
            skew,
            max: BOX_REQUEST_MAX_SKEW_SECS,
        });
    }
    let payload = build_box_request_payload(
        peer_id.as_bytes(),
        host,
        method,
        path,
        timestamp_secs,
        body_sha256,
    )?;
    VerifyingKey::from_peer_id(peer_id)?.verify(&payload, sig)
}

#[cfg(test)]
mod box_request_tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let sk = SigningKey::generate();
        let body = [7u8; 32];
        let sig = sign_box_request(
            &sk,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/refresh",
            1000,
            &body,
        )
        .unwrap();
        let pid = sk.peer_id();
        verify_box_request(
            &pid,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/refresh",
            1000,
            &body,
            &sig,
            1030,
        )
        .unwrap();
        assert!(verify_box_request(
            &pid,
            "evil.example",
            "POST",
            "/connect/google/refresh",
            1000,
            &body,
            &sig,
            1030
        )
        .is_err());
        assert!(verify_box_request(
            &pid,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/exchange",
            1000,
            &body,
            &sig,
            1030
        )
        .is_err());
        assert!(verify_box_request(
            &pid,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/refresh",
            1000,
            &[8u8; 32],
            &sig,
            1030
        )
        .is_err());
        assert!(matches!(
            verify_box_request(
                &pid,
                "oauth.p2claw.com",
                "POST",
                "/connect/google/refresh",
                1000,
                &body,
                &sig,
                1100
            ),
            Err(IdentityError::ClockSkew { .. })
        ));
    }
}
