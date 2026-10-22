//! Checks that make coordination a relay rather than a party to the
//! session.
//!
//! Coordination answers `/v1/connect` with the box's peer id and then
//! relays the box's SDP offer. Without checks, whoever answers for
//! coordination can name any peer and hand over its own offer, and
//! WebRTC would complete the handshake with them. Two signatures close
//! that:
//!
//! - the alias binding, signed by coordination's root key, ties the
//!   requested alias to the peer id ([`check_resolution`]);
//! - the DTLS-fingerprint signature, made by that peer's own key, ties
//!   the offer's certificate fingerprint to this session
//!   ([`check_offer`]). WebRTC then refuses any certificate that
//!   doesn't match the fingerprint.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p2claw_identity::{
    verify_alias_resolution, verify_dtls_fp, AliasBindingRef, PeerId, Signature,
};

/// Production coordination URL, whose root key is built in.
pub const DEFAULT_COORD_URL: &str = "https://coord.p2claw.com";

/// `fp_alg` code for SHA-256 in the DTLS-fingerprint signature.
const FP_ALG_SHA256: u8 = 0x01;

/// The root key to check coordination's answers against: `configured`
/// (z-base-32) if set, else the built-in key for [`DEFAULT_COORD_URL`].
pub fn coord_root(coord_url: &str, configured: Option<&str>) -> Result<PeerId, String> {
    match configured.filter(|s| !s.is_empty()) {
        Some(z32) => PeerId::from_z32(z32).map_err(|e| format!("coord root key: {e}")),
        None if coord_url.trim_end_matches('/') == DEFAULT_COORD_URL => {
            Ok(p2claw_identity::p2claw_coord_root())
        }
        None => Err(format!(
            "no coordination root key configured for {coord_url}"
        )),
    }
}

/// The binding fields of a `/v1/connect` answer, as received.
#[derive(Debug, Default, Clone)]
pub struct Binding {
    pub alias: Option<String>,
    pub sig_b64url: Option<String>,
    pub issued_at: Option<u64>,
}

/// Accept `peer_id` as coordination's answer for `target` only if
/// `root` vouches for it.
pub fn check_resolution(
    root: &PeerId,
    target: &str,
    peer_id: &str,
    binding: &Binding,
) -> Result<PeerId, String> {
    let peer = PeerId::from_z32(peer_id).map_err(|e| format!("peer_id: {e}"))?;
    let sig = match binding.sig_b64url.as_deref() {
        Some(b64) => Some(
            URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|_| "binding signature is not base64url".to_string())?,
        ),
        None => None,
    };
    let fields = match (binding.alias.as_deref(), binding.issued_at, sig.as_deref()) {
        (Some(alias), Some(issued_at), Some(sig)) => Some(AliasBindingRef {
            alias,
            issued_at,
            sig,
        }),
        _ => None,
    };
    verify_alias_resolution(root, target, &peer, fields).map_err(|e| e.to_string())?;
    Ok(peer)
}

/// Accept `sdp` from `peer` for `session_id` only if every fingerprint
/// in it is the SHA-256 fingerprint `sig_b64` (standard base64) signs.
pub fn check_offer(
    peer: &PeerId,
    session_id: &str,
    sdp: &str,
    sig_b64: Option<&str>,
) -> Result<(), String> {
    let sig_b64 = sig_b64
        .filter(|s| !s.is_empty())
        .ok_or("offer carries no DTLS fingerprint signature")?;
    let fp = single_sha256_fingerprint(sdp)?;
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|_| "DTLS fingerprint signature is not base64".to_string())?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| "DTLS fingerprint signature is malformed".to_string())?;
    verify_dtls_fp(peer, session_id, FP_ALG_SHA256, &fp, &sig)
        .map_err(|_| "DTLS fingerprint signature does not verify".to_string())
}

/// The SDP's certificate fingerprint. Every `a=fingerprint` line must be
/// SHA-256 and identical, so the signed one is the only one WebRTC can
/// accept.
fn single_sha256_fingerprint(sdp: &str) -> Result<Vec<u8>, String> {
    let mut found: Option<Vec<u8>> = None;
    for line in sdp.lines() {
        let Some(rest) = line.trim().strip_prefix("a=fingerprint:") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let alg = parts.next().unwrap_or("");
        if !alg.eq_ignore_ascii_case("sha-256") {
            return Err(format!("unsupported fingerprint algorithm {alg:?}"));
        }
        let fp = parse_hex_fingerprint(parts.next().unwrap_or(""))?;
        match &found {
            Some(prev) if prev != &fp => {
                return Err("offer carries more than one fingerprint".into())
            }
            Some(_) => {}
            None => found = Some(fp),
        }
    }
    found.ok_or_else(|| "offer carries no fingerprint".into())
}

fn parse_hex_fingerprint(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s
        .split(':')
        .map(|b| match b.len() {
            2 => u8::from_str_radix(b, 16).map_err(|_| format!("bad fingerprint byte {b:?}")),
            _ => Err(format!("bad fingerprint byte {b:?}")),
        })
        .collect::<Result<Vec<u8>, String>>()?;
    if bytes.len() != 32 {
        return Err(format!("SHA-256 fingerprint is {} bytes", bytes.len()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2claw_identity::{sign_alias_binding, sign_dtls_fp, SigningKey};

    const FP: [u8; 32] = [0xAB; 32];

    fn fp_hex(fp: &[u8]) -> String {
        fp.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    fn sdp_with(fps: &[&[u8]]) -> String {
        let mut s = String::from("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n");
        for fp in fps {
            s.push_str(&format!("a=fingerprint:sha-256 {}\r\n", fp_hex(fp)));
        }
        s.push_str("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
        s
    }

    fn signed(box_sk: &SigningKey, session: &str) -> String {
        STANDARD.encode(
            sign_dtls_fp(box_sk, session, FP_ALG_SHA256, &FP)
                .unwrap()
                .to_bytes(),
        )
    }

    #[test]
    fn default_coord_uses_built_in_root() {
        assert_eq!(
            coord_root("https://coord.p2claw.com/", None).unwrap(),
            p2claw_identity::p2claw_coord_root()
        );
        assert!(coord_root("https://coord.example.net", None).is_err());
        let k = SigningKey::generate().peer_id();
        assert_eq!(
            coord_root("https://coord.example.net", Some(&k.to_z32())).unwrap(),
            k
        );
    }

    #[test]
    fn resolution_needs_a_binding_from_the_root() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let sig = sign_alias_binding(&root, "blue-otter-7392", &peer, 1_700_000_000).unwrap();
        let mut binding = Binding {
            alias: Some("blue-otter-7392".into()),
            sig_b64url: Some(URL_SAFE_NO_PAD.encode(sig.to_bytes())),
            issued_at: Some(1_700_000_000),
        };
        let got =
            check_resolution(&root.peer_id(), "blue-otter-7392", &peer.to_z32(), &binding).unwrap();
        assert_eq!(got, peer);

        let other_root = SigningKey::generate().peer_id();
        assert!(
            check_resolution(&other_root, "blue-otter-7392", &peer.to_z32(), &binding).is_err()
        );

        let impostor = SigningKey::generate().peer_id();
        assert!(check_resolution(
            &root.peer_id(),
            "blue-otter-7392",
            &impostor.to_z32(),
            &binding
        )
        .is_err());

        binding.sig_b64url = None;
        assert!(
            check_resolution(&root.peer_id(), "blue-otter-7392", &peer.to_z32(), &binding).is_err()
        );
    }

    #[test]
    fn offer_signed_by_the_box_is_accepted() {
        let box_sk = SigningKey::generate();
        let sig = signed(&box_sk, "S1");
        check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[&FP]), Some(&sig)).unwrap();
        // Repeated identical fingerprints (one per m-section) are fine.
        check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[&FP, &FP]), Some(&sig)).unwrap();
    }

    #[test]
    fn offer_from_anyone_else_is_rejected() {
        let box_sk = SigningKey::generate();
        let impostor = SigningKey::generate();
        let sig = signed(&impostor, "S1");
        assert!(check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[&FP]), Some(&sig)).is_err());
    }

    #[test]
    fn offer_signed_for_another_session_is_rejected() {
        let box_sk = SigningKey::generate();
        let sig = signed(&box_sk, "S0");
        assert!(check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[&FP]), Some(&sig)).is_err());
    }

    #[test]
    fn offer_with_swapped_or_extra_fingerprint_is_rejected() {
        let box_sk = SigningKey::generate();
        let sig = signed(&box_sk, "S1");
        let other = [0xCD; 32];
        assert!(check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[&other]), Some(&sig)).is_err());
        assert!(check_offer(
            &box_sk.peer_id(),
            "S1",
            &sdp_with(&[&FP, &other]),
            Some(&sig)
        )
        .is_err());
    }

    #[test]
    fn unsigned_or_fingerprintless_offer_is_rejected() {
        let box_sk = SigningKey::generate();
        let sig = signed(&box_sk, "S1");
        assert!(check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[&FP]), None).is_err());
        assert!(check_offer(&box_sk.peer_id(), "S1", &sdp_with(&[]), Some(&sig)).is_err());
        let sha1 = sdp_with(&[&FP]).replace("sha-256", "sha-1");
        assert!(check_offer(&box_sk.peer_id(), "S1", &sha1, Some(&sig)).is_err());
    }
}
