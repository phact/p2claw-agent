//! `POST /v1/connect` client against the coordination service.
//!
//! Sends the native-visitor connect request and parses the response.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p2claw_identity::{verify_alias_resolution, AliasBindingRef, PeerId};
use serde::{Deserialize, Serialize};

use crate::error::PeerClientError;

/// Default coordination URL when neither `--coord` nor `P2CLAW_COORD`
/// is set: `https://coord.<parent_domain>`.
pub fn default_coord_url(parent_domain: &str) -> String {
    format!("https://coord.{parent_domain}")
}

/// The JSON body of `POST /v1/connect`.
#[derive(Debug, Serialize)]
pub struct ConnectRequest<'a> {
    pub alias: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<&'a str>,
    pub visitor_kind: &'static str,
}

/// The native-kind response from `POST /v1/connect`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct NativeConnectResponse {
    /// Box's canonical peer_id (z-base-32).
    pub peer_id: String,
    /// Equals `peer_id`. Iroh's NodeId and p2claw's peer_id are the
    /// same Ed25519 public key.
    pub iroh_node_id: String,
    /// Iroh relay URL the box advertised to coord.
    #[serde(default)]
    pub iroh_relay_url: Option<String>,
    /// Direct UDP socket addresses from the box's latest `addrs_update`.
    #[serde(default)]
    pub iroh_direct_addrs: Vec<String>,
    /// Alias the binding covers. Absent when the target was a peer id.
    #[serde(default)]
    pub alias: Option<String>,
    /// Root-key signature binding `alias` to `peer_id`, base64url.
    #[serde(default)]
    pub binding_sig_b64url: Option<String>,
    #[serde(default)]
    pub binding_issued_at: Option<u64>,
}

/// Accept `resp` as coord's answer for `target` only if `root` signed
/// it (see [`p2claw_identity::verify_alias_resolution`]) and the node to
/// dial is the bound peer.
pub fn verify_response(
    root: &PeerId,
    target: &str,
    resp: &NativeConnectResponse,
) -> Result<PeerId, PeerClientError> {
    let peer_id = PeerId::from_z32(&resp.peer_id)
        .map_err(|e| PeerClientError::Coord(format!("invalid peer_id: {e}")))?;
    if resp.iroh_node_id != resp.peer_id {
        return Err(PeerClientError::UntrustedResolution(
            "iroh_node_id differs from peer_id".into(),
        ));
    }
    let sig = match resp.binding_sig_b64url.as_deref() {
        Some(b64) => Some(URL_SAFE_NO_PAD.decode(b64).map_err(|_| {
            PeerClientError::UntrustedResolution("binding signature is not base64url".into())
        })?),
        None => None,
    };
    let binding = match (
        resp.alias.as_deref(),
        resp.binding_issued_at,
        sig.as_deref(),
    ) {
        (Some(alias), Some(issued_at), Some(sig)) => Some(AliasBindingRef {
            alias,
            issued_at,
            sig,
        }),
        _ => None,
    };
    verify_alias_resolution(root, target, &peer_id, binding)
        .map_err(|e| PeerClientError::UntrustedResolution(e.to_string()))?;
    Ok(peer_id)
}

/// Error-shape from coord when `/v1/connect` rejects.
#[derive(Debug, Deserialize)]
struct ConnectError {
    error: String,
    #[serde(default)]
    retry_after: Option<u64>,
}

/// Call `POST {coord}/v1/connect` with the given alias/app, return the
/// native response.
pub async fn connect(
    coord_url: &str,
    alias: &str,
    app: Option<&str>,
    timeout: Duration,
) -> Result<NativeConnectResponse, PeerClientError> {
    let endpoint = format!("{}/v1/connect", coord_url.trim_end_matches('/'));

    let body = ConnectRequest {
        alias,
        app,
        visitor_kind: "native",
    };

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| PeerClientError::Coord(format!("build client: {e}")))?;

    tracing::debug!(%endpoint, ?body, "coord /v1/connect");

    let resp = client
        .post(&endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|e| PeerClientError::Coord(format!("send: {e}")))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| PeerClientError::Coord(format!("read body: {e}")))?;

    if status.is_success() {
        serde_json::from_str::<NativeConnectResponse>(&text)
            .map_err(|e| PeerClientError::Coord(format!("parse response: {e}: {text}")))
    } else {
        if let Ok(err) = serde_json::from_str::<ConnectError>(&text) {
            Err(match err.error.as_str() {
                "no_such_peer" => PeerClientError::NoSuchPeer,
                "revoked" => PeerClientError::PeerRevoked,
                "box_offline" => PeerClientError::BoxOffline,
                "rate_limited" => PeerClientError::RateLimited(err.retry_after.unwrap_or(0)),
                other => PeerClientError::Coord(format!(
                    "{status} {other}{}",
                    if text.is_empty() {
                        String::new()
                    } else {
                        format!(": {text}")
                    }
                )),
            })
        } else {
            Err(PeerClientError::Coord(format!("{status}: {text}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2claw_identity::{sign_alias_binding, SigningKey};

    fn signed_response(root: &SigningKey, alias: &str, peer: &PeerId) -> NativeConnectResponse {
        let sig = sign_alias_binding(root, alias, peer, 1_700_000_000).unwrap();
        NativeConnectResponse {
            peer_id: peer.to_z32(),
            iroh_node_id: peer.to_z32(),
            iroh_relay_url: None,
            iroh_direct_addrs: vec![],
            alias: Some(alias.into()),
            binding_sig_b64url: Some(URL_SAFE_NO_PAD.encode(sig.to_bytes())),
            binding_issued_at: Some(1_700_000_000),
        }
    }

    #[test]
    fn verify_accepts_signed_binding() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let resp = signed_response(&root, "blue-otter-7392", &peer);
        let got = verify_response(&root.peer_id(), "blue-otter-7392", &resp).unwrap();
        assert_eq!(got, peer);
    }

    #[test]
    fn verify_rejects_binding_from_another_root() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let resp = signed_response(&SigningKey::generate(), "blue-otter-7392", &peer);
        let err = verify_response(&root.peer_id(), "blue-otter-7392", &resp).unwrap_err();
        assert!(
            matches!(err, PeerClientError::UntrustedResolution(_)),
            "{err}"
        );
    }

    #[test]
    fn verify_rejects_unsigned_alias_answer() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let mut resp = signed_response(&root, "blue-otter-7392", &peer);
        resp.binding_sig_b64url = None;
        let err = verify_response(&root.peer_id(), "blue-otter-7392", &resp).unwrap_err();
        assert!(
            matches!(err, PeerClientError::UntrustedResolution(_)),
            "{err}"
        );
    }

    #[test]
    fn verify_rejects_node_id_other_than_bound_peer() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let mut resp = signed_response(&root, "blue-otter-7392", &peer);
        resp.iroh_node_id = SigningKey::generate().peer_id().to_z32();
        let err = verify_response(&root.peer_id(), "blue-otter-7392", &resp).unwrap_err();
        assert!(
            matches!(err, PeerClientError::UntrustedResolution(_)),
            "{err}"
        );
    }

    #[test]
    fn verify_accepts_peer_id_target_without_binding() {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let mut resp = signed_response(&root, "blue-otter-7392", &peer);
        resp.alias = None;
        resp.binding_sig_b64url = None;
        resp.binding_issued_at = None;
        verify_response(&root.peer_id(), &peer.to_z32(), &resp).unwrap();
    }

    #[test]
    fn default_coord_url_builds() {
        assert_eq!(default_coord_url("p2claw.com"), "https://coord.p2claw.com");
        assert_eq!(
            default_coord_url("example.net"),
            "https://coord.example.net"
        );
    }

    #[test]
    fn request_serialises_without_app() {
        let req = ConnectRequest {
            alias: "blue-otter-7392",
            app: None,
            visitor_kind: "native",
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"alias\":\"blue-otter-7392\""));
        assert!(s.contains("\"visitor_kind\":\"native\""));
        assert!(!s.contains("\"app\""), "empty app should be omitted: {s}");
    }

    #[test]
    fn request_serialises_with_app() {
        let req = ConnectRequest {
            alias: "blue-otter-7392",
            app: Some("recipes"),
            visitor_kind: "native",
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"app\":\"recipes\""));
    }

    #[test]
    fn parses_native_response() {
        let body = r#"{
            "peer_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_node_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_relay_url": "https://relay.example.net/",
            "iroh_direct_addrs": ["198.51.100.7:54321", "[2001:db8::1]:54321"]
        }"#;
        let parsed: NativeConnectResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.iroh_direct_addrs.len(), 2);
        assert_eq!(
            parsed.iroh_relay_url.as_deref(),
            Some("https://relay.example.net/")
        );
    }

    #[test]
    fn parses_native_response_without_relay() {
        let body = r#"{
            "peer_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_node_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_direct_addrs": ["198.51.100.7:54321"]
        }"#;
        let parsed: NativeConnectResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.iroh_relay_url.is_none());
    }

    #[test]
    fn parses_native_response_with_binding_fields() {
        let body = r#"{
            "peer_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_node_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_relay_url": "https://relay.example.net/",
            "iroh_direct_addrs": ["198.51.100.7:54321"],
            "alias": "blue-otter-7392",
            "alias_kind": "haiku",
            "binding_sig_b64url": "MEUCIQDxxxxx",
            "binding_issued_at": 1730000000
        }"#;
        let parsed: NativeConnectResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.alias.as_deref(), Some("blue-otter-7392"));
        assert_eq!(parsed.binding_sig_b64url.as_deref(), Some("MEUCIQDxxxxx"));
        assert_eq!(parsed.binding_issued_at, Some(1730000000));
    }
}
