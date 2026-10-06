//! `POST /v1/connect` client against the coordination service.
//!
//! Sends the native-visitor connect request and parses the response.

use std::time::Duration;

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
#[derive(Debug, Deserialize, Clone)]
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

    /// Coord's haiku-binding fields (`alias_kind`,
    /// `binding_sig_b64url`, `binding_issued_at`) ride alongside the
    /// fields we deserialise. The native client doesn't verify the
    /// binding; Iroh's QUIC TLS authenticates the NodeId. Pin that
    /// the deserialiser accepts the extra fields (no
    /// `deny_unknown_fields`).
    #[test]
    fn parses_native_response_with_binding_fields() {
        let body = r#"{
            "peer_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_node_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "iroh_relay_url": "https://relay.example.net/",
            "iroh_direct_addrs": ["198.51.100.7:54321"],
            "alias_kind": "haiku",
            "binding_sig_b64url": "MEUCIQDxxxxx...",
            "binding_issued_at": 1730000000
        }"#;
        let parsed: NativeConnectResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.iroh_direct_addrs.len(), 1);
        assert_eq!(
            parsed.iroh_relay_url.as_deref(),
            Some("https://relay.example.net/")
        );
    }
}
