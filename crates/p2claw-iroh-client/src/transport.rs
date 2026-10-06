//! Iroh transport setup — builds an [`iroh::Endpoint`], dials a box
//! using the addressing info from coord's native `/v1/connect`
//! response, opens a bidirectional QUIC stream, and returns the
//! [`tokio::io::AsyncRead`] / [`tokio::io::AsyncWrite`] halves joined
//! into a single stream for the translator.

use std::net::SocketAddr;
use std::str::FromStr;

use iroh::endpoint::presets;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
};
use tokio::io::{join, Join};

use crate::connect::NativeConnectResponse;
use crate::error::PeerClientError;

/// ALPN identifier for p2claw's native transport.
pub const P2CLAW_ALPN: &[u8] = b"p2claw/1";

/// Bidirectional stream joined from an Iroh [`iroh::endpoint::RecvStream`]
/// and [`iroh::endpoint::SendStream`]. This type implements
/// [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] and is the
/// concrete stream handed to [`p2claw_translator::ClientConnection::spawn`].
pub type PeerStream = Join<iroh::endpoint::RecvStream, iroh::endpoint::SendStream>;

/// Owned handles that keep an Iroh connection alive for the lifetime
/// of a [`crate::PeerClient`]. Separate from the joined stream
/// (returned alongside) because the stream typically moves into the
/// translator task while these stay with the client handle for drop
/// ordering.
pub struct TransportHolder {
    pub endpoint_id: EndpointId,
    pub connection: iroh::endpoint::Connection,
    pub endpoint: Endpoint,
}

/// Build a fresh Iroh endpoint configured for outbound p2claw
/// connections. Generates an ephemeral [`SecretKey`] — the
/// native client is a visitor, not a peer, so its own identity is
/// not persisted.
///
/// `relay_url` is the optional iroh-relay URL. Two
/// modes only:
/// - **`None`**: direct-only (`presets::Minimal` + `RelayMode::Disabled`).
///   Works whenever the box has direct addrs the client can reach.
/// - **`Some(url)`**: relay-mediated traffic falls back through the
///   given URL only (`RelayMode::Custom(RelayMap::from(url))`). No
///   n0 canary. Should match the operator's coord/agent relay config.
pub async fn build_endpoint(relay_url: Option<&str>) -> Result<Endpoint, PeerClientError> {
    let relay_mode = match relay_url {
        None => RelayMode::Disabled,
        Some(url_str) => {
            let url: RelayUrl = url_str.parse().map_err(|e| {
                PeerClientError::Iroh(format!("parse iroh relay URL {url_str:?}: {e}"))
            })?;
            RelayMode::Custom(RelayMap::from(url))
        }
    };
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![P2CLAW_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .bind()
        .await
        .map_err(|e| PeerClientError::Iroh(format!("bind endpoint: {e}")))
}

/// Parse the native `/v1/connect` response into an [`EndpointAddr`]
/// that Iroh can dial.
pub fn endpoint_addr_from_response(
    resp: &NativeConnectResponse,
) -> Result<EndpointAddr, PeerClientError> {
    let id = EndpointId::from_z32(&resp.iroh_node_id)
        .map_err(|e| PeerClientError::Iroh(format!("parse iroh_node_id: {e}")))?;

    let mut addrs: Vec<TransportAddr> = Vec::new();
    if let Some(url_str) = &resp.iroh_relay_url {
        let url = RelayUrl::from_str(url_str)
            .map_err(|e| PeerClientError::Iroh(format!("parse iroh_relay_url: {e}")))?;
        addrs.push(TransportAddr::Relay(url));
    }
    for a in &resp.iroh_direct_addrs {
        let socket: SocketAddr = a
            .parse()
            .map_err(|e| PeerClientError::Iroh(format!("parse direct addr {a:?}: {e}")))?;
        addrs.push(TransportAddr::Ip(socket));
    }
    if addrs.is_empty() {
        return Err(PeerClientError::Iroh(
            "no relay or direct addresses in /v1/connect response".to_string(),
        ));
    }
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// Dial the given endpoint over ALPN `p2claw/1` and open one
/// bidirectional stream. Returns the holder (for drop-lifetime
/// control) and the joined stream (for the translator).
pub async fn dial(
    endpoint: Endpoint,
    addr: EndpointAddr,
) -> Result<(TransportHolder, PeerStream), PeerClientError> {
    let endpoint_id = addr.id;
    tracing::debug!(
        peer = %endpoint_id.fmt_short(),
        n_addrs = addr.addrs.len(),
        "iroh: connecting"
    );
    let connection = endpoint
        .connect(addr, P2CLAW_ALPN)
        .await
        .map_err(|e| PeerClientError::Iroh(format!("connect: {e}")))?;
    tracing::debug!(peer = %endpoint_id.fmt_short(), "iroh: connected");

    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| PeerClientError::Iroh(format!("open_bi: {e}")))?;
    tracing::debug!("iroh: opened bidirectional stream");

    let stream = join(recv, send);
    let holder = TransportHolder {
        endpoint_id,
        connection,
        endpoint,
    };
    Ok((holder, stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syntactically-valid z-base-32 iroh EndpointId for tests.
    fn fresh_node_id_z32() -> String {
        SecretKey::generate().public().to_z32()
    }

    #[test]
    fn rejects_response_with_no_addresses() {
        let id = fresh_node_id_z32();
        let resp = NativeConnectResponse {
            peer_id: id.clone(),
            iroh_node_id: id,
            iroh_relay_url: None,
            iroh_direct_addrs: Vec::new(),
        };
        let err = endpoint_addr_from_response(&resp).unwrap_err();
        match err {
            PeerClientError::Iroh(msg) => assert!(msg.contains("no relay or direct")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn builds_endpoint_addr_with_relay_and_direct() {
        let id = fresh_node_id_z32();
        let resp = NativeConnectResponse {
            peer_id: id.clone(),
            iroh_node_id: id,
            iroh_relay_url: Some("https://relay.example.net/".to_string()),
            iroh_direct_addrs: vec![
                "198.51.100.7:54321".to_string(),
                "[2001:db8::1]:54321".to_string(),
            ],
        };
        let addr = endpoint_addr_from_response(&resp).unwrap();
        assert_eq!(addr.addrs.len(), 3);
    }

    #[test]
    fn rejects_malformed_direct_addr() {
        let id = fresh_node_id_z32();
        let resp = NativeConnectResponse {
            peer_id: id.clone(),
            iroh_node_id: id,
            iroh_relay_url: None,
            iroh_direct_addrs: vec!["not-an-addr".to_string()],
        };
        let err = endpoint_addr_from_response(&resp).unwrap_err();
        assert!(matches!(err, PeerClientError::Iroh(_)));
    }
}
