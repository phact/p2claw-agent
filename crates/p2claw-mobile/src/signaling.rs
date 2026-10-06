//! Signaling client for `coord.p2claw.com/v1/connect` + `/v1/signal/*`.
//!
//! The Rust core owns the protocol — DTO shapes, message envelopes,
//! handshake sequencing — but no transport. Callers supply a
//! [`SignalingTransport`] implementation that drives HTTPS and the
//! signaling WS using whatever the host platform prefers
//! (`URLSession` + `URLSessionWebSocketTask` on iOS, OkHttp +
//! Java-WebSocket on Android). This keeps the crate free of
//! reqwest / rustls / tokio-tungstenite weight, lets host apps honor
//! their own proxy / cert-pinning / network configuration, and gives
//! the App Store reviewer fewer dependencies to argue about.
//!
//! Shape of the exchange:
//!
//! 1. `POST /v1/connect` with `{alias, app?, visitor_kind: "browser"}`.
//!    The mobile SDK presents as `browser` because the visitor side of
//!    the wire is WebRTC + DataChannel, identical to the browser path.
//!    The platform attaches any auth headers it needs (e.g. an
//!    `Authorization: Bearer <device_binding_cert>` and a per-request
//!    timestamp signature) when it makes the call.
//! 2. WSS to the `signal_url` the response carries. Send an `auth`
//!    message with the `signal_token`; await `auth_ack`.
//! 3. Exchange `relay` messages bidirectionally. The relay payload is
//!    opaque base64 — the platform-layer WebRTC wrapper interprets it
//!    as offer / answer / candidate JSON.
//! 4. Send `end` when the session terminates.

use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One header pair carried on signaling HTTPS / WS requests. Distinct
/// from [`crate::codec::Header`] (which holds raw bytes for wire
/// frames) — signaling headers are UTF-8 by construction.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StringPair {
    pub name: String,
    pub value: String,
}

impl StringPair {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Reason codes mirroring coord's `SignalEndReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Connected,
    Aborted,
    Timeout,
    Error,
}

/// Caller-supplied configuration for [`SignalingClient::connect`].
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct SignalingConfig {
    /// Base URL, e.g. `https://coord.p2claw.com`. No trailing slash.
    pub coord_url: String,
    /// Alias label of the target box.
    pub alias: String,
    /// Optional app subdomain prefix.
    pub app: Option<String>,
    /// Headers the platform attaches to the `POST /v1/connect` call.
    /// Typical values: an `Authorization` bearer of the device-binding
    /// cert plus a per-request `X-P2claw-Device-Sig` timestamp
    /// signature. Empty for unauthenticated boxes.
    pub auth_headers: Vec<StringPair>,
}

/// Errors raised by the signaling client and session.
///
/// Not using `#[uniffi(flat_error)]` here even though the variants
/// are flat with String payloads. UniFFI 0.31's `flat_error` codegen
/// is asymmetric: the read half deserializes discriminant + payload,
/// but the write half emits only the 4-byte discriminant. That
/// breaks the round trip when a foreign-implemented trait throws
/// back into Rust (e.g. `SignalingTransport::post_connect` on the
/// platform side surfacing a network failure as `Transport(msg)` —
/// UniFFI panics at "Can't lift flat errors"). Plain tagged-enum
/// codegen handles both halves correctly.
#[derive(Debug, Error, uniffi::Error)]
#[non_exhaustive]
pub enum SignalingError {
    /// Transport-layer failure surfaced from the platform.
    #[error("transport: {0}")]
    Transport(String),
    /// Coord rejected the request (non-2xx HTTP, or an `error`
    /// envelope on the WS).
    #[error("coord rejected request: {0}")]
    Rejected(String),
    /// Response shape didn't match the protocol contract.
    #[error("malformed response: {0}")]
    Malformed(String),
    /// Session ended before the operation could complete.
    #[error("session ended")]
    SessionEnded,
}

impl From<serde_json::Error> for SignalingError {
    fn from(err: serde_json::Error) -> Self {
        Self::Malformed(err.to_string())
    }
}

/// Platform-supplied transport for the signaling exchange.
///
/// The Rust core never touches sockets — it constructs requests and
/// hands them to the trait impl. Two methods, both async:
///
/// - [`post_connect`](Self::post_connect) executes the HTTPS POST to
///   `/v1/connect` and returns the response body bytes.
/// - [`open_ws`](Self::open_ws) opens a WebSocket connection to the
///   `signal_url` returned by the connect call and yields a
///   [`WsTransport`] handle for subsequent send/recv.
#[uniffi::export(with_foreign)]
// async_trait marks its boxed futures #[must_use] on top of Future's own.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait SignalingTransport: Send + Sync {
    async fn post_connect(
        &self,
        url: String,
        body: Vec<u8>,
        headers: Vec<StringPair>,
    ) -> Result<Vec<u8>, SignalingError>;

    /// Open a signaling WebSocket and return its connection id. The
    /// caller drives subsequent traffic by re-entering the foreign
    /// side via the [`WsTransport`] callback interface keyed off the
    /// returned id — this two-trait split avoids returning a foreign
    /// trait object through async_trait, which UniFFI 0.31's
    /// `with_foreign` codegen can't dyn-cast through.
    async fn open_ws(&self, url: String, headers: Vec<StringPair>) -> Result<u64, SignalingError>;
}

/// One open signaling WebSocket, addressed by the `conn_id` returned
/// from [`SignalingTransport::open_ws`]. Frames are UTF-8 JSON text;
/// the trait accepts and yields `Vec<u8>` so platform impls don't
/// need to transcode through `String` on every message.
#[uniffi::export(with_foreign)]
// async_trait marks its boxed futures #[must_use] on top of Future's own.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait WsTransport: Send + Sync {
    /// Send one text frame on the named connection. The bytes are
    /// valid UTF-8.
    async fn send(&self, conn_id: u64, frame: Vec<u8>) -> Result<(), SignalingError>;
    /// Receive the next text frame. Returns `None` when the peer
    /// closed cleanly.
    async fn recv(&self, conn_id: u64) -> Result<Option<Vec<u8>>, SignalingError>;
    /// Close the connection. Idempotent.
    async fn close(&self, conn_id: u64) -> Result<(), SignalingError>;
}

/// Mirror of coord's `ConnectRequest`.
#[derive(Debug, Serialize)]
struct ConnectRequest<'a> {
    alias: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<&'a str>,
    visitor_kind: &'static str,
}

/// Mirror of coord's `BrowserResponse` — the only variant the mobile
/// SDK consumes; native (Iroh) responses belong to the headless
/// peer-client.
///
/// `ice_servers` is exposed as `Vec<String>` (each entry is the
/// JSON-serialized ICE-server spec). The platform-layer WebRTC
/// wrapper feeds each string verbatim into its
/// `RTCConfiguration.iceServers` parser. Keeping them opaque here
/// avoids re-encoding the ICE-server schema and avoids dragging
/// `serde_json::Value` across the FFI boundary.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BrowserConnectResponse {
    pub session_id: String,
    pub peer_id: String,
    pub signal_url: String,
    pub signal_token: String,
    pub ice_servers: Vec<String>,
    pub turn_expires_at: u64,
}

/// Browser → coord signaling messages. Mirrors coord's `BrowserMsg`.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutboundMsg {
    Auth {
        v: u32,
        signal_token: String,
    },
    Relay {
        v: u32,
        seq: u32,
        payload_b64: String,
    },
    End {
        v: u32,
        reason: EndReason,
    },
}

/// Coord → browser signaling messages. Mirrors coord's `CoordSignalMsg`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InboundMsg {
    AuthAck {
        #[allow(dead_code)]
        v: u32,
        heartbeat_interval_s: u32,
    },
    Relay {
        #[allow(dead_code)]
        v: u32,
        seq: u32,
        payload_b64: String,
    },
    End {
        #[allow(dead_code)]
        v: u32,
        reason: EndReason,
    },
    Error {
        #[allow(dead_code)]
        v: u32,
        code: String,
        #[serde(default)]
        message: Option<String>,
    },
}

/// Raw ICE-server entry as coord returns it; serialized verbatim into
/// [`BrowserConnectResponse::ice_servers`] for platform consumption.
#[derive(Debug, Deserialize)]
struct RawConnectResponse {
    session_id: String,
    peer_id: String,
    signal_url: String,
    signal_token: String,
    #[serde(default)]
    ice_servers: Vec<serde_json::Value>,
    #[serde(default)]
    turn_expires_at: u64,
}

impl RawConnectResponse {
    fn into_public(self) -> BrowserConnectResponse {
        BrowserConnectResponse {
            session_id: self.session_id,
            peer_id: self.peer_id,
            signal_url: self.signal_url,
            signal_token: self.signal_token,
            ice_servers: self
                .ice_servers
                .into_iter()
                .map(|v| v.to_string())
                .collect(),
            turn_expires_at: self.turn_expires_at,
        }
    }
}

/// Top-level client. Holds two platform-supplied transports — one for
/// HTTPS (`SignalingTransport`) and one for the persistent signaling
/// WebSocket (`WsTransport`). Cheap to clone (the inner `Arc`s are
/// shared).
#[derive(uniffi::Object)]
pub struct SignalingClient {
    http: Arc<dyn SignalingTransport>,
    ws: Arc<dyn WsTransport>,
}

#[uniffi::export(async_runtime = "tokio")]
impl SignalingClient {
    /// New client backed by `http` (drives `POST /v1/connect`) and
    /// `ws` (drives the persistent signaling WebSocket). The two
    /// transports are separate so the foreign side can implement
    /// them independently — URLSession + URLSessionWebSocketTask on
    /// iOS, OkHttp + Java-WebSocket on Android.
    #[uniffi::constructor]
    pub fn new(http: Arc<dyn SignalingTransport>, ws: Arc<dyn WsTransport>) -> Self {
        Self { http, ws }
    }

    /// Run the full handshake — POST `/v1/connect`, open the
    /// signaling WS, send `auth`, await `auth_ack`. Returns a
    /// [`SignalingSession`] ready for relay traffic.
    pub async fn connect(
        &self,
        config: SignalingConfig,
    ) -> Result<Arc<SignalingSession>, SignalingError> {
        let connect_url = format!("{}/v1/connect", config.coord_url.trim_end_matches('/'));
        let req = ConnectRequest {
            alias: &config.alias,
            app: config.app.as_deref(),
            visitor_kind: "browser",
        };
        let body = serde_json::to_vec(&req)?;
        let mut headers = config.auth_headers.clone();
        headers.push(StringPair::new("content-type", "application/json"));

        let response_bytes = self.http.post_connect(connect_url, body, headers).await?;
        let parsed: BrowserConnectResponse =
            serde_json::from_slice::<RawConnectResponse>(&response_bytes)?.into_public();

        let conn_id = self
            .http
            .open_ws(parsed.signal_url.clone(), Vec::new())
            .await?;

        let auth = OutboundMsg::Auth {
            v: 1,
            signal_token: parsed.signal_token.clone(),
        };
        self.ws.send(conn_id, serde_json::to_vec(&auth)?).await?;

        let frame = self
            .ws
            .recv(conn_id)
            .await?
            .ok_or_else(|| SignalingError::Transport("ws closed before auth_ack".into()))?;
        let heartbeat_s = match serde_json::from_slice::<InboundMsg>(&frame)? {
            InboundMsg::AuthAck {
                heartbeat_interval_s,
                ..
            } => heartbeat_interval_s,
            InboundMsg::Error { code, message, .. } => {
                return Err(SignalingError::Rejected(format!(
                    "auth rejected: {code}{}",
                    message.map(|m| format!(" — {m}")).unwrap_or_default()
                )));
            }
            other => {
                return Err(SignalingError::Malformed(format!(
                    "expected auth_ack, got {other:?}"
                )));
            }
        };

        Ok(Arc::new(SignalingSession {
            session_id: parsed.session_id,
            peer_id: parsed.peer_id,
            ice_servers: parsed.ice_servers,
            heartbeat_interval_s: heartbeat_s,
            conn_id,
            ws: self.ws.clone(),
            inner: Mutex::new(SessionInner { next_seq: 0 }),
        }))
    }
}

#[derive(Debug)]
struct SessionInner {
    next_seq: u32,
}

/// One authenticated signaling session. The held WS connection is
/// closed when the session drops.
#[derive(uniffi::Object)]
pub struct SignalingSession {
    pub session_id: String,
    pub peer_id: String,
    pub ice_servers: Vec<String>,
    pub heartbeat_interval_s: u32,
    conn_id: u64,
    ws: Arc<dyn WsTransport>,
    inner: Mutex<SessionInner>,
}

/// Event yielded by [`SignalingSession::next_event`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignalingEvent {
    /// Inbound relay payload from coord.
    Payload { seq: u32, bytes: Vec<u8> },
    /// Inbound error notification.
    Error {
        code: String,
        message: Option<String>,
    },
    /// Coord ended the session.
    Ended { reason: EndReason },
}

#[uniffi::export(async_runtime = "tokio")]
impl SignalingSession {
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }
    pub fn ice_servers(&self) -> Vec<String> {
        self.ice_servers.clone()
    }
    pub fn heartbeat_interval_s(&self) -> u32 {
        self.heartbeat_interval_s
    }

    /// Send a relay payload up to coord. The bytes are wrapped in a
    /// base64 envelope; the caller's job is to construct the inner
    /// shape (the SDP / ICE-candidate JSON for WebRTC).
    pub async fn send_payload(&self, bytes: Vec<u8>) -> Result<(), SignalingError> {
        let seq = {
            let mut inner = self.inner.lock().unwrap();
            let seq = inner.next_seq;
            inner.next_seq = inner.next_seq.wrapping_add(1);
            seq
        };
        let msg = OutboundMsg::Relay {
            v: 1,
            seq,
            payload_b64: BASE64.encode(&bytes),
        };
        self.ws.send(self.conn_id, serde_json::to_vec(&msg)?).await
    }

    /// Await the next inbound event. Returns `None` when the session
    /// has ended and there will be no further events.
    pub async fn next_event(&self) -> Option<SignalingEvent> {
        loop {
            let frame = self.ws.recv(self.conn_id).await.ok()??;
            let msg: InboundMsg = match serde_json::from_slice(&frame) {
                Ok(m) => m,
                Err(_) => continue,
            };
            match msg {
                InboundMsg::Relay {
                    seq, payload_b64, ..
                } => {
                    let bytes = BASE64.decode(payload_b64.as_bytes()).unwrap_or_default();
                    return Some(SignalingEvent::Payload { seq, bytes });
                }
                InboundMsg::Error { code, message, .. } => {
                    return Some(SignalingEvent::Error { code, message });
                }
                InboundMsg::End { reason, .. } => {
                    return Some(SignalingEvent::Ended { reason });
                }
                InboundMsg::AuthAck { .. } => continue,
            }
        }
    }

    /// Close the session, sending an `end` message to coord. Best
    /// effort — succeeds even if the WS is already torn down.
    pub async fn end(&self, reason: EndReason) -> Result<(), SignalingError> {
        let msg = OutboundMsg::End { v: 1, reason };
        if let Ok(bytes) = serde_json::to_vec(&msg) {
            let _ = self.ws.send(self.conn_id, bytes).await;
        }
        self.ws.close(self.conn_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// Scripted in-process transport. Tests push expected exchanges
    /// onto it; the client drives them.
    struct MockTransport {
        connect_response: Mutex<Option<Vec<u8>>>,
        ws_script: Mutex<Vec<MockWsStep>>,
    }

    #[derive(Debug)]
    enum MockWsStep {
        /// Client must send this exact text next.
        ExpectSend(&'static str),
        /// Client will receive this on its next `recv()`.
        Deliver(&'static str),
        /// `recv()` should yield `Ok(None)` (clean close).
        Eof,
    }

    impl MockTransport {
        fn new(connect_response: &str, script: Vec<MockWsStep>) -> Arc<Self> {
            Arc::new(Self {
                connect_response: Mutex::new(Some(connect_response.as_bytes().to_vec())),
                ws_script: Mutex::new(script),
            })
        }
    }

    #[async_trait]
    impl SignalingTransport for MockTransport {
        async fn post_connect(
            &self,
            _url: String,
            _body: Vec<u8>,
            _headers: Vec<StringPair>,
        ) -> Result<Vec<u8>, SignalingError> {
            self.connect_response
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| SignalingError::Transport("connect already consumed".into()))
        }

        async fn open_ws(
            &self,
            _url: String,
            _headers: Vec<StringPair>,
        ) -> Result<u64, SignalingError> {
            // Mock returns a sentinel; the matching MockWs holds the
            // scripted exchanges keyed off this id (the test uses only
            // one connection so id 1 always lines up).
            Ok(1)
        }
    }

    /// One WS that pairs with the MockTransport above. Holds the
    /// scripted exchanges; the conn_id arg is asserted to match.
    struct MockWs {
        script: Mutex<Vec<MockWsStep>>,
    }

    #[async_trait]
    impl WsTransport for MockWs {
        async fn send(&self, conn_id: u64, frame: Vec<u8>) -> Result<(), SignalingError> {
            assert_eq!(conn_id, 1, "conn_id must match the open_ws return");
            let mut s = self.script.lock().unwrap();
            match s.first() {
                Some(MockWsStep::ExpectSend(expected)) => {
                    let got = String::from_utf8(frame).unwrap();
                    assert_eq!(&got, *expected, "unexpected outbound frame");
                    s.remove(0);
                    Ok(())
                }
                other => panic!("send called with no ExpectSend at head: {other:?}"),
            }
        }

        async fn recv(&self, conn_id: u64) -> Result<Option<Vec<u8>>, SignalingError> {
            assert_eq!(conn_id, 1);
            let mut s = self.script.lock().unwrap();
            match s.first() {
                Some(MockWsStep::Deliver(_)) => {
                    if let Some(MockWsStep::Deliver(text)) = s.remove(0).into() {
                        Ok(Some(text.as_bytes().to_vec()))
                    } else {
                        unreachable!()
                    }
                }
                Some(MockWsStep::Eof) => {
                    s.remove(0);
                    Ok(None)
                }
                other => panic!("recv called with no Deliver/Eof at head: {other:?}"),
            }
        }

        async fn close(&self, _conn_id: u64) -> Result<(), SignalingError> {
            Ok(())
        }
    }

    fn build_client(transport: Arc<MockTransport>) -> SignalingClient {
        let ws: Arc<dyn WsTransport> = Arc::new(MockWs {
            script: Mutex::new(std::mem::take(&mut *transport.ws_script.lock().unwrap())),
        });
        let http: Arc<dyn SignalingTransport> = transport;
        SignalingClient::new(http, ws)
    }

    fn connect_response() -> &'static str {
        r#"{
            "session_id":"01HXXFAKE",
            "peer_id":"abcdef",
            "signal_url":"wss://coord.p2claw.com/v1/signal/01HXXFAKE",
            "signal_token":"tok-1",
            "ice_servers":[],
            "turn_expires_at":1750000000
        }"#
    }

    #[tokio::test]
    async fn handshake_authenticates_and_returns_session() {
        let transport = MockTransport::new(
            connect_response(),
            vec![
                MockWsStep::ExpectSend(r#"{"type":"auth","v":1,"signal_token":"tok-1"}"#),
                MockWsStep::Deliver(r#"{"type":"auth_ack","v":1,"heartbeat_interval_s":15}"#),
            ],
        );
        let client = build_client(transport);
        let session = client
            .connect(SignalingConfig {
                coord_url: "https://coord.p2claw.com".into(),
                alias: "blue-otter-7392".into(),
                app: None,
                auth_headers: Vec::new(),
            })
            .await
            .expect("handshake ok");
        assert_eq!(session.session_id, "01HXXFAKE");
        assert_eq!(session.peer_id, "abcdef");
        assert_eq!(session.heartbeat_interval_s, 15);
    }

    #[tokio::test]
    async fn handshake_propagates_coord_error_envelope() {
        let transport = MockTransport::new(
            connect_response(),
            vec![
                MockWsStep::ExpectSend(r#"{"type":"auth","v":1,"signal_token":"tok-1"}"#),
                MockWsStep::Deliver(
                    r#"{"type":"error","v":1,"code":"bad_token","message":"expired"}"#,
                ),
            ],
        );
        let client = build_client(transport);
        let result = client
            .connect(SignalingConfig {
                coord_url: "https://coord.p2claw.com".into(),
                alias: "x".into(),
                app: None,
                auth_headers: Vec::new(),
            })
            .await;
        assert!(matches!(result, Err(SignalingError::Rejected(_))));
    }

    #[tokio::test]
    async fn relay_round_trip_through_session() {
        let transport = MockTransport::new(
            connect_response(),
            vec![
                MockWsStep::ExpectSend(r#"{"type":"auth","v":1,"signal_token":"tok-1"}"#),
                MockWsStep::Deliver(r#"{"type":"auth_ack","v":1,"heartbeat_interval_s":15}"#),
                // base64("hello") = aGVsbG8=
                MockWsStep::ExpectSend(
                    r#"{"type":"relay","v":1,"seq":0,"payload_b64":"aGVsbG8="}"#,
                ),
                // base64("world") = d29ybGQ=
                MockWsStep::Deliver(r#"{"type":"relay","v":1,"seq":7,"payload_b64":"d29ybGQ="}"#),
                MockWsStep::Deliver(r#"{"type":"end","v":1,"reason":"connected"}"#),
            ],
        );
        let client = build_client(transport);
        let session = client
            .connect(SignalingConfig {
                coord_url: "https://coord.p2claw.com".into(),
                alias: "x".into(),
                app: None,
                auth_headers: Vec::new(),
            })
            .await
            .expect("handshake");

        session
            .send_payload(b"hello".to_vec())
            .await
            .expect("send ok");
        match session.next_event().await {
            Some(SignalingEvent::Payload { seq, bytes }) => {
                assert_eq!(seq, 7);
                assert_eq!(bytes, b"world");
            }
            other => panic!("unexpected event {other:?}"),
        }
        match session.next_event().await {
            Some(SignalingEvent::Ended { reason }) => assert_eq!(reason, EndReason::Connected),
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_after_eof_yields_none() {
        let transport = MockTransport::new(
            connect_response(),
            vec![
                MockWsStep::ExpectSend(r#"{"type":"auth","v":1,"signal_token":"tok-1"}"#),
                MockWsStep::Deliver(r#"{"type":"auth_ack","v":1,"heartbeat_interval_s":15}"#),
                MockWsStep::Eof,
            ],
        );
        let client = build_client(transport);
        let session = client
            .connect(SignalingConfig {
                coord_url: "https://coord.p2claw.com".into(),
                alias: "x".into(),
                app: None,
                auth_headers: Vec::new(),
            })
            .await
            .expect("handshake");
        assert!(session.next_event().await.is_none());
    }

    #[test]
    fn outbound_auth_serializes_as_browser_msg() {
        let json = serde_json::to_string(&OutboundMsg::Auth {
            v: 1,
            signal_token: "tok".into(),
        })
        .unwrap();
        assert!(json.contains(r#""type":"auth""#));
        assert!(json.contains(r#""v":1"#));
        assert!(json.contains(r#""signal_token":"tok""#));
    }

    #[test]
    fn outbound_relay_includes_seq_and_payload() {
        let json = serde_json::to_string(&OutboundMsg::Relay {
            v: 1,
            seq: 42,
            payload_b64: "abc".into(),
        })
        .unwrap();
        assert!(json.contains(r#""type":"relay""#));
        assert!(json.contains(r#""seq":42"#));
        assert!(json.contains(r#""payload_b64":"abc""#));
    }

    #[test]
    fn outbound_end_uses_snake_case_reason() {
        let json = serde_json::to_string(&OutboundMsg::End {
            v: 1,
            reason: EndReason::Connected,
        })
        .unwrap();
        assert!(json.contains(r#""reason":"connected""#));
    }

    #[test]
    fn inbound_auth_ack_round_trip() {
        let parsed: InboundMsg =
            serde_json::from_str(r#"{"type":"auth_ack","v":1,"heartbeat_interval_s":15}"#).unwrap();
        match parsed {
            InboundMsg::AuthAck {
                heartbeat_interval_s,
                ..
            } => assert_eq!(heartbeat_interval_s, 15),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn inbound_end_round_trip() {
        let parsed: InboundMsg =
            serde_json::from_str(r#"{"type":"end","v":1,"reason":"aborted"}"#).unwrap();
        match parsed {
            InboundMsg::End { reason, .. } => assert_eq!(reason, EndReason::Aborted),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn browser_response_skips_missing_ice_servers() {
        let parsed = serde_json::from_str::<RawConnectResponse>(
            r#"{
                "session_id":"01HXX",
                "peer_id":"xyz",
                "signal_url":"wss://coord.p2claw.com/v1/signal/01HXX",
                "signal_token":"tok"
            }"#,
        )
        .unwrap()
        .into_public();
        assert!(parsed.ice_servers.is_empty());
        assert_eq!(parsed.turn_expires_at, 0);
    }
}
