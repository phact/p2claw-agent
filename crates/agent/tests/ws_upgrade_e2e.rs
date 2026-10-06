//! Browser-shape WebSocket through the translator wire's
//! `WS_UPGRADE` verb — the path the bootstrap WS-shim will take once
//! it stops encoding `new WebSocket(url)` as a plain HTTP REQ frame
//! with `Upgrade: websocket` headers.
//!
//! This exercises the same on-box machinery as `edge/tests/ws_e2e.rs`
//! (the edge-tunnel shape) but bypasses iroh + the edge router and
//! talks the translator wire end-to-end over an in-process duplex.
//! That matches what a browser running bootstrap will look like:
//!
//! ```text
//! browser bootstrap ── DC ── translator wire (WS_UPGRADE) ──▶ box
//! ```
//!
//! Asserts:
//!
//! - `open_websocket` resolves (translator handshake completed via
//!   `WsForwarder::decide` → Accept → `run`).
//! - Five text frames + one binary frame round-trip (echo upstream
//!   bounces them straight back).
//! - Close from the client side propagates cleanly.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use ed25519_dalek::SigningKey as DalekSk;
use futures_util::{SinkExt, StreamExt};
use p2claw_agent::forwarder::Forwarder;
use p2claw_agent::oauth::jwks::{Jwk, Jwks};
use p2claw_agent::oauth::{jwt, OAuthConfig, OAuthValidator};
use p2claw_agent::routes::{RouteRecord, RouteTable};
use p2claw_agent::ws_forwarder::WsForwarder;
use p2claw_control_proto::AuthMethod;
use p2claw_translator::{ClientConnection, ClientWsUpgrade, WsHandler, WsMessage};
use p2claw_wire::WsOpcode;
use rand::rngs::OsRng;
use serde_json::json;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::Message;

const PARENT_DOMAIN: &str = "p2claw.test";
const ALIAS: &str = "blue-otter-7392";
const APP: &str = "wsapp";
const OAUTH_APP: &str = "wsoauthapp";

// Test OAuth constants mirror `oauth_middleware_e2e.rs` / `edge/tests/ws_e2e.rs`.
const ISS: &str = "https://broker.p2claw.test";
const AUD: &str = "wsoauth1234567890123456789012345678901234567890123";
const KID: &str = "test-kid";

type UpgradeHeadersCapture = tokio::sync::mpsc::UnboundedSender<Vec<(String, String)>>;

/// Echo WS upstream on `127.0.0.1:<ephemeral>`. Mirrors the helper in
/// `crates/edge/tests/ws_e2e.rs`; kept inline here to keep this test
/// hermetic with no shared `mod common`. When `capture` is `Some`,
/// each accepted upgrade's request headers are sent over the channel
/// for the test to inspect.
async fn start_echo_upstream() -> u16 {
    start_echo_upstream_with_capture(None).await
}

// Tungstenite's `ErrorResponse = http::Response<Option<String>>` is
// the dictated type for `accept_hdr_async`'s callback. We never emit
// an `Err`, but the closure's signature carries the variant.
#[allow(clippy::result_large_err)]
async fn start_echo_upstream_with_capture(capture: Option<UpgradeHeadersCapture>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let capture = capture.clone();
            tokio::spawn(async move {
                let cb = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                          resp: tokio_tungstenite::tungstenite::handshake::server::Response|
                 -> Result<
                    tokio_tungstenite::tungstenite::handshake::server::Response,
                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
                > {
                    if let Some(tx) = capture.as_ref() {
                        let pairs: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(n, v)| {
                                (n.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect();
                        let _ = tx.send(pairs);
                    }
                    Ok(resp)
                };
                let mut ws = match tokio_tungstenite::accept_hdr_async(stream, cb).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                while let Some(Ok(msg)) = ws.next().await {
                    match msg {
                        Message::Text(_) | Message::Binary(_) | Message::Ping(_) => {
                            if ws.send(msg).await.is_err() {
                                return;
                            }
                        }
                        Message::Pong(_) | Message::Frame(_) => {}
                        Message::Close(_) => return,
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_upgrade_verb_round_trips_through_wsforwarder() {
    let upstream_port = start_echo_upstream().await;

    let dir = tempdir().unwrap();
    let routes = RouteTable::load_or_empty(dir.path().join("routes.json"));
    routes
        .upsert(RouteRecord {
            name: APP.into(),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            registered_at: 0,
            auth: Vec::new(),
            ..Default::default()
        })
        .await
        .expect("upsert ws route");

    let forwarder = Forwarder::new(routes, PARENT_DOMAIN.into());
    let ws_handler: Arc<dyn WsHandler> = Arc::new(WsForwarder::new(forwarder.clone()));

    // In-process translator transport: client end → ws_upgrade →
    // server end (dispatch via Forwarder + WsForwarder). Mirrors
    // `forwarder_e2e.rs`'s duplex shape; just adds the WsHandler.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let serve_handle = tokio::spawn({
        let forwarder = forwarder.clone();
        async move {
            let opts = p2claw_translator::ServeOptions {
                ws_handler: Some(ws_handler),
                ..Default::default()
            };
            let _ = p2claw_translator::serve_with(server_io, forwarder, opts).await;
        }
    });

    let client = ClientConnection::spawn(client_io);
    let host_header = format!("{APP}-{ALIAS}.{PARENT_DOMAIN}");
    let upgrade = ClientWsUpgrade::new(Bytes::from_static(b"/echo"))
        .header(
            Bytes::from_static(b"host"),
            Bytes::from(host_header.clone()),
        )
        .header(
            Bytes::from_static(b"upgrade"),
            Bytes::from_static(b"websocket"),
        )
        .header(
            Bytes::from_static(b"connection"),
            Bytes::from_static(b"upgrade"),
        );

    let ws = tokio::time::timeout(Duration::from_secs(10), client.open_websocket(upgrade))
        .await
        .expect("open_websocket within 10s")
        .expect("open_websocket ok");

    for i in 0..5u32 {
        let payload = format!("hello-{i}");
        ws.send(WsMessage::text(Bytes::from(payload.clone())))
            .await
            .expect("send text");
        let echoed = tokio::time::timeout(Duration::from_secs(5), ws.recv())
            .await
            .expect("recv text within 5s")
            .expect("recv ok")
            .expect("frame present");
        assert_eq!(echoed.opcode, WsOpcode::Text);
        assert_eq!(echoed.payload, Bytes::from(payload), "text echo {i}");
    }

    let bin: Vec<u8> = (0..256u32).map(|x| (x & 0xFF) as u8).collect();
    ws.send(WsMessage::binary(Bytes::from(bin.clone())))
        .await
        .expect("send binary");
    let echoed_bin = tokio::time::timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect("recv bin within 5s")
        .expect("recv ok")
        .expect("frame present");
    assert_eq!(echoed_bin.opcode, WsOpcode::Binary);
    assert_eq!(echoed_bin.payload.as_ref(), bin.as_slice(), "binary echo");

    ws.close(1000, Bytes::from_static(b""))
        .await
        .expect("close");

    // Drop client to let the server-side select on EOF and tear down
    // (otherwise `serve_with` keeps the duplex half-open).
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve_handle).await;
    std::mem::forget(dir);
}

/// Same shape as the public-route test above, but the route's `auth`
/// is `[AuthMethod::oauth_any]`. The client sends a JWT via the
/// `Cookie: __p2claw_session=...` header; the box validates it,
/// derives identity headers from the claims, and attaches them to
/// the upstream WS dial. Assertion: the echo upstream sees
/// `X-P2claw-User` matching the JWT's `sub`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_upgrade_forwards_identity_headers_to_oauth_gated_upstream() {
    let (cap_tx, mut cap_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<(String, String)>>();
    let upstream_port = start_echo_upstream_with_capture(Some(cap_tx)).await;

    // Box's OAuth validator with JWKS pre-loaded — no broker server.
    let sk = DalekSk::generate(&mut OsRng);
    let cfg = OAuthConfig {
        broker_url: ISS.into(),
        expected_aud_z32: AUD.into(),
    };
    let validator = Arc::new(OAuthValidator::new(cfg));
    validator
        .jwks()
        .install_for_test(Jwks {
            keys: vec![Jwk {
                kid: KID.into(),
                verifying_key: sk.verifying_key(),
            }],
        })
        .await;

    let dir = tempdir().unwrap();
    let routes = RouteTable::load_or_empty(dir.path().join("routes.json"));
    routes
        .upsert(RouteRecord {
            name: OAUTH_APP.into(),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            registered_at: 0,
            auth: vec![AuthMethod::oauth_any()],
            ..Default::default()
        })
        .await
        .expect("upsert oauth route");

    let forwarder =
        Forwarder::new_with_oauth(routes, PARENT_DOMAIN.into(), Some(Arc::clone(&validator)));
    let ws_handler: Arc<dyn WsHandler> = Arc::new(WsForwarder::new(forwarder.clone()));

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let serve_handle = tokio::spawn({
        let forwarder = forwarder.clone();
        async move {
            let opts = p2claw_translator::ServeOptions {
                ws_handler: Some(ws_handler),
                ..Default::default()
            };
            let _ = p2claw_translator::serve_with(server_io, forwarder, opts).await;
        }
    });

    let client = ClientConnection::spawn(client_io);
    let host_header = format!("{OAUTH_APP}-{ALIAS}.{PARENT_DOMAIN}");
    let jwt_str = mint_jwt(&sk, KID, 60);
    // p2claw's own session cookie (auth) alongside an app-owned cookie
    // the SW jar replayed. `oauth_mw::apply` validates + strips the
    // `__p2claw_session` credential but keeps other cookies; the forward
    // filter then passes those surviving app cookies to the upstream.
    let cookie_header = format!("__p2claw_session={jwt_str}; app_session=appcookie123");
    let upgrade = ClientWsUpgrade::new(Bytes::from_static(b"/echo"))
        .header(
            Bytes::from_static(b"host"),
            Bytes::from(host_header.clone()),
        )
        .header(
            Bytes::from_static(b"upgrade"),
            Bytes::from_static(b"websocket"),
        )
        .header(
            Bytes::from_static(b"connection"),
            Bytes::from_static(b"upgrade"),
        )
        .header(Bytes::from_static(b"cookie"), Bytes::from(cookie_header))
        // The app's own auth headers (native apps use these, not a
        // cookie) must reach the upstream.
        .header(
            Bytes::from_static(b"authorization"),
            Bytes::from_static(b"Bearer app-token-xyz"),
        )
        .header(
            Bytes::from_static(b"x-immich-user-token"),
            Bytes::from_static(b"immichtok"),
        )
        // Spoofed identity header — must be stripped by oauth_mw and
        // replaced with the trusted value from the validated JWT.
        .header(
            Bytes::from_static(b"x-p2claw-user"),
            Bytes::from_static(b"attacker"),
        );

    let ws = tokio::time::timeout(Duration::from_secs(10), client.open_websocket(upgrade))
        .await
        .expect("open_websocket within 10s")
        .expect("open_websocket ok");

    // One round-trip so we know the bridge fully came up before we
    // poll the captured headers.
    ws.send(WsMessage::text(Bytes::from_static(b"authed-hello")))
        .await
        .expect("send");
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect("recv within 5s")
        .expect("recv ok")
        .expect("frame present");
    assert_eq!(echoed.payload, Bytes::from_static(b"authed-hello"));

    let captured = cap_rx
        .recv()
        .await
        .expect("upstream upgrade headers captured");
    let user = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("x-p2claw-user"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        user.as_deref(),
        Some("gh:42"),
        "upstream must receive X-P2claw-User matching the JWT sub; \
         got: {captured:?}",
    );
    let email = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("x-p2claw-email"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        email.as_deref(),
        Some("alice@example.com"),
        "upstream must receive X-P2claw-Email matching the JWT claim",
    );
    // The WS handshake must forward the app-owned `Cookie` the SW
    // cookie-jar replayed, so the upstream app authenticates its
    // realtime socket the same way the plain-HTTP path does.
    let cookie = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        .map(|(_, v)| v.clone());
    let cookie = cookie
        .as_deref()
        .expect("upstream must receive a forwarded Cookie on the WS handshake");
    assert!(
        cookie.contains("app_session=appcookie123"),
        "app-owned cookie must reach the upstream WS; got: {cookie:?}",
    );
    // p2claw's own session credential must NOT leak upstream — oauth_mw
    // strips `__p2claw_session` before the forward filter runs.
    assert!(
        !cookie.contains("__p2claw_session"),
        "p2claw session cookie must be stripped, not forwarded; got: {cookie:?}",
    );
    // Arbitrary app headers must reach the upstream — native apps
    // authenticate their socket with these, not a cookie.
    let immich = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("x-immich-user-token"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        immich.as_deref(),
        Some("immichtok"),
        "upstream must receive an arbitrary app auth header; got: {captured:?}",
    );
    // On a GATED route `Authorization: Bearer` is p2claw's own credential
    // channel — `oauth_mw` validates + strips it, so it must NOT reach
    // the upstream (proof the credential doesn't leak). A public route
    // forwards it instead; see `ws_upgrade_forwards_app_authorization_on_public_route`.
    assert!(
        captured
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("authorization")),
        "p2claw credential channel (Authorization) must not leak upstream on a gated route; \
         got: {captured:?}",
    );
    // The spoofed inbound `X-P2claw-User: attacker` must not survive —
    // oauth_mw strips inbound identity headers, so the only value the
    // upstream sees is the trusted `gh:42` asserted above.
    assert!(
        captured
            .iter()
            .all(|(n, v)| !(n.eq_ignore_ascii_case("x-p2claw-user") && v == "attacker")),
        "spoofed X-P2claw-User must be stripped, not forwarded; got: {captured:?}",
    );
    // WS-handshake mechanics must NOT be forwarded from the visitor —
    // the dialer regenerates Host for the loopback upstream. If the
    // alias Host leaked through, the upstream would receive the p2claw
    // hostname instead of its own.
    let host = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());
    assert!(
        host.as_deref().is_none_or(|h| !h.contains(PARENT_DOMAIN)),
        "visitor alias Host must not be forwarded to the upstream; got: {host:?}",
    );

    ws.close(1000, Bytes::from_static(b""))
        .await
        .expect("close");
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve_handle).await;
    std::mem::forget(dir);
}

/// On a PUBLIC route (no p2claw OAuth gate — the common case for
/// an app with its own login, e.g. Immich), the app's own auth headers
/// must reach the upstream WS. `Authorization: Bearer <app-token>` is
/// not a valid p2claw JWT, so `oauth_mw` leaves it untouched, and the
/// forward filter must carry it (plus arbitrary custom headers). The
/// old allowlist dropped everything but `x-p2claw-*`/`cookie`, so the
/// native app's socket.io handshake 401'd on every retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_upgrade_forwards_app_authorization_on_public_route() {
    let (cap_tx, mut cap_rx) = tokio::sync::mpsc::unbounded_channel();
    let upstream_port = start_echo_upstream_with_capture(Some(cap_tx)).await;

    let dir = tempdir().unwrap();
    let routes = RouteTable::load_or_empty(dir.path().join("routes.json"));
    routes
        .upsert(RouteRecord {
            name: APP.into(),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            registered_at: 0,
            auth: Vec::new(), // public — no p2claw gate
            ..Default::default()
        })
        .await
        .expect("upsert public ws route");

    let forwarder = Forwarder::new(routes, PARENT_DOMAIN.into());
    let ws_handler: Arc<dyn WsHandler> = Arc::new(WsForwarder::new(forwarder.clone()));

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let serve_handle = tokio::spawn({
        let forwarder = forwarder.clone();
        async move {
            let opts = p2claw_translator::ServeOptions {
                ws_handler: Some(ws_handler),
                ..Default::default()
            };
            let _ = p2claw_translator::serve_with(server_io, forwarder, opts).await;
        }
    });

    let client = ClientConnection::spawn(client_io);
    let host_header = format!("{APP}-{ALIAS}.{PARENT_DOMAIN}");
    let upgrade = ClientWsUpgrade::new(Bytes::from_static(b"/echo"))
        .header(
            Bytes::from_static(b"host"),
            Bytes::from(host_header.clone()),
        )
        .header(
            Bytes::from_static(b"upgrade"),
            Bytes::from_static(b"websocket"),
        )
        .header(
            Bytes::from_static(b"connection"),
            Bytes::from_static(b"upgrade"),
        )
        .header(
            Bytes::from_static(b"authorization"),
            Bytes::from_static(b"Bearer immich-access-token"),
        )
        .header(
            Bytes::from_static(b"x-api-key"),
            Bytes::from_static(b"immich-api-key"),
        );

    let ws = tokio::time::timeout(Duration::from_secs(10), client.open_websocket(upgrade))
        .await
        .expect("open_websocket within 10s")
        .expect("open_websocket ok");

    ws.send(WsMessage::text(Bytes::from_static(b"hi")))
        .await
        .expect("send");
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect("recv within 5s")
        .expect("recv ok")
        .expect("frame present");
    assert_eq!(echoed.payload, Bytes::from_static(b"hi"));

    let captured = cap_rx
        .recv()
        .await
        .expect("upstream upgrade headers captured");
    let authz = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        authz.as_deref(),
        Some("Bearer immich-access-token"),
        "public route must forward the app's Authorization to the upstream WS; got: {captured:?}",
    );
    let api_key = captured
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("x-api-key"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        api_key.as_deref(),
        Some("immich-api-key"),
        "public route must forward arbitrary app headers to the upstream WS; got: {captured:?}",
    );

    ws.close(1000, Bytes::from_static(b""))
        .await
        .expect("close");
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve_handle).await;
    std::mem::forget(dir);
}

/// Mint a JWT against the given signing key. Mirrors the helper in
/// `crates/edge/tests/ws_e2e.rs::mint_jwt`.
fn mint_jwt(sk: &DalekSk, kid: &str, exp_offset_secs: i64) -> String {
    use ed25519_dalek::Signer;
    let now = jwt::unix_now() as i64;
    let exp = (now + exp_offset_secs).max(0) as u64;
    let claims = jwt::Claims {
        iss: ISS.into(),
        aud: AUD.into(),
        sub: "gh:42".into(),
        email: "alice@example.com".into(),
        email_verified: true,
        name: Some("Alice".into()),
        picture: Some("https://avatars/alice".into()),
        provider: "github".into(),
        iat: now as u64,
        exp,
    };
    let header = json!({"alg":"EdDSA","typ":"JWT","kid":kid});
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
    let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{h_b64}.{p_b64}.{s_b64}")
}

/// When the loopback upstream WS dies mid-session, the visitor must
/// see an explicit `BAD_GATEWAY (1014)` close instead of either a
/// clean `NORMAL (1000)` (which makes a crash look indistinguishable
/// from a graceful shutdown) or a hang waiting for the next message.
///
/// Upstream shape: an "echo-once-then-die" server that accepts the
/// upgrade, echoes a single message, then drops the TCP socket
/// without sending a Close frame. The visitor sends one text frame,
/// receives the echo, sends another — by the second send the box's
/// `pump_visitor_to_upstream` finds the sink dead and propagates a
/// `BAD_GATEWAY` close back. The visitor's `recv()` then returns
/// `Ok(None)` and `peer_close()` carries the 1014.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_visitor_sees_bad_gateway_when_upstream_dies_mid_stream() {
    // One-shot upstream: echo first message, then `shutdown()` the
    // TCP stream (no Close frame). Mirrors a crash / port-killed
    // local app.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws = match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                // Echo the first inbound message, then drop the
                // socket abruptly (no Close handshake).
                if let Some(Ok(msg)) = ws.next().await {
                    let _ = ws.send(msg).await;
                }
                // tungstenite's split has no direct "RST" — closing
                // the underlying stream by dropping is the only way
                // to simulate an upstream crash short of unsafe.
                drop(ws);
            });
        }
    });

    let dir = tempdir().unwrap();
    let routes = RouteTable::load_or_empty(dir.path().join("routes.json"));
    routes
        .upsert(RouteRecord {
            name: APP.into(),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            registered_at: 0,
            auth: Vec::new(),
            ..Default::default()
        })
        .await
        .expect("upsert route");

    let forwarder = Forwarder::new(routes, PARENT_DOMAIN.into());
    let ws_handler: Arc<dyn WsHandler> = Arc::new(WsForwarder::new(forwarder.clone()));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let serve_handle = tokio::spawn({
        let forwarder = forwarder.clone();
        async move {
            let opts = p2claw_translator::ServeOptions {
                ws_handler: Some(ws_handler),
                ..Default::default()
            };
            let _ = p2claw_translator::serve_with(server_io, forwarder, opts).await;
        }
    });

    let client = ClientConnection::spawn(client_io);
    let host_header = format!("{APP}-{ALIAS}.{PARENT_DOMAIN}");
    let upgrade = ClientWsUpgrade::new(Bytes::from_static(b"/echo"))
        .header(Bytes::from_static(b"host"), Bytes::from(host_header))
        .header(
            Bytes::from_static(b"upgrade"),
            Bytes::from_static(b"websocket"),
        )
        .header(
            Bytes::from_static(b"connection"),
            Bytes::from_static(b"upgrade"),
        );
    let ws = tokio::time::timeout(Duration::from_secs(10), client.open_websocket(upgrade))
        .await
        .expect("open_websocket within 10s")
        .expect("open_websocket ok");

    // First message echoes cleanly.
    ws.send(WsMessage::text(Bytes::from_static(b"first")))
        .await
        .expect("send first");
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect("recv echo within 5s")
        .expect("recv ok")
        .expect("frame present");
    assert_eq!(echoed.opcode, WsOpcode::Text);
    assert_eq!(echoed.payload, Bytes::from_static(b"first"));

    // Drain whatever comes next: the upstream has died so the box
    // surfaces a Close frame. `recv` returns `Ok(None)` once it
    // arrives. Send a noop frame first to push the pump past the
    // sink-error path; the pump's close-on-error then races with
    // the visitor's next recv.
    let _ = ws
        .send(WsMessage::text(Bytes::from_static(b"after-upstream-died")))
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.recv().await {
                Ok(Some(_msg)) => continue, // drain any in-flight echo
                Ok(None) => return Ok::<(), &'static str>(()),
                Err(_) => return Err("transport error before close"),
            }
        }
    })
    .await
    .expect("visitor must see ws close within 5s after upstream dies")
    .expect("close path");
    let peer_close = ws.peer_close().await;
    assert!(
        peer_close.is_some(),
        "visitor must see an explicit peer close frame (not silent EOF)"
    );
    let (code, _reason) = peer_close.unwrap();
    assert_eq!(
        code, 1014,
        "upstream-death must surface as BAD_GATEWAY (1014), got {code}"
    );

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve_handle).await;
    std::mem::forget(dir);
}
