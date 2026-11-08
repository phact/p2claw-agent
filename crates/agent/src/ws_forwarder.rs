//! WebSocket-upgrade bridge for the edge-tunnel transport.
//!
//! Implements the translator's [`WsHandler`] verb on top of the same
//! [`Forwarder`] state (routes + OAuth + parent domain). The edge
//! tunnel speaks the first-class `ClientWsUpgrade` verb to the box;
//! the box answers with `WsUpgradeDecision::Accept` and then bridges
//! the visitor-side `WsConnection` to a freshly-dialed upstream
//! WebSocket server.
//!
//! Why a separate type from [`Forwarder`]: the plain-HTTP path uses
//! hyper + a connection pool and bodies stream end-to-end. The WS
//! path uses tokio-tungstenite, has no connection pool, and is fully
//! bidirectional. Splitting the type keeps the WS surface small and
//! the plain-HTTP body machinery off the WS hot path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use p2claw_iroh_client::url::P2clawHost;
use p2claw_translator::{
    IncomingBody, ServerRequest, ServerWsUpgrade, WsConnection, WsHandler, WsHandlerState,
    WsMessage, WsUpgradeDecision,
};
use p2claw_wire::WsOpcode;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Message};
use tracing::{debug, info, warn};

use crate::forwarder::Forwarder;
use crate::oauth::middleware as oauth_mw;
use crate::oauth::IDENTITY_HEADER_PREFIX;
use crate::routes::RouteRecord;
use crate::shares::PEER_HEADER;
use crate::validate::unix_upstream_path;

/// 1000 = normal closure, RFC 6455 §7.4.1.
const WS_CLOSE_NORMAL: u16 = 1000;
/// 1011 = server (the bridge) encountered an unexpected condition.
const WS_CLOSE_INTERNAL_ERROR: u16 = 1011;
/// 1014 = bad gateway (upstream unreachable or refused).
const WS_CLOSE_BAD_GATEWAY: u16 = 1014;

/// A [`WsHandler`] that resolves the app from `Host`, runs the same
/// auth gate as [`Forwarder`], dials the local upstream over plain
/// `ws://`, and bridges the two halves until either side closes.
pub struct WsForwarder {
    forwarder: Forwarder,
}

impl WsForwarder {
    pub fn new(forwarder: Forwarder) -> Self {
        Self { forwarder }
    }
}

impl WsHandler for WsForwarder {
    fn decide(
        &self,
        upgrade: &ServerWsUpgrade,
    ) -> Pin<Box<dyn Future<Output = WsUpgradeDecision> + Send + '_>> {
        // Validate the route and auth, then dial the upstream, all
        // before answering: a failure is a `Reject` (→ HTTP-style RES)
        // rather than an `Accept` followed by an immediate WS_CLOSE,
        // and the upstream's chosen `Sec-WebSocket-Protocol` goes on
        // the WS_ACCEPT.
        let forwarder = self.forwarder.clone();
        let upgrade_headers = upgrade.headers.clone();
        let upgrade_path = upgrade.path.clone();
        Box::pin(async move { decide_session(&forwarder, upgrade_path, upgrade_headers).await })
    }

    fn run(
        &self,
        _upgrade: ServerWsUpgrade,
        state: Option<WsHandlerState>,
        conn: WsConnection,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            match state.and_then(WsHandlerState::downcast::<UpstreamWs>) {
                Some(UpstreamWs::Tcp(ws)) => bridge_session(ws, conn).await,
                Some(UpstreamWs::Unix(ws)) => bridge_session(ws, conn).await,
                None => {
                    warn!("ws: accepted without an upstream socket");
                    let _ = conn
                        .close(WS_CLOSE_INTERNAL_ERROR, Bytes::from_static(b"no upstream"))
                        .await;
                }
            }
        })
    }
}

/// Validate route + auth and dial the upstream before WS_ACCEPT
/// lands. Returns `Reject` (mapped by the wire to a status-carrying
/// RES) on any failure so the visitor side sees a clean rejection
/// rather than a 101 + immediate close.
async fn decide_session(
    forwarder: &Forwarder,
    path: Bytes,
    headers: Vec<(Bytes, Bytes)>,
) -> WsUpgradeDecision {
    // ---- Host → app → route -----------------------------------------
    let Some(host_raw) = take_header(&headers, b"host") else {
        warn!("ws: upgrade missing Host header");
        return WsUpgradeDecision::Reject {
            status: 400,
            headers: Vec::new(),
        };
    };
    let Ok(host_str) = std::str::from_utf8(host_raw) else {
        warn!("ws: Host header is not UTF-8");
        return WsUpgradeDecision::Reject {
            status: 400,
            headers: Vec::new(),
        };
    };
    let parsed = match P2clawHost::parse(strip_port(host_str), forwarder.parent_domain()) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "ws: host parse failed");
            return WsUpgradeDecision::Reject {
                status: 400,
                headers: Vec::new(),
            };
        }
    };
    let Some(app) = parsed.app else {
        // Apex has no app to route to.
        return WsUpgradeDecision::Reject {
            status: 400,
            headers: Vec::new(),
        };
    };
    let Some(route) = forwarder.routes().get(&app).await else {
        debug!(%app, "ws: no such app");
        return WsUpgradeDecision::Reject {
            status: 404,
            headers: Vec::new(),
        };
    };

    // ---- Share gate ---------------------------------------------
    //
    // Same enforcement as the plain-HTTP path: share required,
    // inbound `X-P2claw-*` stripped, `X-P2claw-Peer` injected onto
    // the upstream dial. Private routes skip the OAuth gate
    // entirely.
    if route.is_private() {
        let peer = match forwarder.check_share(&route.name) {
            Ok(p) => p.to_string(),
            Err(denied) => {
                warn!(
                    route = %route.name,
                    peer = denied.peer.as_deref().unwrap_or("<none>"),
                    "ws: private route denied"
                );
                // 404, same as an unknown app — no status differential
                // that would confirm private route names to a probing
                // peer (mirrors the plain-HTTP path).
                return WsUpgradeDecision::Reject {
                    status: 404,
                    headers: Vec::new(),
                };
            }
        };
        let mut upstream_headers: Vec<(Bytes, Bytes)> = headers
            .iter()
            .filter(|(name, _)| !is_ws_hop_or_handshake_header(name) && !is_identity_header(name))
            .cloned()
            .collect();
        upstream_headers.push((
            Bytes::from_static(PEER_HEADER.as_bytes()),
            Bytes::from(peer.into_bytes()),
        ));
        forwarder.set_forwarded_for(&mut upstream_headers);
        return dial_and_accept(&route, &path, &upstream_headers).await;
    }

    // ---- Auth gate --------------------------------------------------
    //
    // `oauth_mw::apply` takes `&mut ServerRequest`. Build a synthetic
    // one carrying the upgrade headers; body is `empty` (a WS_UPGRADE
    // has no body on the wire). On success the middleware:
    //   - strips any inbound `X-P2claw-*` from the request,
    //   - injects fresh `X-P2claw-User/Email/Name/Picture/Provider`
    //     derived from the validated JWT claims.
    // We harvest those injected headers and ship them on the
    // decision so `run_session` can attach them to the upstream WS
    // dial (matching the plain-HTTP path, which forwards identity
    // through `build_hyper_request`).
    let mut auth_req = ServerRequest {
        method: Bytes::from_static(b"GET"),
        path,
        headers,
        body: IncomingBody::empty(),
    };
    if let Err(e) = oauth_mw::apply(
        &mut auth_req,
        &route.auth,
        forwarder.oauth(),
        forwarder.identity(),
    )
    .await
    {
        debug!(error = %e, app = %route.name, "ws: auth rejected at decide");
        return WsUpgradeDecision::Reject {
            status: 401,
            headers: Vec::new(),
        };
    }

    // Forward everything except hop-by-hop + WS-handshake headers the
    // dialer regenerates: native apps authenticate the socket with their
    // own header (bearer / vendor token), so an allowlist would break
    // the handshake. `oauth_mw::apply` has already stripped inbound
    // `X-P2claw-*` and `__p2claw_session`, so what remains is trusted.
    let mut upstream_headers: Vec<(Bytes, Bytes)> = auth_req
        .headers
        .iter()
        .filter(|(name, _)| !is_ws_hop_or_handshake_header(name))
        .cloned()
        .collect();
    // Same `X-Forwarded-For` rule as the plain-HTTP path.
    forwarder.set_forwarded_for(&mut upstream_headers);

    dial_and_accept(&route, &auth_req.path, &upstream_headers).await
}

/// The dialed upstream, handed from `decide` to `run`. It's moved
/// once, already boxed inside `WsHandlerState`, so the variants'
/// size difference costs nothing.
#[allow(clippy::large_enum_variant)]
enum UpstreamWs {
    Tcp(
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ),
    Unix(tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>),
}

/// Dial the route's upstream and accept with the subprotocol it
/// selected, or reject with 502 if it can't be reached or refuses.
async fn dial_and_accept(
    route: &RouteRecord,
    path: &[u8],
    upstream_headers: &[(Bytes, Bytes)],
) -> WsUpgradeDecision {
    // Require origin-form (leading '/'). Without this, a wire-
    // controlled path like `@evil.com/x` spliced into
    // `ws://{host}:{port}{path}` reshapes the authority and makes the
    // BOX dial an arbitrary external host on a peer's behalf.
    let path_str = match std::str::from_utf8(path) {
        Ok(s) if s.starts_with('/') => s,
        _ => "/",
    };
    let bad_gateway = WsUpgradeDecision::Reject {
        status: 502,
        headers: Vec::new(),
    };
    let upstream_url = route.upstream_url();

    let (upstream, resp) = if let Some(sock) = unix_upstream_path(upstream_url) {
        // Private routes may hand off over a Unix socket; the WS
        // handshake then runs over the UnixStream instead of a fresh
        // TCP dial.
        let ws_url = format!("ws://localhost{path_str}");
        let Some(upstream_req) = build_upstream_request(&ws_url, upstream_headers) else {
            return bad_gateway;
        };
        let stream = match tokio::net::UnixStream::connect(sock).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, upstream = %sock, "ws: unix upstream dial failed");
                return bad_gateway;
            }
        };
        match tokio_tungstenite::client_async(upstream_req, stream).await {
            Ok((ws, resp)) => {
                info!(app = %route.name, upstream = %sock, "ws: bridging to unix upstream");
                (UpstreamWs::Unix(ws), resp)
            }
            Err(e) => {
                warn!(error = %e, upstream = %sock, "ws: unix upstream handshake failed");
                return bad_gateway;
            }
        }
    } else {
        let Some(host) = upstream_url.host_str() else {
            warn!(route = %route.name, "ws: route upstream has no host");
            return bad_gateway;
        };
        let port =
            upstream_url
                .port_or_known_default()
                .unwrap_or(if upstream_url.scheme() == "https" {
                    443
                } else {
                    80
                });
        // Plain `ws://`; the local CA only fronts the SNI listener path,
        // and the upstream is always a loopback app speaking ws/wss
        // itself. Caller wires `wss://` upstreams via the standard URL.
        let scheme = if upstream_url.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        let ws_url = format!("{scheme}://{host}:{port}{path_str}");
        info!(
            app = %route.name,
            upstream = %ws_url,
            upstream_header_count = upstream_headers.len(),
            "ws: dialing upstream"
        );
        let Some(upstream_req) = build_upstream_request(&ws_url, upstream_headers) else {
            return bad_gateway;
        };
        match tokio_tungstenite::connect_async(upstream_req).await {
            Ok((ws, resp)) => (UpstreamWs::Tcp(ws), resp),
            Err(e) => {
                warn!(error = %e, upstream = %ws_url, "ws: upstream dial failed");
                return bad_gateway;
            }
        }
    };

    // tungstenite has already checked the upstream picked one of the
    // offered subprotocols (or none when none were offered).
    let headers = resp
        .headers()
        .get(tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
        .map(|v| {
            vec![(
                Bytes::from_static(b"sec-websocket-protocol"),
                Bytes::copy_from_slice(v.as_bytes()),
            )]
        })
        .unwrap_or_default();
    WsUpgradeDecision::Accept {
        headers,
        state: Some(WsHandlerState::new(upstream)),
    }
}

/// Build the upgrade Request via `IntoClientRequest` (which fills
/// in `Sec-WebSocket-Key` / `Host` / RFC-6455 headers correctly),
/// then inject the forwarded headers. Skipping malformed
/// names/values is intentional — the middleware produces
/// well-formed headers, but the wire payload is untrusted bytes
/// and we'd rather drop a bad header than refuse the upgrade.
/// `None` ⇒ the URL didn't make a request.
fn build_upstream_request(
    ws_url: &str,
    upstream_headers: &[(Bytes, Bytes)],
) -> Option<tokio_tungstenite::tungstenite::handshake::client::Request> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
    let mut upstream_req = match ws_url.into_client_request() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, upstream = %ws_url, "ws: building upstream request failed");
            return None;
        }
    };
    {
        let dst = upstream_req.headers_mut();
        for (name, value) in upstream_headers {
            let Ok(hn) = HeaderName::from_bytes(name) else {
                warn!(name = %String::from_utf8_lossy(name), "ws: skipping malformed header name on upstream dial");
                continue;
            };
            // tungstenite 0.24 splits the offer on ',' without trimming,
            // so the browser form `a, b` would fail its check of the
            // upstream's pick; send `a,b`.
            let value =
                if hn == tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL {
                    Bytes::from(
                        String::from_utf8_lossy(value)
                            .split(',')
                            .map(str::trim)
                            .filter(|p| !p.is_empty())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                } else {
                    value.clone()
                };
            let Ok(hv) = HeaderValue::from_bytes(&value) else {
                warn!(name = %String::from_utf8_lossy(name), "ws: skipping malformed header value on upstream dial");
                continue;
            };
            dst.insert(hn, hv);
        }
    }
    Some(upstream_req)
}

/// Pump frames between a translator [`WsConnection`] and a
/// tungstenite WebSocket (any transport) until either side closes.
/// Public because the local API's `/v1/proxy` reuses it with the
/// roles inverted: there `conn` is the client-side session to the
/// remote box and the tungstenite half is the local caller's
/// upgraded socket.
pub async fn bridge_session<WS>(upstream_ws: WS, conn: WsConnection)
where
    WS: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin
        + Send
        + 'static,
{
    let (upstream_sink, upstream_stream) = upstream_ws.split();
    let conn = Arc::new(conn);
    let upstream_sink = Arc::new(Mutex::new(upstream_sink));

    let mut visitor_to_upstream = {
        let conn = Arc::clone(&conn);
        let upstream = Arc::clone(&upstream_sink);
        tokio::spawn(async move { pump_visitor_to_upstream(conn, upstream).await })
    };
    let mut upstream_to_visitor = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move { pump_upstream_to_visitor(upstream_stream, conn).await })
    };

    // Whichever direction closes first ends the session; abort the
    // other so a half-stuck peer can't dangle the bridge open. The
    // returned reason picks the close code we surface to the visitor
    // — an upstream-side failure must round-trip as `BAD_GATEWAY`
    // instead of `NORMAL`, otherwise the visitor sees a clean close
    // and assumes the app finished, when in fact it crashed.
    let reason = tokio::select! {
        r = &mut visitor_to_upstream => {
            upstream_to_visitor.abort();
            let _ = upstream_to_visitor.await;
            r.unwrap_or(ExitReason::Aborted)
        }
        r = &mut upstream_to_visitor => {
            visitor_to_upstream.abort();
            let _ = visitor_to_upstream.await;
            r.unwrap_or(ExitReason::Aborted)
        }
    };

    // Pick visitor + upstream close codes from the reason. Both
    // sides are idempotent (the pumps may have already sent a close
    // matching the reason — `close()` no-ops on already-closed).
    let (visitor_code, upstream_close) = match reason {
        ExitReason::UpstreamErrored => (WS_CLOSE_BAD_GATEWAY, true),
        ExitReason::UpstreamClosed => (WS_CLOSE_NORMAL, false),
        ExitReason::VisitorClosed => (WS_CLOSE_NORMAL, true),
        ExitReason::Aborted => (WS_CLOSE_NORMAL, true),
    };
    let _ = conn.close(visitor_code, Bytes::from_static(b"")).await;
    if upstream_close {
        let mut upstream = upstream_sink.lock().await;
        let _ = upstream
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })))
            .await;
    }
}

/// Outcome of one bridged WS session — drives the close codes the
/// surrounding `run_session` returns to the visitor + upstream.
#[derive(Debug, Clone, Copy)]
enum ExitReason {
    /// Upstream WebSocket errored / aborted mid-stream (TCP RST,
    /// protocol error, etc.). Surface as 1014 (bad gateway) so the
    /// visitor doesn't mistake a crash for a clean shutdown.
    UpstreamErrored,
    /// Upstream sent a normal Close frame.
    UpstreamClosed,
    /// Visitor sent a normal Close (or its DC dropped cleanly).
    VisitorClosed,
    /// `select!` aborted the other pump before it returned. Defaults
    /// to a normal close; the pump that DID return already had the
    /// chance to surface its specific reason.
    Aborted,
}

async fn pump_visitor_to_upstream<S>(conn: Arc<WsConnection>, upstream: Arc<Mutex<S>>) -> ExitReason
where
    S: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin + Send,
{
    while let Ok(Some(msg)) = conn.recv().await {
        // `Vec::from(Bytes)` moves the buffer out when this is the
        // only reference; tungstenite's Vec/String-based `Message`
        // forces owned payloads, so avoid a second copy on top.
        let tg = match msg.opcode {
            WsOpcode::Text => {
                Message::Text(String::from_utf8(Vec::from(msg.payload)).unwrap_or_default())
            }
            WsOpcode::Binary => Message::Binary(Vec::from(msg.payload)),
            WsOpcode::Ping => Message::Ping(Vec::from(msg.payload)),
            WsOpcode::Pong => Message::Pong(Vec::from(msg.payload)),
        };
        let mut sink = upstream.lock().await;
        if let Err(e) = sink.send(tg).await {
            // Upstream socket died mid-stream. Tell the visitor right
            // away so they aren't stuck on a half-open WS waiting on
            // a peer that's gone. `run_session` will also surface the
            // BAD_GATEWAY close once it sees `UpstreamErrored`.
            debug!(error = %e, "ws: upstream sink errored — propagating bad-gateway close");
            let _ = conn
                .close(
                    WS_CLOSE_BAD_GATEWAY,
                    Bytes::from_static(b"upstream errored"),
                )
                .await;
            return ExitReason::UpstreamErrored;
        }
    }
    if let Some((code, reason)) = conn.peer_close().await {
        let mut sink = upstream.lock().await;
        let _ = sink
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: std::str::from_utf8(&reason)
                    .unwrap_or("")
                    .to_string()
                    .into(),
            })))
            .await;
    }
    ExitReason::VisitorClosed
}

async fn pump_upstream_to_visitor<S>(mut stream: S, conn: Arc<WsConnection>) -> ExitReason
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin + Send,
{
    while let Some(item) = stream.next().await {
        let msg = match item {
            Ok(m) => m,
            Err(e) => {
                // Same shape as `pump_visitor_to_upstream`'s sink-
                // error path: send BAD_GATEWAY (1014) so the visitor
                // can distinguish upstream crash from clean close.
                debug!(error = %e, "ws: upstream stream errored");
                let _ = conn
                    .close(
                        WS_CLOSE_BAD_GATEWAY,
                        Bytes::from_static(b"upstream errored"),
                    )
                    .await;
                return ExitReason::UpstreamErrored;
            }
        };
        // Owned payloads move straight into `Bytes` — no re-copy.
        let wm = match msg {
            Message::Text(s) => WsMessage::text(Bytes::from(s.into_bytes())),
            Message::Binary(b) => WsMessage::binary(Bytes::from(b)),
            Message::Ping(b) => WsMessage::ping(Bytes::from(b)),
            Message::Pong(b) => WsMessage::pong(Bytes::from(b)),
            Message::Close(frame) => {
                let (code, reason) = frame
                    .map(|f| (u16::from(f.code), Bytes::from(f.reason.into_owned())))
                    .unwrap_or((WS_CLOSE_NORMAL, Bytes::new()));
                let _ = conn.close(code, reason).await;
                return ExitReason::UpstreamClosed;
            }
            // Raw frames don't appear from `accept_async` / `connect_async`
            // by default; ignore.
            Message::Frame(_) => continue,
        };
        if conn.send(wm).await.is_err() {
            // Visitor's transport went away while upstream was still
            // streaming — clean from upstream's POV, just nobody home.
            return ExitReason::VisitorClosed;
        }
    }
    // Stream ended without a close frame — treat as upstream-clean.
    ExitReason::UpstreamClosed
}

/// True for `X-P2claw-*` names — stripped from inbound
/// private-route upgrades before the trusted `X-P2claw-Peer` is
/// injected.
fn is_identity_header(name: &[u8]) -> bool {
    let prefix = IDENTITY_HEADER_PREFIX.as_bytes();
    name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn take_header<'a>(headers: &'a [(Bytes, Bytes)], wanted: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(wanted))
        .map(|(_, v)| v.as_ref())
}

/// Headers the box must NOT forward onto the freshly-dialed upstream
/// WS handshake:
///   - hop-by-hop (RFC 7230 §6.1), mirroring the plain-HTTP forwarder's
///     `is_hop_by_hop` exclusions, and
///   - the WS-handshake mechanics `tokio_tungstenite`'s
///     `IntoClientRequest` regenerates for the upstream (`Host`,
///     `Upgrade`, `Sec-WebSocket-Key/Version/Extensions`,
///     `Content-Length`).
///
/// `Sec-WebSocket-Protocol` is forwarded: the upstream picks from the
/// client's offer, and its pick goes back on the WS_ACCEPT.
///
/// Forwarding these would clobber the dialer's correct values — most
/// importantly `Host`, which the visitor sends as the p2claw alias but
/// the upstream needs as its own loopback host. Everything else (the
/// app's `Authorization` / `Cookie` / custom auth headers, plus the
/// trusted injected `X-P2claw-*`) is forwarded so the upstream app
/// authenticates the socket the same way it authenticates the app's
/// plain HTTP.
fn is_ws_hop_or_handshake_header(name: &[u8]) -> bool {
    const EXCLUDED: &[&[u8]] = &[
        // Hop-by-hop (RFC 7230 §6.1) — mirrors `forwarder::is_hop_by_hop`.
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"te",
        b"trailer",
        b"transfer-encoding",
        // WS-handshake mechanics the dialer regenerates for the
        // upstream; forwarding the visitor's would corrupt the dial.
        b"host",
        b"upgrade",
        b"sec-websocket-key",
        b"sec-websocket-version",
        b"sec-websocket-extensions",
        b"content-length",
    ];
    EXCLUDED.iter().any(|h| name.eq_ignore_ascii_case(h))
}

fn strip_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(i) if host[i + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..i],
        _ => host,
    }
}
