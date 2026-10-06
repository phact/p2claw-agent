//! Reverse-proxy request handler.
//!
//! Bridges [`p2claw_translator`] to a localhost upstream selected by
//! `Host`-header lookup against
//! [`RouteTable`](crate::routes::RouteTable). One [`Forwarder`]
//! instance is cloned (Arc-internally) into both transport paths;
//! per-route hyper pools materialize lazily.
//!
//! Bodies stream end-to-end in both directions; nothing is buffered
//! whole. WebSocket upgrades bypass hyper's upgrade machinery and
//! run over raw TCP, since the translator already ferries bytes.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Uri};
use http_body_util::BodyExt;
use hyper::body::Frame as HyperFrame;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use p2claw_translator::{IncomingBody, OutgoingBody, ServerRequest, ServerResponse};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};

use p2claw_iroh_client::url::{P2clawHost, UrlParseError};

use crate::oauth::{middleware as oauth_mw, OAuthValidator};
use crate::routes::{RouteRecord, RouteTable};
use crate::shares::{Shares, PEER_HEADER};
use crate::validate::{resolve_loopback, unix_upstream_path, ValidateError};

/// Per-request wall-clock cap, first byte out to last byte in.
/// Exceeded → 502.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound on idle keep-alive connections per upstream host:port.
/// hyper-util's default is unbounded; capping caps the FD working
/// set so a leaky upstream can't drain the agent's FD budget.
const POOL_MAX_IDLE_PER_HOST: usize = 32;

/// Drop idle pooled connections after this long. hyper-util defaults
/// to 90s; the shorter window returns FDs to the OS quickly after a
/// burst.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// TTL for memoized loopback re-check verdicts. Short enough to
/// catch resolver drift, long enough to keep getaddrinfo off the
/// per-request path.
const LOOPBACK_CACHE_TTL: Duration = Duration::from_secs(60);

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

type Pool = LegacyClient<HttpConnector, BoxBody>;

/// Maps `origin -> Client`. Key is `host:port` of the upstream, which
/// is invariant for a given `RouteRecord`.
type PoolMap = Mutex<HashMap<String, Pool>>;

/// A [`p2claw_translator::Handler`] that resolves the app name from
/// `Host`, looks up the route, and forwards. State lives behind an
/// `Arc`, so cloning is cheap.
#[derive(Clone)]
pub struct Forwarder {
    inner: Arc<ForwarderInner>,
    /// z-base-32 peer id of the authenticated caller, when the
    /// transport has one (iroh QUIC connections — see
    /// [`Forwarder::for_peer`]). `None` on visitor paths
    /// (browser/WebRTC sessions), which therefore can never reach a
    /// private route. Per-connection: lives on the clone, not in the
    /// shared inner state.
    caller_peer: Option<String>,
}

struct ForwarderInner {
    routes: RouteTable,
    parent_domain: String,
    pools: PoolMap,
    /// OAuth validator. `None` when no app is auth-gated, so a
    /// deployment without OAuth doesn't fail closed on a missing
    /// broker. The middleware still runs for the `X-P2claw-*` header
    /// strip; it only validates a JWT when the per-route auth list
    /// asks for one.
    oauth: Option<Arc<OAuthValidator>>,
    /// Box identity key. `Some` in production (loaded at startup);
    /// `None` in tests that don't exercise the attestation path.
    /// When `Some`, the middleware mints + injects
    /// `X-P2claw-Identity-Token` on every authenticated request so
    /// upstreams can verify the `X-P2claw-*` headers actually came
    /// through the daemon.
    identity: Option<Arc<p2claw_identity::SigningKey>>,
    /// Share store gating private routes. `None` in tests that
    /// never touch private routes; a private route is denied either
    /// way without a matching share.
    shares: Option<Shares>,
    /// Memoized loopback re-check verdicts keyed by upstream
    /// (host, port). `resolve_loopback` is a blocking getaddrinfo;
    /// on a miss it runs on the blocking pool, and the hot path is
    /// a map lookup.
    loopback_cache: std::sync::Mutex<HashMap<(String, u16), LoopbackVerdict>>,
}

struct LoopbackVerdict {
    checked_at: Instant,
    result: Result<(), ValidateError>,
}

impl Forwarder {
    pub fn new(routes: RouteTable, parent_domain: String) -> Self {
        Self::new_with_oauth(routes, parent_domain, None)
    }

    pub fn new_with_oauth(
        routes: RouteTable,
        parent_domain: String,
        oauth: Option<Arc<OAuthValidator>>,
    ) -> Self {
        Self::new_with_oauth_and_identity(routes, parent_domain, oauth, None)
    }

    pub fn new_with_oauth_and_identity(
        routes: RouteTable,
        parent_domain: String,
        oauth: Option<Arc<OAuthValidator>>,
        identity: Option<Arc<p2claw_identity::SigningKey>>,
    ) -> Self {
        Self::new_with_shares(routes, parent_domain, oauth, identity, None)
    }

    pub fn new_with_shares(
        routes: RouteTable,
        parent_domain: String,
        oauth: Option<Arc<OAuthValidator>>,
        identity: Option<Arc<p2claw_identity::SigningKey>>,
        shares: Option<Shares>,
    ) -> Self {
        Self {
            inner: Arc::new(ForwarderInner {
                routes,
                parent_domain,
                pools: Mutex::new(HashMap::new()),
                oauth,
                identity,
                shares,
                loopback_cache: std::sync::Mutex::new(HashMap::new()),
            }),
            caller_peer: None,
        }
    }

    /// Clone of this forwarder bound to an authenticated caller. The
    /// iroh listener calls this once per accepted connection with
    /// `conn.remote_id()` so private-route enforcement can
    /// attribute every request on that connection.
    pub fn for_peer(&self, peer_z32: String) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            caller_peer: Some(peer_z32),
        }
    }

    /// Shared accessors used by [`crate::ws_forwarder::WsForwarder`]
    /// so the WS-upgrade path reuses one [`RouteTable`] + OAuth state.
    pub(crate) fn routes(&self) -> &RouteTable {
        &self.inner.routes
    }
    pub(crate) fn parent_domain(&self) -> &str {
        &self.inner.parent_domain
    }
    pub(crate) fn oauth(&self) -> Option<&Arc<OAuthValidator>> {
        self.inner.oauth.as_ref()
    }
    pub(crate) fn identity(&self) -> Option<&Arc<p2claw_identity::SigningKey>> {
        self.inner.identity.as_ref()
    }
    /// Share check for a private route: `Ok(peer_z32)` when the
    /// route is shared with this connection's caller, else the
    /// denial to surface as 403 `not_shared`.
    pub(crate) fn check_share(&self, route_name: &str) -> Result<&str, ShareDenied> {
        let Some(peer) = self.caller_peer.as_deref() else {
            return Err(ShareDenied {
                peer: None,
                route: route_name.to_string(),
            });
        };
        let allowed = self
            .inner
            .shares
            .as_ref()
            .is_some_and(|s| s.is_shared(route_name, peer));
        if allowed {
            Ok(peer)
        } else {
            Err(ShareDenied {
                peer: Some(peer.to_string()),
                route: route_name.to_string(),
            })
        }
    }

    /// Inherent entry point so integration tests can call it directly
    /// without going through the [`Handler`] trait.
    pub async fn dispatch(&self, req: ServerRequest) -> ServerResponse {
        match self.handle_inner(req).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        }
    }

    async fn handle_inner(&self, mut req: ServerRequest) -> Result<ServerResponse, ForwardError> {
        let host = take_header(&req.headers, b"host")
            .ok_or(ForwardError::MissingHost)?
            .to_vec();
        let host_str =
            std::str::from_utf8(&host).map_err(|_| ForwardError::InvalidHost(host.clone()))?;
        // `P2clawHost::parse` doesn't strip ports; `Host` may carry
        // one. Bare IPv6 literals would fail the grammar regardless.
        let stripped = strip_port(host_str);
        let parsed = P2clawHost::parse(stripped, &self.inner.parent_domain)
            .map_err(ForwardError::Hostname)?;

        let route = self.resolve_route(&parsed).await?;
        debug!(
            route = %route.name,
            auth_methods = route.auth.len(),
            "forwarder: resolved route"
        );

        if route.is_private() {
            // Share gate: the caller must be an authenticated peer
            // the route is shared with. Visitor paths carry no peer
            // identity and are denied unconditionally. On success
            // the inbound `X-P2claw-*` strip + `X-P2claw-Peer`
            // inject replaces the OAuth identity-header machinery.
            let peer = self.check_share(&route.name).map_err(|denied| {
                warn!(
                    route = %route.name,
                    peer = denied.peer.as_deref().unwrap_or("<none>"),
                    "forwarder: private route denied"
                );
                ForwardError::NotShared(denied)
            })?;
            let peer = Bytes::from(peer.as_bytes().to_vec());
            oauth_mw::strip_identity_headers(&mut req);
            req.headers
                .push((Bytes::from_static(PEER_HEADER.as_bytes()), peer));
        } else {
            // Auth gate: strips inbound `X-P2claw-*` always; validates
            // only when `route.auth` is non-empty. Reject short-circuits
            // before any upstream dial. WS arrivals land on the
            // translator wire's WS_UPGRADE verb, dispatched by
            // [`crate::ws_forwarder::WsForwarder`] — this handler covers
            // plain-HTTP only.
            let _outcome = oauth_mw::apply(
                &mut req,
                &route.auth,
                self.inner.oauth.as_ref(),
                self.inner.identity.as_ref(),
            )
            .await
            .map_err(ForwardError::Auth)?;
        }

        let this = self.clone();
        let resp = timeout(FORWARD_TIMEOUT, this.forward_http(route.clone(), req))
            .await
            .map_err(|_| ForwardError::Timeout)??;
        Ok(resp)
    }

    async fn resolve_route(&self, parsed: &P2clawHost) -> Result<RouteRecord, ForwardError> {
        match parsed.app.as_deref() {
            Some(app) => {
                let r = self.inner.routes.get(app).await;
                r.ok_or_else(|| ForwardError::NoSuchApp(app.to_string()))
            }
            // Apex requests belong on the edge listing page; an apex
            // request landing on the agent is misrouted.
            None => Err(ForwardError::ApexAtAgent),
        }
    }

    /// Non-upgrade HTTP forward. `req.body` streams into the upstream.
    async fn forward_http(
        self,
        route: RouteRecord,
        req: ServerRequest,
    ) -> Result<ServerResponse, ForwardError> {
        // Private routes may point at a Unix socket; those skip
        // the loopback machinery and dial the socket per request.
        if let Some(sock) = unix_upstream_path(route.upstream_url()).map(str::to_string) {
            return self.forward_http_unix(route, sock, req).await;
        }
        let upstream = route.upstream_url();
        let host = upstream
            .host_str()
            .ok_or(ForwardError::BadUpstream("no host".into()))?
            .to_string();
        let port = upstream
            .port_or_known_default()
            .ok_or(ForwardError::BadUpstream("no port".into()))?;
        // Re-check loopback at dial time: registration may have
        // accepted but the runtime resolver could have diverged.
        // 502 (not 4xx) because the request itself was valid.
        self.check_loopback(&host, port).await.map_err(|e| {
            warn!(route = %route.name, host = %host, port, error = %e,
                  "forwarder: loopback re-check failed");
            ForwardError::LoopbackFailed(e)
        })?;

        let client = self.pool_for(&host, port).await;
        let hyper_req = build_hyper_request(&route, &host, port, req)?;

        let resp = client
            .request(hyper_req)
            .await
            .map_err(|e| ForwardError::Dial {
                route: route.name.clone(),
                upstream: format!("{host}:{port}"),
                err: e.to_string(),
            })?;

        Ok(stream_response(resp))
    }

    /// Forward to a `unix:` upstream: dial the socket and run one
    /// HTTP/1.1 exchange over it. No connection pool — private-route
    /// traffic is box-to-box service calls, and a per-request
    /// handshake on a local socket is cheap relative to the iroh hop
    /// that precedes it.
    async fn forward_http_unix(
        self,
        route: RouteRecord,
        sock: String,
        req: ServerRequest,
    ) -> Result<ServerResponse, ForwardError> {
        let dial_err = |err: String| ForwardError::Dial {
            route: route.name.clone(),
            upstream: format!("unix:{sock}"),
            err,
        };
        let stream = tokio::net::UnixStream::connect(&sock)
            .await
            .map_err(|e| dial_err(e.to_string()))?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, BoxBody>(io)
            .await
            .map_err(|e| dial_err(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Downgrade the built URI to origin-form: unlike the pooled
        // legacy client on the TCP path, a raw conn writes the URI
        // verbatim, and an absolute-form request line confuses
        // strict upstreams. The upstream sees the forwarded `Host`
        // header, never a URI authority.
        let mut hyper_req = build_hyper_request(&route, "localhost", 80, req)?;
        let origin_form: Uri = hyper_req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .parse()
            .map_err(|e| ForwardError::Build(format!("uri: {e}")))?;
        *hyper_req.uri_mut() = origin_form;
        let resp = sender
            .send_request(hyper_req)
            .await
            .map_err(|e| dial_err(e.to_string()))?;
        Ok(stream_response(resp))
    }
}

/// Translate a hyper upstream response into a streaming
/// [`ServerResponse`]. Shared by the TCP-pool and Unix-socket
/// forward paths.
fn stream_response(resp: http::Response<hyper::body::Incoming>) -> ServerResponse {
    let (parts, body) = resp.into_parts();
    let status = parts.status.as_u16();

    // Deferred-error oneshot: lets the streaming body signal a
    // late upstream failure (mid-body hyper error → upstream
    // crashed/RST) to the translator, which terminates the wire
    // stream with `Frame::Err { LOCAL_APP_DOWN }` instead of a
    // clean `Frame::End`. Without this, edge would translate the
    // truncated body into a clean axum response close and the
    // visitor couldn't distinguish "complete" from "truncated".
    // Sender dropped without sending → translator emits clean End.
    let (err_tx, err_rx) = tokio::sync::oneshot::channel::<(p2claw_translator::ErrorCode, Bytes)>();

    // Upstream trailers are drained, not forwarded: capturing them via
    // a oneshot threaded through the unfold state races the deferred-
    // error path on bodies that end without trailers.
    let body_stream = stream::unfold((body, Some(err_tx)), |(mut b, err_tx)| async move {
        loop {
            match b.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if data.is_empty() {
                            continue;
                        }
                        return Some((data, (b, err_tx)));
                    }
                    // Drain trailers so the conn returns to the pool.
                    debug!("forwarder: dropping upstream trailers");
                    continue;
                }
                Some(Err(e)) => {
                    debug!(error = %e, "forwarder: upstream body errored mid-stream — signalling LOCAL_APP_DOWN");
                    if let Some(tx) = err_tx {
                        let msg = format!("upstream body errored: {e}");
                        let _ = tx.send((
                            p2claw_translator::ErrorCode::LOCAL_APP_DOWN,
                            Bytes::from(msg.into_bytes()),
                        ));
                    }
                    return None;
                }
                None => return None,
            }
        }
    });

    let mut out = ServerResponse::new(status);
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out = out.header(
            Bytes::copy_from_slice(name.as_str().as_bytes()),
            Bytes::copy_from_slice(value.as_bytes()),
        );
    }
    out = out.with_body(OutgoingBody::stream(body_stream));
    out = out.with_deferred_error(err_rx);
    out
}

impl Forwarder {
    /// Loopback re-check with a short-TTL memo (both verdicts are
    /// cached; a rejected upstream re-resolves after the TTL). Cache
    /// miss resolves via `spawn_blocking` so getaddrinfo never
    /// blocks a runtime worker.
    async fn check_loopback(&self, host: &str, port: u16) -> Result<(), ValidateError> {
        let now = Instant::now();
        let key = (host.to_string(), port);
        {
            let cache = self
                .inner
                .loopback_cache
                .lock()
                .expect("loopback cache lock poisoned");
            if let Some(v) = cache.get(&key) {
                if now.duration_since(v.checked_at) < LOOPBACK_CACHE_TTL {
                    return v.result.clone();
                }
            }
        }
        let lookup_host = key.0.clone();
        let result =
            tokio::task::spawn_blocking(move || resolve_loopback(&lookup_host, port).map(drop))
                .await
                .unwrap_or_else(|e| {
                    Err(ValidateError::UpstreamResolve(
                        host.to_string(),
                        e.to_string(),
                    ))
                });
        self.inner
            .loopback_cache
            .lock()
            .expect("loopback cache lock poisoned")
            .insert(
                key,
                LoopbackVerdict {
                    checked_at: now,
                    result: result.clone(),
                },
            );
        result
    }

    async fn pool_for(&self, host: &str, port: u16) -> Pool {
        let key = format!("{host}:{port}");
        let mut guard = self.inner.pools.lock().await;
        if let Some(c) = guard.get(&key) {
            return c.clone();
        }
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        connector.set_nodelay(true);
        let client: Pool = LegacyClient::builder(TokioExecutor::new())
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .build(connector);
        guard.insert(key, client.clone());
        client
    }
}

impl p2claw_translator::Handler for Forwarder {
    fn handle(&self, req: ServerRequest) -> Pin<Box<dyn Future<Output = ServerResponse> + Send>> {
        let this = self.clone();
        Box::pin(async move { this.dispatch(req).await })
    }
}

/// A private-route request that failed the share check. `peer` is
/// `None` when the transport carried no peer identity at all
/// (visitor paths).
#[derive(Debug)]
pub(crate) struct ShareDenied {
    pub peer: Option<String>,
    pub route: String,
}

#[derive(Debug, Error)]
enum ForwardError {
    #[error("request missing Host header")]
    MissingHost,
    #[error("request Host header is not UTF-8")]
    InvalidHost(Vec<u8>),
    #[error("hostname parse: {0}")]
    Hostname(UrlParseError),
    #[error("no such app: {0}")]
    NoSuchApp(String),
    #[error("apex request reached the agent (should be served by edge listing page)")]
    ApexAtAgent,
    #[error("upstream dial for route {route} → {upstream} failed: {err}")]
    Dial {
        route: String,
        upstream: String,
        err: String,
    },
    #[error("forward timed out after {}s", FORWARD_TIMEOUT.as_secs())]
    Timeout,
    #[error("loopback re-check failed at forward time: {0}")]
    LoopbackFailed(ValidateError),
    #[error("malformed upstream in route table: {0}")]
    BadUpstream(String),
    #[error("could not build upstream request: {0}")]
    Build(String),
    /// OAuth middleware rejected (401) or the auth backend is
    /// unavailable (503). The middleware owns the response shape;
    /// [`ForwardError::into_response`] delegates to it.
    #[error("oauth middleware: {0}")]
    Auth(#[from] oauth_mw::MiddlewareError),
    /// Private route without a matching share → 403 `not_shared`.
    #[error("private route {} denied for peer {:?}", .0.route, .0.peer)]
    NotShared(ShareDenied),
}

impl ForwardError {
    fn into_response(self) -> ServerResponse {
        // Auth errors delegate the full response shape (status,
        // `P2claw-Auth-Required` header, body) to the middleware.
        // Early-return on `Auth` so the match below can borrow.
        if let ForwardError::Auth(e) = self {
            return e.into_response();
        }
        if let ForwardError::NotShared(denied) = &self {
            // Indistinguishable from an unknown app — same status and
            // body shape as `NoSuchApp` — so a peer probing Host
            // values can't use a 403/404 differential as an oracle to
            // confirm private route names. The denial specifics are
            // in the structured log on the box.
            return ServerResponse::new(404).with_body(OutgoingBody::once(Bytes::from(format!(
                "no such app: {}\n",
                denied.route
            ))));
        }
        let (status, body) = match &self {
            ForwardError::MissingHost | ForwardError::InvalidHost(_) => (
                400,
                "bad request: missing or malformed Host header\n".to_string(),
            ),
            ForwardError::Hostname(e) => (400, format!("bad request: {e}\n")),
            ForwardError::NoSuchApp(name) => (404, format!("no such app: {name}\n")),
            ForwardError::ApexAtAgent => (
                400,
                "bad request: apex requests are served by the edge listing page, \
                 not the agent\n"
                    .to_string(),
            ),
            ForwardError::Dial {
                route,
                upstream,
                err,
            } => (
                502,
                format!(
                    "bad gateway: could not reach upstream {upstream} \
                     for route {route}: {err}\n"
                ),
            ),
            ForwardError::Timeout => (
                502,
                format!(
                    "bad gateway: upstream did not complete within {}s\n",
                    FORWARD_TIMEOUT.as_secs()
                ),
            ),
            ForwardError::LoopbackFailed(e) => (
                502,
                format!("bad gateway: upstream no longer loopback: {e}\n"),
            ),
            ForwardError::BadUpstream(msg) => (
                502,
                format!("bad gateway: malformed upstream in route table: {msg}\n"),
            ),
            ForwardError::Build(msg) => (502, format!("bad gateway: {msg}\n")),
            // Unreachable — handled above by the early-returns.
            ForwardError::Auth(_) | ForwardError::NotShared(_) => unreachable!(),
        };
        ServerResponse::new(status)
            .header(
                Bytes::from_static(b"content-type"),
                Bytes::from_static(b"text/plain; charset=utf-8"),
            )
            .with_body(OutgoingBody::once(Bytes::from(body)))
    }
}

fn build_hyper_request(
    _route: &RouteRecord,
    upstream_host: &str,
    upstream_port: u16,
    req: ServerRequest,
) -> Result<Request<BoxBody>, ForwardError> {
    let method = std::str::from_utf8(&req.method)
        .map_err(|_| ForwardError::Build("non-utf8 method".into()))?;
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|e| ForwardError::Build(format!("method: {e}")))?;
    let path =
        std::str::from_utf8(&req.path).map_err(|_| ForwardError::Build("non-utf8 path".into()))?;

    // Absolute URI because the pooled legacy client requires
    // scheme+authority as INPUT (it emits origin-form on the wire
    // itself). The raw-conn UDS path must downgrade to origin-form
    // before sending — see the unix branch.
    let uri: Uri = format!("http://{upstream_host}:{upstream_port}{path}")
        .parse()
        .map_err(|e| ForwardError::Build(format!("uri: {e}")))?;

    // Adapt the translator's IncomingBody to hyper directly — chunks
    // are polled in `poll_frame`, no pump task or channel per request.
    let body = IncomingHyperBody {
        body: req.body,
        data_done: false,
    }
    .boxed();

    let mut builder = Request::builder().method(method).uri(uri);

    // Reverse-proxy posture: forward the visitor's `Host` verbatim
    // so the upstream sees what was typed (matches Caddy /
    // Cloudflare Tunnel / Tailscale Funnel defaults). Falls back to
    // `upstream_host:upstream_port` only if no `Host` arrived —
    // defensive, since the caller already rejects `MissingHost`.
    let host_value: String = req
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(b"host"))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{upstream_host}:{upstream_port}"));

    let headers = builder
        .headers_mut()
        .ok_or_else(|| ForwardError::Build("could not access headers".into()))?;
    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(&host_value)
            .map_err(|e| ForwardError::Build(format!("host: {e}")))?,
    );

    for (name, value) in req.headers {
        let Ok(name_str) = std::str::from_utf8(&name) else {
            continue;
        };
        if name_str.eq_ignore_ascii_case("host") {
            continue;
        }
        // Non-WS path uses the full hop-by-hop list (including
        // `connection`) — hyper manages connection-level headers
        // itself and rejecting them here keeps the inbound and
        // outbound proxies consistent.
        if is_hop_by_hop(name_str) {
            continue;
        }
        let Ok(hn) = HeaderName::from_bytes(name_str.as_bytes()) else {
            continue;
        };
        let Ok(hv) = HeaderValue::from_bytes(&value) else {
            continue;
        };
        append_header(headers, hn, hv);
    }

    builder
        .body(body)
        .map_err(|e| ForwardError::Build(format!("body: {e}")))
}

fn append_header(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) {
    headers.append(name, value);
}

/// RFC 7230 §6.1 hop-by-hop headers; never forwarded across a proxy.
fn is_hop_by_hop(name: &str) -> bool {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ];
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Strip a `:port` suffix from a `Host` value before parsing. Only
/// strips when the chars after the last `:` are all ASCII digits,
/// so IPv6 literals fall through to the parser unchanged.
fn strip_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(i) if host[i + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..i],
        _ => host,
    }
}

fn take_header<'a>(headers: &'a [(Bytes, Bytes)], wanted: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(wanted))
        .map(|(_, v)| v.as_ref())
}

/// Adapts the translator's [`IncomingBody`] to a hyper request body.
/// Chunks are polled straight through; once the body drains, visitor
/// trailers (`Frame::Trailers` on the translator wire) surface as a
/// hyper trailers frame so the upstream sees them as HTTP/1.1
/// chunked trailers. Bad-byte trailer entries are skipped, matching
/// the response-side posture of dropping individual malformed
/// headers rather than failing the whole request.
struct IncomingHyperBody {
    body: IncomingBody,
    data_done: bool,
}

impl hyper::body::Body for IncomingHyperBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<HyperFrame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if !this.data_done {
            match this.body.poll_next_chunk(cx) {
                Poll::Ready(Some(chunk)) => return Poll::Ready(Some(Ok(HyperFrame::data(chunk)))),
                Poll::Ready(None) => this.data_done = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        match this.body.poll_trailers(cx) {
            Poll::Ready(Some(headers)) => {
                let mut map = HeaderMap::new();
                for (name, value) in headers {
                    let Ok(hn) = HeaderName::from_bytes(&name) else {
                        debug!("forwarder: skipping malformed request trailer name");
                        continue;
                    };
                    let Ok(hv) = HeaderValue::from_bytes(&value) else {
                        debug!("forwarder: skipping malformed request trailer value");
                        continue;
                    };
                    map.append(hn, hv);
                }
                if map.is_empty() {
                    Poll::Ready(None)
                } else {
                    // `poll_trailers` is idempotent — the next poll
                    // returns `Ready(None)`, ending the body.
                    Poll::Ready(Some(Ok(HyperFrame::trailers(map))))
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_list() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
    }
}
