//! p2claw iroh-client library.
//!
//! Provides [`PeerClient`] — an async handle that opens one peer
//! connection (Iroh QUIC + ALPN `p2claw/1`) to a box and speaks the
//! peer wire protocol on it via [`p2claw_translator`]. End-user CLI
//! access goes through MagicDNS + `curl`; this lib backs the
//! programmatic path (notably the agent's outbound peer-HTTP).
//!
//! # Example
//!
//! ```no_run
//! use p2claw_iroh_client::{PeerClient, Request};
//!
//! # async fn _example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = PeerClient::connect("recipes-blue-otter-7392.p2claw.com").await?;
//! let resp = client.request(Request::get("/api/items")).await?;
//! let body = resp.collect_body().await;
//! println!("{}", String::from_utf8_lossy(&body));
//! # Ok(())
//! # }
//! ```

#![deny(rust_2018_idioms)]

pub mod connect;
pub mod error;
pub mod transport;
pub mod url;

use std::time::Duration;

use bytes::Bytes;
use iroh::Endpoint;
use p2claw_identity::PeerId;
use p2claw_translator::{ClientConnection, ClientRequest, IncomingBody, OutgoingBody};

pub use error::PeerClientError;
pub use iroh;
pub use transport::P2CLAW_ALPN;
pub use url::{P2clawHost, P2clawUrl, UrlParseError, DEFAULT_PARENT_DOMAIN};

/// HTTP method helpers. The wire protocol treats methods as opaque
/// bytes, so these constants exist for ergonomics only — custom
/// methods are valid.
pub struct Method;

impl Method {
    pub const GET: &'static [u8] = b"GET";
    pub const POST: &'static [u8] = b"POST";
    pub const PUT: &'static [u8] = b"PUT";
    pub const DELETE: &'static [u8] = b"DELETE";
    pub const PATCH: &'static [u8] = b"PATCH";
    pub const HEAD: &'static [u8] = b"HEAD";
    pub const OPTIONS: &'static [u8] = b"OPTIONS";
}

/// A request to send via [`PeerClient::request`]. Wraps
/// [`p2claw_translator::ClientRequest`] with a small builder for
/// discoverability.
#[derive(Debug)]
pub struct Request {
    inner: ClientRequest,
}

impl Request {
    pub fn get(path: impl Into<Bytes>) -> Self {
        Self {
            inner: ClientRequest::get(path),
        }
    }

    pub fn post(path: impl Into<Bytes>, body: impl Into<Bytes>) -> Self {
        Self {
            inner: ClientRequest::post(path, OutgoingBody::once(body)),
        }
    }

    /// Fresh request with an arbitrary method + path + body.
    pub fn new(method: impl Into<Bytes>, path: impl Into<Bytes>, body: OutgoingBody) -> Self {
        Self {
            inner: ClientRequest {
                method: method.into(),
                path: path.into(),
                headers: Vec::new(),
                body,
            },
        }
    }

    pub fn header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.inner.headers.push((name.into(), value.into()));
        self
    }

    /// Consume and return the inner translator request.
    pub fn into_inner(self) -> ClientRequest {
        self.inner
    }
}

/// A response returned by [`PeerClient::request`]. Wraps
/// [`p2claw_translator::ClientResponse`]; body streams in via
/// [`Response::next_chunk`] or collect-all via
/// [`Response::collect_body`].
#[derive(Debug)]
pub struct Response {
    status: u16,
    headers: Vec<(Bytes, Bytes)>,
    body: IncomingBody,
}

impl Response {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &[(Bytes, Bytes)] {
        &self.headers
    }

    pub async fn next_chunk(&mut self) -> Option<Bytes> {
        self.body.next_chunk().await
    }

    pub async fn collect_body(self) -> Bytes {
        self.body.collect().await
    }
}

/// A handle to one open peer-HTTP connection to a box.
///
/// Created by [`PeerClient::connect`] or [`PeerClient::connect_with`].
/// Safe to share across tasks; methods take `&self`. Drop closes the
/// underlying QUIC connection.
pub struct PeerClient {
    peer_id: PeerId,
    tx: ClientConnection,
    /// Peer-label hostname the client was connected against — the
    /// value to inject as the `Host` request header when the caller
    /// didn't set one explicitly. Reconstructed from the parsed URL
    /// as `[app "-"] alias "." parent`. The forwarder routes on
    /// `Host`; auto-populating mirrors what stock HTTP clients do.
    host: Bytes,
    /// Held for the lifetime of the client so the Iroh connection and
    /// endpoint outlive every in-flight request. Must drop AFTER `tx`
    /// (which runs the reader/writer tasks and will stop cleanly when
    /// its stream halves EOF — those halves are owned by the spawned
    /// tasks, not this struct).
    _holder: transport::TransportHolder,
}

/// Options for [`PeerClient::connect_with`].
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Parent domain to parse URLs against. Defaults to
    /// [`DEFAULT_PARENT_DOMAIN`].
    pub parent_domain: String,
    /// Coordination service URL. `None` → derived from
    /// [`parent_domain`](Self::parent_domain) as `https://coord.<domain>`.
    pub coord_url: Option<String>,
    /// Timeout applied to the coord `/v1/connect` call and the Iroh
    /// dial. Individual requests on the resulting connection are not
    /// bounded by this.
    pub timeout: Duration,
    /// Pre-built Iroh endpoint to dial with. When `None` (the default)
    /// a fresh endpoint is created internally via
    /// [`transport::build_endpoint`]. Exists mainly for tests that
    /// want to run the client fully offline (loopback-only, no n0
    /// DNS / relay usage) — supply an [`Endpoint`] built with e.g.
    /// `iroh::endpoint::presets::Minimal` + `RelayMode::Disabled`.
    pub endpoint: Option<Endpoint>,
    /// Optional iroh-relay URL. When `None`, the
    /// internally-built endpoint is direct-only. When `Some(url)`,
    /// the endpoint relays through that URL. Ignored if
    /// `endpoint` is supplied (the caller is responsible for the
    /// pre-built endpoint's relay config).
    pub relay_url: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            parent_domain: DEFAULT_PARENT_DOMAIN.to_string(),
            coord_url: None,
            timeout: Duration::from_secs(30),
            endpoint: None,
            relay_url: None,
        }
    }
}

impl PeerClient {
    /// Convenience: connect using the default [`ClientOptions`].
    ///
    /// `target` may be a full URL or a bare hostname:
    /// `blue-otter-7392.p2claw.com` (apex "listing page" form) or
    /// `recipes-blue-otter-7392.p2claw.com` (app-plus-alias form).
    pub async fn connect(target: impl AsRef<str>) -> Result<Self, PeerClientError> {
        Self::connect_with(target, ClientOptions::default()).await
    }

    /// Connect with explicit options.
    ///
    /// `target` accepts anything that derefs to `&str`: a full URL
    /// (`https://recipes-blue-otter-7392.p2claw.com/`) or a bare
    /// hostname (`recipes-blue-otter-7392.p2claw.com`). `String`,
    /// `&String`, `&str` all work.
    pub async fn connect_with(
        target: impl AsRef<str>,
        opts: ClientOptions,
    ) -> Result<Self, PeerClientError> {
        let target = target.as_ref();
        let normalised = if target.starts_with("https://") || target.starts_with("http://") {
            target.to_string()
        } else {
            format!("https://{target}/")
        };
        let parsed = P2clawUrl::parse(&normalised, &opts.parent_domain)?;

        let coord_url = opts
            .coord_url
            .clone()
            .unwrap_or_else(|| connect::default_coord_url(&opts.parent_domain));

        let timeout = opts.timeout;
        let resp = tokio::time::timeout(
            timeout,
            connect::connect(
                &coord_url,
                &parsed.alias_label,
                parsed.app.as_deref(),
                timeout,
            ),
        )
        .await
        .map_err(|_| PeerClientError::Timeout {
            secs: timeout.as_secs(),
        })??;

        tracing::debug!(peer = %resp.peer_id, "coord resolved peer_id");

        // No client-side prefix-binding check: the haiku alias
        // carries no cryptographic content. Iroh's QUIC handshake
        // authenticates the remote NodeId via its TLS cert, so the
        // dial below fails if coord handed us a mismatched peer_id.
        let peer_id = PeerId::from_z32(&resp.peer_id)
            .map_err(|e| PeerClientError::Coord(format!("invalid peer_id: {e}")))?;

        let endpoint_addr = transport::endpoint_addr_from_response(&resp)?;
        let endpoint = match opts.endpoint {
            Some(e) => e,
            None => transport::build_endpoint(opts.relay_url.as_deref()).await?,
        };

        let (holder, stream) =
            tokio::time::timeout(timeout, transport::dial(endpoint, endpoint_addr))
                .await
                .map_err(|_| PeerClientError::Timeout {
                    secs: timeout.as_secs(),
                })??;

        let tx = ClientConnection::spawn(stream);

        // Host header the forwarder routes on — see the `host` field
        // doc. The app label travels verbatim if present.
        let host = match &parsed.app {
            Some(app) => format!("{app}-{}.{}", parsed.alias_label, parsed.parent_domain),
            None => format!("{}.{}", parsed.alias_label, parsed.parent_domain),
        };

        Ok(Self {
            peer_id,
            tx,
            host: Bytes::from(host),
            _holder: holder,
        })
    }

    /// The box's peer_id.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Issue a request on this connection. Resolves once the response
    /// headers (RES frame) arrive; the body streams in afterwards.
    ///
    /// The `Host` header is injected from the URL the client was
    /// connected against unless the caller already set one (in which
    /// case we pass the caller's value through unchanged — useful for
    /// tests that want to assert forwarder-side host parsing directly).
    pub async fn request(&self, req: Request) -> Result<Response, PeerClientError> {
        let mut inner = req.into_inner();
        if !has_host_header(&inner.headers) {
            inner
                .headers
                .insert(0, (Bytes::from_static(b"host"), self.host.clone()));
        }
        let resp = self.tx.request(inner).await?;
        Ok(Response {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }

    /// Open a WebSocket session on this connection (the translator
    /// wire's WS_UPGRADE verb). The `Host` header is injected from
    /// the dial target unless the caller already set one, mirroring
    /// [`request`](Self::request).
    pub async fn open_websocket(
        &self,
        mut req: p2claw_translator::ClientWsUpgrade,
    ) -> Result<p2claw_translator::WsConnection, PeerClientError> {
        if !has_host_header(&req.headers) {
            req.headers
                .insert(0, (Bytes::from_static(b"host"), self.host.clone()));
        }
        Ok(self.tx.open_websocket(req).await?)
    }
}

/// Case-insensitive search for `Host` on outgoing request headers.
/// Peer-HTTP header names are ASCII, so a case-fold suffices.
fn has_host_header(headers: &[(Bytes, Bytes)]) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"host"))
}
