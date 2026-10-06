//! Iroh QUIC listener — the box-side server for native peer
//! connections.
//!
//! Builds an [`iroh::Endpoint`] keyed off the agent's Ed25519 seed so
//! the iroh `EndpointId` is byte-identical to the p2claw `peer_id`,
//! advertises ALPN `p2claw/1`, and accepts inbound connections. For
//! each connection we loop accepting bidirectional streams and feed
//! every stream to [`p2claw_translator::serve`] with the agent-wide
//! [`Forwarder`].
//!
//! While the endpoint runs, it also publishes its current network
//! addresses (relay URL + direct UDP socket addrs) on a `watch`
//! channel in the wire format coordination expects:
//! `"relay:<url>"` and `"udp:<ip>:<port>"`. The control-connection
//! task reads that channel to populate `Hello.iroh_addrs` and emit
//! `addrs_update` frames whenever addresses change.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures_util::StreamExt;
use iroh::{Endpoint, EndpointAddr, TransportAddr, Watcher};
use thiserror::Error;
use tokio::io::join;
use tokio::sync::watch;
use tracing::{debug, info};

use p2claw_translator::Handler;
// `Forwarder` + `SecretKey` + `presets` are only referenced from
// the test module (the production path builds the endpoint in
// `main.rs::cmd_run` and passes it to `serve_endpoint`).

/// ALPN identifier for p2claw's native transport. Must match
/// `p2claw_iroh_client::transport::P2CLAW_ALPN`.
pub const P2CLAW_ALPN: &[u8] = b"p2claw/1";

#[derive(Debug, Error)]
pub enum IrohListenerError {}

/// Transport of an iroh connection's selected network path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrohTransport {
    Unknown,
    Direct,
    Relay,
}

impl IrohTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            IrohTransport::Unknown => "unknown",
            IrohTransport::Direct => "direct",
            IrohTransport::Relay => "relay",
        }
    }
}

/// One active iroh connection, as reported by `GET /v1/sessions`.
/// Metadata only — no addresses.
#[derive(Debug, Clone)]
pub struct IrohSessionSnapshot {
    pub id: String,
    pub transport: IrohTransport,
    pub age_secs: u64,
}

/// Active inbound iroh connections, for `GET /v1/sessions`.
///
/// One entry per accepted QUIC connection — inserted when
/// `handle_connection` starts, removed when it returns (RAII guard,
/// so error paths deregister too). Note the caveat this implies for
/// the sessions API: an iroh connection is a *connection*, not a
/// visitor. The edge tunnel holds one pooled connection that carries
/// traffic for many visitors; a native client is one connection per
/// device.
#[derive(Default)]
pub struct IrohSessionRegistry {
    next_id: AtomicU64,
    conns: std::sync::Mutex<HashMap<u64, IrohConnEntry>>,
}

struct IrohConnEntry {
    conn: iroh::endpoint::Connection,
    started_at: Instant,
}

/// Deregisters its connection from the registry on drop.
pub struct IrohSessionGuard {
    registry: Arc<IrohSessionRegistry>,
    id: u64,
}

impl Drop for IrohSessionGuard {
    fn drop(&mut self) {
        self.registry
            .conns
            .lock()
            .expect("iroh session registry mutex poisoned")
            .remove(&self.id);
    }
}

impl IrohSessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a live connection; the returned guard deregisters it
    /// on drop.
    fn track(self: &Arc<Self>, conn: iroh::endpoint::Connection) -> IrohSessionGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns
            .lock()
            .expect("iroh session registry mutex poisoned")
            .insert(
                id,
                IrohConnEntry {
                    conn,
                    started_at: Instant::now(),
                },
            );
        IrohSessionGuard {
            registry: self.clone(),
            id,
        }
    }

    /// Snapshot of the active connections. Transport is sampled live
    /// from each connection's selected network path, so a connection
    /// that migrates between relay and direct reports its current
    /// path.
    pub fn list_sessions(&self) -> Vec<IrohSessionSnapshot> {
        self.conns
            .lock()
            .expect("iroh session registry mutex poisoned")
            .iter()
            .map(|(id, entry)| IrohSessionSnapshot {
                id: format!("iroh-{id}"),
                transport: conn_transport(&entry.conn),
                age_secs: entry.started_at.elapsed().as_secs(),
            })
            .collect()
    }
}

/// Best-effort transport of a connection's selected path: `Relay`
/// if the path goes through a relay server, `Direct` for an IP path,
/// `Unknown` when no path is selected (yet).
fn conn_transport(conn: &iroh::endpoint::Connection) -> IrohTransport {
    let paths = conn.paths();
    let selected_is_relay = paths.iter().find(|p| p.is_selected()).map(|p| p.is_relay());
    match selected_is_relay {
        Some(true) => IrohTransport::Relay,
        Some(false) => IrohTransport::Direct,
        None => IrohTransport::Unknown,
    }
}

// There's no convenience `run(seed, addrs_tx, shutdown, forwarder)`
// entry point that builds its own endpoint internally. The shape
// is: `main.rs::cmd_run` builds ONE Iroh `Endpoint` up-front and
// clones it into both this module's `serve_endpoint` (inbound
// peer-HTTP via `P2CLAW_ALPN`) and `coord_conn::run` (outbound
// coord dial via `ALPN_COORD_V1`). One UDP socket, one identity.
// Add the convenience wrapper back only if a single-purpose
// consumer ever needs it.

// `serve_endpoint` is generic over `H: Handler + Clone` so the real
// agent passes a [`Forwarder`] (Clone; internal Arc); tests can pass
// any other `Handler + Clone` (see `iroh_roundtrip_via_stub_handler`).

/// Serve translator requests on an already-built [`Endpoint`]. The
/// endpoint must already advertise ALPN [`P2CLAW_ALPN`].
///
/// Owns the endpoint for the duration of the call and closes it on
/// shutdown. Spawns one background task that mirrors the endpoint's
/// current address set onto `addrs_tx` in the wire format the
/// control protocol expects.
pub async fn serve_endpoint<H>(
    endpoint: Endpoint,
    addrs_tx: watch::Sender<Vec<String>>,
    shutdown: watch::Receiver<bool>,
    handler: H,
) -> Result<(), IrohListenerError>
where
    H: Handler + Clone,
{
    serve_endpoint_with_ws(endpoint, addrs_tx, shutdown, handler, None, None).await
}

/// Variant of [`serve_endpoint`] that wires a [`WsHandler`] into the
/// translator's WS-upgrade verb. Edge-tunneled WebSocket arrivals
/// land on this handler; plain HTTP traffic still falls through to
/// the [`Handler`].
pub async fn serve_endpoint_with_ws<H>(
    endpoint: Endpoint,
    addrs_tx: watch::Sender<Vec<String>>,
    shutdown: watch::Receiver<bool>,
    handler: H,
    ws_handler: Option<std::sync::Arc<dyn p2claw_translator::WsHandler>>,
    sessions: Option<Arc<IrohSessionRegistry>>,
) -> Result<(), IrohListenerError>
where
    H: Handler + Clone,
{
    serve_endpoint_per_peer(
        endpoint,
        addrs_tx,
        shutdown,
        move |_remote| (handler.clone(), ws_handler.clone()),
        sessions,
    )
    .await
}

/// Variant of [`serve_endpoint_with_ws`] that builds the handler
/// pair per accepted connection, from the authenticated remote
/// `EndpointId`. Production uses this to bind the connection's peer
/// identity into the [`crate::forwarder::Forwarder`] (via
/// `Forwarder::for_peer`) so private-route enforcement can
/// attribute every request; the simpler entry points above ignore
/// the identity and reuse one handler for all peers.
pub async fn serve_endpoint_per_peer<H, F>(
    endpoint: Endpoint,
    addrs_tx: watch::Sender<Vec<String>>,
    mut shutdown: watch::Receiver<bool>,
    make_session: F,
    sessions: Option<Arc<IrohSessionRegistry>>,
) -> Result<(), IrohListenerError>
where
    H: Handler + Clone,
    F: Fn(iroh::EndpointId) -> (H, Option<std::sync::Arc<dyn p2claw_translator::WsHandler>>)
        + Send
        + Sync
        + Clone
        + 'static,
{
    info!(
        endpoint_id = %endpoint.id().to_z32(),
        bound = ?endpoint.bound_sockets(),
        "iroh: endpoint serving"
    );

    // Spawn a task that watches the endpoint's address set and
    // publishes the wire-format strings.
    let watcher_handle = {
        let endpoint = endpoint.clone();
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            // Push the initial value immediately (will likely be just
            // direct sockets; relay arrives after net-report finishes).
            let initial = encode_addrs(&endpoint.watch_addr().get());
            let _ = addrs_tx.send(initial);

            let mut stream = endpoint.watch_addr().stream();
            loop {
                tokio::select! {
                    next = stream.next() => match next {
                        Some(addr) => {
                            let encoded = encode_addrs(&addr);
                            debug!(?encoded, "iroh: address set updated");
                            // send_if_modified avoids spurious wakeups
                            // when iroh re-publishes an unchanged set.
                            addrs_tx.send_if_modified(|cur| {
                                if *cur != encoded {
                                    *cur = encoded;
                                    true
                                } else {
                                    false
                                }
                            });
                        }
                        None => return,
                    },
                    _ = shutdown.changed() => return,
                }
            }
        })
    };

    let result = accept_loop(&endpoint, &mut shutdown, make_session, sessions).await;
    endpoint.close().await;
    watcher_handle.abort();
    let _ = watcher_handle.await;
    result
}

async fn accept_loop<H, F>(
    endpoint: &Endpoint,
    shutdown: &mut watch::Receiver<bool>,
    make_session: F,
    sessions: Option<Arc<IrohSessionRegistry>>,
) -> Result<(), IrohListenerError>
where
    H: Handler + Clone,
    F: Fn(iroh::EndpointId) -> (H, Option<std::sync::Arc<dyn p2claw_translator::WsHandler>>)
        + Send
        + Sync
        + Clone
        + 'static,
{
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    info!("iroh: endpoint accept loop closed");
                    return Ok(());
                };
                let accepting = match incoming.accept() {
                    Ok(a) => a,
                    Err(e) => {
                        debug!(error = %e, "iroh: incoming.accept() rejected");
                        continue;
                    }
                };
                let make_session = make_session.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    match accepting.await {
                        Ok(conn) => {
                            // Handler construction happens AFTER the
                            // QUIC handshake, so the remote id fed to
                            // the factory is authenticated.
                            let (handler, ws_handler) = make_session(conn.remote_id());
                            handle_connection(conn, handler, ws_handler, sessions).await
                        }
                        Err(e) => debug!(error = %e, "iroh: accepting handshake failed"),
                    }
                });
            }
            _ = shutdown.changed() => {
                info!("iroh: shutdown");
                return Ok(());
            }
        }
    }
}

async fn handle_connection<H>(
    conn: iroh::endpoint::Connection,
    handler: H,
    ws_handler: Option<std::sync::Arc<dyn p2claw_translator::WsHandler>>,
    sessions: Option<Arc<IrohSessionRegistry>>,
) where
    H: Handler + Clone,
{
    let remote = conn.remote_id();
    info!(peer = %remote.fmt_short(), "iroh: connection accepted");
    // Registered for the connection's lifetime; the guard
    // deregisters on every exit path.
    let _session = sessions.as_ref().map(|r| r.track(conn.clone()));
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let stream = join(recv, send);
                let handler = handler.clone();
                let ws_handler = ws_handler.clone();
                tokio::spawn(async move {
                    let options = p2claw_translator::ServeOptions {
                        ws_handler,
                        ..Default::default()
                    };
                    if let Err(e) = p2claw_translator::serve_with(stream, handler, options).await {
                        debug!(error = %e, "iroh: translator session ended with error");
                    }
                });
            }
            Err(e) => {
                debug!(peer = %remote.fmt_short(), error = %e, "iroh: connection ended");
                return;
            }
        }
    }
}

/// Convert an [`EndpointAddr`] into the `Vec<String>` wire-format the
/// control protocol uses. Sorted for stable equality (so spurious
/// `addrs_update` frames don't fire on re-orderings).
fn encode_addrs(addr: &EndpointAddr) -> Vec<String> {
    let mut out: Vec<String> = addr
        .addrs
        .iter()
        .filter_map(|a| match a {
            TransportAddr::Relay(url) => Some(format!("relay:{url}")),
            TransportAddr::Ip(socket) => Some(format!("udp:{socket}")),
            // `Custom` is iroh-internal; we don't expose it on the
            // control protocol.
            _ => None,
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::presets;
    use iroh::SecretKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    use std::future::Future;
    use std::pin::Pin;

    use bytes::Bytes;
    use iroh::RelayMode;
    use p2claw_translator::{
        ClientConnection, ClientRequest, Handler, OutgoingBody, ServerRequest, ServerResponse,
    };

    /// Inline handler used by the iroh loopback roundtrip test.
    /// We don't exercise the real [`Forwarder`] here — that has its
    /// own hyper-backed tests in `forwarder.rs` and
    /// `tests/forwarder_e2e.rs`; this test just proves the iroh
    /// transport end of the pipe still wires into
    /// [`p2claw_translator::serve`].
    #[derive(Clone)]
    struct EchoHandler;
    impl Handler for EchoHandler {
        fn handle(
            &self,
            req: ServerRequest,
        ) -> Pin<Box<dyn Future<Output = ServerResponse> + Send>> {
            Box::pin(async move {
                let path = String::from_utf8_lossy(&req.path).into_owned();
                let method = String::from_utf8_lossy(&req.method).into_owned();
                let body = format!("method={method} path={path}\n");
                ServerResponse::new(200)
                    .header(
                        Bytes::from_static(b"content-type"),
                        Bytes::from_static(b"text/plain"),
                    )
                    .with_body(OutgoingBody::once(Bytes::from(body)))
            })
        }
    }

    #[test]
    fn encode_addrs_emits_sorted_relay_and_udp_strings() {
        let id = SecretKey::generate().public();
        let url = iroh::RelayUrl::from_str("https://relay.example.net/").unwrap();
        let v4: SocketAddr = "198.51.100.7:54321".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:54321".parse().unwrap();

        let addr = EndpointAddr::from_parts(
            id,
            [
                TransportAddr::Ip(v4),
                TransportAddr::Relay(url),
                TransportAddr::Ip(v6),
            ],
        );

        let got = encode_addrs(&addr);
        let mut expected = vec![
            "relay:https://relay.example.net/".to_string(),
            "udp:198.51.100.7:54321".to_string(),
            "udp:[2001:db8::1]:54321".to_string(),
        ];
        expected.sort();
        assert_eq!(got, expected);
    }

    #[test]
    fn encode_addrs_empty_when_no_addresses() {
        let id = SecretKey::generate().public();
        let addr = EndpointAddr::from_parts(id, []);
        assert!(encode_addrs(&addr).is_empty());
    }

    #[test]
    fn iroh_secret_key_derives_p2claw_peer_id() {
        // The whole reason we feed our seed into iroh: the iroh
        // `EndpointId` z-base-32 must equal the p2claw `peer_id`
        // z-base-32 so coord can use one identifier across both
        // protocols.
        let p2sk = p2claw_identity::SigningKey::generate();
        let seed = p2sk.seed();
        let isk = SecretKey::from_bytes(&seed);
        assert_eq!(isk.public().to_z32(), p2sk.peer_id().to_z32());
    }

    /// Build a sandboxed iroh endpoint suitable for in-process
    /// integration testing: minimal preset (just a crypto provider),
    /// `RelayMode::Disabled` (no n0 relay or DNS lookups), and
    /// p2claw's ALPN. Optional `secret_key` lets the caller pin the
    /// `EndpointId`.
    async fn test_endpoint(secret_key: Option<SecretKey>) -> Endpoint {
        let mut builder = Endpoint::builder(presets::Minimal)
            .alpns(vec![P2CLAW_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled);
        if let Some(sk) = secret_key {
            builder = builder.secret_key(sk);
        }
        builder.bind().await.expect("bind test endpoint")
    }

    /// End-to-end: spin up a server endpoint serving the stub
    /// handler, dial it from a fresh client endpoint, send a
    /// translator GET, and check the response. No external network
    /// required — both sides run with `RelayMode::Disabled` and dial
    /// via the loopback-bound UDP port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn iroh_roundtrip_via_stub_handler() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .try_init();

        let server_seed = p2claw_identity::SigningKey::generate().seed();
        let server_sk = SecretKey::from_bytes(&server_seed);
        let server_id = server_sk.public();

        let server_endpoint = test_endpoint(Some(server_sk)).await;
        let bound = server_endpoint.bound_sockets();
        let port = bound
            .iter()
            .find_map(|s| if s.is_ipv4() { Some(s.port()) } else { None })
            .expect("server should bind an IPv4 socket");
        let dial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        let (addrs_tx, _addrs_rx) = watch::channel::<Vec<String>>(Vec::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        let server_handle = tokio::spawn({
            let endpoint = server_endpoint.clone();
            async move { serve_endpoint(endpoint, addrs_tx, sd_rx, EchoHandler).await }
        });

        // Client side.
        let client_endpoint = test_endpoint(None).await;
        let server_addr = EndpointAddr::from_parts(server_id, [TransportAddr::Ip(dial_addr)]);

        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            client_endpoint.connect(server_addr, P2CLAW_ALPN),
        )
        .await
        .expect("dial timed out")
        .expect("dial failed");

        let (send, recv) = connection.open_bi().await.expect("open_bi");
        let stream = join(recv, send);
        let client = ClientConnection::spawn(stream);

        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.request(ClientRequest::get(Bytes::from_static(b"/health"))),
        )
        .await
        .expect("request timed out")
        .expect("request errored");

        assert_eq!(resp.status, 200, "stub handler should return 200");
        let body = resp.body.collect().await;
        let body_str = std::str::from_utf8(&body).expect("body utf8");
        assert!(
            body_str.contains("path=/health"),
            "body should echo path: {body_str}"
        );
        assert!(
            body_str.contains("method=GET"),
            "body should echo method: {body_str}"
        );

        // Tear everything down explicitly so the test exits cleanly.
        connection.close(0u32.into(), b"done");
        client_endpoint.close().await;
        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    }

    /// A connection registers a session for its lifetime: the registry
    /// reports one direct-transport entry while the loopback connection
    /// is up and drains back to zero after it closes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_registry_tracks_connection_lifetime() {
        let server_seed = p2claw_identity::SigningKey::generate().seed();
        let server_sk = SecretKey::from_bytes(&server_seed);
        let server_id = server_sk.public();

        let server_endpoint = test_endpoint(Some(server_sk)).await;
        let bound = server_endpoint.bound_sockets();
        let port = bound
            .iter()
            .find_map(|s| if s.is_ipv4() { Some(s.port()) } else { None })
            .expect("server should bind an IPv4 socket");
        let dial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        let (addrs_tx, _addrs_rx) = watch::channel::<Vec<String>>(Vec::new());
        let (sd_tx, sd_rx) = watch::channel(false);
        let registry = IrohSessionRegistry::new();

        let server_handle = tokio::spawn({
            let endpoint = server_endpoint.clone();
            let registry = registry.clone();
            async move {
                serve_endpoint_with_ws(endpoint, addrs_tx, sd_rx, EchoHandler, None, Some(registry))
                    .await
            }
        });

        let client_endpoint = test_endpoint(None).await;
        let server_addr = EndpointAddr::from_parts(server_id, [TransportAddr::Ip(dial_addr)]);
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            client_endpoint.connect(server_addr, P2CLAW_ALPN),
        )
        .await
        .expect("dial timed out")
        .expect("dial failed");

        // Registration happens when the server's accept completes;
        // poll briefly rather than racing it.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let session = loop {
            let sessions = registry.list_sessions();
            if let Some(s) = sessions.into_iter().next() {
                break s;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "session never appeared in the registry"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(session.id.starts_with("iroh-"), "id: {}", session.id);
        // Loopback IP path — never a relay. `Unknown` is tolerated
        // only until a path is selected, so wait for a definite answer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match registry.list_sessions().first().map(|s| s.transport) {
                Some(IrohTransport::Direct) => break,
                Some(IrohTransport::Relay) => panic!("loopback connection reported relay"),
                _ => {}
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "transport never resolved to direct"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        connection.close(0u32.into(), b"done");
        client_endpoint.close().await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !registry.list_sessions().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "session was not deregistered after close"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    }
}
