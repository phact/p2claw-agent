//! Private-route enforcement end-to-end:
//!
//! - [`Forwarder`] wired into [`p2claw_translator::serve`] over a
//!   duplex pair, exercising the share gate: deny without a share,
//!   deny without peer identity (the visitor path), allow with a
//!   share (including the `X-P2claw-*` strip + `X-P2claw-Peer`
//!   inject), and a `unix:` upstream round-trip.
//! - Two in-process iroh endpoints proving deny-by-default over the
//!   real QUIC transport: the caller's authenticated peer id is
//!   what the share check keys on, so a dial from an unshared peer
//!   gets an unknown-app-shaped 404 and the same dial succeeds after the share lands.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use p2claw_agent::forwarder::Forwarder;
use p2claw_agent::routes::{RouteRecord, RouteTable, Visibility};
use p2claw_agent::shares::{ShareRecord, Shares};
use p2claw_translator::{ClientConnection, ClientRequest};
use tempfile::tempdir;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::oneshot;

const PARENT_DOMAIN: &str = "p2claw.test";
const ALIAS: &str = "blue-otter-7392";

/// Hyper handler that echoes the method, path, and every
/// `x-p2claw-*` header — lets tests assert the strip + inject.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut body = format!("method={} path={}\n", req.method(), req.uri().path());
    for (name, value) in req.headers() {
        let n = name.as_str();
        if n.starts_with("x-p2claw-") {
            body.push_str(&format!("hdr:{n}={}\n", value.to_str().unwrap_or("<bad>")));
        }
    }
    Ok(Response::new(Full::new(Bytes::from(body))))
}

async fn spawn_tcp_echo() -> (u16, oneshot::Sender<()>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind echo server");
    let port = listener.local_addr().unwrap().port();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else { return };
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(echo))
                            .await;
                    });
                }
            }
        }
    });
    (port, shutdown_tx)
}

fn spawn_unix_echo(path: &std::path::Path) -> oneshot::Sender<()> {
    let listener = UnixListener::bind(path).expect("bind unix echo server");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else { return };
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(echo))
                            .await;
                    });
                }
            }
        }
    });
    shutdown_tx
}

struct Fixture {
    routes: RouteTable,
    shares: Shares,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new(upstream: String) -> Self {
        let dir = tempdir().unwrap();
        let routes = RouteTable::load_or_empty(dir.path().join("routes.json"));
        routes
            .upsert(RouteRecord {
                name: "mysvc".into(),
                upstream,
                visibility: Visibility::Private,
                ..Default::default()
            })
            .await
            .expect("upsert private route");
        let shares = Shares::load_or_empty(dir.path().join("shares.json"));
        Self {
            routes,
            shares,
            _dir: dir,
        }
    }

    fn forwarder(&self) -> Forwarder {
        Forwarder::new_with_shares(
            self.routes.clone(),
            PARENT_DOMAIN.into(),
            None,
            None,
            Some(self.shares.clone()),
        )
    }
}

/// Serve `forwarder` over a duplex pair, returning the client half.
fn spawn_duplex(forwarder: Forwarder) -> ClientConnection {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(p2claw_translator::serve(server_io, forwarder));
    ClientConnection::spawn(client_io)
}

fn private_req(path: &'static str) -> ClientRequest {
    ClientRequest::get(Bytes::from_static(path.as_bytes())).header(
        Bytes::from_static(b"host"),
        Bytes::from(format!("mysvc-{ALIAS}.{PARENT_DOMAIN}")),
    )
}

fn z32_peer() -> String {
    p2claw_identity::SigningKey::generate().peer_id().to_z32()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_denied_without_share() {
    let (port, _shutdown) = spawn_tcp_echo().await;
    let fx = Fixture::new(format!("http://127.0.0.1:{port}")).await;

    // Authenticated peer, but no share row → 404, shaped exactly
    // like an unknown app so probing can't confirm the name exists.
    let client = spawn_duplex(fx.forwarder().for_peer(z32_peer()));
    let resp = client
        .request(private_req("/hello"))
        .await
        .expect("request");
    assert_eq!(resp.status, 404);
    let body = resp.body.collect().await;
    assert_eq!(std::str::from_utf8(&body).unwrap(), "no such app: mysvc\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_denied_without_peer_identity() {
    let (port, _shutdown) = spawn_tcp_echo().await;
    let fx = Fixture::new(format!("http://127.0.0.1:{port}")).await;
    let caller = z32_peer();
    fx.shares
        .replace(vec![ShareRecord {
            app: "mysvc".into(),
            peers: vec![caller],
        }])
        .await
        .unwrap();

    // Visitor path: base forwarder, no `for_peer` — even a fully
    // shared route must deny when the transport carries no peer
    // identity.
    let client = spawn_duplex(fx.forwarder());
    let resp = client
        .request(private_req("/hello"))
        .await
        .expect("request");
    assert_eq!(resp.status, 404);
    let body = resp.body.collect().await;
    assert_eq!(std::str::from_utf8(&body).unwrap(), "no such app: mysvc\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_peer_reaches_route_with_stripped_and_injected_headers() {
    let (port, _shutdown) = spawn_tcp_echo().await;
    let fx = Fixture::new(format!("http://127.0.0.1:{port}")).await;
    let caller = z32_peer();
    fx.shares
        .replace(vec![ShareRecord {
            app: "mysvc".into(),
            peers: vec![caller.clone()],
        }])
        .await
        .unwrap();

    let client = spawn_duplex(fx.forwarder().for_peer(caller.clone()));
    // Spoofed identity header must be stripped before forwarding.
    let req = private_req("/hello").header(
        Bytes::from_static(b"x-p2claw-user"),
        Bytes::from_static(b"mallory@example.com"),
    );
    let resp = client.request(req).await.expect("request");
    assert_eq!(resp.status, 200);
    let body = resp.body.collect().await;
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains(&format!("hdr:x-p2claw-peer={caller}")),
        "caller peer id must be injected: {text}"
    );
    assert!(
        !text.contains("x-p2claw-user"),
        "spoofed inbound identity header must be stripped: {text}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_peer_reaches_unix_upstream() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("echo.sock");
    let _shutdown = spawn_unix_echo(&sock);

    let fx = Fixture::new(format!("unix:{}", sock.display())).await;
    let caller = z32_peer();
    fx.shares
        .replace(vec![ShareRecord {
            app: "mysvc".into(),
            peers: vec![caller.clone()],
        }])
        .await
        .unwrap();

    let client = spawn_duplex(fx.forwarder().for_peer(caller.clone()));
    let resp = client
        .request(private_req("/unix-hello"))
        .await
        .expect("request");
    assert_eq!(resp.status, 200);
    let body = resp.body.collect().await;
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("path=/unix-hello"), "{text}");
    assert!(
        text.contains(&format!("hdr:x-p2claw-peer={caller}")),
        "{text}"
    );
}

/// Deny-by-default over the real iroh transport: the share check
/// keys on the QUIC-authenticated remote id, so the same dial flips
/// from 404 to 200 when (and only when) the share row lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iroh_peer_identity_gates_private_route_end_to_end() {
    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
    use p2claw_agent::iroh_listener::{serve_endpoint_per_peer, P2CLAW_ALPN};
    use tokio::io::join;
    use tokio::sync::watch;

    let (port, _shutdown) = spawn_tcp_echo().await;
    let fx = Fixture::new(format!("http://127.0.0.1:{port}")).await;
    let forwarder = fx.forwarder();

    // Server endpoint pinned to a known key.
    let server_seed = p2claw_identity::SigningKey::generate().seed();
    let server_sk = SecretKey::from_bytes(&server_seed);
    let server_id = server_sk.public();
    let server_endpoint = Endpoint::builder(presets::Minimal)
        .alpns(vec![P2CLAW_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .secret_key(server_sk)
        .bind()
        .await
        .expect("bind server endpoint");
    let bound = server_endpoint.bound_sockets();
    let dial_port = bound
        .iter()
        .find_map(|s| s.is_ipv4().then(|| s.port()))
        .expect("ipv4 socket");

    let (addrs_tx, _addrs_rx) = watch::channel(Vec::new());
    let (sd_tx, sd_rx) = watch::channel(false);
    let server_handle = tokio::spawn({
        let endpoint = server_endpoint.clone();
        async move {
            serve_endpoint_per_peer(
                endpoint,
                addrs_tx,
                sd_rx,
                move |remote| (forwarder.for_peer(remote.to_z32()), None),
                None,
            )
            .await
        }
    });

    // Client endpoint with its own pinned key — its z32 is what the
    // share row must name.
    let client_identity = p2claw_identity::SigningKey::generate();
    let client_z32 = client_identity.peer_id().to_z32();
    let client_endpoint = Endpoint::builder(presets::Minimal)
        .alpns(vec![P2CLAW_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .secret_key(SecretKey::from_bytes(&client_identity.seed()))
        .bind()
        .await
        .expect("bind client endpoint");

    let server_addr = EndpointAddr::from_parts(
        server_id,
        [TransportAddr::Ip(SocketAddr::from((
            [127, 0, 0, 1],
            dial_port,
        )))],
    );
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        client_endpoint.connect(server_addr, P2CLAW_ALPN),
    )
    .await
    .expect("dial timed out")
    .expect("dial failed");
    let (send, recv) = connection.open_bi().await.expect("open_bi");
    let client = ClientConnection::spawn(join(recv, send));

    // 1. No share row yet → denied.
    let resp = tokio::time::timeout(Duration::from_secs(5), client.request(private_req("/one")))
        .await
        .expect("request timed out")
        .expect("request errored");
    assert_eq!(resp.status, 404, "unshared peer must be denied");
    let body = resp.body.collect().await;
    assert_eq!(std::str::from_utf8(&body).unwrap(), "no such app: mysvc\n");

    // 2. Share with this peer → the SAME connection now passes (the
    //    check is per-request, so a live share edit applies at once).
    fx.shares
        .replace(vec![ShareRecord {
            app: "mysvc".into(),
            peers: vec![client_z32.clone()],
        }])
        .await
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), client.request(private_req("/two")))
        .await
        .expect("request timed out")
        .expect("request errored");
    assert_eq!(resp.status, 200, "shared peer must pass");
    let body = resp.body.collect().await;
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains(&format!("hdr:x-p2claw-peer={client_z32}")),
        "attribution header must carry the caller: {text}"
    );

    connection.close(0u32.into(), b"done");
    client_endpoint.close().await;
    let _ = sd_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}

// ---- WebSocket-upgrade path -----------------------------------------

/// Tungstenite echo server that reports each accepted upgrade's
/// headers over a channel.
async fn spawn_ws_echo(capture: tokio::sync::mpsc::UnboundedSender<Vec<(String, String)>>) -> u16 {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::handshake::server as hs;
    use tokio_tungstenite::tungstenite::Message;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let capture = capture.clone();
            tokio::spawn(async move {
                #[allow(clippy::result_large_err)]
                let cb = |req: &hs::Request,
                          resp: hs::Response|
                 -> Result<hs::Response, hs::ErrorResponse> {
                    let pairs = req
                        .headers()
                        .iter()
                        .map(|(n, v)| {
                            (n.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                        })
                        .collect();
                    let _ = capture.send(pairs);
                    Ok(resp)
                };
                let mut ws = match tokio_tungstenite::accept_hdr_async(stream, cb).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                while let Some(Ok(msg)) = ws.next().await {
                    match msg {
                        Message::Text(_) | Message::Binary(_) => {
                            if ws.send(msg).await.is_err() {
                                return;
                            }
                        }
                        Message::Close(_) => return,
                        _ => {}
                    }
                }
            });
        }
    });
    port
}

/// Serve `forwarder` (plus its WS handler) over a duplex pair.
fn spawn_duplex_with_ws(forwarder: Forwarder) -> ClientConnection {
    use p2claw_agent::ws_forwarder::WsForwarder;
    let ws_handler: Arc<dyn p2claw_translator::WsHandler> =
        Arc::new(WsForwarder::new(forwarder.clone()));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let opts = p2claw_translator::ServeOptions {
            ws_handler: Some(ws_handler),
            ..Default::default()
        };
        let _ = p2claw_translator::serve_with(server_io, forwarder, opts).await;
    });
    ClientConnection::spawn(client_io)
}

fn private_ws_upgrade() -> p2claw_translator::ClientWsUpgrade {
    p2claw_translator::ClientWsUpgrade::new(Bytes::from_static(b"/ws"))
        .header(
            Bytes::from_static(b"host"),
            Bytes::from(format!("mysvc-{ALIAS}.{PARENT_DOMAIN}")),
        )
        .header(
            Bytes::from_static(b"x-p2claw-user"),
            Bytes::from_static(b"mallory@example.com"),
        )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_upgrade_to_private_route_rejected_without_share() {
    let (capture_tx, _capture_rx) = tokio::sync::mpsc::unbounded_channel();
    let port = spawn_ws_echo(capture_tx).await;
    let fx = Fixture::new(format!("http://127.0.0.1:{port}")).await;

    let client = spawn_duplex_with_ws(fx.forwarder().for_peer(z32_peer()));
    let err = client
        .open_websocket(private_ws_upgrade())
        .await
        .expect_err("unshared peer must be rejected at upgrade time");
    match err {
        p2claw_translator::TranslatorError::Cancelled(code) => {
            assert_eq!(code.0, 404, "rejection must be unknown-app-shaped (404)");
        }
        other => panic!("expected Cancelled(404), got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_upgrade_to_private_route_bridges_with_share() {
    let (capture_tx, mut capture_rx) = tokio::sync::mpsc::unbounded_channel();
    let port = spawn_ws_echo(capture_tx).await;
    let fx = Fixture::new(format!("http://127.0.0.1:{port}")).await;
    let caller = z32_peer();
    fx.shares
        .replace(vec![ShareRecord {
            app: "mysvc".into(),
            peers: vec![caller.clone()],
        }])
        .await
        .unwrap();

    let client = spawn_duplex_with_ws(fx.forwarder().for_peer(caller.clone()));
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        client.open_websocket(private_ws_upgrade()),
    )
    .await
    .expect("upgrade timed out")
    .expect("shared peer must upgrade");

    // The upstream dial carried the injected attribution header and
    // not the spoofed identity.
    let headers = tokio::time::timeout(Duration::from_secs(5), capture_rx.recv())
        .await
        .expect("capture timed out")
        .expect("capture channel open");
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == "x-p2claw-peer" && v == &caller),
        "x-p2claw-peer must reach the upstream: {headers:?}"
    );
    assert!(
        !headers.iter().any(|(n, _)| n == "x-p2claw-user"),
        "spoofed identity header must be stripped: {headers:?}"
    );

    // Frames round-trip through the bridge.
    conn.send(p2claw_translator::WsMessage::text(Bytes::from_static(
        b"ping-frame",
    )))
    .await
    .expect("send");
    let echoed = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .expect("recv timed out")
        .expect("recv")
        .expect("ws open");
    assert_eq!(&echoed.payload[..], b"ping-frame");
    let _ = conn.close(1000, Bytes::new()).await;
}
