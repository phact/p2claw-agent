//! `p2claw apps connect`: serve a private app that another box shared
//! with this one on a local port.
//!
//! Each request is rewritten to `/v1/proxy/<peer>/<app><path>` and
//! sent to the running agent over its Unix socket, which carries it to
//! the other box. Bodies stream both ways. A WebSocket upgrade is
//! passed through; once the agent answers 101, the two upgraded
//! connections are spliced byte for byte.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, UnixStream};

type Body = BoxBody<Bytes, hyper::Error>;

/// Request headers that describe the hop to us, not the request.
const HOP_BY_HOP: &[header::HeaderName] = &[
    header::CONNECTION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

struct Target {
    peer: String,
    app: String,
    sock: PathBuf,
}

/// Split and validate `<peer>/<app>`. `peer` is an alias or a
/// z-base-32 peer id; `app` a route name.
pub fn parse_target(s: &str) -> Result<(String, String), String> {
    let (peer, app) = s
        .split_once('/')
        .ok_or_else(|| format!("`{s}`: expected <peer>/<app>"))?;
    let peer_ok = p2claw_identity::PeerId::from_z32(peer).is_ok()
        || p2claw_identity::alias_label::is_valid_alias_label(peer);
    if !peer_ok {
        return Err(format!("`{peer}` is neither an alias nor a peer id"));
    }
    if p2claw_agent::validate::validate_app_name(app).is_err() {
        return Err(format!("`{app}` is not a valid app name"));
    }
    Ok((peer.to_string(), app.to_string()))
}

pub async fn cmd_connect(target: String, listen: SocketAddr) -> ExitCode {
    let (peer, app) = match parse_target(&target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let sock = match crate::cli_client::agent_sock() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = UnixStream::connect(&sock).await {
        eprintln!(
            "error: agent not reachable at {} ({e}); is `p2claw run` up?",
            sock.display()
        );
        return ExitCode::from(2);
    }
    let listener = match TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot listen on {listen}: {e}");
            return ExitCode::from(2);
        }
    };
    let local = listener.local_addr().unwrap_or(listen);
    if !local.ip().is_loopback() {
        eprintln!(
            "warning: listening on {local}, which other machines can reach; \
             anyone who can connect gets this machine's access to {peer}/{app}"
        );
    }
    println!("connected {app} on {peer}");
    println!("  http://{local}/");
    println!("  (Ctrl-C to stop)");

    let target = Arc::new(Target { peer, app, sock });
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = tokio::signal::ctrl_c() => return ExitCode::SUCCESS,
        };
        let (tcp, _) = match accepted {
            Ok(a) => a,
            Err(e) => {
                eprintln!("warning: accept failed: {e}");
                continue;
            }
        };
        let target = Arc::clone(&target);
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(req, Arc::clone(&target)));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), svc)
                .with_upgrades()
                .await;
        });
    }
}

async fn handle(req: Request<Incoming>, target: Arc<Target>) -> Result<Response<Body>, Infallible> {
    Ok(match forward(req, &target).await {
        Ok(resp) => resp,
        Err(msg) => {
            let body = Full::new(Bytes::from(format!("p2claw connect: {msg}\n")))
                .map_err(|never| match never {})
                .boxed();
            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            resp
        }
    })
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

async fn forward(mut req: Request<Incoming>, target: &Target) -> Result<Response<Body>, String> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("/v1/proxy/{}/{}{path_and_query}", target.peer, target.app);
    let websocket = is_websocket_upgrade(&req);
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));

    let (mut parts, body) = req.into_parts();
    parts.uri = uri.parse().map_err(|e| format!("bad request path: {e}"))?;
    parts
        .headers
        .insert(header::HOST, HeaderValue::from_static("localhost"));
    if !websocket {
        for name in HOP_BY_HOP {
            parts.headers.remove(name);
        }
    }

    let stream = UnixStream::connect(&target.sock)
        .await
        .map_err(|e| format!("agent socket {}: {e}", target.sock.display()))?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(stream))
            .await
            .map_err(|e| format!("agent handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let mut resp = sender
        .send_request(Request::from_parts(parts, body))
        .await
        .map_err(|e| format!("agent request: {e}"))?;

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let agent_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(client), Ok(agent)) = (client_upgrade.await, agent_upgrade.await) {
                    let mut client = TokioIo::new(client);
                    let mut agent = TokioIo::new(agent);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut agent).await;
                }
            });
        }
    }
    Ok(resp.map(|b| b.boxed()))
}
