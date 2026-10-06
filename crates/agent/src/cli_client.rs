//! Client-side handlers for the `expose` / `unexpose` / `routes`
//! subcommands. These talk to the running agent's local API over its
//! Unix-domain socket using hyper's HTTP/1 client — the server side
//! lives in `local_api.rs`, so the CLI and daemon ship in the same
//! binary and resolve the same socket path through `config::resolve`.
//!
//! Output format: table-by-default with a `--json` escape hatch. QR
//! codes are rendered inline (Unicode half-blocks) so a phone camera
//! can grab a freshly-exposed URL without typing it — useful on the
//! "claude runs on the box" flow.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UnixStream;

use crate::config;

/// Response body shape for `POST /v1/routes` (`local_api.rs`).
#[derive(Deserialize)]
struct ExposeResponse {
    name: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    pending_announce: bool,
}

/// An entry in `GET /v1/routes`, including the `url` the local-API
/// now computes server-side (see the `RouteWithUrl` struct in
/// `local_api.rs`).
#[derive(Deserialize, Serialize)]
struct RouteListEntry {
    name: String,
    upstream: String,
    #[serde(default)]
    registered_at: Option<i64>,
    #[serde(default)]
    url: Option<String>,
    /// Auth method list as the local-API returns it. Empty = public app.
    #[serde(default)]
    auth: Vec<p2claw_control_proto::AuthMethod>,
    /// `public` or `private`. Defaulted for agents that predate the
    /// field.
    #[serde(default = "default_visibility")]
    visibility: String,
}

fn default_visibility() -> String {
    "public".into()
}

#[derive(Deserialize)]
struct RoutesListBody {
    routes: Vec<RouteListEntry>,
}

/// Response shape for `GET /v1/status` (`local_api::StatusBody`).
#[derive(Deserialize)]
struct StatusResponse {
    version: String,
    uptime_secs: u64,
    peer_id: String,
    #[serde(default)]
    alias: Option<String>,
    route_count: usize,
    coord: CoordStatusResponse,
}

#[derive(Deserialize)]
struct CoordStatusResponse {
    state: String,
    since_secs: u64,
    #[serde(default)]
    last_ack_age_secs: Option<u64>,
}

/// Response shape for `GET /v1/sessions` (`local_api::SessionsBody`).
#[derive(Deserialize)]
struct SessionsResponse {
    count: usize,
    sessions: Vec<SessionEntryResponse>,
}

#[derive(Deserialize)]
struct SessionEntryResponse {
    id: String,
    /// `browser` or `iroh`. Defaulted for agents that predate the
    /// field.
    #[serde(default)]
    kind: String,
    transport: String,
    age_secs: u64,
}

#[derive(Serialize)]
struct ExposeRequestBody<'a> {
    name: &'a str,
    upstream: String,
    /// Per-app auth method list. Empty = public app —
    /// `skip_serializing_if`
    /// keeps the wire shape parser-compatible with older agents
    /// that ignored it (they treat the request as public, matching
    /// the omitted-field semantics). A populated list triggers the
    /// daemon middleware to gate the route.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    auth: Vec<p2claw_control_proto::AuthMethod>,
    /// `Some("private")` for private routes; omitted for public so
    /// older agents parse the request unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<&'a str>,
}

/// Wire shape of `GET/PUT /v1/shares` (`local_api::SharesBody`).
#[derive(Deserialize, Serialize)]
struct SharesBody {
    shares: Vec<ShareEntry>,
}

#[derive(Deserialize, Serialize)]
struct ShareEntry {
    app: String,
    peers: Vec<String>,
}

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    #[error(
        "the p2claw agent is not running — start it with `p2claw run` \
         (expected socket at {0})"
    )]
    AgentNotRunning(String),
    #[error("could not connect to the p2claw agent socket at {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("HTTP error talking to the agent: {0}")]
    Hyper(#[source] hyper::Error),
    #[error("could not build HTTP request: {0}")]
    Build(#[source] hyper::http::Error),
    #[error("agent returned invalid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("could not resolve agent paths: {0}")]
    Config(#[source] config::ConfigError),
}

/// Perform a single one-shot HTTP request against the agent's UDS.
/// The socket path is resolved through [`config::resolve`] so the CLI
/// and daemon agree on the location. Returns `(status, body_bytes)`.
pub(crate) async fn uds_request(
    sock: &Path,
    method: Method,
    path: &str,
    body: Option<Bytes>,
) -> Result<(StatusCode, Bytes), ClientError> {
    let stream = UnixStream::connect(sock).await.map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::ConnectionRefused {
            ClientError::AgentNotRunning(sock.display().to_string())
        } else {
            ClientError::Connect {
                path: sock.display().to_string(),
                source: e,
            }
        }
    })?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(ClientError::Hyper)?;
    // The connection task has to be driven concurrently with
    // `send_request` or the request never makes it onto the wire.
    // Per-request spawn is fine — the connection dies with the
    // request (we read the body to completion and drop).
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("connection", "close");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(Full::new(body.unwrap_or_default()))
        .map_err(ClientError::Build)?;

    let resp = sender.send_request(req).await.map_err(ClientError::Hyper)?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(ClientError::Hyper)?
        .to_bytes();
    Ok((status, bytes))
}

/// Path of the running agent's local-API socket.
pub fn agent_sock() -> Result<std::path::PathBuf, String> {
    resolve_sock().map_err(|e| e.to_string())
}

pub(crate) fn resolve_sock() -> Result<std::path::PathBuf, ClientError> {
    let paths = config::resolve().map_err(ClientError::Config)?;
    Ok(paths.agent_sock())
}

/// `unix:` upstream for a socket path, made absolute against the
/// current directory. The daemon reads the path back out of the URL
/// verbatim, so characters a URL would percent-encode are refused.
pub fn socket_upstream(path: &std::path::Path) -> Result<String, String> {
    let abs = std::path::absolute(path)
        .map_err(|e| format!("cannot resolve socket path {}: {e}", path.display()))?;
    let s = abs
        .to_str()
        .ok_or_else(|| format!("socket path {} is not valid UTF-8", abs.display()))?;
    if let Some(c) = s
        .chars()
        .find(|c| !c.is_ascii_graphic() || "%?#\"<>`{}^|\\".contains(*c))
    {
        return Err(format!(
            "socket path {s} contains {c:?}; use a path without spaces or URL-special characters"
        ));
    }
    Ok(format!("unix:{s}"))
}

/// `p2claw apps expose <name>` → register a route, print the URL
/// and an inline QR code (unless `--no-qr`).
pub async fn cmd_expose(
    name: String,
    upstream: String,
    json: bool,
    qr: bool,
    auth: Vec<p2claw_control_proto::AuthMethod>,
    private: bool,
    public: bool,
) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    // Tri-state on the wire: omitting `visibility` preserves an
    // existing route's class daemon-side, so a bare re-expose can't
    // silently flip a private route public. Only an explicit
    // `--private` / `--public` sends the field.
    let visibility = if private {
        Some("private")
    } else if public {
        Some("public")
    } else {
        None
    };
    let socket_path = upstream.strip_prefix("unix:").map(str::to_string);
    let body_bytes = match serde_json::to_vec(&ExposeRequestBody {
        name: &name,
        upstream,
        auth,
        visibility,
    }) {
        Ok(b) => Bytes::from(b),
        Err(e) => return fail(&ClientError::Json(e)),
    };

    let (status, bytes) =
        match uds_request(&sock, Method::POST, "/v1/routes", Some(body_bytes)).await {
            Ok(v) => v,
            Err(e) => return fail(&e),
        };

    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }

    let parsed: ExposeResponse = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };

    // Skew guard: a daemon that predates private routes ignores the
    // unknown `visibility` field, registers a PUBLIC route, and
    // announces its name to coord — the response's non-null `url` is
    // the tell (a private register always returns `url: null`). Roll
    // the route back best-effort and fail loud rather than report a
    // private route that is actually public. The skew window is built
    // in: a staged auto-upgrade swaps this CLI binary while the old
    // daemon keeps running until its restart.
    if private && parsed.url.is_some() {
        let rollback =
            uds_request(&sock, Method::DELETE, &format!("/v1/routes/{name}"), None).await;
        let rolled_back = matches!(&rollback, Ok((s, _)) if s.is_success());
        eprintln!(
            "error: the running daemon predates private routes — it registered \
             '{name}' as PUBLIC and announced the name to coord."
        );
        if rolled_back {
            eprintln!("The route has been removed again.");
        } else {
            eprintln!("Automatic removal failed — run `p2claw apps unexpose {name}` now.");
        }
        eprintln!("Restart the daemon to pick up the staged upgrade, then retry.");
        return ExitCode::from(2);
    }

    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }

    if private {
        println!("exposed {} (private)", parsed.name);
        if let Some(sock) = &socket_path {
            println!("  upstream: unix socket {sock}");
        }
        println!(
            "  no public URL — share it with a peer: p2claw apps share {} --with <peer>",
            parsed.name
        );
        return ExitCode::SUCCESS;
    }
    let url = parsed.url.unwrap_or_else(|| "(pending)".into());
    println!("exposed {}", parsed.name);
    println!("  {}", url);
    if parsed.pending_announce {
        println!(
            "  (announce to coord is pending — the route is live locally \
             but visitors may see 404 until coord sees it)"
        );
    }
    if qr && url != "(pending)" {
        println!();
        render_qr_into(&url, &mut io::stdout());
    }
    ExitCode::SUCCESS
}

/// `p2claw apps share <name> --with <peer>...` → merge the peers
/// into the app's share row via GET + PUT `/v1/shares`.
pub async fn cmd_share(name: String, with: Vec<String>) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let mut body = match fetch_shares(&sock).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    match body.shares.iter_mut().find(|s| s.app == name) {
        Some(row) => {
            for p in with {
                if !row.peers.contains(&p) {
                    row.peers.push(p);
                }
            }
        }
        None => body.shares.push(ShareEntry {
            app: name.clone(),
            peers: with,
        }),
    }
    let saved = match put_shares(&sock, &body).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    let peers = saved
        .shares
        .iter()
        .find(|s| s.app == name)
        .map(|s| s.peers.clone())
        .unwrap_or_default();
    println!("{name}: shared with {} peer(s)", peers.len());
    for p in peers {
        println!("  - {p}");
    }
    ExitCode::SUCCESS
}

/// `p2claw apps unshare <name> [--with <peer>]` → remove one peer
/// from the app's share row, or the whole row when no peer given.
pub async fn cmd_unshare(name: String, with: Option<String>) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let mut body = match fetch_shares(&sock).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    let Some(row) = body.shares.iter_mut().find(|s| s.app == name) else {
        eprintln!("error: app `{name}` has no shares");
        return ExitCode::from(2);
    };
    match &with {
        Some(peer) => {
            let before = row.peers.len();
            row.peers.retain(|p| p != peer);
            if row.peers.len() == before {
                eprintln!("error: app `{name}` is not shared with {peer}");
                return ExitCode::from(2);
            }
        }
        None => row.peers.clear(),
    }
    // Empty rows are dropped server-side; sending them is fine.
    if put_shares(&sock, &body).await.is_err() {
        return ExitCode::from(2);
    }
    match with {
        Some(peer) => println!("{name}: unshared from {peer}"),
        None => println!("{name}: all shares removed"),
    }
    ExitCode::SUCCESS
}

/// `p2claw apps shares` → list share rows.
pub async fn cmd_shares(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let (status, bytes) = match uds_request(&sock, Method::GET, "/v1/shares", None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let body: SharesBody = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };
    if body.shares.is_empty() {
        println!("no shares. Share a private app with: p2claw apps share <name> --with <peer>");
        return ExitCode::SUCCESS;
    }
    for s in &body.shares {
        println!("{}", s.app);
        for p in &s.peers {
            println!("  - {p}");
        }
    }
    ExitCode::SUCCESS
}

async fn fetch_shares(sock: &Path) -> Result<SharesBody, ExitCode> {
    let (status, bytes) = match uds_request(sock, Method::GET, "/v1/shares", None).await {
        Ok(v) => v,
        Err(e) => return Err(fail(&e)),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return Err(ExitCode::from(2));
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        eprintln!("error: agent returned unexpected JSON: {e}");
        ExitCode::from(2)
    })
}

async fn put_shares(sock: &Path, body: &SharesBody) -> Result<SharesBody, ExitCode> {
    let bytes = match serde_json::to_vec(body) {
        Ok(b) => Bytes::from(b),
        Err(e) => return Err(fail(&ClientError::Json(e))),
    };
    let (status, resp) = match uds_request(sock, Method::PUT, "/v1/shares", Some(bytes)).await {
        Ok(v) => v,
        Err(e) => return Err(fail(&e)),
    };
    if status != StatusCode::OK {
        print_server_error(status, &resp);
        return Err(ExitCode::from(2));
    }
    serde_json::from_slice(&resp).map_err(|e| {
        eprintln!("error: agent returned unexpected JSON: {e}");
        ExitCode::from(2)
    })
}

/// `p2claw apps show <name>` → GET the route record + render
/// the auth method list in human-readable form. Backed by the
/// existing `GET /v1/routes` endpoint (no new wire surface) — we
/// just filter to the named entry on the client side.
pub async fn cmd_show(name: String, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let (status, bytes) = match uds_request(&sock, Method::GET, "/v1/routes", None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    let body: RoutesListBody = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let entry = match body.routes.iter().find(|r| r.name == name) {
        Some(e) => e,
        None => {
            eprintln!("error: no such app: {name}");
            return ExitCode::from(2);
        }
    };
    if json {
        let raw = match serde_json::to_vec_pretty(entry) {
            Ok(b) => b,
            Err(e) => return fail(&ClientError::Json(e)),
        };
        stdout_write_raw(&raw);
        return ExitCode::SUCCESS;
    }
    println!("name:       {}", entry.name);
    println!("visibility: {}", entry.visibility);
    match entry.upstream.strip_prefix("unix:") {
        Some(sock) => println!("upstream:   unix socket {sock}"),
        None => println!("upstream:   {}", entry.upstream),
    }
    if let Some(url) = entry.url.as_deref() {
        println!("url:        {url}");
    }
    if entry.auth.is_empty() {
        println!("auth:       none");
    } else {
        println!("auth:");
        for m in &entry.auth {
            println!("  - {}", render_auth_method(m));
        }
    }
    ExitCode::SUCCESS
}

/// `p2claw apps set-auth <name> [--auth-oauth providers...]`
/// → POST a fresh route record with the same upstream + new auth
/// list. Replaces the existing route in place (upsert preserves
/// `registered_at`).
pub async fn cmd_set_auth(name: String, auth: Vec<p2claw_control_proto::AuthMethod>) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    // Pull the existing record so we know the upstream port to keep
    // (set-auth must not require re-typing the port).
    let (status, bytes) = match uds_request(&sock, Method::GET, "/v1/routes", None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    let body: RoutesListBody = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let existing = match body.routes.iter().find(|r| r.name == name) {
        Some(e) => e,
        None => {
            eprintln!("error: no such app: {name}");
            return ExitCode::from(2);
        }
    };
    let is_private = existing.visibility == "private";
    if is_private && !auth.is_empty() {
        eprintln!(
            "error: `{name}` is a private app — access is controlled by \
             `p2claw apps share`, not OAuth"
        );
        return ExitCode::from(2);
    }
    let body_bytes = match serde_json::to_vec(&ExposeRequestBody {
        name: &name,
        upstream: existing.upstream.clone(),
        auth: auth.clone(),
        // Re-POSTing replaces the record; carry the class so a
        // private app doesn't silently flip public.
        visibility: is_private.then_some("private"),
    }) {
        Ok(b) => Bytes::from(b),
        Err(e) => return fail(&ClientError::Json(e)),
    };
    let (status, bytes) =
        match uds_request(&sock, Method::POST, "/v1/routes", Some(body_bytes)).await {
            Ok(v) => v,
            Err(e) => return fail(&e),
        };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    if auth.is_empty() {
        println!("{name}: auth cleared (app is now public)");
    } else {
        println!("{name}: auth updated");
        for m in &auth {
            println!("  - {}", render_auth_method(m));
        }
    }
    ExitCode::SUCCESS
}

/// `p2claw apps clear-auth <name>` → shortcut for
/// `set_auth` with an empty method list. Equivalent to
/// `set-auth <name>` with no methods specified, but reads
/// clearer in operator scripts.
pub async fn cmd_clear_auth(name: String) -> ExitCode {
    cmd_set_auth(name, Vec::new()).await
}

/// Render a whole-second duration compactly (`3d 4h`, `12m 5s`, `8s`).
fn fmt_duration(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86400,
        (secs % 86400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
    );
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// `p2claw status` → live agent self-report over the local API.
pub async fn cmd_status(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let (status, bytes) = match uds_request(&sock, Method::GET, "/v1/status", None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    if json {
        print!("{}", String::from_utf8_lossy(&bytes));
        return ExitCode::SUCCESS;
    }
    let s: StatusResponse = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };
    println!("version:  {}", s.version);
    println!("uptime:   {}", fmt_duration(s.uptime_secs));
    println!(
        "alias:    {}",
        s.alias.as_deref().unwrap_or("(unregistered)")
    );
    println!("peer_id:  {}", s.peer_id);
    println!("apps:     {}", s.route_count);
    let ack = match s.coord.last_ack_age_secs {
        Some(a) => format!("last ack {} ago", fmt_duration(a)),
        None => "no ack yet".to_string(),
    };
    println!(
        "coord:    {} (for {}, {ack})",
        s.coord.state,
        fmt_duration(s.coord.since_secs),
    );
    ExitCode::SUCCESS
}

/// `p2claw sessions` → active visitor sessions over the local API.
pub async fn cmd_sessions(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let (status, bytes) = match uds_request(&sock, Method::GET, "/v1/sessions", None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    if json {
        print!("{}", String::from_utf8_lossy(&bytes));
        return ExitCode::SUCCESS;
    }
    let s: SessionsResponse = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };
    if s.sessions.is_empty() {
        println!("no active visitor sessions");
        return ExitCode::SUCCESS;
    }
    println!("{:<40}  {:<8}  {:<9}  AGE", "SESSION", "KIND", "TRANSPORT");
    for e in &s.sessions {
        println!(
            "{:<40}  {:<8}  {:<9}  {}",
            e.id,
            e.kind,
            e.transport,
            fmt_duration(e.age_secs)
        );
    }
    println!("\n{} active session(s)", s.count);
    ExitCode::SUCCESS
}

fn render_auth_method(m: &p2claw_control_proto::AuthMethod) -> String {
    match m {
        p2claw_control_proto::AuthMethod::Oauth { providers: None } => {
            "oauth (any configured provider)".into()
        }
        p2claw_control_proto::AuthMethod::Oauth { providers: Some(p) } => {
            format!("oauth (providers: {})", p.join(", "))
        }
    }
}

/// `p2claw unexpose <name>` → DELETE the route.
pub async fn cmd_unexpose(name: String) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = format!("/v1/routes/{name}");
    let (status, bytes) = match uds_request(&sock, Method::DELETE, &path, None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    match status {
        StatusCode::NO_CONTENT => {
            println!("removed {name}");
            ExitCode::SUCCESS
        }
        StatusCode::NOT_FOUND => {
            eprintln!("error: no such route: {name}");
            ExitCode::from(2)
        }
        _ => {
            print_server_error(status, &bytes);
            ExitCode::from(2)
        }
    }
}

/// `p2claw routes` → GET the route table. Renders a human table by
/// default; `--json` dumps the raw response; `--qr` adds a QR code
/// per route (after the table).
pub async fn cmd_routes(json: bool, qr: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let (status, bytes) = match uds_request(&sock, Method::GET, "/v1/routes", None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return ExitCode::from(2);
    }
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let parsed: RoutesListBody = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: agent returned unexpected JSON: {e}");
            return ExitCode::from(2);
        }
    };
    if parsed.routes.is_empty() {
        println!("no routes registered — try `p2claw expose <name> <port>`");
        return ExitCode::SUCCESS;
    }
    render_table(&parsed.routes);
    if qr {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        for r in &parsed.routes {
            if let Some(url) = &r.url {
                let _ = writeln!(lock);
                let _ = writeln!(lock, "{} — {}", r.name, url);
                render_qr_into(url, &mut lock);
            }
        }
    }
    ExitCode::SUCCESS
}

// ---------- table + QR rendering ----------

fn render_table(routes: &[RouteListEntry]) {
    let name_w = routes
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let url_w = routes
        .iter()
        .map(|r| r.url.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(3)
        .max(3);
    let upstream_w = routes
        .iter()
        .map(|r| r.upstream.len())
        .max()
        .unwrap_or(8)
        .max(8);

    println!(
        "{:<nw$}  {:<uw$}  {:<pw$}  AGE",
        "NAME",
        "URL",
        "UPSTREAM",
        nw = name_w,
        uw = url_w,
        pw = upstream_w,
    );
    for r in routes {
        let url = r.url.as_deref().unwrap_or("-");
        let age = r
            .registered_at
            .map(format_age)
            .unwrap_or_else(|| "—".into());
        println!(
            "{:<nw$}  {:<uw$}  {:<pw$}  {}",
            r.name,
            url,
            r.upstream,
            age,
            nw = name_w,
            uw = url_w,
            pw = upstream_w,
        );
    }
}

/// Render a QR for `text` as dense half-block Unicode (2 QR rows per
/// terminal line) with a 2-cell quiet zone. Writes to `out` so callers
/// can keep a stdout lock across many QRs without interleaving.
fn render_qr_into<W: Write>(text: &str, out: &mut W) {
    let code = match QrCode::new(text.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(out, "  (QR render failed: {e})");
            return;
        }
    };
    let rendered = code
        .render::<Dense1x2>()
        .quiet_zone(true)
        .dark_color(Dense1x2::Dark)
        .light_color(Dense1x2::Light)
        .build();
    let _ = writeln!(out, "{rendered}");
}

pub(crate) fn format_age(ts: i64) -> String {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "—".into();
    };
    let age_s = (now.as_secs() as i64).saturating_sub(ts).max(0);
    if age_s < 60 {
        format!("{age_s}s ago")
    } else if age_s < 3600 {
        format!("{}m ago", age_s / 60)
    } else if age_s < 86_400 {
        format!("{}h ago", age_s / 3600)
    } else {
        format!("{}d ago", age_s / 86_400)
    }
}

// ---------- error plumbing ----------

pub(crate) fn fail(e: &ClientError) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::from(2)
}

pub(crate) fn print_server_error(status: StatusCode, body: &[u8]) {
    eprintln!("error: agent returned HTTP {status}");
    if !body.is_empty() {
        // Try to pretty-print a known error shape; fall through to
        // raw if it isn't JSON.
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(v) => {
                if let Some(s) = v.get("error").and_then(|s| s.as_str()) {
                    eprint!("  {s}");
                    if let Some(d) = v.get("detail").and_then(|d| d.as_str()) {
                        eprint!(": {d}");
                    }
                    eprintln!();
                } else {
                    eprintln!("  {v}");
                }
            }
            Err(_) => eprintln!("  {}", String::from_utf8_lossy(body)),
        }
    }
}

pub(crate) fn stdout_write_raw(bytes: &[u8]) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(bytes);
    if bytes.last() != Some(&b'\n') {
        let _ = lock.write_all(b"\n");
    }
}
