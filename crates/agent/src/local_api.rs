//! Local HTTP API served over a Unix-domain socket.
//!
//! Authn is SO_PEERCRED-based:
//! the accept loop reads the peer credentials from every accepted
//! socket and drops anything whose effective UID differs from the
//! agent's. No header auth, no tokens. Inside the same-UID trust
//! boundary, any local process can call the API.
//!
//! Endpoints:
//! - `GET /v1/identity` → `{peer_id, alias, registered}` JSON.
//!   `registered` is `true` iff this process has loaded its
//!   `agent.state` (i.e. registration completed during this run or
//!   was already on disk at boot). For real-time "is the control WS
//!   currently up?", callers ask coord at `/internal/alias/<alias>`
//!   — the agent can never honestly answer that question itself
//!   (a dead process can't answer at all; a stale field would lie
//!   on hard crash). An earlier `online` field was reverted for
//!   that reason.
//! - `GET /v1/status` → live agent self-report (version, uptime,
//!   alias, route count, coord control-connection state). Every field
//!   is computed at request time from in-process state — nothing is
//!   persisted, so it cannot go stale after a crash. This is why it
//!   does NOT reintroduce the reverted `online` field: that field
//!   lied because it was cached on disk and a hard crash left it
//!   saying "online"; a live socket answer can't lie, because a dead
//!   process answers nothing at all. `coord.state` is the agent's own
//!   VIEW of its control link (connected / connecting / disconnected),
//!   never a claim about end-to-end reachability — the box can believe
//!   it is connected while coord has already evicted it. Authoritative
//!   reachability stays coord's/edge's to answer.
//! - `GET /v1/sessions` → active visitor sessions: id, best-effort
//!   transport path (direct / relay / unknown), age. Metadata only —
//!   no visitor IPs (coordination-is-metadata-only).
//! - `POST /v1/routes` → register or replace a route.
//! - `GET /v1/routes` → list all routes.
//! - `GET /v1/routes/<name>` → one route.
//! - `DELETE /v1/routes/<name>` → remove a route.
//! - `/v1/email/...` → inbound mail settings and inbox (`email.rs`).
//! - `/v1/oauth-grants/...` → consent flows and grants through p2claw
//!   Connect (`oauth_grants.rs`).

mod email;
mod oauth_grants;

use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use p2claw_identity::SigningKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config;
use crate::email_link::{EmailLink, EmailShared};
use crate::route_announcer::{AnnounceWaitError, RouteAnnouncer};
use crate::state_store::AgentState;
use p2claw_agent::oauth_grants::OauthGrants;
use p2claw_agent::peer_dialer::PeerClientCache;
use p2claw_agent::routes::{RouteError, RouteRecord, RouteTable, Visibility};
use p2claw_agent::shares::{ShareError, ShareRecord, Shares};
use p2claw_agent::validate::ValidateError;

/// Response body type: boxed so plain JSON handlers (`Full`) and the
/// streaming `/v1/proxy` forward can share one service signature.
type ApiBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// Wrap a fixed byte payload as an [`ApiBody`].
fn full_body(bytes: Bytes) -> ApiBody {
    Full::new(bytes).boxed()
}

/// How long `POST /v1/routes` waits for coord's `route_announce_ack`
/// before falling back to `pending_announce: true`: on timeout the
/// route is kept locally and the response signals that the operator
/// should re-check later.
const ANNOUNCE_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum LocalApiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("socket-path error: {0}")]
    Path(String),
    /// `accept()` returned EMFILE / ENFILE (process or system FD
    /// limit hit). Surfaced separately so `main.rs` can fail-fast
    /// the whole agent process — restarting just the local API
    /// task in-process can't free leaked FDs held elsewhere
    /// (forwarder pools, signaling sessions, …); only a process
    /// restart via launchd / systemd KeepAlive recovers.
    #[error("local API accept hit FD-limit (fd_count={fd_count:?}): {source}")]
    AcceptFdLimit {
        fd_count: Option<usize>,
        #[source]
        source: std::io::Error,
    },
}

/// `header_read_timeout` for the per-connection hyper builder. UDS
/// peers are same-uid by SO_PEERCRED, but we still want a bounded
/// hold time so a buggy local CLI that connects and then forgets
/// to write doesn't pin an FD forever. 5 s is generous for
/// loopback request shaping and short enough to clear backlog
/// quickly under FD pressure.
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Returns `true` if `e` is "Too many open files" — either the
/// per-process EMFILE or the system-wide ENFILE. We treat both as
/// the same fatal condition; either way the accept loop can't make
/// progress and the only safe recovery is a process restart.
fn is_fd_limit(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        // Linux + macOS: EMFILE = 24, ENFILE = 23. The libc
        // crate would let us reference these by name but adding a
        // dep just for two integer constants is overkill — the
        // values are stable POSIX errnos shared across both
        // targets the agent builds for.
        Some(23) | Some(24)
    )
}

/// Shared read-only view of the agent's current identity + state.
pub struct LocalApi {
    /// Identity is stable for the life of the process.
    pub identity: Arc<SigningKey>,
    /// State can be replaced after a re-registration. `Some` iff this
    /// process has completed `POST /v1/register` (or loaded an
    /// existing `agent.state` at boot) — see the `registered` field
    /// on `GET /v1/identity`.
    pub state: RwLock<Option<AgentState>>,
    /// Route table — shared with the forwarder.
    pub routes: RouteTable,
    /// Bridge to the control connection for `route_announce` emission.
    /// Cloned freely; the announcer is itself an `Arc` underneath.
    pub announcer: RouteAnnouncer,
    /// Process start, for `GET /v1/status` uptime. Monotonic clock.
    pub process_start: std::time::Instant,
    /// Live coord control-connection health, driven by the reconnect
    /// loop. `GET /v1/status` reads the CURRENT value per request — it
    /// is never persisted, so it can't lie after a crash (a dead
    /// process answers nothing). It is the agent's own *belief* about
    /// its control link, NOT end-to-end reachability (only coord/edge
    /// can answer that — see the module doc).
    pub coord_health: watch::Receiver<crate::auto_upgrade::CoordHealth>,
    /// When the current `coord_health` value was entered — powers the
    /// `since_secs` field. Maintained by a watcher task in `main`.
    pub coord_state_since: Arc<std::sync::Mutex<std::time::Instant>>,
    /// Visitor-session source for `GET /v1/sessions`, wired after the
    /// signal registry is built (it's constructed later than this
    /// struct). Empty until then → `/v1/sessions` reports zero.
    pub sessions: Arc<std::sync::OnceLock<Arc<crate::signal_handler::SignalRegistry>>>,
    /// Second session source: inbound iroh connections (edge tunnel +
    /// native clients), wired when the iroh listener starts. Note one
    /// iroh entry is a *connection*, not necessarily one visitor —
    /// the edge tunnel pools many visitors over one connection.
    pub iroh_sessions:
        Arc<std::sync::OnceLock<Arc<p2claw_agent::iroh_listener::IrohSessionRegistry>>>,
    /// Share store gating private routes — shared with the
    /// forwarder's enforcement; `GET/PUT /v1/shares` read/replace
    /// it live.
    pub shares: Shares,
    /// Outbound peer-connection cache backing `/v1/proxy`. Wired
    /// once the agent's iroh endpoint exists; before that the proxy
    /// answers 503.
    pub peer_proxy: Arc<std::sync::OnceLock<Arc<PeerClientCache>>>,
    /// Email settings and inbox, shared with the coord session that
    /// fills the inbox.
    pub email: EmailShared,
    /// Bridge to the coord session for `email_config` and rejection
    /// lookups.
    pub email_link: EmailLink,
    /// Consent flows and stored grants; the coord session delivers
    /// callbacks into its flow table.
    pub oauth_grants: Arc<OauthGrants>,
}

impl LocalApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: Arc<SigningKey>,
        state: Option<AgentState>,
        routes: RouteTable,
        announcer: RouteAnnouncer,
        process_start: std::time::Instant,
        coord_health: watch::Receiver<crate::auto_upgrade::CoordHealth>,
        coord_state_since: Arc<std::sync::Mutex<std::time::Instant>>,
        sessions: Arc<std::sync::OnceLock<Arc<crate::signal_handler::SignalRegistry>>>,
        iroh_sessions: Arc<
            std::sync::OnceLock<Arc<p2claw_agent::iroh_listener::IrohSessionRegistry>>,
        >,
        shares: Shares,
        peer_proxy: Arc<std::sync::OnceLock<Arc<PeerClientCache>>>,
        email: EmailShared,
        email_link: EmailLink,
        oauth_grants: Arc<OauthGrants>,
    ) -> Self {
        Self {
            identity,
            state: RwLock::new(state),
            routes,
            announcer,
            process_start,
            coord_health,
            coord_state_since,
            sessions,
            iroh_sessions,
            shares,
            peer_proxy,
            email,
            email_link,
            oauth_grants,
        }
    }
}

/// Run the local API until `shutdown` flips to `true`. Binds the Unix
/// socket at `sock_path` (its parent directory is created with
/// mode `0700` and verified to be owned by the current user).
pub async fn serve(
    sock_path: &Path,
    api: Arc<LocalApi>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), LocalApiError> {
    config::check_sock_path(sock_path).map_err(LocalApiError::Io)?;

    prepare_socket_dir(sock_path)?;
    if sock_path.exists() {
        // Stale socket from a previous run.
        std::fs::remove_file(sock_path)?;
    }
    let listener = UnixListener::bind(sock_path)?;
    info!(path = %sock_path.display(), "local API: listening");

    let our_uid = config::current_uid();

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, _addr) = match res {
                    Ok(v) => v,
                    Err(e) if is_fd_limit(&e) => {
                        // EMFILE / ENFILE on the local-API accept socket
                        // is a cliff: every retry just spins on the same
                        // error, no new FDs free up while we're hot-
                        // looping, and the rest of the agent can't take
                        // new sockets either. The only honest recovery
                        // is a process restart. Surface to main; it
                        // panics the supervised task to trip the
                        // panic-cascade -> non-zero exit -> launchd /
                        // systemd `KeepAlive` / `Restart=on-failure`
                        // brings us back with all FDs reclaimed.
                        // See the EMFILE production incident docs.
                        let fd_count = crate::fd_count::fd_count();
                        error!(
                            error = %e,
                            fd_count = ?fd_count,
                            "local API: accept hit FD-limit; failing fast for process restart"
                        );
                        return Err(LocalApiError::AcceptFdLimit {
                            fd_count,
                            source: e,
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "local API: accept() failed");
                        continue;
                    }
                };

                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == our_uid => {
                        let api = Arc::clone(&api);
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let svc = service_fn(move |req: Request<Incoming>| {
                                let api = Arc::clone(&api);
                                async move {
                                    Ok::<Response<ApiBody>, Infallible>(
                                        dispatch(api, req).await,
                                    )
                                }
                            });
                            // `header_read_timeout` bounds how long a
                            // peer can dawdle between connect and the
                            // end of the request line + headers — a
                            // buggy local CLI connecting and then
                            // forgetting to write must not pin an FD
                            // here forever. The timeout
                            // requires a registered timer; `TokioTimer`
                            // is the standard hyper-util impl over
                            // `tokio::time`.
                            let mut builder = hyper::server::conn::http1::Builder::new();
                            builder
                                .timer(TokioTimer::new())
                                .header_read_timeout(HEADER_READ_TIMEOUT);
                            // `.with_upgrades()` lets `/v1/proxy`
                            // WebSocket upgrades take over the
                            // connection after the 101.
                            if let Err(e) =
                                builder
                                    .serve_connection(io, svc)
                                    .with_upgrades()
                                    .await
                            {
                                debug!(error = %e, "local API: conn ended with error");
                            }
                        });
                    }
                    Ok(cred) => {
                        // Close without writing any bytes; the
                        // mismatched caller sees EOF.
                        warn!(
                            peer_uid = cred.uid(),
                            our_uid,
                            "local API: rejected — peer uid mismatch"
                        );
                        drop(stream);
                    }
                    Err(e) => {
                        warn!(error = %e, "local API: peer_cred() failed — dropping conn");
                        drop(stream);
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("local API: shutdown");
                let _ = std::fs::remove_file(sock_path);
                return Ok(());
            }
        }
    }
}

/// Create the socket's parent directory with mode 0700, verifying it
/// isn't owned by a different user.
fn prepare_socket_dir(sock_path: &Path) -> Result<(), LocalApiError> {
    let parent = match sock_path.parent() {
        Some(p) => p,
        None => {
            return Err(LocalApiError::Path(format!(
                "socket path {} has no parent directory",
                sock_path.display()
            )));
        }
    };
    std::fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(parent)?;
        let our_uid = config::current_uid();
        if meta.uid() != our_uid {
            return Err(LocalApiError::Io(std::io::Error::other(format!(
                "socket directory {} is owned by uid {}, expected {our_uid} — \
                 refusing to create the socket",
                parent.display(),
                meta.uid(),
            ))));
        }
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn dispatch(api: Arc<LocalApi>, req: Request<Incoming>) -> Response<ApiBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    match (&method, path.as_str()) {
        (&Method::GET, "/v1/identity") => identity_handler(&api).await,
        (&Method::GET, "/v1/status") => status_handler(&api).await,
        (&Method::GET, "/v1/sessions") => sessions_handler(&api).await,
        (&Method::GET, "/v1/routes") => list_routes_handler(&api).await,
        (&Method::POST, "/v1/routes") => register_route_handler(&api, req).await,
        (&Method::GET, "/v1/shares") => get_shares_handler(&api).await,
        (&Method::PUT, "/v1/shares") => put_shares_handler(&api, req).await,
        _ => {
            // ANY method: forward to a private service on another box.
            if path.starts_with("/v1/proxy/") {
                return proxy_handler(&api, req).await;
            }
            if path == "/v1/email" || path.starts_with("/v1/email/") {
                return email::dispatch(&api, req, &method, &path).await;
            }
            if path == "/v1/oauth-grants" || path.starts_with("/v1/oauth-grants/") {
                return oauth_grants::dispatch(&api, req, &method, &path).await;
            }
            if let Some(name) = path.strip_prefix("/v1/routes/") {
                if name.is_empty() || name.contains('/') {
                    return json_response(
                        StatusCode::NOT_FOUND,
                        &ErrorBody {
                            error: "not_found",
                            detail: None,
                        },
                    );
                }
                return match method {
                    Method::GET => get_route_handler(&api, name).await,
                    Method::DELETE => delete_route_handler(&api, name).await,
                    _ => json_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        &ErrorBody {
                            error: "method_not_allowed",
                            detail: None,
                        },
                    ),
                };
            }
            json_response(
                StatusCode::NOT_FOUND,
                &ErrorBody {
                    error: "not_found",
                    detail: None,
                },
            )
        }
    }
}

async fn identity_handler(api: &LocalApi) -> Response<ApiBody> {
    // Read `state` once and derive both fields from the same snapshot
    // — `alias` is `Some` exactly when `registered` is `true`, so
    // splitting them across two reads would be needlessly racy.
    let state_snap = api.state.read().await;
    let registered = state_snap.is_some();
    let alias = state_snap.as_ref().map(|s| s.alias.clone());
    let body = IdentityBody {
        peer_id: api.identity.peer_id().to_z32(),
        alias,
        registered,
    };
    json_response(StatusCode::OK, &body)
}

/// Live agent self-report. Every field is computed at request time
/// from in-process state — nothing here is persisted, so it cannot
/// go stale after a crash (a dead process answers nothing at all).
/// `coord.state` is the agent's own VIEW of its control link, not a
/// claim about end-to-end reachability — see the module doc.
async fn status_handler(api: &LocalApi) -> Response<ApiBody> {
    let alias = api.state.read().await.as_ref().map(|s| s.alias.clone());
    let route_count = api.routes.list().await.len();

    let coord_state = match *api.coord_health.borrow() {
        crate::auto_upgrade::CoordHealth::ConnectedHelloAck => "connected",
        crate::auto_upgrade::CoordHealth::Connecting => "connecting",
        crate::auto_upgrade::CoordHealth::Disconnected => "disconnected",
    };
    let since_secs = api
        .coord_state_since
        .lock()
        .expect("coord_state_since mutex poisoned")
        .elapsed()
        .as_secs();

    let body = StatusBody {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: api.process_start.elapsed().as_secs(),
        peer_id: api.identity.peer_id().to_z32(),
        alias,
        route_count,
        coord: CoordStatus {
            state: coord_state,
            since_secs,
            last_ack_age_secs: api.announcer.last_ack_age_secs().await,
        },
    };
    json_response(StatusCode::OK, &body)
}

/// Active visitor sessions — metadata only, no visitor IPs. Reads the
/// live signal registry once it has been wired (empty before then).
async fn sessions_handler(api: &LocalApi) -> Response<ApiBody> {
    let mut sessions: Vec<SessionEntry> = match api.sessions.get() {
        Some(reg) => reg
            .list_sessions()
            .await
            .into_iter()
            .map(|s| SessionEntry {
                id: s.id,
                kind: "browser",
                transport: s.transport.as_str(),
                age_secs: s.age_secs,
            })
            .collect(),
        None => Vec::new(),
    };
    if let Some(reg) = api.iroh_sessions.get() {
        sessions.extend(reg.list_sessions().into_iter().map(|s| SessionEntry {
            id: s.id,
            kind: "iroh",
            transport: s.transport.as_str(),
            age_secs: s.age_secs,
        }));
    }
    let body = SessionsBody {
        count: sessions.len(),
        sessions,
    };
    json_response(StatusCode::OK, &body)
}

async fn list_routes_handler(api: &LocalApi) -> Response<ApiBody> {
    let routes = api.routes.list().await;
    let state = api.state.read().await.clone();
    let enriched: Vec<RouteWithUrl> = routes
        .into_iter()
        .map(|r| {
            let url = state
                .as_ref()
                .and_then(|s| build_route_url(&s.alias, &s.parent_domain, &r));
            RouteWithUrl { route: r, url }
        })
        .collect();
    json_response(StatusCode::OK, &RoutesListBody { routes: enriched })
}

async fn get_route_handler(api: &LocalApi, name: &str) -> Response<ApiBody> {
    match api.routes.get(name).await {
        Some(r) => {
            let state = api.state.read().await.clone();
            let url = state
                .as_ref()
                .and_then(|s| build_route_url(&s.alias, &s.parent_domain, &r));
            json_response(StatusCode::OK, &RouteWithUrl { route: r, url })
        }
        None => json_response(
            StatusCode::NOT_FOUND,
            &ErrorBody {
                error: "not_found",
                detail: Some(format!("route `{name}` is not registered")),
            },
        ),
    }
}

async fn delete_route_handler(api: &LocalApi, name: &str) -> Response<ApiBody> {
    // Private routes were never announced, so their removal isn't
    // either — coord's view is unchanged.
    let was_private = api
        .routes
        .get(name)
        .await
        .map(|r| r.is_private())
        .unwrap_or(false);
    match api.routes.remove(name).await {
        Ok(()) => {
            // DELETE has no rejection path on coord's side (you can't
            // exceed quota by removing) — fire the announce and don't
            // wait. The next inbound `route_announce_ack` updates the
            // shared latest_ack snapshot for `GET /v1/quota`.
            if !was_private {
                api.announcer.request_fire_and_forget();
            }
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(full_body(Bytes::new()))
                .expect("no-content response")
        }
        Err(RouteError::NotFound(_)) => json_response(
            StatusCode::NOT_FOUND,
            &ErrorBody {
                error: "not_found",
                detail: Some(format!("route `{name}` is not registered")),
            },
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &ErrorBody {
                error: "internal",
                detail: Some(e.to_string()),
            },
        ),
    }
}

async fn register_route_handler(api: &LocalApi, req: Request<Incoming>) -> Response<ApiBody> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorBody {
                    error: "bad_body",
                    detail: Some(e.to_string()),
                },
            );
        }
    };
    let mut record: RouteRecord = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorBody {
                    error: "bad_json",
                    detail: Some(e.to_string()),
                },
            );
        }
    };

    // Visibility is tri-state on the wire even though `RouteRecord`
    // serde-defaults it: an ABSENT `visibility` key on a re-register
    // preserves the existing route's class rather than silently
    // flipping a private route public (which would fire-announce the
    // private name to coord — one typo'd re-expose = permanent
    // disclosure). Only an explicit `"visibility": "public"` flips.
    // `set-auth` already preserves the class; this closes the same
    // hazard on the register path, for old CLIs (which never send the
    // field) and bare curl alike.
    #[derive(Default, serde::Deserialize)]
    struct VisibilityProbe {
        visibility: Option<Visibility>,
    }
    let probe: VisibilityProbe = serde_json::from_slice(&body).unwrap_or_default();
    if probe.visibility.is_none() {
        if let Some(existing) = api.routes.get(&record.name).await {
            record.visibility = existing.visibility;
        }
    }

    let saved = match api.routes.upsert(record).await {
        Ok(saved) => saved,
        Err(RouteError::Validate(v)) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorBody {
                    error: validate_error_code(&v),
                    detail: Some(v.to_string()),
                },
            );
        }
        Err(e) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &ErrorBody {
                    error: "internal",
                    detail: Some(e.to_string()),
                },
            );
        }
    };

    // Trigger an announce and wait up to ANNOUNCE_WAIT_TIMEOUT for
    // coord's verdict. Four outcomes:
    //
    // - Accepted ⇒ 200 with `pending_announce: false`.
    // - Rejected with `reason: "quota_exceeded"` ⇒ remove the local
    //   route, return 403 `quota_exceeded`. We remove *before*
    //   failing so the operator can retry after deleting another
    //   route; leaving the row would re-announce on next mutation and
    //   re-trip the quota.
    // - Rejected with `reason: "daily_limit_exceeded"` ⇒ remove the
    //   local route, return 429 `daily_limit_exceeded`. Same rollback
    //   reasoning, plus `retry_after_s` carries the wait until the
    //   UTC-midnight reset.
    // - Pending (no ack within budget OR control conn offline) ⇒
    //   200 with `pending_announce: true`. The route stays local; the
    //   next reconnect's hello_ack-triggered announce re-syncs.
    // Private routes are never announced: coord never learns their
    // names, they take no quota, and there is no verdict to wait
    // for.
    if saved.is_private() {
        return json_response(
            StatusCode::OK,
            &RouteRegisterOk {
                name: saved.name.clone(),
                url: None,
                pending_announce: false,
            },
        );
    }

    let state = api.state.read().await.clone();
    let url = match &state {
        Some(s) => build_route_url(&s.alias, &s.parent_domain, &saved),
        None => None,
    };

    match api.announcer.request_and_wait(ANNOUNCE_WAIT_TIMEOUT).await {
        Ok(ack) => {
            if let Some(reject) = ack.rejected.iter().find(|r| r.name == saved.name) {
                // Roll the local table back so a future re-announce
                // doesn't keep tripping the same rejection.
                let _ = api.routes.remove(&saved.name).await;
                return rejection_response(reject, &ack);
            }
            json_response(
                StatusCode::OK,
                &RouteRegisterOk {
                    name: saved.name.clone(),
                    url,
                    pending_announce: false,
                },
            )
        }
        Err(AnnounceWaitError::Pending) => json_response(
            StatusCode::OK,
            &RouteRegisterOk {
                name: saved.name.clone(),
                url,
                pending_announce: true,
            },
        ),
    }
}

/// Map a `RejectedRoute.reason` to the right HTTP status + body shape.
/// - `quota_exceeded` ⇒ 403 `QuotaExceededBody`.
/// - `daily_limit_exceeded` ⇒ 429 `DailyLimitExceededBody` (uses
///   `ack.daily_changes` for `daily_limit` / `changes_today`).
/// - Anything else (forward-compat for new reason codes) ⇒ 403 with
///   the quota body shape and the raw reason string echoed back.
fn rejection_response(
    reject: &p2claw_control_proto::RejectedRoute,
    ack: &crate::route_announcer::AnnounceAck,
) -> Response<ApiBody> {
    if reject.reason == "daily_limit_exceeded" {
        // Pull the counters from `daily_changes`; coord always sends
        // them alongside this reason. Fall back to 0 if absent so we never panic on a
        // malformed ack — operator sees the rejection either way.
        let (daily_limit, changes_today) = ack
            .daily_changes
            .as_ref()
            .map(|dc| (dc.limit.unwrap_or(0), dc.used))
            .unwrap_or((0, 0));
        return json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &DailyLimitExceededBody {
                error: "daily_limit_exceeded",
                daily_limit,
                changes_today,
                retry_after_s: reject.retry_after_s,
                message: "Too many route changes today. Quota resets at the next UTC midnight.",
            },
        );
    }
    json_response(
        StatusCode::FORBIDDEN,
        &QuotaExceededBody {
            error: "quota_exceeded",
            reason: reject.reason.clone(),
            max_apps: ack.max_apps,
            used_apps: ack.used_apps,
            retry_after_s: reject.retry_after_s,
        },
    )
}

// ---- Shares + private-route proxy --------------------------------

/// Wire shape of `GET /v1/shares` and `PUT /v1/shares`.
#[derive(Serialize, Deserialize)]
struct SharesBody {
    shares: Vec<ShareRecord>,
}

async fn get_shares_handler(api: &LocalApi) -> Response<ApiBody> {
    json_response(
        StatusCode::OK,
        &SharesBody {
            shares: api.shares.list(),
        },
    )
}

async fn put_shares_handler(api: &LocalApi, req: Request<Incoming>) -> Response<ApiBody> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorBody {
                    error: "bad_body",
                    detail: Some(e.to_string()),
                },
            );
        }
    };
    let parsed: SharesBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorBody {
                    error: "bad_json",
                    detail: Some(e.to_string()),
                },
            );
        }
    };
    match api.shares.replace(parsed.shares).await {
        Ok(saved) => json_response(StatusCode::OK, &SharesBody { shares: saved }),
        Err(e @ ShareError::Io { .. }) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &ErrorBody {
                error: "internal",
                detail: Some(e.to_string()),
            },
        ),
        Err(e) => json_response(
            StatusCode::BAD_REQUEST,
            &ErrorBody {
                error: "bad_share",
                detail: Some(e.to_string()),
            },
        ),
    }
}

/// Structured failure body for `/v1/proxy`. `stage` distinguishes
/// `resolve` (coord could not name the peer) from `dial` (peer
/// known but unreachable / transport error); a far-side
/// `not_shared` denial is not an error here — its 403 passes
/// through verbatim.
#[derive(Serialize)]
struct ProxyErrorBody {
    error: &'static str,
    stage: &'static str,
    detail: String,
}

fn proxy_failure_response(e: &p2claw_iroh_client::PeerClientError) -> Response<ApiBody> {
    use p2claw_iroh_client::PeerClientError as E;
    let stage = match e {
        E::InvalidUrl(_) | E::Coord(_) | E::NoSuchPeer | E::PeerRevoked | E::RateLimited(_) => {
            "resolve"
        }
        _ => "dial",
    };
    json_response(
        StatusCode::BAD_GATEWAY,
        &ProxyErrorBody {
            error: "proxy_failed",
            stage,
            detail: e.to_string(),
        },
    )
}

fn bad_proxy_path() -> Response<ApiBody> {
    json_response(
        StatusCode::BAD_REQUEST,
        &ErrorBody {
            error: "bad_proxy_path",
            detail: Some("expected /v1/proxy/{peer}/{service}/{path}".into()),
        },
    )
}

fn is_ws_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// `ANY /v1/proxy/{peer}/{service}/{path...}` — forward to private
/// route `{service}` on `{peer}` over iroh. Bodies stream both
/// ways; WebSocket upgrades bridge through the translator's WS
/// verb.
async fn proxy_handler(api: &Arc<LocalApi>, req: Request<Incoming>) -> Response<ApiBody> {
    let path = req.uri().path().to_string();
    let rest = path.strip_prefix("/v1/proxy/").unwrap_or_default();
    let Some((peer, after_peer)) = rest.split_once('/') else {
        return bad_proxy_path();
    };
    let (service, tail) = match after_peer.split_once('/') {
        Some((s, t)) => (s, t),
        None => (after_peer, ""),
    };
    if peer.is_empty() || service.is_empty() {
        return bad_proxy_path();
    }
    // Validate both segments before anything is built from them:
    // `peer` must be a z-base-32 peer id or a well-formed alias
    // label, `service` a valid app name. Everything downstream fails
    // closed on garbage anyway (coord 404s, Host parse rejects), but
    // rejecting here keeps junk out of the coord resolve and turns
    // "mystery 404" into a 400 that names the bad segment.
    let peer_ok = p2claw_identity::PeerId::from_z32(peer).is_ok()
        || p2claw_identity::alias_label::is_valid_alias_label(peer);
    if !peer_ok {
        return json_response(
            StatusCode::BAD_REQUEST,
            &ErrorBody {
                error: "bad_proxy_peer",
                detail: Some(format!(
                    "`{peer}` is neither a z-base-32 peer id nor a valid alias"
                )),
            },
        );
    }
    if p2claw_agent::validate::validate_app_name(service).is_err() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &ErrorBody {
                error: "bad_proxy_service",
                detail: Some(format!("`{service}` is not a valid app name")),
            },
        );
    }
    let Some(cache) = api.peer_proxy.get().cloned() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &ErrorBody {
                error: "proxy_unavailable",
                detail: Some("peer dialer not ready".into()),
            },
        );
    };
    // Dial by bare alias: coord's resolve sees only the peer, never
    // the private route name — that travels solely in the Host
    // header on the iroh leg. Also keys the connection cache
    // per-peer instead of per-(peer, service).
    let dial_host = format!("{peer}.{}", cache.options().parent_domain);
    let target_host = format!("{service}-{peer}.{}", cache.options().parent_domain);
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target_path = format!("/{tail}{query}");

    if is_ws_upgrade(req.headers()) {
        return proxy_ws(cache, req, dial_host, target_host, target_path).await;
    }

    let (mut parts, body) = req.into_parts();
    parts.uri = target_path
        .parse()
        .unwrap_or_else(|_| hyper::Uri::from_static("/"));
    // `forward_request` injects the target host; the local socket's
    // Host header must not travel.
    parts.headers.remove(hyper::header::HOST);
    let req = Request::from_parts(parts, body);
    match p2claw_agent::peer_dialer::forward_request(&cache, req, &dial_host, &target_host).await {
        Ok(resp) => resp,
        Err(e) => proxy_failure_response(&e),
    }
}

/// Headers not forwarded onto the translator WS_UPGRADE: hop-by-hop
/// plus the local handshake mechanics — the far side's dialer
/// regenerates its own, and `host` is set to the target explicitly.
fn is_proxy_ws_excluded_header(name: &str) -> bool {
    const EXCLUDED: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "host",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        "content-length",
    ];
    EXCLUDED.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// WebSocket half of `/v1/proxy`: open the translator WS verb toward
/// the peer first, and only answer 101 to the local caller once the
/// far side accepted — a far-side rejection maps to its HTTP status
/// instead of a doomed upgrade.
async fn proxy_ws(
    cache: Arc<PeerClientCache>,
    mut req: Request<Incoming>,
    dial_host: String,
    target_host: String,
    target_path: String,
) -> Response<ApiBody> {
    let Some(key) = req
        .headers()
        .get(hyper::header::SEC_WEBSOCKET_KEY)
        .map(|v| v.as_bytes().to_vec())
    else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &ErrorBody {
                error: "bad_ws_upgrade",
                detail: Some("missing Sec-WebSocket-Key".into()),
            },
        );
    };

    let mut upgrade =
        p2claw_translator::ClientWsUpgrade::new(Bytes::from(target_path.into_bytes()));
    upgrade = upgrade.header(
        Bytes::from_static(b"host"),
        Bytes::from(target_host.clone().into_bytes()),
    );
    for (name, value) in req.headers() {
        if is_proxy_ws_excluded_header(name.as_str()) {
            continue;
        }
        upgrade = upgrade.header(
            Bytes::copy_from_slice(name.as_str().as_bytes()),
            Bytes::copy_from_slice(value.as_bytes()),
        );
    }

    let client = match cache.client_for(&dial_host).await {
        Ok(c) => c,
        Err(e) => return proxy_failure_response(&e),
    };
    let ws_conn = match client.open_websocket(upgrade).await {
        Ok(c) => c,
        Err(e) => {
            // A far-side rejection arrives as `Cancelled(status)` —
            // pass the status through (`not_shared` rides its 403).
            if let p2claw_iroh_client::PeerClientError::Translator(
                p2claw_translator::TranslatorError::Cancelled(code),
            ) = &e
            {
                if let Ok(status) = StatusCode::from_u16(code.0) {
                    if status == StatusCode::FORBIDDEN {
                        return json_response(status, &serde_json::json!({"error": "not_shared"}));
                    }
                    return json_response(
                        status,
                        &ProxyErrorBody {
                            error: "proxy_failed",
                            stage: "dial",
                            detail: e.to_string(),
                        },
                    );
                }
            }
            cache.invalidate(&dial_host, &client).await;
            return proxy_failure_response(&e);
        }
    };

    // Far side accepted: upgrade the local connection and bridge.
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(&key);
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = hyper_util::rt::TokioIo::new(upgraded);
                let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    io,
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
                p2claw_agent::ws_forwarder::bridge_session(ws, ws_conn).await;
            }
            Err(e) => {
                warn!(error = %e, "proxy: local upgrade failed after far side accepted");
                let _ = ws_conn
                    .close(1011, Bytes::from_static(b"local upgrade failed"))
                    .await;
            }
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "Upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .header(hyper::header::SEC_WEBSOCKET_ACCEPT, accept)
        .body(full_body(Bytes::new()))
        .expect("static 101 response builds")
}

/// Every route is reached at `<name>-<alias>.<parent>`. The apex
/// (`<alias>.<parent>`) is served by the edge as a listing page —
/// the agent never owns it.
fn build_route_url(alias: &str, parent_domain: &str, route: &RouteRecord) -> Option<String> {
    // Private routes have no visitor URL — they are reachable only
    // by peers they are shared with.
    if route.is_private() {
        return None;
    }
    if alias.is_empty() || parent_domain.is_empty() {
        return None;
    }
    Some(format!("https://{}-{alias}.{parent_domain}/", route.name))
}

fn validate_error_code(v: &ValidateError) -> &'static str {
    match v {
        ValidateError::AppName => "bad_app_name",
        ValidateError::ReservedAppName(_) => "reserved_app_name",
        ValidateError::UpstreamParse(_)
        | ValidateError::UpstreamScheme
        | ValidateError::UpstreamNoHost
        | ValidateError::UpstreamPath(_)
        | ValidateError::UpstreamNoPort
        | ValidateError::UpstreamResolve(_, _)
        | ValidateError::UpstreamResolveEmpty(_)
        | ValidateError::UpstreamUnixNotAbsolute(_)
        | ValidateError::UpstreamUnixNotAllowed => "bad_upstream",
        ValidateError::UpstreamNonLoopback(_, _) => "non_loopback_upstream",
        ValidateError::PrivateWithAuth => "private_with_auth",
    }
}

#[derive(Serialize)]
struct IdentityBody {
    peer_id: String,
    alias: Option<String>,
    /// `true` iff this process has loaded its `agent.state`
    /// (registration completed during this run or was already on
    /// disk at boot). Does NOT claim anything about the control-WS
    /// state — same-host callers that want real-time online status
    /// ask coord at `/internal/alias/<alias>`.
    registered: bool,
}

#[derive(Serialize)]
struct StatusBody {
    version: &'static str,
    uptime_secs: u64,
    peer_id: String,
    /// `Some` once registered (mirrors `GET /v1/identity`).
    alias: Option<String>,
    route_count: usize,
    coord: CoordStatus,
}

#[derive(Serialize)]
struct CoordStatus {
    /// `connected` (past hello_ack) / `connecting` (dialing) /
    /// `disconnected`. The agent's own view of its control link —
    /// NOT a claim about end-to-end reachability.
    state: &'static str,
    /// Seconds the connection has held its current `state`.
    since_secs: u64,
    /// Seconds since the last `route_announce_ack` — evidence the
    /// link is actually round-tripping. `None` if no ack yet.
    last_ack_age_secs: Option<u64>,
}

#[derive(Serialize)]
struct SessionsBody {
    count: usize,
    sessions: Vec<SessionEntry>,
}

#[derive(Serialize)]
struct SessionEntry {
    id: String,
    /// `browser` (WebRTC visitor session) or `iroh` (inbound iroh
    /// connection — an edge-tunnel or native-client link, which may
    /// carry pooled traffic for many visitors).
    kind: &'static str,
    /// `direct` / `relay` / `unknown` (best-effort network path).
    transport: &'static str,
    age_secs: u64,
}

#[derive(Serialize)]
struct RoutesListBody {
    routes: Vec<RouteWithUrl>,
}

/// A route record plus the visitor-facing URL, assembled from the
/// agent's alias + parent domain.
/// The `url` is `null` when the agent has no state (pre-registration)
/// or when either the alias or parent domain is empty.
#[derive(Serialize)]
struct RouteWithUrl {
    #[serde(flatten)]
    route: RouteRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RouteRegisterOk {
    name: String,
    url: Option<String>,
    /// `true` when the local upsert succeeded but the agent could not
    /// confirm with coord within the announce budget (control conn
    /// offline, or coord slow). The route is still live locally; the
    /// next reconnect's hello_ack-triggered announce re-syncs.
    #[serde(default)]
    pending_announce: bool,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Body of the 403 `POST /v1/routes` response when coord's
/// `route_announce_ack` rejects the route with `reason:
/// "quota_exceeded"` (peer is at `max_apps`). `retry_after_s` is
/// `None` for this reason — the only way out is `DELETE`-ing an
/// existing route or upgrading tier. Future reason codes that share
/// the 403 shape may set it.
#[derive(Serialize)]
struct QuotaExceededBody {
    error: &'static str,
    reason: String,
    max_apps: u32,
    used_apps: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_s: Option<u64>,
}

/// Body of the 429 `POST /v1/routes` response when coord rejects the
/// route with `reason: "daily_limit_exceeded"`. `daily_limit` /
/// `changes_today` come from the ack's `daily_changes` block;
/// `retry_after_s` is seconds until the next UTC-midnight reset.
#[derive(Serialize)]
struct DailyLimitExceededBody {
    error: &'static str,
    daily_limit: u32,
    changes_today: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_s: Option<u64>,
    message: &'static str,
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<ApiBody> {
    let bytes = match serde_json::to_vec(body) {
        Ok(b) => b,
        // Infallible for the concrete types above; keep a fallback
        // just in case a future caller passes something exotic.
        Err(_) => br#"{"error":"serialize_failed"}"#.to_vec(),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(bytes)))
        .expect("response builder infallible for these inputs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_announcer::{AnnounceAck, AnnounceJob, AnnouncerInbox};
    use p2claw_control_proto::{DailyChanges, RejectedRoute};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// What the test's stand-in for `control_conn::session` should
    /// answer with for every inbound `AnnounceJob`. Real coord is
    /// modeled separately by [`spawn_acker`]; tests that need to
    /// suppress the ack entirely (offline-control case) just don't
    /// spawn one.
    #[derive(Clone)]
    pub(super) enum AckMode {
        AcceptAll,
        RejectName {
            name: String,
            reason: String,
            retry_after_s: Option<u64>,
            /// Populated only for `daily_limit_exceeded` to mirror
            /// what coord sends.
            /// Omitted (`None`) for `quota_exceeded`.
            daily_changes: Option<DailyChanges>,
        },
    }

    /// Drive an `AnnouncerInbox` like `control_conn::session` would,
    /// fulfilling every `AnnounceJob` with a canned ack. Lets local-
    /// API tests run without any WebSocket plumbing.
    fn spawn_acker(mut inbox: AnnouncerInbox, mode: AckMode) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(AnnounceJob::Send { reply }) = inbox.job_rx.recv().await {
                let ack = match &mode {
                    AckMode::AcceptAll => AnnounceAck {
                        accepted: vec![],
                        rejected: vec![],
                        max_apps: 100,
                        used_apps: 0,
                        daily_changes: None,
                        accepted_apps: vec![],
                    },
                    AckMode::RejectName {
                        name,
                        reason,
                        retry_after_s,
                        daily_changes,
                    } => AnnounceAck {
                        accepted: vec![],
                        rejected: vec![RejectedRoute {
                            name: name.clone(),
                            reason: reason.clone(),
                            retry_after_s: *retry_after_s,
                        }],
                        max_apps: 3,
                        used_apps: 3,
                        daily_changes: daily_changes.clone(),
                        accepted_apps: vec![],
                    },
                };
                inbox.store_latest(ack.clone()).await;
                if let Some(tx) = reply {
                    let _ = tx.send(ack);
                }
            }
        })
    }

    /// A `Disconnected` coord-health receiver whose sender is leaked so
    /// the channel stays open for the test's lifetime. Most tests don't
    /// exercise `/v1/status`; this is a neutral baseline.
    fn disconnected_health() -> watch::Receiver<crate::auto_upgrade::CoordHealth> {
        let (tx, rx) = watch::channel(crate::auto_upgrade::CoordHealth::Disconnected);
        Box::leak(Box::new(tx));
        rx
    }

    /// Stand-in for the coord session's email side: acks every config
    /// with one address (recorded into the settings first, as the
    /// session does) and answers `rejected` with a fixed table.
    fn spawn_email_coord(mut inbox: crate::email_link::EmailLinkInbox, email: EmailShared) {
        use crate::email_link::{ConfigAck, EmailJob};
        tokio::spawn(async move {
            while let Some(job) = inbox.job_rx.recv().await {
                match job {
                    EmailJob::SendConfig { reply } => {
                        let addresses = vec!["y9abcdefghijk@p2claw.com".to_string()];
                        email
                            .settings
                            .record_ack(addresses.clone(), None)
                            .await
                            .unwrap();
                        if let Some(tx) = reply {
                            let _ = tx.send(ConfigAck {
                                addresses,
                                error: None,
                            });
                        }
                    }
                    EmailJob::Rejected { reply } => {
                        let mut r = p2claw_control_proto::EmailRejections {
                            admitted_today: 2,
                            daily_limit: 1000,
                            ..Default::default()
                        };
                        r.totals.insert("not_allowed".into(), 3);
                        r.recent.push(p2claw_control_proto::RejectedSender {
                            from: "spam@example.net".into(),
                            reason: "not_allowed".into(),
                            count: 3,
                            last_seen: 1_791_126_131,
                        });
                        let _ = reply.send(Ok(r));
                    }
                }
            }
        });
    }

    /// Build a `LocalApi` whose announcer is wired to a default
    /// AcceptAll acker — keeps existing tests insulated from the
    /// route-announce machinery.
    fn make_api() -> (
        Arc<LocalApi>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        make_api_with_ack(AckMode::AcceptAll)
    }

    fn make_api_with_ack(
        mode: AckMode,
    ) -> (
        Arc<LocalApi>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        make_api_with_broker(mode, "http://127.0.0.1:9")
    }

    /// Grant manager against `broker_url`, storing under `dir`.
    pub(super) fn test_oauth_grants(
        sk: &Arc<SigningKey>,
        dir: &Path,
        broker_url: &str,
    ) -> Arc<OauthGrants> {
        let broker =
            p2claw_agent::oauth_grants::BrokerClient::new(broker_url, Arc::clone(sk)).unwrap();
        let store =
            p2claw_agent::oauth_grants::GrantStore::load_or_empty(dir.join("oauth-grants.json"));
        Arc::new(OauthGrants::new(broker, store))
    }

    pub(super) fn make_api_with_broker(
        mode: AckMode,
        broker_url: &str,
    ) -> (
        Arc<LocalApi>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let routes = RouteTable::load_or_empty(tmp.path().join("routes.json"));
        let sk = Arc::new(SigningKey::generate());
        let oauth_grants = test_oauth_grants(&sk, tmp.path(), broker_url);
        let (announcer, inbox) = RouteAnnouncer::new();
        let acker = spawn_acker(inbox, mode);
        let (email_link, email_inbox) = EmailLink::new();
        let email = EmailShared::load(tmp.path());
        spawn_email_coord(email_inbox, email.clone());
        let api = Arc::new(LocalApi::new(
            sk,
            Some(AgentState {
                alias: "y9abcdefghijk".into(),
                coord_domain: "coord.p2claw.com".into(),
                parent_domain: "p2claw.com".into(),
                // local_api never reads coord_root_pubkey; sentinel ok.
                coord_root_pubkey: p2claw_identity::PeerId::from_bytes([0u8; 32]),
                // local_api never reads the iroh-addr fields either;
                // empties are fine for these test fixtures.
                coord_iroh_relay_url: None,
                coord_iroh_direct_addrs: Vec::new(),
            }),
            routes,
            announcer,
            std::time::Instant::now(),
            disconnected_health(),
            Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
            Arc::new(std::sync::OnceLock::new()),
            Arc::new(std::sync::OnceLock::new()),
            Shares::load_or_empty(tmp.path().join("shares.json")),
            Arc::new(std::sync::OnceLock::new()),
            email,
            email_link,
            oauth_grants,
        ));
        (api, acker, tmp)
    }

    /// Build a `LocalApi` with **no** acker attached — every request
    /// to `request_and_wait` will time out. Used to test the
    /// `pending_announce: true` graceful-degrade path.
    fn make_api_offline_control() -> (Arc<LocalApi>, AnnouncerInbox, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let routes = RouteTable::load_or_empty(tmp.path().join("routes.json"));
        let sk = Arc::new(SigningKey::generate());
        let oauth_grants = test_oauth_grants(&sk, tmp.path(), "http://127.0.0.1:9");
        let (announcer, inbox) = RouteAnnouncer::new();
        let api = Arc::new(LocalApi::new(
            sk,
            Some(AgentState {
                alias: "y9abcdefghijk".into(),
                coord_domain: "coord.p2claw.com".into(),
                parent_domain: "p2claw.com".into(),
                // local_api never reads coord_root_pubkey; sentinel ok.
                coord_root_pubkey: p2claw_identity::PeerId::from_bytes([0u8; 32]),
                // local_api never reads the iroh-addr fields either;
                // empties are fine for these test fixtures.
                coord_iroh_relay_url: None,
                coord_iroh_direct_addrs: Vec::new(),
            }),
            routes,
            announcer,
            std::time::Instant::now(),
            disconnected_health(),
            Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
            Arc::new(std::sync::OnceLock::new()),
            Arc::new(std::sync::OnceLock::new()),
            Shares::load_or_empty(tmp.path().join("shares.json")),
            Arc::new(std::sync::OnceLock::new()),
            EmailShared::load(tmp.path()),
            EmailLink::new().0,
            oauth_grants,
        ));
        (api, inbox, tmp)
    }

    pub(super) async fn http_over_uds(sock: &Path, raw: &[u8]) -> String {
        let mut s = UnixStream::connect(sock).await.unwrap();
        s.write_all(raw).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    async fn with_server<F, Fut>(f: F)
    where
        F: FnOnce(std::path::PathBuf, Arc<LocalApi>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let (api, _acker, _rtmp) = make_api();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });

        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(sock.exists(), "socket did not appear");

        f(sock, api).await;

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn get_identity_returns_peer_id_and_alias() {
        with_server(|sock, _api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("200 OK"), "unexpected response:\n{text}");
            assert!(
                text.contains("\"alias\":\"y9abcdefghijk\""),
                "missing alias:\n{text}"
            );
            assert!(text.contains("\"peer_id\":"), "missing peer_id:\n{text}");
            // Default fixture has Some(state), so registered:true.
            assert!(
                text.contains("\"registered\":true"),
                "expected registered:true on a registered fixture:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn get_status_reports_live_fields() {
        with_server(|sock, _api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("200 OK"), "unexpected response:\n{text}");
            assert!(text.contains("\"version\":"), "missing version:\n{text}");
            assert!(text.contains("\"uptime_secs\":"), "missing uptime:\n{text}");
            assert!(
                text.contains("\"route_count\":"),
                "missing route_count:\n{text}"
            );
            assert!(
                text.contains("\"alias\":\"y9abcdefghijk\""),
                "missing alias:\n{text}"
            );
            // The fixture wires a `Disconnected` coord-health receiver.
            assert!(
                text.contains("\"state\":\"disconnected\""),
                "expected disconnected coord state on the fixture:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn get_sessions_empty_without_registry() {
        // The fixture never wires a signal registry, so the endpoint
        // must degrade to an empty list rather than error.
        with_server(|sock, _api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/sessions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("200 OK"), "unexpected response:\n{text}");
            assert!(
                text.contains("\"count\":0"),
                "expected zero sessions:\n{text}"
            );
            assert!(
                text.contains("\"sessions\":[]"),
                "expected empty sessions array:\n{text}"
            );
        })
        .await;
    }

    /// An agent process that hasn't yet completed registration
    /// (no `agent.state` loaded) must report `registered: false` on
    /// `GET /v1/identity`, and omit `alias`. Today's `cmd_run` only
    /// brings the local API up *after* registration succeeds, so this
    /// is mostly an honesty check — but it also pins the contract for
    /// any future shape that exposes the local-API earlier.
    #[tokio::test]
    async fn get_identity_returns_registered_false_when_no_state() {
        let tmp = tempfile::tempdir().unwrap();
        let routes = RouteTable::load_or_empty(tmp.path().join("routes.json"));
        let (announcer, _inbox) = RouteAnnouncer::new();
        let sk = Arc::new(SigningKey::generate());
        let api = Arc::new(LocalApi::new(
            Arc::clone(&sk),
            None,
            routes,
            announcer,
            std::time::Instant::now(),
            disconnected_health(),
            Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
            Arc::new(std::sync::OnceLock::new()),
            Arc::new(std::sync::OnceLock::new()),
            Shares::load_or_empty(tmp.path().join("shares.json")),
            Arc::new(std::sync::OnceLock::new()),
            EmailShared::load(tmp.path()),
            EmailLink::new().0,
            test_oauth_grants(&sk, tmp.path(), "http://127.0.0.1:9"),
        ));

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sock.exists(), "socket did not appear");

        let text = http_over_uds(
            &sock,
            b"GET /v1/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(text.contains("200 OK"), "unexpected response:\n{text}");
        assert!(
            text.contains("\"registered\":false"),
            "expected registered:false pre-registration:\n{text}"
        );
        // No alias when state is None — keeps the body shape honest.
        assert!(
            !text.contains("\"alias\":\""),
            "alias must be omitted (or null) when registered:false:\n{text}"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        with_server(|sock, _api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/does-not-exist HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("404"), "unexpected response:\n{text}");
            assert!(text.contains("\"not_found\""), "missing body:\n{text}");
        })
        .await;
    }

    #[tokio::test]
    async fn post_route_registers_and_lists() {
        with_server(|sock, _api| async move {
            // URL form `<name>-<alias>.<parent>`. The apex
            // (`<alias>.<parent>`) is the edge listing page; the
            // agent never owns it.
            let body = br#"{"name":"recipes","upstream":"http://127.0.0.1:5173"}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("200 OK"), "register failed:\n{text}");
            assert!(
                text.contains("\"url\":\"https://recipes-y9abcdefghijk.p2claw.com/\"")
                    || text.contains("\"url\": \"https://recipes-y9abcdefghijk.p2claw.com/\""),
                "expected full URL in response body:\n{text}"
            );
            assert!(
                !text.contains("\"default\""),
                "register response must not echo the dropped `default` field:\n{text}"
            );

            // GET list.
            let text = http_over_uds(
                &sock,
                b"GET /v1/routes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(
                text.contains("\"name\":\"recipes\""),
                "list missing route:\n{text}"
            );
            assert!(
                !text.contains("\"default\""),
                "list must not emit the dropped `default` field:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn post_route_rejects_reserved_name() {
        with_server(|sock, _api| async move {
            let body = br#"{"name":"admin","upstream":"http://127.0.0.1:5173"}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("400"), "expected 400:\n{text}");
            assert!(
                text.contains("\"reserved_app_name\""),
                "missing error code:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn post_route_rejects_non_loopback_upstream() {
        with_server(|sock, _api| async move {
            let body = br#"{"name":"evil","upstream":"http://8.8.8.8:80"}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("400"), "expected 400:\n{text}");
            assert!(
                text.contains("\"non_loopback_upstream\""),
                "missing error code:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn post_route_rejects_https_scheme() {
        with_server(|sock, _api| async move {
            let body = br#"{"name":"secure","upstream":"https://127.0.0.1:5173"}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("400"), "expected 400:\n{text}");
            assert!(
                text.contains("\"bad_upstream\""),
                "missing error code:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn delete_route_removes() {
        with_server(|sock, _api| async move {
            let body = br#"{"name":"recipes","upstream":"http://127.0.0.1:5173"}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let _ = http_over_uds(&sock, &full).await;

            let text = http_over_uds(
                &sock,
                b"DELETE /v1/routes/recipes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("204 No Content"), "delete failed:\n{text}");

            let text = http_over_uds(
                &sock,
                b"DELETE /v1/routes/recipes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("404"), "second delete should 404:\n{text}");
        })
        .await;
    }

    #[tokio::test]
    async fn get_one_route_404() {
        with_server(|sock, _api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/routes/ghost HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("404"), "expected 404:\n{text}");
        })
        .await;
    }

    #[tokio::test]
    async fn post_route_ignores_legacy_passthrough_hosts_field() {
        // Legacy callers still POST `passthrough_hosts`. The field
        // was dropped from the route record; serde ignores
        // unknown fields by default, so the request must succeed and
        // the response must not echo the field back.
        with_server(|sock, _api| async move {
            let body = br#"{"name":"legacy","upstream":"http://127.0.0.1:5173","passthrough_hosts":["fonts.googleapis.com","*.example.com"],"default":false}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("200 OK"), "legacy POST should succeed:\n{text}");
            assert!(
                !text.contains("passthrough_hosts"),
                "response must not echo the dropped field:\n{text}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn post_route_with_legacy_default_field_returns_named_url() {
        // Old callers may still POST `"default":true`. The agent
        // ignores the field and always emits the named subdomain
        // form; the apex is never owned by the agent (there is no
        // default-route concept).
        with_server(|sock, _api| async move {
            let body = br#"{"name":"site","upstream":"http://127.0.0.1:5173","default":true}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("200 OK"), "register failed:\n{text}");
            assert!(
                text.contains("\"url\":\"https://site-y9abcdefghijk.p2claw.com/\"")
                    || text.contains("\"url\": \"https://site-y9abcdefghijk.p2claw.com/\""),
                "expected named URL even with legacy `default:true`:\n{text}"
            );
        })
        .await;
    }

    /// `POST /v1/routes` happy path emits exactly one `AnnounceJob`
    /// (the post-mutation announce) and surfaces `pending_announce:
    /// false` because the AcceptAll acker resolves it inside the 2s
    /// budget. Inverse-asserts the legacy "200 + nothing else" shape
    /// to make sure the field shows up on the wire.
    #[tokio::test]
    async fn post_route_accepts_returns_pending_announce_false() {
        with_server(|sock, _api| async move {
            let body = br#"{"name":"recipes","upstream":"http://127.0.0.1:5173"}"#;
            let req = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = req.into_bytes();
            full.extend_from_slice(body);
            let text = http_over_uds(&sock, &full).await;
            assert!(text.contains("200 OK"), "register failed:\n{text}");
            assert!(
                text.contains("\"pending_announce\":false"),
                "expected pending_announce:false:\n{text}"
            );
        })
        .await;
    }

    /// `POST /v1/routes` with a coord stub that rejects the route
    /// with `reason: "quota_exceeded"` returns 403 and rolls the
    /// local table back so a future re-announce doesn't keep tripping
    /// the same quota.
    #[tokio::test]
    async fn post_route_returns_403_when_quota_exceeded() {
        let (api, _acker, _tmp) = make_api_with_ack(AckMode::RejectName {
            name: "extra".into(),
            reason: "quota_exceeded".into(),
            retry_after_s: None,
            daily_changes: None,
        });
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        let body = br#"{"name":"extra","upstream":"http://127.0.0.1:5173"}"#;
        let req = format!(
            "POST /v1/routes HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let mut full = req.into_bytes();
        full.extend_from_slice(body);
        let text = http_over_uds(&sock, &full).await;
        assert!(text.contains("403"), "expected 403:\n{text}");
        assert!(
            text.contains("\"quota_exceeded\""),
            "expected quota_exceeded reason in body:\n{text}"
        );
        // And the local table was rolled back — list returns no row.
        assert!(
            api.routes.list().await.is_empty(),
            "route should have been removed after rejection"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    /// `POST /v1/routes` with a coord stub that rejects the route
    /// with `reason: "daily_limit_exceeded"` returns **429**
    /// (not 403): `daily_limit` /
    /// `changes_today` come from the ack's `daily_changes` block,
    /// `retry_after_s` mirrors the rejection. Local table is rolled
    /// back; no point keeping a row coord refused.
    #[tokio::test]
    async fn post_route_returns_429_when_daily_limit_exceeded() {
        let (api, _acker, _tmp) = make_api_with_ack(AckMode::RejectName {
            name: "extra".into(),
            reason: "daily_limit_exceeded".into(),
            retry_after_s: Some(43200),
            daily_changes: Some(DailyChanges {
                used: 20,
                limit: Some(20),
                resets_at: 1767398400,
            }),
        });
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        let body = br#"{"name":"extra","upstream":"http://127.0.0.1:5173"}"#;
        let req = format!(
            "POST /v1/routes HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let mut full = req.into_bytes();
        full.extend_from_slice(body);
        let text = http_over_uds(&sock, &full).await;
        assert!(text.contains("429"), "expected 429:\n{text}");
        assert!(
            text.contains("\"daily_limit_exceeded\""),
            "expected daily_limit_exceeded error in body:\n{text}"
        );
        assert!(
            text.contains("\"daily_limit\":20"),
            "expected daily_limit:20 from ack.daily_changes.limit:\n{text}"
        );
        assert!(
            text.contains("\"changes_today\":20"),
            "expected changes_today:20 from ack.daily_changes.used:\n{text}"
        );
        assert!(
            text.contains("\"retry_after_s\":43200"),
            "expected retry_after_s:43200 from rejection:\n{text}"
        );
        // 403 path's quota counters must not leak into the 429 body.
        assert!(
            !text.contains("\"quota_exceeded\""),
            "429 body must not carry the 403 reason:\n{text}"
        );
        assert!(
            !text.contains("\"max_apps\""),
            "429 body must not carry quota counters:\n{text}"
        );
        // Rolled back same as the 403 path.
        assert!(
            api.routes.list().await.is_empty(),
            "route should have been removed after rejection"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    /// `POST /v1/routes` with no acker attached (control conn down)
    /// returns 200 with `pending_announce: true` — the route is
    /// preserved locally and the next reconnect's hello_ack-triggered
    /// announce re-syncs.
    #[tokio::test(start_paused = true)]
    async fn post_route_returns_pending_announce_true_when_control_offline() {
        let (api, _inbox, _tmp) = make_api_offline_control();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        // start_paused = true means no real time elapses; advance by
        // hand instead of polling for the socket.
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        // Spawn the request, then advance the virtual clock past the
        // 2s announce budget — `request_and_wait` has no real listener
        // (the inbox just sits in the closure) so it must time out
        // and return Pending.
        let body = br#"{"name":"orphan","upstream":"http://127.0.0.1:5173"}"#;
        let req = format!(
            "POST /v1/routes HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let mut full = req.into_bytes();
        full.extend_from_slice(body);
        let req_task = tokio::spawn(async move { http_over_uds(&sock, &full).await });
        tokio::time::advance(Duration::from_secs(3)).await;
        let text = req_task.await.expect("req task");
        assert!(text.contains("200 OK"), "expected 200:\n{text}");
        assert!(
            text.contains("\"pending_announce\":true"),
            "expected pending_announce:true:\n{text}"
        );
        // Route stays local — operator can keep using it.
        assert_eq!(api.routes.list().await.len(), 1);

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    /// `DELETE /v1/routes/<name>` enqueues an `AnnounceJob` so coord
    /// learns about the removal even though the response doesn't wait
    /// for the ack.
    #[tokio::test]
    async fn delete_route_emits_announce_job() {
        let (api, mut inbox, _tmp) = make_api_offline_control();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        // Seed a route directly so the DELETE has something to remove.
        // Bypasses POST so we can drain the inbox cleanly afterwards.
        api.routes
            .upsert(RouteRecord {
                name: "doomed".into(),
                upstream: "http://127.0.0.1:5173".into(),
                registered_at: 0,
                auth: Vec::new(),
                ..Default::default()
            })
            .await
            .unwrap();

        let _ = http_over_uds(
            &sock,
            b"DELETE /v1/routes/doomed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        // The DELETE handler fires `request_fire_and_forget` after a
        // successful remove; the inbox should see exactly one job
        // with `reply: None`.
        let job = tokio::time::timeout(Duration::from_secs(1), inbox.job_rx.recv())
            .await
            .expect("announce job arrives within 1s")
            .expect("inbox not closed");
        match job {
            AnnounceJob::Send { reply } => {
                assert!(
                    reply.is_none(),
                    "DELETE-driven announce must not block on ack"
                );
            }
        }

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    /// `POST /v1/routes` enqueues exactly one `AnnounceJob` with a
    /// reply slot — used by the announce-and-wait path. Pairs with
    /// the DELETE test above so future readers can see the difference
    /// between blocking + non-blocking emit.
    #[tokio::test]
    async fn post_route_emits_announce_job_with_reply() {
        let (api, mut inbox, _tmp) = make_api_offline_control();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        // Drain in a background task so the POST doesn't block the
        // test on the 2s announce budget.
        let drainer = tokio::spawn(async move {
            let job = inbox.job_rx.recv().await.expect("job");
            match job {
                AnnounceJob::Send { reply } => {
                    let tx = reply.expect("POST-driven announce carries a reply slot");
                    let _ = tx.send(AnnounceAck {
                        accepted: vec!["fresh".into()],
                        rejected: vec![],
                        max_apps: 3,
                        used_apps: 1,
                        daily_changes: None,
                        accepted_apps: vec![],
                    });
                }
            }
        });

        let body = br#"{"name":"fresh","upstream":"http://127.0.0.1:5173"}"#;
        let req = format!(
            "POST /v1/routes HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let mut full = req.into_bytes();
        full.extend_from_slice(body);
        let text = http_over_uds(&sock, &full).await;
        assert!(text.contains("200 OK"));
        assert!(text.contains("\"pending_announce\":false"));
        drainer.await.expect("drainer task");

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    /// `POST /v1/routes` with `visibility: private` succeeds without
    /// waiting on coord (no announce job is emitted), returns no
    /// visitor URL, and the route lists with `url` omitted.
    #[tokio::test]
    async fn post_private_route_skips_announce_and_has_no_url() {
        // Offline-control fixture: a public POST would block on the
        // 2s announce budget; the private path must return at once.
        let (api, mut inbox, _tmp) = make_api_offline_control();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        let body = br#"{"name":"mysvc","upstream":"http://127.0.0.1:5173","visibility":"private"}"#;
        let req = format!(
            "POST /v1/routes HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let mut full = req.into_bytes();
        full.extend_from_slice(body);
        let text = tokio::time::timeout(Duration::from_secs(1), http_over_uds(&sock, &full))
            .await
            .expect("private POST must not wait on the announce budget");
        assert!(text.contains("200 OK"), "register failed:\n{text}");
        assert!(
            text.contains("\"url\":null"),
            "private route must have no visitor URL:\n{text}"
        );
        // No announce job was queued.
        assert!(
            inbox.job_rx.try_recv().is_err(),
            "private route registration must not announce to coord"
        );

        // List: the private route appears, with no `url` key.
        let text = http_over_uds(
            &sock,
            b"GET /v1/routes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(text.contains("\"name\":\"mysvc\""), "{text}");
        assert!(
            text.contains("\"visibility\":\"private\""),
            "list must carry the route class:\n{text}"
        );
        assert!(
            !text.contains("mysvc-y9abcdefghijk"),
            "no visitor URL may be built for a private route:\n{text}"
        );

        // DELETE of a private route also skips the announce.
        let _ = http_over_uds(
            &sock,
            b"DELETE /v1/routes/mysvc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            inbox.job_rx.try_recv().is_err(),
            "private route removal must not announce to coord"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    /// A re-register WITHOUT a `visibility` key preserves the
    /// existing route's class — a bare `apps expose` (old CLI, or a
    /// typo'd re-expose) cannot silently flip a private route public
    /// and fire-announce its name to coord. An explicit
    /// `"visibility":"public"` still flips deliberately.
    #[tokio::test]
    async fn reregister_without_visibility_preserves_private() {
        let (api, mut inbox, _tmp) = make_api_offline_control();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        let post = |body: &'static [u8]| {
            let head = format!(
                "POST /v1/routes HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let mut full = head.into_bytes();
            full.extend_from_slice(body);
            full
        };

        // Register private, then re-register with NO visibility key
        // (different port — the typo'd-re-expose shape).
        let text = tokio::time::timeout(
            Duration::from_secs(1),
            http_over_uds(
                &sock,
                &post(br#"{"name":"mysvc","upstream":"http://127.0.0.1:5173","visibility":"private"}"#),
            ),
        )
        .await
        .expect("private register");
        assert!(text.contains("200 OK"), "{text}");

        let text = tokio::time::timeout(
            Duration::from_secs(1),
            http_over_uds(
                &sock,
                &post(br#"{"name":"mysvc","upstream":"http://127.0.0.1:5174"}"#),
            ),
        )
        .await
        .expect("bare re-register must not block on an announce (stays private)");
        assert!(text.contains("200 OK"), "{text}");
        assert!(
            text.contains("\"url\":null"),
            "route must STAY private on a bare re-register:\n{text}"
        );
        let route = api.routes.get("mysvc").await.unwrap();
        assert!(route.is_private(), "visibility flipped on bare re-register");
        assert_eq!(route.upstream, "http://127.0.0.1:5174");
        assert!(
            inbox.job_rx.try_recv().is_err(),
            "no announce may fire while the route stays private"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    /// `GET /v1/shares` starts empty; `PUT` replaces the set and the
    /// stored rows come back on the next `GET`. Invalid peers 400.
    #[tokio::test]
    async fn shares_endpoints_roundtrip_and_validate() {
        with_server(|sock, api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/shares HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            assert!(
                text.contains("\"shares\":[]"),
                "expected empty set:\n{text}"
            );

            let peer = SigningKey::generate().peer_id().to_z32();
            let body = format!(r#"{{"shares":[{{"app":"mysvc","peers":["{peer}"]}}]}}"#);
            let req = format!(
                "PUT /v1/shares HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let text = http_over_uds(&sock, req.as_bytes()).await;
            assert!(text.contains("200 OK"), "PUT failed:\n{text}");
            assert!(
                text.contains(&peer),
                "saved set must echo the peer:\n{text}"
            );

            // Live for the enforcement side too — same store instance.
            assert!(api.shares.is_shared("mysvc", &peer));

            let text = http_over_uds(
                &sock,
                b"GET /v1/shares HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(
                text.contains(&peer),
                "GET must return the stored row:\n{text}"
            );

            // Invalid peer id → 400, store untouched.
            let body = r#"{"shares":[{"app":"mysvc","peers":["nope"]}]}"#;
            let req = format!(
                "PUT /v1/shares HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let text = http_over_uds(&sock, req.as_bytes()).await;
            assert!(text.contains("400"), "expected 400:\n{text}");
            assert!(text.contains("\"bad_share\""), "{text}");
            assert!(
                api.shares.is_shared("mysvc", &peer),
                "store must be untouched"
            );
        })
        .await;
    }

    /// `/v1/proxy` without a wired peer-connection cache answers 503;
    /// malformed paths answer 400.
    #[tokio::test]
    async fn proxy_unwired_and_bad_paths() {
        with_server(|sock, _api| async move {
            let text = http_over_uds(
                &sock,
                b"GET /v1/proxy/somepeer/mysvc/hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("503"), "expected 503 before wiring:\n{text}");
            assert!(text.contains("\"proxy_unavailable\""), "{text}");

            let text = http_over_uds(
                &sock,
                b"GET /v1/proxy/onlypeer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("400"), "expected 400:\n{text}");
            assert!(text.contains("\"bad_proxy_path\""), "{text}");
        })
        .await;
    }

    /// `/v1/proxy` with a cache whose coord is unreachable maps the
    /// failure to 502 with `stage: "resolve"`.
    #[tokio::test]
    async fn proxy_resolve_failure_maps_to_502_resolve() {
        with_server(|sock, api| async move {
            // 127.0.0.1:9 (discard) — nothing listens there.
            let opts = p2claw_iroh_client::ClientOptions {
                parent_domain: "p2claw.com".into(),
                coord_url: Some("http://127.0.0.1:9".into()),
                timeout: Duration::from_secs(2),
                endpoint: None,
                relay_url: None,
            };
            let _ = api
                .peer_proxy
                .set(Arc::new(PeerClientCache::new(opts)));

            let text = http_over_uds(
                &sock,
                b"GET /v1/proxy/blue-otter-7392/mysvc/hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("502"), "expected 502:\n{text}");
            assert!(text.contains("\"proxy_failed\""), "{text}");
            assert!(
                text.contains("\"stage\":\"resolve\""),
                "coord-unreachable must map to the resolve stage:\n{text}"
            );
        })
        .await;
    }

    /// `/v1/proxy` happy path against a real far-side box: two
    /// in-process iroh endpoints, an in-process coord `/v1/connect`
    /// stub, and a private route on the far side. The far side's
    /// 403 `not_shared` passes through until the share lands; then
    /// the request round-trips with the URI rewritten and the
    /// caller's peer id injected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_end_to_end_deny_then_allow() {
        use iroh::endpoint::presets;
        use iroh::{Endpoint, RelayMode, SecretKey};
        use p2claw_agent::iroh_listener::{serve_endpoint_per_peer, P2CLAW_ALPN};
        use p2claw_agent::routes::Visibility;

        const PARENT: &str = "p2claw.com";
        const REMOTE_ALIAS: &str = "blue-otter-7392";

        // ---- Far side (box B): echo upstream + private route ------
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let mut body = format!(
                            "pq={}\n",
                            req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
                        );
                        for (name, value) in req.headers() {
                            if name.as_str().starts_with("x-p2claw-") {
                                body.push_str(&format!(
                                    "hdr:{}={}\n",
                                    name.as_str(),
                                    value.to_str().unwrap_or("<bad>")
                                ));
                            }
                        }
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let remote_dir = tempfile::tempdir().unwrap();
        let remote_routes = RouteTable::load_or_empty(remote_dir.path().join("routes.json"));
        remote_routes
            .upsert(RouteRecord {
                name: "mysvc".into(),
                upstream: format!("http://127.0.0.1:{upstream_port}"),
                visibility: Visibility::Private,
                ..Default::default()
            })
            .await
            .unwrap();
        let remote_shares = Shares::load_or_empty(remote_dir.path().join("shares.json"));
        let remote_forwarder = p2claw_agent::forwarder::Forwarder::new_with_shares(
            remote_routes,
            PARENT.into(),
            None,
            None,
            Some(remote_shares.clone()),
        );

        let remote_seed = SigningKey::generate().seed();
        let remote_sk = SecretKey::from_bytes(&remote_seed);
        let remote_z32 = remote_sk.public().to_z32();
        let remote_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![P2CLAW_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .secret_key(remote_sk)
            .bind()
            .await
            .expect("bind remote endpoint");
        let remote_port = remote_endpoint
            .bound_sockets()
            .iter()
            .find_map(|s| s.is_ipv4().then(|| s.port()))
            .expect("ipv4 socket");
        let (addrs_tx, _addrs_rx) = watch::channel(Vec::new());
        let (remote_sd_tx, remote_sd_rx) = watch::channel(false);
        let remote_handle = tokio::spawn({
            let endpoint = remote_endpoint.clone();
            async move {
                serve_endpoint_per_peer(
                    endpoint,
                    addrs_tx,
                    remote_sd_rx,
                    move |remote| (remote_forwarder.for_peer(remote.to_z32()), None),
                    None,
                )
                .await
            }
        });

        // ---- Coord stub: /v1/connect resolves the far side --------
        let coord = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let coord_url = format!("http://{}", coord.local_addr().unwrap());
        let connect_body = serde_json::json!({
            "peer_id": remote_z32,
            "iroh_node_id": remote_z32,
            "iroh_direct_addrs": [format!("127.0.0.1:{remote_port}")],
        })
        .to_string();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = coord.accept().await else {
                    return;
                };
                let connect_body = connect_body.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |_req: Request<Incoming>| {
                        let body = connect_body.clone();
                        async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        // ---- Near side (box A): local API + proxy cache -----------
        let (api, _acker, _rtmp) = make_api();
        let caller_identity = SigningKey::generate();
        let caller_z32 = caller_identity.peer_id().to_z32();
        let caller_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![P2CLAW_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .secret_key(SecretKey::from_bytes(&caller_identity.seed()))
            .bind()
            .await
            .expect("bind caller endpoint");
        let opts = p2claw_iroh_client::ClientOptions {
            parent_domain: PARENT.into(),
            coord_url: Some(coord_url),
            timeout: Duration::from_secs(5),
            endpoint: Some(caller_endpoint.clone()),
            relay_url: None,
        };
        let _ = api.peer_proxy.set(Arc::new(PeerClientCache::new(opts)));

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sock.exists());

        let proxy_req = format!(
            "GET /v1/proxy/{REMOTE_ALIAS}/mysvc/hello?x=1 HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-P2claw-User: spoof@example.com\r\n\
             Connection: close\r\n\r\n"
        );

        // 1. Not shared yet: the far side denies with a 404 shaped
        //    exactly like an unknown app — no 403/404 differential
        //    that would confirm private route names to a probing
        //    peer.
        let text = http_over_uds(&sock, proxy_req.as_bytes()).await;
        assert!(text.contains("404"), "expected far-side denial:\n{text}");
        assert!(text.contains("no such app: mysvc"), "{text}");

        // 2. Share with the caller: same proxy call now round-trips.
        remote_shares
            .replace(vec![p2claw_agent::shares::ShareRecord {
                app: "mysvc".into(),
                peers: vec![caller_z32.clone()],
            }])
            .await
            .unwrap();
        let text = http_over_uds(&sock, proxy_req.as_bytes()).await;
        assert!(text.contains("200 OK"), "proxy round-trip failed:\n{text}");
        assert!(
            text.contains("pq=/hello?x=1"),
            "URI must be rewritten to the service-relative path:\n{text}"
        );
        assert!(
            text.contains(&format!("hdr:x-p2claw-peer={caller_z32}")),
            "far side must attribute the calling box:\n{text}"
        );
        assert!(
            !text.contains("x-p2claw-user"),
            "spoofed identity header must not survive:\n{text}"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        caller_endpoint.close().await;
        let _ = remote_sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), remote_handle).await;
    }

    /// FD-leak regression guard: drive N sequential requests through
    /// the local API and assert the process FD count returns to
    /// baseline (with slack for parallel test churn). The local-API
    /// hot path was the observed-failure surface in the prod EMFILE
    /// incident, so this is the one place where a regression that
    /// piles up FDs would directly reproduce it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_api_does_not_leak_fds_across_n_requests() {
        // 256 is large enough that a per-request FD leak would push
        // the count up by hundreds (visible above parallel-test
        // noise), but small enough to keep the test fast.
        const N: usize = 256;
        // Slack to absorb FD churn from other tests running in
        // parallel under cargo's multi-thread runner. Tested empirically
        // — without a leak the post-stress count usually lands within
        // ±5 of baseline; we double that for safety.
        const SLACK: usize = 32;

        let (api, _acker, _rtmp) = make_api();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sock.exists(), "socket did not appear");

        // Warm the path so transient FDs (e.g. tokio reactor lazy
        // init) settle before we sample baseline.
        for _ in 0..4 {
            let _ = http_over_uds(
                &sock,
                b"GET /v1/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
        }
        // Give the server task time to drop accepted sockets after the
        // warmup sweep so the baseline reading isn't elevated by
        // still-cleaning-up connections.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let baseline = crate::fd_count::fd_count().expect("fd_count must succeed on Linux/macOS");

        // Stress: N sequential requests, each closing its end. With
        // `Connection: close` the server side completes the response
        // and drops the accepted UnixStream — the FD is returned to
        // the OS before the next request connects.
        for _ in 0..N {
            let text = http_over_uds(
                &sock,
                b"GET /v1/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(text.contains("200 OK"), "request failed mid-stress: {text}");
        }

        // Spawned per-conn tasks may need a moment to finish
        // serve_connection cleanup after the client closed its end.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let after = crate::fd_count::fd_count().expect("fd_count must succeed on Linux/macOS");
        assert!(
            after <= baseline + SLACK,
            "FD count grew across {N} sequential requests: \
             baseline={baseline}, after={after} (slack={SLACK}). \
             A monotonic growth points at a leak in the local-API \
             accept loop or its per-connection handler."
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    // ---------- email ----------------------------------------------------

    fn email_meta(id: &str) -> p2claw_email_proto::Metadata {
        p2claw_email_proto::Metadata {
            id: id.into(),
            kind: p2claw_email_proto::Kind::Message,
            received_at: 1_791_126_131,
            to: "y9abcdefghijk@p2claw.com".into(),
            envelope_from: "you@gmail.com".into(),
            from: "you@gmail.com".into(),
            forwarded_by: None,
            auth: p2claw_email_proto::Auth {
                dkim: "pass".into(),
                dkim_domain: Some("gmail.com".into()),
                arc: "none".into(),
            },
        }
    }

    const EMAIL_RAW: &str = "From: you@gmail.com\r\n\
To: y9abcdefghijk@p2claw.com\r\n\
Subject: receipt\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
thanks for your order\r\n\
--b\r\n\
Content-Type: text/plain; name=\"note.txt\"\r\n\
Content-Disposition: attachment; filename=\"note.txt\"\r\n\
\r\n\
attached note\r\n\
--b--\r\n";

    pub(super) fn request(method: &str, path: &str, body: Option<&str>) -> Vec<u8> {
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(b) = body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }
        req.into_bytes()
    }

    pub(super) fn body_json(text: &str) -> serde_json::Value {
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {text}"))
    }

    #[tokio::test]
    async fn email_settings_and_allowlist_roundtrip() {
        with_server(|sock, api| async move {
            let text = http_over_uds(&sock, &request("GET", "/v1/email", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["enabled"], false);
            assert_eq!(v["addresses"], serde_json::json!([]));
            assert_eq!(v["unread"], 0);
            assert_eq!(v["rejections_available"], true);
            assert_eq!(v["rejections"]["totals"]["not_allowed"], 3);
            assert_eq!(v["rejections"]["daily_limit"], 1000);

            let text = http_over_uds(
                &sock,
                &request("PUT", "/v1/email", Some(r#"{"enabled":true}"#)),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["enabled"], true);
            assert_eq!(
                v["addresses"],
                serde_json::json!(["y9abcdefghijk@p2claw.com"])
            );
            assert!(v.get("pending_sync").is_none(), "acked in time: {v}");
            assert!(api.email.settings.snapshot().enabled);

            let text = http_over_uds(
                &sock,
                &request(
                    "PUT",
                    "/v1/email/allowlist",
                    Some(r#"{"allowlist":["You+x@Gmail.com","nope"]}"#),
                ),
            )
            .await;
            assert!(text.contains("400"), "{text}");
            assert!(text.contains("\"bad_address\""), "{text}");
            assert!(api.email.settings.snapshot().allowlist.is_empty());

            let text = http_over_uds(
                &sock,
                &request(
                    "PUT",
                    "/v1/email/allowlist",
                    Some(r#"{"allowlist":["You+x@Gmail.com","b@x.org"]}"#),
                ),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            assert_eq!(
                body_json(&text)["allowlist"],
                serde_json::json!(["you@gmail.com", "b@x.org"])
            );

            let text = http_over_uds(&sock, &request("GET", "/v1/email", None)).await;
            assert_eq!(
                body_json(&text)["allowlist"],
                serde_json::json!(["you@gmail.com", "b@x.org"])
            );

            let text = http_over_uds(&sock, &request("GET", "/v1/email/rejected", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            assert_eq!(body_json(&text)["recent"][0]["from"], "spam@example.net");
        })
        .await;
    }

    /// With no coord session answering, settings still save and the
    /// response says the sync is pending; rejection totals are
    /// marked unavailable instead of failing the call.
    #[tokio::test]
    async fn email_settings_degrade_when_coord_is_offline() {
        let (api, _inbox, _tmp) = make_api_offline_control();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let text = http_over_uds(
            &sock,
            &request("PUT", "/v1/email", Some(r#"{"enabled":true}"#)),
        )
        .await;
        assert!(text.contains("200 OK"), "{text}");
        let v = body_json(&text);
        assert_eq!(v["enabled"], true);
        assert_eq!(v["pending_sync"], true);
        assert_eq!(v["rejections_available"], false);
        assert!(v["rejections"].is_null());

        let text = http_over_uds(&sock, &request("GET", "/v1/email/rejected", None)).await;
        assert!(text.contains("503"), "{text}");
        assert!(text.contains("\"coord_unreachable\""), "{text}");

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn email_forwarding_endpoints() {
        with_server(|sock, api| async move {
            api.email
                .inbox
                .store_forwarding_request(p2claw_agent::email::ForwardingRequest {
                    id: "m_f".into(),
                    account: Some("acct@gmail.com".into()),
                    link: Some("https://mail-settings.google.com/mail/vf-secret".into()),
                    received_at: 1_791_126_131,
                })
                .await
                .unwrap();

            let text = http_over_uds(&sock, &request("GET", "/v1/email/forwarding", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["requests"][0]["account"], "acct@gmail.com");
            assert_eq!(
                v["requests"][0]["link"],
                "https://mail-settings.google.com/mail/vf-secret"
            );
            assert_eq!(v["approved"], serde_json::json!([]));

            // The request never shows up as mail.
            let text = http_over_uds(&sock, &request("GET", "/v1/email/messages", None)).await;
            assert_eq!(body_json(&text)["messages"], serde_json::json!([]));

            let text = http_over_uds(
                &sock,
                &request("POST", "/v1/email/forwarding/Acct@gmail.com", None),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["approved"], serde_json::json!(["acct@gmail.com"]));
            assert_eq!(
                v["requests"],
                serde_json::json!([]),
                "approved request is cleared"
            );
            assert_eq!(
                api.email.settings.config().forwarders,
                vec!["acct@gmail.com"]
            );

            let text = http_over_uds(
                &sock,
                &request("DELETE", "/v1/email/forwarding/acct@gmail.com", None),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            assert_eq!(body_json(&text)["approved"], serde_json::json!([]));

            let text = http_over_uds(
                &sock,
                &request("DELETE", "/v1/email/forwarding/acct@gmail.com", None),
            )
            .await;
            assert!(text.contains("404"), "{text}");

            let text = http_over_uds(
                &sock,
                &request("POST", "/v1/email/forwarding/not-an-address", None),
            )
            .await;
            assert!(text.contains("400"), "{text}");
        })
        .await;
    }

    #[tokio::test]
    async fn email_message_endpoints() {
        with_server(|sock, api| async move {
            api.email
                .inbox
                .store_message(&email_meta("m_1"), EMAIL_RAW.as_bytes())
                .await
                .unwrap();

            let text = http_over_uds(&sock, &request("GET", "/v1/email/messages", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            let m = &v["messages"][0];
            assert_eq!(m["id"], "m_1");
            assert_eq!(m["kind"], "message");
            assert_eq!(m["subject"], "receipt");
            assert_eq!(m["received_at"], "2026-10-04T15:02:11Z");
            assert_eq!(m["acked"], false);
            assert_eq!(m["attachment_count"], 1);
            assert!(m.get("text").is_none(), "listing carries no bodies: {m}");

            let text = http_over_uds(&sock, &request("GET", "/v1/email", None)).await;
            assert_eq!(body_json(&text)["unread"], 1);

            let text = http_over_uds(&sock, &request("GET", "/v1/email/messages/m_1", None)).await;
            let v = body_json(&text);
            assert_eq!(v["text"], "thanks for your order");
            assert_eq!(v["attachments"][0]["id"], "a_1");
            assert_eq!(v["attachments"][0]["name"], "note.txt");
            assert_eq!(v["attachments"][0]["type"], "text/plain");
            assert_eq!(v["auth"]["dkim"], "pass");

            let text = http_over_uds(
                &sock,
                &request("GET", "/v1/email/messages/m_1?format=raw", None),
            )
            .await;
            assert!(text.contains("content-type: message/rfc822"), "{text}");
            assert!(text.ends_with(EMAIL_RAW), "{text}");

            let text = http_over_uds(
                &sock,
                &request("GET", "/v1/email/messages/m_1/attachments/a_1", None),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            assert!(text.contains("content-type: text/plain"), "{text}");
            assert!(text.contains("filename=\"note.txt\""), "{text}");
            assert!(text.ends_with("attached note"), "{text}");

            let text = http_over_uds(
                &sock,
                &request("GET", "/v1/email/messages/m_1/attachments/a_9", None),
            )
            .await;
            assert!(text.contains("404"), "{text}");

            let text =
                http_over_uds(&sock, &request("POST", "/v1/email/messages/m_1/ack", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            assert_eq!(body_json(&text)["acked"], true);
            let text =
                http_over_uds(&sock, &request("GET", "/v1/email/messages?unread=1", None)).await;
            assert_eq!(body_json(&text)["messages"], serde_json::json!([]));
            let text = http_over_uds(&sock, &request("GET", "/v1/email/messages", None)).await;
            assert_eq!(
                body_json(&text)["messages"].as_array().unwrap().len(),
                1,
                "ack keeps"
            );

            let text =
                http_over_uds(&sock, &request("DELETE", "/v1/email/messages/m_1", None)).await;
            assert!(text.contains("204"), "{text}");
            let text = http_over_uds(&sock, &request("GET", "/v1/email/messages/m_1", None)).await;
            assert!(text.contains("404"), "{text}");
            let text = http_over_uds(&sock, &request("GET", "/v1/email/messages/../x", None)).await;
            assert!(text.contains("404"), "{text}");
        })
        .await;
    }

    #[tokio::test]
    async fn email_watch_streams_new_ids() {
        with_server(|sock, api| async move {
            let mut s = UnixStream::connect(&sock).await.unwrap();
            s.write_all(b"GET /v1/email/messages?watch=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            // Headers arrive before any message does.
            loop {
                let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&got).to_string();
            assert!(head.contains("200 OK"), "{head}");
            assert!(head.contains("application/x-ndjson"), "{head}");

            api.email
                .inbox
                .store_message(&email_meta("m_w"), EMAIL_RAW.as_bytes())
                .await
                .unwrap();
            loop {
                let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0, "stream ended");
                got.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&got).contains("{\"id\":\"m_w\"}\n") {
                    break;
                }
            }
        })
        .await;
    }
}
