//! Persistent Iroh-QUIC connection to coordination.
//!
//! Dial coord, open the long-lived control stream, send
//! `StreamHello { kind: Control }` then `Message::Hello`, wait for
//! `HelloAck`. From there: relay control envelopes outbound on the
//! control stream; accept inbound bidi streams (each is a
//! per-visitor signaling stream coord opens for us).
//!
//! Iroh's TLS handshake binds the connection to the dialer's
//! `peer_id` — no bearer token in the Hello.
//!
//! Coord signals fatal conditions via QUIC application close codes:
//! 4001 unknown peer_id (transparent re-register, rate-limited;
//! three in five minutes trips [`LoopOutcome::AuthFailedTooMany`]),
//! 4010 revoked, 4009 superseded by another instance, 4002 the box
//! itself rejected an inbound Control stream coord shouldn't have
//! opened.
//!
//! Framing: length-prefixed JSON via
//! `p2claw_control_proto::encode_frame` / `decode_frame_length`,
//! `MAX_FRAME_BYTES = 1 MiB`. Reconnect uses
//! exponential-backoff-with-jitter (1s base, 60s cap, ×2 per
//! attempt, ±20%), reset to base after a successful re-register.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use p2claw_control_proto::{
    decode_frame_length, encode_frame, Envelope, Message, RouteAnnounceEntry, StreamHelloEnvelope,
    StreamKind, ALPN_COORD_V1, CLOSE_AUTH_FAILED, CLOSE_NORMAL, CLOSE_POLICY_REPLACED_BY_NEWER,
    CLOSE_PROTOCOL_ERROR, CLOSE_REVOKED,
};
use p2claw_identity::{PeerId, SigningKey};
use rand::Rng;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::email_link::{ConfigAck, EmailJob, EmailLinkInbox, EmailShared};
use crate::register::{self, RegisterError, RegisterRetryPolicy};
use crate::route_announcer::{AnnounceAck, AnnounceJob, AnnouncerInbox};
use crate::signal_handler::{OutboundSignal, SignalRegistry};
use crate::state_store::{self, AgentState};
use p2claw_agent::email::{drain, EmailStream, Inbox};
use p2claw_agent::routes::{RouteRecord, RouteTable};

/// Build the `route_announce` payload from a route-table snapshot.
/// The announce is authoritative — coord deletes any name the box
/// omits — and private routes are filtered here precisely because
/// coord never accepted them: omitting them deletes nothing, and
/// coord never learns private service names.
fn announce_snapshot(routes: Vec<RouteRecord>) -> Vec<RouteAnnounceEntry> {
    routes
        .into_iter()
        .filter(|r| !r.is_private())
        .map(|r| RouteAnnounceEntry {
            name: r.name,
            registered_at: r.registered_at,
            auth: r.auth,
            requires_auth: None,
        })
        .collect()
}

/// Window over which repeated `4001 AUTH_FAILED` closes count as a
/// single event for the rate-limit guard.
const AUTH_FAIL_WINDOW: Duration = Duration::from_secs(300);
const AUTH_FAIL_LIMIT: usize = 3;

/// Coalesce `addrs_update` frames: iroh's address watcher fires
/// several times during net-report and relay handshake; debounce
/// to a single update.
const ADDRS_DEBOUNCE: Duration = Duration::from_secs(1);

/// After a failed queue drain, try again on this delay without
/// waiting for another `email_pending`.
const DRAIN_RETRY: Duration = Duration::from_secs(30);

/// Outcome of a [`run`] invocation. `main.rs::wait_for_exit` maps
/// each variant to an exit code.
#[derive(Debug)]
pub enum LoopOutcome {
    Revoked,
    AuthFailedTooMany,
    ReregisterPermanent { status: u16, error: String },
    Shutdown,
    Superseded,
}

pub use p2claw_agent::auto_upgrade::CoordHealth;

#[derive(Debug, Error)]
enum SessionError {
    #[error("iroh dial: {0}")]
    Dial(String),
    #[error("iroh connection: {0}")]
    Connection(String),
    #[error("framing: {0}")]
    Framing(#[from] p2claw_control_proto::FramingError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
}

enum SessionEnd {
    Closed,
    Revoked,
    Superseded,
    AuthFailed,
    Shutdown,
}

/// Consecutive dial failures before the loop refreshes
/// `/v1/coord-self`. One failure could be transient; two in a row
/// suggests coord's UDP coordinates moved. Refresh is cheap (HTTP
/// on the already-trusted HTTPS path).
const DIAL_FAIL_THRESHOLD: u32 = 2;

/// Hit `GET /v1/coord-self`, parse the response, persist into
/// `agent.state`. Used by the dial-fail recovery branch in the
/// main loop.
///
/// Refreshes `coord_iroh_direct_addrs`, `coord_iroh_relay_url`,
/// and (defensively) `coord_root_pubkey` in `AgentState`. The
/// direct-addrs refresh is the load-bearing fix — coord rebinds
/// UDP on restart and our persisted addrs go stale.
///
/// Persists to disk; a write failure surfaces as `Err(_)` and the
/// caller falls through to the existing backoff + re-register path.
async fn try_refresh_coord_self(
    coord_url: &str,
    state: &mut AgentState,
    state_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resp = crate::register::fetch_coord_self(coord_url).await?;

    // `from_z32`, not `from_str`: coord encodes via Phil Zimmermann
    // z-base-32; `from_str` tries RFC4648 after uppercasing and
    // the round-trip doesn't match.
    let new_endpoint_id = EndpointId::from_z32(&resp.endpoint_id)?;
    let new_pubkey = PeerId::from_bytes(*new_endpoint_id.as_bytes());

    if new_pubkey != state.coord_root_pubkey {
        warn!(
            "coord_conn: /v1/coord-self reports a different coord pubkey \
             than persisted; coord-key rotation is unsupported — \
             updating state, but the bootstrap pin will reject signaling \
             against the new key until the bundle is rebuilt"
        );
        state.coord_root_pubkey = new_pubkey;
    }

    let prior_addrs = state.coord_iroh_direct_addrs.clone();
    state.coord_iroh_relay_url = resp.relay_url;
    state.coord_iroh_direct_addrs = resp.direct_addrs;
    info!(
        old_count = prior_addrs.len(),
        new_count = state.coord_iroh_direct_addrs.len(),
        new_addrs = ?state.coord_iroh_direct_addrs,
        "coord_conn: refreshed coord_iroh_direct_addrs from /v1/coord-self"
    );

    crate::state_store::save(state_path, state)?;
    Ok(())
}

/// Run the coord-connection loop until shutdown or a fatal close.
///
/// `coord_url` is the HTTPS base used only for `register_with_retry`
/// on 4001; the QUIC dial bypasses it (Iroh resolves coord's NodeID
/// via its own relay network). `iroh_endpoint` is shared with
/// `iroh_listener::run` — one endpoint serves both inbound peer-HTTP
/// and outbound coord.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    coord_url: String,
    coord_domain: String,
    state: AgentState,
    state_path: PathBuf,
    // Arc so cmd_run can hand the same instance it loaded BEFORE
    // priv_drop. The on-disk identity.key stays root:0600 and is
    // unreadable under the dropped user, so re-reading from disk
    // would fail.
    identity: Arc<SigningKey>,
    iroh_endpoint: Endpoint,
    iroh_addrs: watch::Receiver<Vec<String>>,
    mut shutdown: watch::Receiver<bool>,
    signal_registry: Arc<SignalRegistry>,
    mut signal_outbound_rx: mpsc::Receiver<OutboundSignal>,
    routes: RouteTable,
    mut announcer_inbox: AnnouncerInbox,
    email: EmailShared,
    mut email_inbox: EmailLinkInbox,
    // Sender for `CoordHealth`; receiver lives on the post-upgrade
    // watchdog (or is dropped if no watchdog is running).
    coord_health: watch::Sender<CoordHealth>,
) -> LoopOutcome {
    let mut backoff_ms: u64 = 1_000;
    let mut state = state;
    // `iroh_node_id` field on each Hello frame; coord uses the QUIC
    // cert handshake as the authoritative peer_id, this is purely
    // for log-grep continuity.
    let agent_peer_id = identity.peer_id();
    let mut auth_failures: VecDeque<Instant> = VecDeque::with_capacity(AUTH_FAIL_LIMIT);
    // After `DIAL_FAIL_THRESHOLD` consecutive dial failures, refresh
    // `/v1/coord-self` — coord rebinds UDP on restart and our
    // persisted addrs go stale. Reset on any clean session end.
    let mut consecutive_dial_fails: u32 = 0;

    loop {
        if *shutdown.borrow() {
            return LoopOutcome::Shutdown;
        }

        // Zero-sentinel pubkey means the wire decode in `register`
        // fell back to all-zeros — no sane NodeID to dial. Synthesize
        // an AuthFailed outcome and let the existing handler
        // re-register.
        if state.coord_root_pubkey.as_bytes() == &[0u8; 32] {
            warn!(
                "coord_conn: agent.state.coord_root_pubkey is the zero sentinel; \
                 forcing re-register"
            );
            let outcome = SessionEnd::AuthFailed;
            match handle_session_end(
                outcome,
                &mut state,
                &state_path,
                &coord_url,
                &coord_domain,
                &identity,
                &mut auth_failures,
                shutdown.clone(),
            )
            .await
            {
                Some(loop_outcome) => return loop_outcome,
                None => {
                    backoff_ms = 1_000;
                    continue;
                }
            }
        }

        let coord_node_id = match EndpointId::from_bytes(state.coord_root_pubkey.as_bytes()) {
            Ok(id) => id,
            Err(e) => {
                // Only failure mode is an invalid Ed25519 point;
                // shouldn't happen for a key coord minted.
                error!(error = %e, "coord_conn: coord_root_pubkey is not a valid Ed25519 point — coord bug");
                return LoopOutcome::ReregisterPermanent {
                    status: 0,
                    error: "coord_root_pubkey_invalid".into(),
                };
            }
        };
        info!(node_id = %coord_node_id, "coord_conn: dialing");
        let _ = coord_health.send(CoordHealth::Connecting);

        let outcome = tokio::select! {
            res = session(
                &iroh_endpoint,
                coord_node_id,
                agent_peer_id,
                &mut state,
                &state_path,
                iroh_addrs.clone(),
                Arc::clone(&signal_registry),
                &mut signal_outbound_rx,
                shutdown.clone(),
                &routes,
                &mut announcer_inbox,
                &email,
                &mut email_inbox,
                &identity,
                &coord_health,
            ) => res,
            _ = shutdown.changed() => Ok(SessionEnd::Shutdown),
        };

        let _ = coord_health.send(CoordHealth::Disconnected);

        // Coord forgets in-flight signaling sessions when the
        // connection drops, so drop the local RTCPeerConnections
        // ourselves rather than waiting on a signal that won't come.
        signal_registry.shutdown_all().await;

        let session_end = match outcome {
            Ok(end) => {
                // Any clean session end means coord's addressing
                // worked — reset the dial-fail counter.
                consecutive_dial_fails = 0;
                end
            }
            Err(SessionError::Dial(msg)) => {
                consecutive_dial_fails = consecutive_dial_fails.saturating_add(1);
                warn!(
                    msg,
                    n = consecutive_dial_fails,
                    threshold = DIAL_FAIL_THRESHOLD,
                    "coord_conn: iroh dial failed"
                );
                if consecutive_dial_fails >= DIAL_FAIL_THRESHOLD {
                    // Persisted addrs are likely stale (coord
                    // restarted onto a fresh UDP port). Refresh via
                    // `/v1/coord-self`; on failure fall through to
                    // the backoff + re-register path.
                    match try_refresh_coord_self(&coord_url, &mut state, &state_path).await {
                        Ok(()) => {
                            info!(
                                "coord_conn: refreshed coord transport state; \
                                 retrying dial with fresh addrs"
                            );
                            consecutive_dial_fails = 0;
                            backoff_ms = 1_000;
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "coord_conn: /v1/coord-self refresh failed; \
                                 falling through to backoff + re-register"
                            );
                        }
                    }
                }
                SessionEnd::Closed
            }
            Err(e) => {
                warn!(error = %e, "coord_conn: session error; will reconnect");
                SessionEnd::Closed
            }
        };

        match handle_session_end(
            session_end,
            &mut state,
            &state_path,
            &coord_url,
            &coord_domain,
            &identity,
            &mut auth_failures,
            shutdown.clone(),
        )
        .await
        {
            Some(loop_outcome) => return loop_outcome,
            None => {
                // Reconnect after a normal close — backoff loop.
            }
        }

        let wait = jittered_backoff(backoff_ms);
        info!(wait_ms = wait, "coord_conn: backing off before reconnect");
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(wait)) => {}
            _ = shutdown.changed() => return LoopOutcome::Shutdown,
        }
        backoff_ms = (backoff_ms.saturating_mul(2)).min(60_000);
    }
}

/// Process a `SessionEnd` value and decide whether the loop
/// should exit (returning `Some(LoopOutcome)`) or continue
/// reconnecting (returning `None`). Pulled out so the
/// zero-sentinel pre-dial path can drive the same logic without
/// going through `session()`.
#[allow(clippy::too_many_arguments)]
async fn handle_session_end(
    end: SessionEnd,
    state: &mut AgentState,
    state_path: &Path,
    coord_url: &str,
    coord_domain: &str,
    identity: &SigningKey,
    auth_failures: &mut VecDeque<Instant>,
    shutdown: watch::Receiver<bool>,
) -> Option<LoopOutcome> {
    match end {
        SessionEnd::Revoked => {
            error!("coord_conn: peer_id revoked by coordination — exiting");
            Some(LoopOutcome::Revoked)
        }
        SessionEnd::AuthFailed => {
            if !record_auth_failure(auth_failures) {
                error!(
                    attempts = auth_failures.len(),
                    window_secs = AUTH_FAIL_WINDOW.as_secs(),
                    "coord_conn: 4001 AUTH_FAILED hit the rate-limit guard — exiting"
                );
                return Some(LoopOutcome::AuthFailedTooMany);
            }
            warn!("coord_conn: peer_id rejected (4001); re-registering");
            match register::register_with_retry(
                coord_url,
                coord_domain,
                identity,
                RegisterRetryPolicy::default(),
                shutdown,
            )
            .await
            {
                Ok(resp) => {
                    let new_state: AgentState = resp.into();
                    if let Err(e) = state_store::save(state_path, &new_state) {
                        warn!(
                            error = %e,
                            "coord_conn: re-register succeeded but persisting state failed"
                        );
                    } else {
                        info!(
                            alias = %new_state.alias,
                            "coord_conn: re-registered; reconnecting"
                        );
                    }
                    *state = new_state;
                    None
                }
                Err(RegisterError::Cancelled) => Some(LoopOutcome::Shutdown),
                Err(RegisterError::Permanent { status, error, .. }) => {
                    error!(
                        status, error = %error,
                        "coord_conn: re-register returned permanent failure — exiting"
                    );
                    Some(LoopOutcome::ReregisterPermanent { status, error })
                }
                Err(e) => {
                    error!(error = %e, "coord_conn: re-register failed; exiting");
                    Some(LoopOutcome::ReregisterPermanent {
                        status: 0,
                        error: "register_internal".into(),
                    })
                }
            }
        }
        SessionEnd::Superseded => {
            warn!("coord_conn: replaced by a newer connection (4009) — exiting");
            Some(LoopOutcome::Superseded)
        }
        SessionEnd::Shutdown => Some(LoopOutcome::Shutdown),
        SessionEnd::Closed => {
            warn!("coord_conn: connection closed; will reconnect");
            None
        }
    }
}

/// Drive one Iroh QUIC session against coord. Opens the control
/// stream, sends stream-hello + Hello, awaits HelloAck, then
/// runs the inbound/outbound multiplex loop until the connection
/// closes or shutdown fires.
#[allow(clippy::too_many_arguments)]
async fn session(
    endpoint: &Endpoint,
    coord_node_id: EndpointId,
    agent_peer_id: PeerId,
    state: &mut AgentState,
    // Kept on the signature for forward-compat (future
    // state-mutation paths will persist on coord-driven
    // rotation); the session loop currently only reads `state`.
    _state_path: &Path,
    mut iroh_addrs: watch::Receiver<Vec<String>>,
    signal_registry: Arc<SignalRegistry>,
    signal_outbound_rx: &mut mpsc::Receiver<OutboundSignal>,
    mut shutdown: watch::Receiver<bool>,
    routes: &RouteTable,
    announcer_inbox: &mut AnnouncerInbox,
    email: &EmailShared,
    email_inbox: &mut EmailLinkInbox,
    identity: &Arc<SigningKey>,
    coord_health: &watch::Sender<CoordHealth>,
) -> Result<SessionEnd, SessionError> {
    // Build an addressed `EndpointAddr` from the persisted relay URL
    // + direct addrs. Dialing by NodeID alone relies on Iroh's
    // pkarr/relay discovery, which fails under `RelayMode::Disabled`
    // hermetic mode. Empty addrs (legacy agent.state) falls back to
    // NodeID-only dial — works under default-relay mode, fails
    // hermetic.
    let mut transport_addrs: Vec<TransportAddr> = Vec::new();
    if let Some(url_str) = state.coord_iroh_relay_url.as_deref() {
        match RelayUrl::from_str(url_str) {
            Ok(url) => transport_addrs.push(TransportAddr::Relay(url)),
            Err(e) => warn!(
                url = %url_str,
                error = %e,
                "coord_conn: persisted coord_iroh_relay_url did not parse; ignoring"
            ),
        }
    }
    for raw in &state.coord_iroh_direct_addrs {
        match raw.parse::<SocketAddr>() {
            Ok(socket) => transport_addrs.push(TransportAddr::Ip(socket)),
            Err(e) => warn!(
                addr = %raw,
                error = %e,
                "coord_conn: persisted coord_iroh_direct_addrs entry did not parse; ignoring"
            ),
        }
    }
    let coord_addr = EndpointAddr::from_parts(coord_node_id, transport_addrs);

    let connection = endpoint
        .connect(coord_addr, ALPN_COORD_V1)
        .await
        .map_err(|e| SessionError::Dial(e.to_string()))?;
    info!(node_id = %coord_node_id, "coord_conn: connected");

    let (mut ctrl_send, mut ctrl_recv) = connection
        .open_bi()
        .await
        .map_err(|e| SessionError::Connection(e.to_string()))?;

    write_envelope_json(
        &mut ctrl_send,
        &StreamHelloEnvelope::new(StreamKind::Control).to_json(),
    )
    .await?;

    let initial_addrs = iroh_addrs.borrow().clone();
    let hello = Envelope::new(Message::Hello {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        iroh_node_id: agent_peer_id.to_z32(),
        iroh_addrs: initial_addrs,
        hostname_hint: None,
    });
    write_envelope_json(&mut ctrl_send, &hello.to_json()).await?;

    iroh_addrs.mark_unchanged();

    match read_envelope(&mut ctrl_recv).await? {
        env if matches!(env.body, Message::HelloAck { .. }) => {
            if let Message::HelloAck { server_time } = env.body {
                info!(server_time, "coord_conn: hello_ack");
            }
            let _ = coord_health.send(CoordHealth::ConnectedHelloAck);
        }
        env => {
            return Err(SessionError::Protocol(format!(
                "expected hello_ack, got {:?}",
                env.body
            )));
        }
    }

    // Post-hello_ack route announce.
    //
    // This is an *authoritative* snapshot: coord replaces the box's
    // live app set with whatever we send here. Suppress it when the
    // snapshot is empty AND the initial routes load was degraded
    // (routes.json absent or corrupt) — an unverified-empty table
    // must not be asserted as "I have no apps", which coord would
    // honor by deleting the box's registrations. The operator's next
    // expose (a verified write) clears the degraded flag and the
    // announce resumes normally. A genuinely-empty box (present,
    // valid `[]` on disk) is NOT degraded and still announces empty.
    let snapshot = announce_snapshot(routes.list().await);

    // FIFO of route_announce_ack reply slots in send order.
    let mut pending_announce_replies: VecDeque<Option<oneshot::Sender<AnnounceAck>>> =
        VecDeque::new();

    if snapshot.is_empty() && routes.initial_load_degraded() {
        warn!(
            "coord_conn: initial routes load was degraded (routes.json absent or corrupt) \
             and the table is empty — suppressing the authoritative empty route_announce so \
             coord keeps this box's existing app registrations. Re-expose to restore local routes."
        );
    } else {
        let announce_env = Envelope::new(Message::RouteAnnounce { routes: snapshot });
        write_envelope_json(&mut ctrl_send, &announce_env.to_json()).await?;
        // The post-HelloAck announce gets a `None` reply slot so the
        // next inbound ack matches. Only pushed when we actually sent.
        pending_announce_replies.push_back(None);
    }

    // Email settings are a full snapshot too; coord's ack carries the
    // box's addresses. Same FIFO discipline as route announces.
    let mut pending_config_replies: VecDeque<Option<oneshot::Sender<ConfigAck>>> = VecDeque::new();
    write_email_config(&mut ctrl_send, email).await?;
    pending_config_replies.push_back(None);

    // Queue drains run off the select loop so a large mailbox never
    // stalls control traffic. `Notify` holds at most one permit, so
    // a burst of `email_pending` collapses into one extra pass.
    let drain_notify = Arc::new(Notify::new());
    let _drain_task = AbortOnDrop(tokio::spawn(drain_loop(
        connection.clone(),
        Arc::clone(&drain_notify),
        email.inbox.clone(),
        Arc::clone(identity),
    )));

    let mut pending_addrs_fire: Option<Instant> = None;

    // session_id → outbound writer for the per-session signaling
    // stream coord opens (one bidi per visitor session). Demux by
    // id when forwarding OutboundSignal frames from the registry.
    let signal_streams: Arc<
        tokio::sync::Mutex<std::collections::HashMap<String, mpsc::Sender<OutboundSignal>>>,
    > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    loop {
        let next_deadline = pending_addrs_fire;
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                info!("coord_conn: shutdown — sending Goodbye and closing");
                let env = Envelope::new(Message::Goodbye {
                    reason: Some("shutdown".to_string()),
                });
                let _ = write_envelope_json(&mut ctrl_send, &env.to_json()).await;
                let _ = ctrl_send.finish();
                connection.close((CLOSE_NORMAL as u32).into(), b"shutdown");
                return Ok(SessionEnd::Shutdown);
            }

            _ = async {
                match next_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let snapshot = iroh_addrs.borrow().clone();
                debug!(?snapshot, "coord_conn: sending coalesced addrs_update");
                let env = Envelope::new(Message::AddrsUpdate { iroh_addrs: snapshot });
                write_envelope_json(&mut ctrl_send, &env.to_json()).await?;
                pending_addrs_fire = None;
            }

            changed = iroh_addrs.changed() => {
                if changed.is_err() {
                    debug!("coord_conn: iroh addrs sender dropped; ending session");
                    return Ok(SessionEnd::Closed);
                }
                if pending_addrs_fire.is_none() {
                    pending_addrs_fire = Some(Instant::now() + ADDRS_DEBOUNCE);
                }
            }

            out = signal_outbound_rx.recv() => {
                let Some(out_signal) = out else {
                    debug!("coord_conn: signal outbound sender dropped");
                    return Ok(SessionEnd::Closed);
                };
                let session_id = match &out_signal {
                    OutboundSignal::Relay { session_id, .. } => session_id.clone(),
                    OutboundSignal::End { session_id, .. } => session_id.clone(),
                };
                let streams = signal_streams.lock().await;
                if let Some(tx) = streams.get(&session_id) {
                    if tx.send(out_signal).await.is_err() {
                        debug!(%session_id, "coord_conn: per-session writer dropped");
                    }
                } else {
                    warn!(%session_id, "coord_conn: outbound signal for unknown session; dropping");
                }
            }

            job = announcer_inbox.job_rx.recv() => {
                let Some(AnnounceJob::Send { reply }) = job else {
                    debug!("coord_conn: announcer inbox sender dropped");
                    return Ok(SessionEnd::Closed);
                };
                let snapshot = announce_snapshot(routes.list().await);
                // Info-level so operators can trace the announce
                // flow without flipping RUST_LOG=debug — useful when
                // diagnosing `no_such_peer` from a dialing client.
                info!(
                    routes = ?snapshot.iter().map(|r| &r.name).collect::<Vec<_>>(),
                    "coord_conn: sending route_announce"
                );
                let env = Envelope::new(Message::RouteAnnounce { routes: snapshot });
                write_envelope_json(&mut ctrl_send, &env.to_json()).await?;
                pending_announce_replies.push_back(reply);
            }

            job = email_inbox.job_rx.recv() => {
                let Some(job) = job else {
                    debug!("coord_conn: email link sender dropped");
                    return Ok(SessionEnd::Closed);
                };
                match job {
                    EmailJob::SendConfig { reply } => {
                        write_email_config(&mut ctrl_send, email).await?;
                        pending_config_replies.push_back(reply);
                    }
                    EmailJob::Rejected { reply } => {
                        let conn = connection.clone();
                        tokio::spawn(async move {
                            let res = fetch_rejected(conn).await.map_err(|e| e.to_string());
                            let _ = reply.send(res);
                        });
                    }
                }
            }

            res = read_envelope(&mut ctrl_recv) => {
                let env = match res {
                    Ok(e) => e,
                    Err(e) => {
                        // EOF or framing error; close-code dispatch
                        // below decides whether it's fatal.
                        debug!(error = %e, "coord_conn: control stream read error");
                        return classify_close(&connection);
                    }
                };
                match env.body {
                    Message::HelloAck { .. } => {
                        warn!("coord_conn: unexpected second hello_ack on live stream; ignoring");
                    }
                    Message::RouteAnnounceAck {
                        accepted,
                        rejected,
                        max_apps,
                        used_apps,
                        daily_changes,
                        accepted_apps,
                    } => {
                        info!(
                            ?accepted,
                            rejected_count = rejected.len(),
                            max_apps,
                            used_apps,
                            "coord_conn: route_announce_ack"
                        );
                        for r in &rejected {
                            warn!(
                                name = %r.name,
                                reason = %r.reason,
                                retry_after_s = ?r.retry_after_s,
                                "coord_conn: route_announce_ack rejection"
                            );
                        }
                        // Sync local `RouteRecord.auth` against
                        // coord's authoritative view; handles
                        // out-of-band admin updates. Typical case is
                        // identity (we announced what coord echoes)
                        // — upsert is a no-op write.
                        for a in &accepted_apps {
                            if let Some(mut existing) = routes.get(&a.name).await {
                                if existing.auth != a.auth {
                                    info!(
                                        name = %a.name,
                                        local_methods = existing.auth.len(),
                                        coord_methods = a.auth.len(),
                                        "coord_conn: auth method list diverged from coord — syncing"
                                    );
                                    existing.auth = a.auth.clone();
                                    if let Err(e) = routes.upsert(existing).await {
                                        warn!(
                                            name = %a.name,
                                            error = %e,
                                            "coord_conn: auth sync upsert failed"
                                        );
                                    }
                                }
                            }
                        }
                        let ack = AnnounceAck {
                            accepted,
                            rejected,
                            max_apps,
                            used_apps,
                            daily_changes,
                            accepted_apps,
                        };
                        announcer_inbox.store_latest(ack.clone()).await;
                        match pending_announce_replies.pop_front() {
                            Some(Some(tx)) => { let _ = tx.send(ack); }
                            Some(None) => {}
                            None => {
                                warn!(
                                    "coord_conn: route_announce_ack with no pending announce; \
                                     ignoring"
                                );
                            }
                        }
                    }
                    Message::Revoke { reason } => {
                        warn!(reason = ?reason, "coord_conn: revoke message");
                        return Ok(SessionEnd::Revoked);
                    }
                    Message::SignalPush { .. }
                    | Message::SignalRelay { .. }
                    | Message::SignalEnd { .. } => {
                        // Signaling rides per-session streams, not
                        // the control stream.
                        warn!("coord_conn: signaling message on control stream — coord bug; ignoring");
                    }
                    Message::EmailConfigAck { addresses, error } => {
                        match &error {
                            Some(err) => warn!(error = %err, "coord_conn: email_config refused"),
                            None => info!(?addresses, "coord_conn: email_config_ack"),
                        }
                        if let Err(e) = email.settings.record_ack(addresses.clone(), error.clone()).await {
                            warn!(error = %e, "coord_conn: could not persist email addresses");
                        }
                        match pending_config_replies.pop_front() {
                            Some(Some(tx)) => {
                                let _ = tx.send(ConfigAck { addresses, error });
                            }
                            Some(None) => {}
                            None => warn!("coord_conn: email_config_ack with no pending config; ignoring"),
                        }
                    }
                    Message::EmailPending { count } => {
                        debug!(count, "coord_conn: email_pending");
                        drain_notify.notify_one();
                    }
                    Message::Hello { .. }
                    | Message::AddrsUpdate { .. }
                    | Message::Goodbye { .. }
                    | Message::RouteAnnounce { .. }
                    | Message::EmailConfig { .. } => {
                        warn!("coord_conn: unexpected client-side message inbound; ignoring");
                    }
                }
            }

            // Inbound bidi stream from coord — should be a
            // signaling stream. Coord never opens Control streams
            // (the box does that); a Control kind from coord is a
            // protocol error and gets rejected with
            // CLOSE_PROTOCOL_ERROR.
            stream_res = connection.accept_bi() => {
                let (send, recv) = match stream_res {
                    Ok(s) => s,
                    Err(e) => {
                        debug!(error = %e, "coord_conn: accept_bi error");
                        return classify_close(&connection);
                    }
                };
                let signal_streams = Arc::clone(&signal_streams);
                let signal_registry = Arc::clone(&signal_registry);
                tokio::spawn(handle_inbound_stream(
                    send,
                    recv,
                    signal_registry,
                    signal_streams,
                ));
            }
        }
    }
}

/// Per-inbound-stream handler. Reads stream-hello, validates the
/// kind, and wires the stream to the signaling registry on
/// `Signaling`. Any other kind (today: only `Control`, which
/// coord must never open) gets rejected with `CLOSE_PROTOCOL_ERROR`.
async fn handle_inbound_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    signal_registry: Arc<SignalRegistry>,
    signal_streams: Arc<
        tokio::sync::Mutex<std::collections::HashMap<String, mpsc::Sender<OutboundSignal>>>,
    >,
) {
    let env = match read_stream_hello(&mut recv).await {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "coord_conn: malformed stream-hello; closing");
            let _ = send.reset((CLOSE_PROTOCOL_ERROR as u32).into());
            return;
        }
    };

    match env.kind {
        StreamKind::Signaling { session_id } => {
            // Per-session writer mpsc: registry pumps OutboundSignal
            // in, we drain and write to the stream.
            let (writer_tx, mut writer_rx) = mpsc::channel::<OutboundSignal>(32);
            signal_streams
                .lock()
                .await
                .insert(session_id.clone(), writer_tx);

            let push_env = match read_envelope(&mut recv).await {
                Ok(e) => e,
                Err(e) => {
                    debug!(%session_id, error = %e, "coord_conn: signaling stream first frame read failed");
                    signal_streams.lock().await.remove(&session_id);
                    return;
                }
            };
            let visitor_kind = match push_env.body {
                Message::SignalPush {
                    session_id: pushed_sid,
                    visitor_kind,
                } => {
                    // session_id on SignalPush is redundant with
                    // the stream-hello but the consistency check
                    // catches coord bugs.
                    if pushed_sid != session_id {
                        warn!(
                            stream_sid = %session_id,
                            push_sid = %pushed_sid,
                            "coord_conn: SignalPush session_id mismatches stream-hello; aborting"
                        );
                        signal_streams.lock().await.remove(&session_id);
                        return;
                    }
                    visitor_kind
                }
                other => {
                    warn!(
                        ?other,
                        "coord_conn: signaling stream's first frame wasn't SignalPush; aborting"
                    );
                    signal_streams.lock().await.remove(&session_id);
                    return;
                }
            };

            signal_registry
                .on_push(session_id.clone(), visitor_kind)
                .await;

            let session_id_for_reader = session_id.clone();
            let registry_for_reader = Arc::clone(&signal_registry);
            let signal_streams_for_reader = Arc::clone(&signal_streams);
            // Reader half: forward inbound SignalRelay/SignalEnd
            // to the registry.
            let reader_task = tokio::spawn(async move {
                while let Ok(env) = read_envelope(&mut recv).await {
                    match env.body {
                        Message::SignalRelay {
                            seq, payload_b64, ..
                        } => {
                            registry_for_reader
                                .on_relay(&session_id_for_reader, seq, payload_b64)
                                .await;
                        }
                        Message::SignalEnd { reason, .. } => {
                            registry_for_reader
                                .on_end(&session_id_for_reader, reason)
                                .await;
                            break;
                        }
                        other => {
                            debug!(?other, %session_id_for_reader, "coord_conn: unexpected frame on signaling stream");
                        }
                    }
                }
                signal_streams_for_reader
                    .lock()
                    .await
                    .remove(&session_id_for_reader);
            });

            // Writer half: serialize OutboundSignal from writer_rx
            // and ship them on the stream.
            while let Some(out) = writer_rx.recv().await {
                let env = match out {
                    OutboundSignal::Relay {
                        session_id: sid,
                        seq,
                        payload_b64,
                    } => Envelope::new(Message::SignalRelay {
                        session_id: sid,
                        seq,
                        payload_b64,
                    }),
                    OutboundSignal::End {
                        session_id: sid,
                        reason,
                    } => Envelope::new(Message::SignalEnd {
                        session_id: sid,
                        reason,
                    }),
                };
                if write_envelope_json(&mut send, &env.to_json())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = send.finish();
            reader_task.abort();
        }

        StreamKind::Control | StreamKind::Email => {
            // The box opens control and email streams; coord opening
            // one is a protocol error.
            warn!(
                "coord_conn: coord opened a box-initiated stream kind — protocol error; rejecting"
            );
            let _ = send.reset((CLOSE_PROTOCOL_ERROR as u32).into());
        }
    }
}

/// Aborts a background task when the session that spawned it ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn write_email_config(
    send: &mut SendStream,
    email: &EmailShared,
) -> Result<(), SessionError> {
    let cfg = email.settings.config();
    debug!(
        enabled = cfg.enabled,
        allowlist = cfg.allowlist.len(),
        forwarders = cfg.forwarders.len(),
        "coord_conn: sending email_config"
    );
    let env = Envelope::new(Message::EmailConfig {
        enabled: cfg.enabled,
        allowlist: cfg.allowlist,
        forwarders: cfg.forwarders,
    });
    write_envelope_json(send, &env.to_json()).await
}

async fn open_email_stream(
    connection: &Connection,
) -> Result<EmailStream<RecvStream, SendStream>, SessionError> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| SessionError::Connection(e.to_string()))?;
    EmailStream::open(send, recv)
        .await
        .map_err(|e| SessionError::Protocol(e.to_string()))
}

async fn fetch_rejected(
    connection: Connection,
) -> Result<p2claw_control_proto::EmailRejections, SessionError> {
    let mut stream = open_email_stream(&connection).await?;
    let r = stream
        .rejected()
        .await
        .map_err(|e| SessionError::Protocol(e.to_string()))?;
    let _ = stream.finish().await;
    Ok(r)
}

/// Pull the mail queue whenever notified, one pass at a time. The
/// X25519 secret is derived per pass from the identity key and never
/// leaves this function.
async fn drain_loop(
    connection: Connection,
    notify: Arc<Notify>,
    inbox: Inbox,
    identity: Arc<SigningKey>,
) {
    loop {
        notify.notified().await;
        let mut stream = match open_email_stream(&connection).await {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "coord_conn: could not open email stream; stopping drain loop");
                return;
            }
        };
        let secret = identity.x25519_secret();
        let outcome = drain(&mut stream, &secret, &inbox).await;
        let _ = stream.finish().await;
        if let Err(e) = outcome {
            warn!(error = %e, retry_secs = DRAIN_RETRY.as_secs(), "coord_conn: email drain failed");
            let notify = Arc::clone(&notify);
            tokio::spawn(async move {
                tokio::time::sleep(DRAIN_RETRY).await;
                notify.notify_one();
            });
        }
    }
}

fn classify_close(connection: &Connection) -> Result<SessionEnd, SessionError> {
    if let Some(iroh::endpoint::ConnectionError::ApplicationClosed(close)) =
        connection.close_reason()
    {
        let code: u64 = close.error_code.into();
        match code as u16 {
            CLOSE_AUTH_FAILED => return Ok(SessionEnd::AuthFailed),
            CLOSE_REVOKED => return Ok(SessionEnd::Revoked),
            CLOSE_POLICY_REPLACED_BY_NEWER => return Ok(SessionEnd::Superseded),
            _ => {}
        }
    }
    Ok(SessionEnd::Closed)
}

async fn write_envelope_json(send: &mut SendStream, json: &str) -> Result<(), SessionError> {
    let frame = encode_frame(json.as_bytes())?;
    send.write_all(&frame)
        .await
        .map_err(|e| SessionError::Io(std::io::Error::other(e.to_string())))?;
    Ok(())
}

async fn read_envelope(recv: &mut RecvStream) -> Result<Envelope, SessionError> {
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr)
        .await
        .map_err(|e| SessionError::Io(std::io::Error::other(e.to_string())))?;
    let len = decode_frame_length(hdr)?;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| SessionError::Io(std::io::Error::other(e.to_string())))?;
    let s = std::str::from_utf8(&buf)
        .map_err(|e| SessionError::Protocol(format!("frame not utf-8: {e}")))?;
    Envelope::from_json(s).map_err(|e| SessionError::Protocol(format!("envelope: {e}")))
}

async fn read_stream_hello(recv: &mut RecvStream) -> Result<StreamHelloEnvelope, SessionError> {
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr)
        .await
        .map_err(|e| SessionError::Io(std::io::Error::other(e.to_string())))?;
    let len = decode_frame_length(hdr)?;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| SessionError::Io(std::io::Error::other(e.to_string())))?;
    let s = std::str::from_utf8(&buf)
        .map_err(|e| SessionError::Protocol(format!("stream-hello not utf-8: {e}")))?;
    StreamHelloEnvelope::from_json(s)
        .map_err(|e| SessionError::Protocol(format!("stream-hello: {e}")))
}

fn record_auth_failure(window: &mut VecDeque<Instant>) -> bool {
    let now = Instant::now();
    while let Some(&front) = window.front() {
        if now.duration_since(front) > AUTH_FAIL_WINDOW {
            window.pop_front();
        } else {
            break;
        }
    }
    window.push_back(now);
    window.len() < AUTH_FAIL_LIMIT
}

fn jittered_backoff(base_ms: u64) -> u64 {
    let base = base_ms as i64;
    let span = base / 5;
    let jitter: i64 = rand::thread_rng().gen_range(-span..=span);
    (base + jitter).max(100) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Private routes never appear in a `route_announce` snapshot —
    /// coord must not learn their names, and since coord never
    /// accepted them, omitting them from the authoritative snapshot
    /// deletes nothing.
    #[test]
    fn announce_snapshot_filters_private_routes() {
        let records = vec![
            RouteRecord {
                name: "recipes".into(),
                upstream: "http://127.0.0.1:5173".into(),
                registered_at: 1,
                ..Default::default()
            },
            RouteRecord {
                name: "mysvc".into(),
                upstream: "unix:/run/user/1000/mysvc.sock".into(),
                registered_at: 2,
                visibility: p2claw_agent::routes::Visibility::Private,
                ..Default::default()
            },
        ];
        let snapshot = announce_snapshot(records);
        let names: Vec<&str> = snapshot.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["recipes"], "private route must be filtered");
    }

    #[test]
    fn jittered_backoff_stays_in_window() {
        for base in [1_000u64, 2_000, 10_000, 60_000] {
            for _ in 0..64 {
                let v = jittered_backoff(base);
                let lower = (base as i64 - base as i64 / 5).max(100) as u64;
                let upper = (base as i64 + base as i64 / 5) as u64;
                assert!(
                    v >= lower && v <= upper,
                    "base {base}: jitter {v} out of [{lower}, {upper}]"
                );
            }
        }
    }

    #[test]
    fn jittered_backoff_floor_is_100ms() {
        let v = jittered_backoff(10);
        assert!(v >= 100, "got {v}");
    }

    #[test]
    fn auth_failure_window_admits_two_then_trips_on_third() {
        let mut w = VecDeque::new();
        assert!(record_auth_failure(&mut w));
        assert!(record_auth_failure(&mut w));
        assert!(!record_auth_failure(&mut w));
    }

    #[test]
    fn auth_failure_window_evicts_old_entries() {
        let mut w = VecDeque::new();
        let stale = Instant::now() - AUTH_FAIL_WINDOW - Duration::from_secs(1);
        w.push_back(stale);
        w.push_back(stale);
        assert!(record_auth_failure(&mut w));
        assert_eq!(w.len(), 1);
    }
}
