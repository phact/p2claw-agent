//! WebRTC signaling — box side.
//!
//! Coordination signals an incoming browser visitor; we open a peer
//! connection, sign the DTLS fingerprint with the agent identity key,
//! relay the offer / answer / candidates through coordination as
//! opaque base64 blobs, and once the data channel opens, hand the
//! detached byte stream to [`p2claw_translator::serve`] with the
//! agent-wide [`Forwarder`] — same path the iroh listener uses for
//! native peers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use p2claw_agent::forwarder::Forwarder;
use p2claw_control_proto::{SignalEndReason, VisitorKind};
use p2claw_identity::{sign_dtls_fp, SigningKey};
use p2claw_wire::{Frame, StreamId};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data::data_channel::{DataChannel as DetachedDataChannel, PollDataChannel};
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

const FP_ALG_SHA256: u8 = 0x01;

/// Default STUN URL. Boxes need server-reflexive candidates to be
/// reachable across NAT; without STUN we'd only offer host candidates
/// and lose every non-LAN visitor. Override at runtime with
/// `P2CLAW_AGENT_STUN_URL`; empty string disables STUN.
const DEFAULT_STUN: &str = "stun:stun.cloudflare.com:3478";

const STUN_URL_ENV: &str = "P2CLAW_AGENT_STUN_URL";

fn resolve_stun_url() -> Option<String> {
    match std::env::var(STUN_URL_ENV) {
        Ok(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(_) => Some(DEFAULT_STUN.to_string()),
    }
}

/// Slightly larger than coord's 120s session cap so a clock-skewed
/// coord always closes us first.
const SESSION_MAX_LIFETIME: Duration = Duration::from_secs(150);

const INBOUND_CAP: usize = 32;

/// Per-DATA-frame body cap on the WebRTC visitor path.
/// Single-chunk-per-message keeps iPad sessions reliable on
/// low-MTU tunneled paths.
///
/// Budget on a Tailscale-tunneled (1280 MTU) DTLS-over-UDP path:
/// 1280 − 32 (WG) − 8 (UDP) − 20 (IPv4) − 13 (DTLS) − 16 (SCTP
/// chunk) = 1191 user-message ceiling; minus the wire-codec frame
/// header (~20 B) → ~1170 B for the app payload. 800 leaves headroom
/// for IPv6 and other VPN encapsulations.
const WEBRTC_DATA_FRAME_BYTES: usize = 800;

/// What the registry forwards to a live session task.
#[derive(Debug)]
enum SessionInbound {
    Relay { seq: u32, payload_b64: String },
    End { reason: SignalEndReason },
}

/// Outbound frame from a session task → [`crate::control_conn`] →
/// coordination. The control loop translates these into
/// `SignalRelay` / `SignalEnd` envelopes on the WS.
#[derive(Debug, Clone)]
pub enum OutboundSignal {
    Relay {
        session_id: String,
        seq: u32,
        payload_b64: String,
    },
    End {
        session_id: String,
        reason: SignalEndReason,
    },
}

/// Signaling-payload envelope. End-to-end between bootstrap and box
/// (coordination relays the JSON as an opaque base64 blob). Stays
/// permissive — no `deny_unknown_fields` — so each side can add
/// fields without lockstep deploys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalPayload {
    pub kind: PayloadKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<IceCandidatePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtls_fp_sig_b64: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    Offer,
    Answer,
    Candidate,
}

/// Wire shape mirroring `RTCIceCandidateInit` so the candidate can
/// roundtrip through coord without depending on webrtc-rs's
/// serialization conventions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceCandidatePayload {
    pub candidate: String,
    #[serde(rename = "sdpMid", default, skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(
        rename = "sdpMLineIndex",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sdp_m_line_index: Option<u16>,
}

/// Errors that can prematurely end a signaling session.
#[derive(Debug, Error)]
enum SessionError {
    #[error("webrtc: {0}")]
    Webrtc(#[from] webrtc::Error),
    #[error("could not parse inbound payload: {0}")]
    PayloadJson(#[from] serde_json::Error),
    #[error("could not base64-decode inbound payload: {0}")]
    PayloadBase64(#[from] base64::DecodeError),
    #[error("could not sign DTLS fingerprint: {0}")]
    Sign(#[from] p2claw_identity::IdentityError),
    #[error("DTLS fingerprint missing from generated SDP offer")]
    NoFingerprint,
    #[error("DTLS fingerprint algorithm `{0}` not supported (only SHA-256)")]
    UnsupportedFpAlg(String),
    #[error("DTLS fingerprint hex decode failed: {0}")]
    BadFpHex(String),
    #[error("session aborted: control connection dropped")]
    ControlDropped,
}

/// Errors a bridge task can surface back to the session loop.
#[derive(Debug, Error)]
enum BridgeError {
    #[error("data-channel detach failed: {0}")]
    Detach(#[from] webrtc::Error),
    #[error("translator session ended with error: {0}")]
    Translator(#[from] p2claw_translator::TranslatorError),
}

/// Transport path a visitor's WebRTC session settled on. Best-effort:
/// read from the selected ICE candidate pair when the data channel
/// opens. `Unknown` until then — and if the pair can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTransport {
    Unknown,
    /// Peer-to-peer (host / server-reflexive candidate pair).
    Direct,
    /// TURN-relayed (at least one endpoint is a relay candidate).
    Relay,
}

impl SessionTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionTransport::Unknown => "unknown",
            SessionTransport::Direct => "direct",
            SessionTransport::Relay => "relay",
        }
    }
}

/// One active visitor session, as reported by `GET /v1/sessions`.
/// Metadata only — no visitor IPs (coordination-is-metadata-only).
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub id: String,
    pub transport: SessionTransport,
    pub age_secs: u64,
}

struct SessionHandle {
    inbound_tx: mpsc::Sender<SessionInbound>,
    /// When `signal_push` created this session — powers `age_secs`.
    started_at: Instant,
    /// Filled in when the data channel opens (see `detect_transport`).
    /// Shared with the session task so the snapshot reflects the live
    /// value without threading it back through the registry.
    transport: Arc<std::sync::Mutex<SessionTransport>>,
}

/// Live signaling sessions, indexed by `session_id`. The control loop
/// calls [`Self::on_push`] / [`Self::on_relay`] / [`Self::on_end`] as
/// it parses inbound frames; [`Self::shutdown_all`] drops every
/// session on control-conn reconnect (coord forgets about them when
/// the control channel drops).
pub struct SignalRegistry {
    identity: Arc<SigningKey>,
    outbound_tx: mpsc::Sender<OutboundSignal>,
    sessions: Mutex<HashMap<String, SessionHandle>>,
    /// `None` skips ICE STUN gathering (host candidates only). Used
    /// by tests; production resolves via [`resolve_stun_url`].
    stun_url: Option<String>,
    handler: Forwarder,
}

impl SignalRegistry {
    pub fn new(
        identity: Arc<SigningKey>,
        outbound_tx: mpsc::Sender<OutboundSignal>,
        handler: Forwarder,
    ) -> Self {
        Self {
            identity,
            outbound_tx,
            sessions: Mutex::new(HashMap::new()),
            stun_url: resolve_stun_url(),
            handler,
        }
    }

    /// Test-only constructor: drop the public STUN server so unit
    /// tests don't try to reach the network during ICE gathering.
    #[cfg(test)]
    pub fn new_no_stun(
        identity: Arc<SigningKey>,
        outbound_tx: mpsc::Sender<OutboundSignal>,
        handler: Forwarder,
    ) -> Self {
        Self {
            identity,
            outbound_tx,
            sessions: Mutex::new(HashMap::new()),
            stun_url: None,
            handler,
        }
    }

    pub async fn on_push(self: &Arc<Self>, session_id: String, visitor_kind: VisitorKind) {
        if !matches!(visitor_kind, VisitorKind::Browser) {
            // Native visitors dial iroh directly; coord shouldn't
            // push a non-browser session at us, but tolerate it.
            debug!(
                %session_id,
                ?visitor_kind,
                "signal: ignoring non-browser signal_push"
            );
            return;
        }

        let (inbound_tx, inbound_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let transport = Arc::new(std::sync::Mutex::new(SessionTransport::Unknown));
        {
            let mut sessions = self.sessions.lock().await;
            if sessions.contains_key(&session_id) {
                warn!(%session_id, "signal: duplicate signal_push; ignoring");
                return;
            }
            sessions.insert(
                session_id.clone(),
                SessionHandle {
                    inbound_tx,
                    started_at: Instant::now(),
                    transport: Arc::clone(&transport),
                },
            );
        }

        let registry = Arc::clone(self);
        let sid = session_id.clone();
        tokio::spawn(async move {
            let outcome = run_session(
                sid.clone(),
                inbound_rx,
                registry.outbound_tx.clone(),
                Arc::clone(&registry.identity),
                registry.stun_url.clone(),
                registry.handler.clone(),
                transport,
            )
            .await;
            match outcome {
                Ok(reason) => {
                    info!(%sid, ?reason, "signal: session ended");
                    let _ = registry
                        .outbound_tx
                        .send(OutboundSignal::End {
                            session_id: sid.clone(),
                            reason,
                        })
                        .await;
                }
                Err(e) => {
                    warn!(%sid, error = %e, "signal: session aborted");
                    let _ = registry
                        .outbound_tx
                        .send(OutboundSignal::End {
                            session_id: sid.clone(),
                            reason: SignalEndReason::Error,
                        })
                        .await;
                }
            }
            registry.sessions.lock().await.remove(&sid);
        });
    }

    /// Snapshot of the live visitor sessions for `GET /v1/sessions`.
    /// Metadata only: id, best-effort transport path, and age.
    pub async fn list_sessions(&self) -> Vec<SessionSnapshot> {
        let now = Instant::now();
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .map(|(id, h)| SessionSnapshot {
                id: id.clone(),
                transport: *h.transport.lock().expect("transport mutex poisoned"),
                age_secs: now.saturating_duration_since(h.started_at).as_secs(),
            })
            .collect()
    }

    pub async fn on_relay(&self, session_id: &str, seq: u32, payload_b64: String) {
        let sessions = self.sessions.lock().await;
        let Some(handle) = sessions.get(session_id) else {
            debug!(%session_id, seq, "signal: relay for unknown session; ignoring");
            return;
        };
        if let Err(e) = handle
            .inbound_tx
            .try_send(SessionInbound::Relay { seq, payload_b64 })
        {
            warn!(%session_id, seq, error = %e, "signal: session inbound full or closed");
        }
    }

    pub async fn on_end(&self, session_id: &str, reason: SignalEndReason) {
        // Clone the sender and drop the registry lock before awaiting
        // — End is lifecycle-critical (a missed End leaves the session
        // running until lifetime cap), so backpressure-aware
        // `send().await` replaces `try_send`. Holding the sessions
        // lock across the await would deadlock the next on_push /
        // shutdown_all call.
        let tx = {
            let sessions = self.sessions.lock().await;
            let Some(handle) = sessions.get(session_id) else {
                debug!(%session_id, ?reason, "signal: end for unknown session; ignoring");
                return;
            };
            handle.inbound_tx.clone()
        };
        if let Err(e) = tx.send(SessionInbound::End { reason }).await {
            // Receiver dropped: session task already exited, nothing
            // to do. This is the only legitimate failure mode now
            // that we backpressure on capacity.
            debug!(%session_id, error = %e, "signal: End dropped — session already gone");
        }
    }

    /// Drop all live sessions on control-conn reconnect (coord
    /// forgets in-flight sessions when the control channel drops).
    /// Each session task observes the closed inbound channel from its
    /// select loop, aborts the bridge if one is running, and exits.
    pub async fn shutdown_all(&self) {
        let mut sessions = self.sessions.lock().await;
        let n = sessions.len();
        sessions.clear();
        if n > 0 {
            info!(n, "signal: cleared in-flight sessions on control reconnect");
        }
    }
}

/// Drive a session from `signal_push` to either a connected data
/// channel + handler completion or a fatal error.
///
/// Once [`build_peer_connection`] returns Ok the PC owns ICE-agent
/// UDP sockets, DTLS state, and (after `set_local_description`) an
/// SCTP transport. Every error path must `pc.close().await` before
/// unwinding or those sockets linger for minutes — the
/// [`run_session_after_build`] wrap exists so a single match arm
/// runs the close on every error return.
async fn run_session(
    session_id: String,
    inbound_rx: mpsc::Receiver<SessionInbound>,
    outbound_tx: mpsc::Sender<OutboundSignal>,
    identity: Arc<SigningKey>,
    stun_url: Option<String>,
    handler: Forwarder,
    transport: Arc<std::sync::Mutex<SessionTransport>>,
) -> Result<SignalEndReason, SessionError> {
    info!(%session_id, "signal: session opening");

    let pc = build_peer_connection(stun_url.as_deref()).await?;

    let result = run_session_after_build(
        &pc,
        session_id,
        inbound_rx,
        outbound_tx,
        identity,
        handler,
        transport,
    )
    .await;

    // The Ok branches inside the inner function already call
    // `break_with(&pc)` themselves before returning, but every
    // error path between `build_peer_connection` and the main
    // select-loop entry could skip that step. Drive
    // `pc.close()` unconditionally here — `break_with` is
    // idempotent (webrtc-rs's RTCPeerConnection::close handles
    // double-close), so paying the close cost twice on the happy
    // path is preferable to a leaked socket on the unhappy one.
    if result.is_err() {
        break_with(&pc).await;
    }
    result
}

#[allow(clippy::too_many_arguments)] // single caller; args are conceptually distinct.
/// Best-effort read of the selected ICE candidate pair's path type.
/// webrtc-rs 0.13 exposes the pair only through its `Display` impl
/// (the candidate fields are private), which renders each endpoint as
/// `"<proto> <typ> <addr>"`; a `relay` typ on either endpoint means
/// the visitor is on a TURN fallback. Returns `Unknown` if no pair is
/// selected yet. Never fails — status/observability must not perturb
/// the data path.
async fn detect_transport(pc: &Arc<RTCPeerConnection>) -> SessionTransport {
    let dtls = pc.sctp().transport();
    let ice = dtls.ice_transport();
    match ice.get_selected_candidate_pair().await {
        Some(pair) => {
            if pair.to_string().contains(" relay ") {
                SessionTransport::Relay
            } else {
                SessionTransport::Direct
            }
        }
        None => SessionTransport::Unknown,
    }
}

async fn run_session_after_build(
    pc: &Arc<RTCPeerConnection>,
    session_id: String,
    mut inbound_rx: mpsc::Receiver<SessionInbound>,
    outbound_tx: mpsc::Sender<OutboundSignal>,
    identity: Arc<SigningKey>,
    handler: Forwarder,
    transport: Arc<std::sync::Mutex<SessionTransport>>,
) -> Result<SignalEndReason, SessionError> {
    // Box-initiated channel; browser side learns about it via
    // `ondatachannel` when our offer arrives.
    let dc_init = RTCDataChannelInit {
        ordered: Some(true),
        ..Default::default()
    };
    let dc = pc.create_data_channel("p2claw", Some(dc_init)).await?;

    // on_open can't `.await` translator::serve directly (callback
    // lifetime is narrow); signal back to the main task instead.
    let (dc_open_tx, mut dc_open_rx) = mpsc::channel::<()>(1);
    {
        let dc_open_tx = dc_open_tx.clone();
        dc.on_open(Box::new(move || {
            let dc_open_tx = dc_open_tx.clone();
            Box::pin(async move {
                debug!("signal: data channel opened");
                let _ = dc_open_tx.send(()).await;
            })
        }));
    }

    // Ferry locally-gathered ICE candidates → coord as
    // `signal_relay(candidate)` frames. The offer must reach the
    // browser before any candidate (a candidate arriving while
    // remote-description is null is rejected) — but
    // `set_local_description(offer)` kicks off ICE gathering
    // synchronously, so host candidates can fire before the offer
    // ships. Buffer candidates until the offer is on the wire, then
    // drain in arrival order.
    let outbound_for_ice = outbound_tx.clone();
    let session_for_ice = session_id.clone();
    let local_seq = Arc::new(std::sync::atomic::AtomicU32::new(1));
    let local_seq_for_ice = Arc::clone(&local_seq);
    let offer_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let offer_sent_for_ice = Arc::clone(&offer_sent);
    let cand_buffer: Arc<Mutex<Vec<SignalPayload>>> = Arc::new(Mutex::new(Vec::new()));
    let cand_buffer_for_ice = Arc::clone(&cand_buffer);
    pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let outbound = outbound_for_ice.clone();
        let sid = session_for_ice.clone();
        let local_seq = Arc::clone(&local_seq_for_ice);
        let offer_sent = Arc::clone(&offer_sent_for_ice);
        let cand_buffer = Arc::clone(&cand_buffer_for_ice);
        Box::pin(async move {
            let Some(c) = c else {
                // None == ICE gathering complete. Trickle ICE means
                // we don't need to send an explicit "end of
                // candidates"; coord just stops seeing new ones.
                debug!(%sid, "signal: ICE gathering complete");
                return;
            };
            let init = match c.to_json() {
                Ok(i) => i,
                Err(e) => {
                    warn!(%sid, error = %e, "signal: candidate.to_json failed; dropping");
                    return;
                }
            };
            let payload = SignalPayload {
                kind: PayloadKind::Candidate,
                sdp: None,
                candidate: Some(IceCandidatePayload {
                    candidate: init.candidate,
                    sdp_mid: init.sdp_mid,
                    sdp_m_line_index: init.sdp_mline_index,
                }),
                dtls_fp_sig_b64: None,
            };
            // Decide under the buffer lock so we can't race with the
            // drain path: that path also holds this lock when it
            // flips `offer_sent`, so any callback either lands in
            // the to-be-drained buffer or sees the flipped flag and
            // sends directly. No candidate ever ends up stranded in
            // an already-drained buffer.
            let mut buf = cand_buffer.lock().await;
            if offer_sent.load(std::sync::atomic::Ordering::Relaxed) {
                drop(buf);
                let seq = local_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                send_payload(&outbound, &sid, seq, &payload).await;
            } else {
                buf.push(payload);
            }
        })
    }));

    // Surface PC state for the select! below. `watch` is drop-and-
    // coalesce by design: the callback never blocks even if the
    // select loop is briefly busy elsewhere, and the receiver always
    // sees the latest state (including terminal Failed / Closed).
    let (pc_state_tx, mut pc_state_rx) = watch::channel::<Option<RTCPeerConnectionState>>(None);
    pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
        let tx = pc_state_tx.clone();
        Box::pin(async move {
            debug!(state = ?s, "signal: pc state change");
            let _ = tx.send(Some(s));
        })
    }));

    // Build the offer, sign its DTLS fingerprint, and ship it.
    let offer = pc.create_offer(None).await?;
    pc.set_local_description(offer.clone()).await?;

    let fp = extract_sha256_fingerprint(&offer.sdp)?;
    let sig = sign_dtls_fp(&identity, &session_id, FP_ALG_SHA256, &fp)?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    let offer_payload = SignalPayload {
        kind: PayloadKind::Offer,
        sdp: Some(offer.sdp.clone()),
        candidate: None,
        dtls_fp_sig_b64: Some(sig_b64),
    };
    send_payload(&outbound_tx, &session_id, 0, &offer_payload).await;

    // Drain candidates that fired during offer setup, in arrival
    // order. The lock is held across the await so a concurrent
    // candidate callback either:
    //   - blocks on the lock and ends up appended after we drain
    //     (it'll observe `offer_sent = true` after we Release and
    //     take the fast path on its next call), or
    //   - already pushed before we entered the lock (gets drained).
    // Either way, no candidate is sent before the offer.
    {
        let mut buffer = cand_buffer.lock().await;
        let drained: Vec<SignalPayload> = std::mem::take(&mut *buffer);
        offer_sent.store(true, std::sync::atomic::Ordering::Release);
        drop(buffer);
        for payload in drained {
            let seq = local_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            send_payload(&outbound_tx, &session_id, seq, &payload).await;
        }
    }

    // Main session loop. Resolves to an end reason or a SessionError.
    //
    // The bridge runs on a separate task once the DC opens so the
    // select loop keeps polling inbound (End, control reconnect),
    // pc_state (Failed / Closed), and the lifetime deadline. Every
    // shutdown path aborts the bridge before closing the PC; the
    // bridge task itself releases its resources on abort.
    //
    // Signaling and the data path have different lifetimes. The
    // lifetime cap and the control channel bound SIGNALING; once the
    // bridge is up the session belongs to the data path, whose end
    // conditions are the PC state (Failed / Closed / Disconnected),
    // the bridge finishing, and the translator's liveness timeout.
    // Three inputs therefore must not tear down a live bridge:
    // `end(connected)` (the browser's signaling-complete notice,
    // mirrored by coord after every successful connect), the
    // lifetime cap, and the control connection dropping.
    let lifetime_deadline = tokio::time::sleep(SESSION_MAX_LIFETIME);
    tokio::pin!(lifetime_deadline);
    let mut bridge_handle: Option<JoinHandle<Result<(), BridgeError>>> = None;
    let mut inbound_open = true;

    let end_reason = loop {
        tokio::select! {
            biased;
            // Bounds the signaling phase only — a bridged session
            // lives as long as the visitor does.
            _ = &mut lifetime_deadline, if bridge_handle.is_none() => {
                warn!(%session_id, "signal: session lifetime cap reached; ending");
                break_with(pc).await;
                return Ok(SignalEndReason::Timeout);
            }
            msg = inbound_rx.recv(), if inbound_open => match msg {
                None => {
                    // Registry dropped us (e.g. control-conn
                    // reconnect). Coord forgets signaling sessions,
                    // but a bridged data session no longer needs
                    // coord — stop polling the closed channel and
                    // let the data path decide when the session ends.
                    if bridge_handle.is_some() {
                        debug!(%session_id, "signal: control channel closed; bridge continues");
                        inbound_open = false;
                    } else {
                        debug!(%session_id, "signal: inbound channel closed; ending");
                        break_with(pc).await;
                        return Err(SessionError::ControlDropped);
                    }
                }
                Some(SessionInbound::End { reason }) => {
                    if matches!(reason, SignalEndReason::Connected) {
                        // Normal completion notice: signaling is
                        // done, the data path owns the session.
                        info!(%session_id, "signal: end(connected) from coord; bridge owns the session");
                    } else {
                        info!(%session_id, ?reason, "signal: end from coord");
                        abort_bridge(&mut bridge_handle).await;
                        break_with(pc).await;
                        return Ok(reason);
                    }
                }
                Some(SessionInbound::Relay { seq, payload_b64 }) => {
                    if let Err(e) = handle_inbound_relay(pc, seq, &payload_b64).await {
                        warn!(%session_id, seq, error = %e, "signal: inbound relay handling failed");
                    }
                }
            },
            res = pc_state_rx.changed() => {
                if res.is_err() {
                    // Sender dropped — the PC is gone. Treat as End.
                    abort_bridge(&mut bridge_handle).await;
                    break_with(pc).await;
                    return Ok(SignalEndReason::Aborted);
                }
                let state = *pc_state_rx.borrow_and_update();
                match state {
                    Some(RTCPeerConnectionState::Failed) => {
                        warn!(%session_id, "signal: peer connection failed");
                        abort_bridge(&mut bridge_handle).await;
                        break_with(pc).await;
                        return Ok(SignalEndReason::Error);
                    }
                    Some(RTCPeerConnectionState::Closed | RTCPeerConnectionState::Disconnected) => {
                        info!(%session_id, ?state, "signal: peer connection ended");
                        abort_bridge(&mut bridge_handle).await;
                        break_with(pc).await;
                        return Ok(SignalEndReason::Aborted);
                    }
                    _ => {}
                }
            }
            opened = dc_open_rx.recv(), if bridge_handle.is_none() => {
                if opened.is_none() { continue; }
                // DC open means ICE has a selected pair; classify the
                // transport path for `GET /v1/sessions` (best-effort).
                *transport.lock().expect("transport mutex poisoned") = detect_transport(pc).await;
                let dc = Arc::clone(&dc);
                let sid = session_id.clone();
                let h = handler.clone();
                bridge_handle = Some(tokio::spawn(bridge_to_translator(dc, sid, h)));
            }
            res = wait_for_bridge(&mut bridge_handle) => {
                // Bridge finished on its own. Classify by the inner
                // result: a clean translator exit → Connected; a
                // bridge-internal error or a panic → Error. The
                // handle is taken inside `wait_for_bridge`.
                let reason = match res {
                    Ok(Ok(())) => {
                        debug!(%session_id, "signal: bridge completed cleanly");
                        SignalEndReason::Connected
                    }
                    Ok(Err(e)) => {
                        warn!(%session_id, error = %e, "signal: bridge surfaced an error");
                        SignalEndReason::Error
                    }
                    Err(e) => {
                        warn!(%session_id, error = %e, "signal: bridge task panicked or was cancelled");
                        SignalEndReason::Error
                    }
                };
                break reason;
            }
        }
    };

    break_with(pc).await;
    Ok(end_reason)
}

/// Wait for the bridge task to finish iff one is running. Takes the
/// handle out on completion so a re-poll won't double-await. The
/// outer `JoinError` covers panics / cancellation; the inner
/// `BridgeError` covers detach + translator failures the task
/// surfaces normally.
async fn wait_for_bridge(
    slot: &mut Option<JoinHandle<Result<(), BridgeError>>>,
) -> Result<Result<(), BridgeError>, tokio::task::JoinError> {
    match slot.as_mut() {
        Some(h) => {
            let res = h.await;
            *slot = None;
            res
        }
        None => std::future::pending().await,
    }
}

/// Abort the bridge if one is running, then await its termination so
/// the PollDataChannel + sampler task settle before the PC is closed.
async fn abort_bridge(slot: &mut Option<JoinHandle<Result<(), BridgeError>>>) {
    if let Some(h) = slot.take() {
        h.abort();
        let _ = h.await;
    }
}

/// The box is the controlling ICE agent, so it decides when a pair is
/// good enough. webrtc-ice's defaults hold back non-host pairs (500 ms
/// srflx, 1 s prflx, 2 s relay) hoping a better pair turns up; browsers
/// hide host candidates behind mDNS, so on a LAN the box usually sees
/// prflx and every connect paid that full wait. Accept any working pair
/// immediately; a relay pair can still be upgraded once a direct path
/// is found.
fn ice_acceptance_waits(se: &mut SettingEngine) {
    let now = Some(Duration::ZERO);
    se.set_host_acceptance_min_wait(now);
    se.set_srflx_acceptance_min_wait(now);
    se.set_prflx_acceptance_min_wait(now);
    se.set_relay_acceptance_min_wait(now);
}

/// Build an [`RTCPeerConnection`] with detached data channels — lets
/// the open DC become an `AsyncRead + AsyncWrite` for
/// translator::serve.
async fn build_peer_connection(
    stun_url: Option<&str>,
) -> Result<Arc<RTCPeerConnection>, SessionError> {
    let mut setting_engine = SettingEngine::default();
    setting_engine.detach_data_channels();
    ice_acceptance_waits(&mut setting_engine);

    let api = APIBuilder::new()
        .with_setting_engine(setting_engine)
        .build();

    let mut config = RTCConfiguration::default();
    if let Some(u) = stun_url {
        config.ice_servers.push(RTCIceServer {
            urls: vec![u.to_string()],
            ..Default::default()
        });
    }

    let pc = api.new_peer_connection(config).await?;
    Ok(Arc::new(pc))
}

async fn handle_inbound_relay(
    pc: &Arc<RTCPeerConnection>,
    seq: u32,
    payload_b64: &str,
) -> Result<(), SessionError> {
    let raw = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
    let payload: SignalPayload = serde_json::from_slice(&raw)?;
    debug!(seq, kind = ?payload.kind, "signal: inbound payload");

    match payload.kind {
        PayloadKind::Answer => {
            let Some(sdp) = payload.sdp else {
                warn!("signal: answer with no SDP; ignoring");
                return Ok(());
            };
            let answer = RTCSessionDescription::answer(sdp)?;
            pc.set_remote_description(answer).await?;
        }
        PayloadKind::Candidate => {
            let Some(c) = payload.candidate else {
                warn!("signal: candidate with no payload; ignoring");
                return Ok(());
            };
            let init = RTCIceCandidateInit {
                candidate: c.candidate,
                sdp_mid: c.sdp_mid,
                sdp_mline_index: c.sdp_m_line_index,
                username_fragment: None,
            };
            pc.add_ice_candidate(init).await?;
        }
        PayloadKind::Offer => {
            // Only the box originates offers.
            warn!("signal: unexpected inbound offer; ignoring");
        }
    }
    Ok(())
}

/// Detach the data channel and pump translator::serve over the
/// resulting byte stream. Wires a [`SessionTxLogger`] tap so each
/// outbound frame logs a `[p2claw:dc.tx] …` line correlated with the
/// browser's `[p2claw:dc] rx …` counters, plus a 500 ms sampler on
/// `bufferedAmount` to surface backpressure between frames.
async fn bridge_to_translator(
    dc: Arc<RTCDataChannel>,
    session_id: String,
    handler: Forwarder,
) -> Result<(), BridgeError> {
    let raw = dc.detach().await?;

    let logger = Arc::new(SessionTxLogger::new(session_id.clone(), Arc::clone(&raw)));

    let sampler_logger = Arc::clone(&logger);
    let (cancel_sampler, sampler_done) = tokio::sync::oneshot::channel::<()>();
    let sampler_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // tokio::interval's first tick is immediate; drop it so the
        // first sample reflects 500 ms of real session activity.
        tick.tick().await;
        let mut last_logged: Option<usize> = None;
        tokio::pin!(sampler_done);
        loop {
            tokio::select! {
                biased;
                _ = &mut sampler_done => return,
                _ = tick.tick() => {
                    let now = sampler_logger.buffered_amount();
                    let delta_significant = match last_logged {
                        None => now > 0,
                        Some(prev) => now != prev && (now.abs_diff(prev) >= 4 * 1024 || now == 0),
                    };
                    if delta_significant {
                        sampler_logger.log_buffered_amount(now);
                        last_logged = Some(now);
                    }
                }
            }
        }
    });

    // PollDataChannel's default 8 KiB read buffer errors with "Short
    // buffer (size: 8192) to be filled" on any inbound SCTP message
    // larger than that. Translator's client-side default outbound
    // cap is 16 KiB, so legitimate browser POST chunks routinely hit
    // it. Bump to the SCTP `maxMessageSize=65536` ceiling.
    let mut stream = PollDataChannel::new(raw);
    stream.set_read_buf_capacity(64 * 1024);
    // One write is one SCTP message; large frames (e.g. a big WS
    // message) must be split or the send fails and kills the writer.
    let stream = p2claw_agent::dc_stream::MessageSizeCap::new(stream);

    let observer_logger = Arc::clone(&logger);
    let options = p2claw_translator::ServeOptions {
        tx_observer: Some(Arc::new(move |frame| {
            observer_logger.observe(frame);
        })),
        max_data_frame_payload: WEBRTC_DATA_FRAME_BYTES,
        // Route WS_UPGRADE to `WsForwarder` instead of the translator's
        // built-in 501, matching the iroh-listener path.
        ws_handler: Some(std::sync::Arc::new(
            p2claw_agent::ws_forwarder::WsForwarder::new(handler.clone()),
        )),
        ..Default::default()
    };
    info!(
        %session_id,
        max_data_frame_payload = WEBRTC_DATA_FRAME_BYTES,
        "signal: bridging data channel to translator"
    );

    // `SessionCleanup`'s Drop ensures `log_session_summary` fires even
    // if this task is aborted mid-`serve_with` (End / control drop /
    // lifetime cap / pc_state Failed all trigger an abort from the
    // session loop). `finish()` runs the happy-path cleanup so the
    // sampler is properly awaited before the summary lands.
    let summary_logger = Arc::clone(&logger);
    let cleanup = SessionCleanup::new(cancel_sampler, sampler_task, move || {
        summary_logger.log_session_summary()
    });

    let outcome = p2claw_translator::serve_with(stream, handler, options).await;

    cleanup.finish().await;

    outcome.map_err(BridgeError::Translator)
}

/// Cleanup guard for the per-bridge background work.
///
/// `finish()` is the normal-return path: cancel the sampler, await
/// its termination, then flush the session summary. If the task is
/// dropped (aborted) before `finish()` runs, the Drop impl still
/// fires the summary so journalctl carries a closing tally for every
/// session — including those torn down by abort.
///
/// The Drop path can't `.await`, so the sampler isn't joined there;
/// it sees the cancel signal (or the dropped oneshot) and exits on
/// its next tick.
struct SessionCleanup<F>
where
    F: FnOnce() + Send + 'static,
{
    cancel_sampler: Option<tokio::sync::oneshot::Sender<()>>,
    sampler_task: Option<JoinHandle<()>>,
    summary: Option<F>,
}

impl<F> SessionCleanup<F>
where
    F: FnOnce() + Send + 'static,
{
    fn new(
        cancel_sampler: tokio::sync::oneshot::Sender<()>,
        sampler_task: JoinHandle<()>,
        summary: F,
    ) -> Self {
        Self {
            cancel_sampler: Some(cancel_sampler),
            sampler_task: Some(sampler_task),
            summary: Some(summary),
        }
    }

    /// Happy-path cleanup: cancel + await the sampler so its last
    /// `bufferedAmount` sample lands before the summary, then flush
    /// the summary. Taking each field via `Option::take` leaves Drop
    /// with nothing to do.
    async fn finish(mut self) {
        if let Some(tx) = self.cancel_sampler.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.sampler_task.take() {
            let _ = t.await;
        }
        if let Some(f) = self.summary.take() {
            f();
        }
    }
}

impl<F> Drop for SessionCleanup<F>
where
    F: FnOnce() + Send + 'static,
{
    fn drop(&mut self) {
        // Abort path: fire cancel (best-effort), detach the sampler
        // (we can't await), and flush the summary so abort still
        // leaves a journalctl entry.
        if let Some(tx) = self.cancel_sampler.take() {
            let _ = tx.send(());
        }
        // `sampler_task` is detached on drop; the cancel signal (or
        // the dropped oneshot receiver) wakes it on the next tick.
        self.sampler_task.take();
        if let Some(f) = self.summary.take() {
            f();
        }
    }
}

/// Per-stream tallies behind the `stream_done` aggregate. DATA /
/// WS_MSG contributions are recorded only when trace is enabled
/// (see `observe`); session-level totals stay exact via the
/// `total_frames` / `total_bytes` atomics.
struct StreamCounters {
    frames: u64,
    bytes: u64,
    /// Wall-clock start so `elapsed_ms` reflects RES → END_STREAM
    /// rather than handler-dispatch latency.
    started_at: Instant,
}

/// Per-frame send-side observer for the WebRTC visitor path. Logs
/// outbound `Frame`s (kind, stream_id, payload size,
/// `bufferedAmount`) tagged with `session_id` so a journalctl grep
/// can collate a whole session even when streams interleave.
/// High-volume DATA / WS_MSG lines are trace-level; stream-terminal
/// `stream_done` aggregates and the final `session_summary` stay at
/// info.
struct SessionTxLogger {
    session_id: String,
    dc: Arc<DetachedDataChannel>,
    streams: Mutex<HashMap<StreamId, StreamCounters>>,
    total_frames: AtomicU64,
    total_bytes: AtomicU64,
}

impl SessionTxLogger {
    fn new(session_id: String, dc: Arc<DetachedDataChannel>) -> Self {
        Self {
            session_id,
            dc,
            streams: Mutex::new(HashMap::new()),
            total_frames: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    fn buffered_amount(&self) -> usize {
        self.dc.buffered_amount()
    }

    fn log_buffered_amount(&self, n: usize) {
        info!(
            target: "p2claw::dc::tx",
            session = %self.session_id,
            buffered_amount = n,
            "[p2claw:dc.tx] buffered_sample"
        );
    }

    fn log_session_summary(&self) {
        let frames = self.total_frames.load(AtomicOrdering::Relaxed);
        let bytes = self.total_bytes.load(AtomicOrdering::Relaxed);
        // try_lock so summary stays sync-callable. Sampler is the
        // only other holder and we've cancelled it by the time this
        // runs; leftover_streams is a best-effort signal.
        let leftover_streams = self.streams.try_lock().map(|g| g.len()).unwrap_or(0);
        info!(
            target: "p2claw::dc::tx",
            session = %self.session_id,
            frames,
            bytes,
            leftover_streams,
            buffered_amount = self.buffered_amount(),
            "[p2claw:dc.tx] session_summary"
        );
    }

    /// Must stay cheap — runs on the writer task's critical path;
    /// blocking it backs up the wire.
    fn observe(&self, frame: &Frame) {
        self.total_frames.fetch_add(1, AtomicOrdering::Relaxed);
        let payload_bytes = frame_payload_len(frame);
        if payload_bytes > 0 {
            self.total_bytes
                .fetch_add(payload_bytes as u64, AtomicOrdering::Relaxed);
        }
        let session = self.session_id.as_str();

        // `buffered_amount()` is read inside each event macro so the
        // sample is only taken when the line actually emits.
        match frame {
            Frame::Res {
                stream_id,
                flags,
                status,
                ..
            } => {
                self.touch_stream(*stream_id, payload_bytes);
                info!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "res",
                    stream_id = stream_id.0,
                    status = *status,
                    end_stream = flags.end_stream(),
                    size = payload_bytes,
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
                if flags.end_stream() {
                    self.finalize_stream(*stream_id, "res_end_stream");
                }
            }
            Frame::Data {
                stream_id,
                flags,
                body,
            } => {
                // Trace-only: at the frame cap a large response is
                // thousands of DATA frames on the writer task's
                // critical path. The per-stream counter update is
                // gated too; session totals (atomics above) and the
                // stream-terminal aggregates stay on at info.
                if tracing::enabled!(target: "p2claw::dc::tx", tracing::Level::TRACE) {
                    self.touch_stream(*stream_id, payload_bytes);
                    trace!(
                        target: "p2claw::dc::tx",
                        session,
                        kind = "data",
                        stream_id = stream_id.0,
                        end_stream = flags.end_stream(),
                        size = body.len(),
                        buffered_amount = self.dc.buffered_amount(),
                        "[p2claw:dc.tx] frame"
                    );
                }
                if flags.end_stream() {
                    self.finalize_stream(*stream_id, "data_end_stream");
                }
            }
            Frame::End { stream_id } => {
                self.touch_stream(*stream_id, payload_bytes);
                info!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "end",
                    stream_id = stream_id.0,
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
                self.finalize_stream(*stream_id, "end");
            }
            Frame::Trailers { stream_id, headers } => {
                self.touch_stream(*stream_id, payload_bytes);
                info!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "trailers",
                    stream_id = stream_id.0,
                    n_trailers = headers.len(),
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
                self.finalize_stream(*stream_id, "trailers");
            }
            Frame::Err {
                stream_id, code, ..
            } => {
                self.touch_stream(*stream_id, payload_bytes);
                warn!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "err",
                    stream_id = stream_id.0,
                    code = code.0,
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
                self.finalize_stream(*stream_id, "err");
            }
            Frame::WsAccept { stream_id, .. } => {
                self.touch_stream(*stream_id, payload_bytes);
                info!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "ws_accept",
                    stream_id = stream_id.0,
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
            }
            Frame::WsMsg {
                stream_id,
                opcode,
                payload,
            } => {
                // Trace-only, same reasoning as DATA — one line per
                // outbound WS message would dominate a busy socket.
                if tracing::enabled!(target: "p2claw::dc::tx", tracing::Level::TRACE) {
                    self.touch_stream(*stream_id, payload_bytes);
                    trace!(
                        target: "p2claw::dc::tx",
                        session,
                        kind = "ws_msg",
                        stream_id = stream_id.0,
                        opcode = ?opcode,
                        size = payload.len(),
                        buffered_amount = self.dc.buffered_amount(),
                        "[p2claw:dc.tx] frame"
                    );
                }
            }
            Frame::WsClose {
                stream_id, code, ..
            } => {
                self.touch_stream(*stream_id, payload_bytes);
                info!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "ws_close",
                    stream_id = stream_id.0,
                    code = *code,
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
                self.finalize_stream(*stream_id, "ws_close");
            }
            Frame::Goaway { code, message, .. } => {
                warn!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "goaway",
                    code = code.0,
                    reason = %String::from_utf8_lossy(message),
                    buffered_amount = self.dc.buffered_amount(),
                    total_frames = self.total_frames.load(AtomicOrdering::Relaxed),
                    total_bytes = self.total_bytes.load(AtomicOrdering::Relaxed),
                    "[p2claw:dc.tx] giveup"
                );
            }
            Frame::Ping { .. } | Frame::Pong { .. } => {
                // Connection-level chatter; debug-level so it doesn't
                // drown out the per-stream signal.
                debug!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = if matches!(frame, Frame::Ping { .. }) { "ping" } else { "pong" },
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
            }
            Frame::Probe { id, payload } => {
                info!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "probe",
                    probe_id = *id,
                    size = payload.len(),
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
            }
            Frame::ProbeAck { id } => {
                // Box doesn't originate ProbeAck; fires only if the
                // wrapper sent us a Probe and the defensive-symmetry
                // path echoed back. Debug breadcrumb.
                debug!(
                    target: "p2claw::dc::tx",
                    session,
                    kind = "probe_ack",
                    probe_id = *id,
                    buffered_amount = self.dc.buffered_amount(),
                    "[p2claw:dc.tx] frame"
                );
            }
            Frame::Req { stream_id, .. } | Frame::WsUpgrade { stream_id, .. } => {
                // REQ/WS_UPGRADE flow browser → box only; an
                // outbound one would be a logic regression.
                warn!(
                    target: "p2claw::dc::tx",
                    session,
                    stream_id = stream_id.0,
                    kind = "unexpected_outbound_request",
                    "[p2claw:dc.tx] frame"
                );
            }
        }
    }

    fn touch_stream(&self, stream_id: StreamId, payload_bytes: usize) {
        // try_lock so the observer never blocks the writer task. A
        // missed update only costs aggregate fidelity; the per-emit
        // log line above still went out.
        if let Ok(mut guard) = self.streams.try_lock() {
            let entry = guard.entry(stream_id).or_insert_with(|| StreamCounters {
                frames: 0,
                bytes: 0,
                started_at: Instant::now(),
            });
            entry.frames += 1;
            entry.bytes += payload_bytes as u64;
        }
    }

    fn finalize_stream(&self, stream_id: StreamId, reason: &'static str) {
        let Ok(mut guard) = self.streams.try_lock() else {
            return;
        };
        let Some(counters) = guard.remove(&stream_id) else {
            return;
        };
        let elapsed_ms = counters.started_at.elapsed().as_millis() as u64;
        info!(
            target: "p2claw::dc::tx",
            session = %self.session_id,
            stream_id = stream_id.0,
            frames = counters.frames,
            bytes = counters.bytes,
            elapsed_ms,
            reason,
            buffered_amount = self.dc.buffered_amount(),
            "[p2claw:dc.tx] stream_done"
        );
    }
}

/// Approximate payload length for the per-frame `size` log field.
/// Exact for DATA; for other frame types, sums the parts that
/// dominate the SCTP message (body, header values, message strings)
/// without coupling to the codec's exact byte count.
fn frame_payload_len(frame: &Frame) -> usize {
    match frame {
        Frame::Data { body, .. } => body.len(),
        Frame::WsMsg { payload, .. } => payload.len(),
        Frame::Res { headers, .. }
        | Frame::Trailers { headers, .. }
        | Frame::WsAccept { headers, .. } => headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>(),
        Frame::Err { message, .. } | Frame::Goaway { message, .. } => message.len(),
        Frame::WsClose { reason, .. } => reason.len(),
        Frame::Req { headers, path, .. } | Frame::WsUpgrade { headers, path, .. } => {
            path.len()
                + headers
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
        }
        Frame::Probe { payload, .. } => payload.len(),
        Frame::End { .. } | Frame::Ping { .. } | Frame::Pong { .. } | Frame::ProbeAck { .. } => 0,
    }
}

async fn send_payload(
    outbound_tx: &mpsc::Sender<OutboundSignal>,
    session_id: &str,
    seq: u32,
    payload: &SignalPayload,
) {
    let json = match serde_json::to_vec(payload) {
        Ok(j) => j,
        Err(e) => {
            error!(error = %e, "signal: could not encode outbound payload");
            return;
        }
    };
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(json);
    let frame = OutboundSignal::Relay {
        session_id: session_id.to_string(),
        seq,
        payload_b64,
    };
    if outbound_tx.send(frame).await.is_err() {
        warn!(session_id, "signal: outbound channel closed; cannot send");
    }
}

async fn break_with(pc: &Arc<RTCPeerConnection>) {
    if let Err(e) = pc.close().await {
        debug!(error = %e, "signal: pc close errored");
    }
}

/// Parse the SHA-256 DTLS fingerprint from an SDP blob. Matches
/// `a=fingerprint:sha-256 AB:CD:EF:...` (algorithm name
/// case-insensitive, colon-separated hex bytes).
fn extract_sha256_fingerprint(sdp: &str) -> Result<Vec<u8>, SessionError> {
    for line in sdp.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("a=fingerprint:") else {
            continue;
        };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let alg = parts.next().unwrap_or("");
        let hex_str = parts.next().unwrap_or("");
        if !alg.eq_ignore_ascii_case("sha-256") {
            return Err(SessionError::UnsupportedFpAlg(alg.to_string()));
        }
        let cleaned: String = hex_str.chars().filter(|c| *c != ':').collect();
        let bytes = hex::decode(&cleaned).map_err(|e| SessionError::BadFpHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(SessionError::BadFpHex(format!(
                "expected 32 bytes for sha-256, got {}",
                bytes.len()
            )));
        }
        return Ok(bytes);
    }
    Err(SessionError::NoFingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2claw_agent::routes::RouteTable;
    use p2claw_identity::{verify_dtls_fp, PeerId};

    /// Empty forwarder for tests. With no Host header on the request,
    /// the forwarder returns 400 "bad Host" — the shape the loopback
    /// test asserts to prove bytes round-tripped end-to-end.
    fn test_forwarder() -> Forwarder {
        let dir = tempfile::tempdir().unwrap();
        let routes = RouteTable::load_or_empty(dir.path().join("routes.json"));
        // Tempdir must outlive RouteTable; tests are short-lived so
        // leaking is the simplest path.
        Box::leak(Box::new(dir));
        Forwarder::new(routes, "p2claw.com".into())
    }

    #[test]
    fn extract_sha256_fingerprint_parses_canonical_sdp() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 0.0.0.0\r\n\
                   a=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
                   AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        let fp = extract_sha256_fingerprint(sdp).expect("parse");
        assert_eq!(fp.len(), 32);
        assert_eq!(fp[0], 0xAB);
        assert_eq!(fp[31], 0x89);
    }

    #[test]
    fn extract_sha256_fingerprint_case_insensitive_alg() {
        let sdp = "a=fingerprint:SHA-256 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:\
                   ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89\r\n";
        assert!(extract_sha256_fingerprint(sdp).is_ok());
    }

    #[test]
    fn extract_sha256_fingerprint_rejects_other_algs() {
        let sdp = "a=fingerprint:sha-1 AB:CD\r\n";
        let err = extract_sha256_fingerprint(sdp).unwrap_err();
        assert!(matches!(err, SessionError::UnsupportedFpAlg(_)), "{err:?}");
    }

    #[test]
    fn extract_sha256_fingerprint_missing() {
        let err = extract_sha256_fingerprint("v=0\r\n").unwrap_err();
        assert!(matches!(err, SessionError::NoFingerprint), "{err:?}");
    }

    #[test]
    fn payload_offer_roundtrip_json() {
        let p = SignalPayload {
            kind: PayloadKind::Offer,
            sdp: Some("v=0\r\n…".into()),
            candidate: None,
            dtls_fp_sig_b64: Some("c2lnbmF0dXJl".into()),
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"kind\":\"offer\""));
        assert!(j.contains("\"sdp\""));
        assert!(j.contains("\"dtls_fp_sig_b64\""));
        assert!(
            !j.contains("\"candidate\""),
            "should omit None candidate: {j}"
        );
        let back: SignalPayload = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn payload_candidate_roundtrip_json() {
        let p = SignalPayload {
            kind: PayloadKind::Candidate,
            sdp: None,
            candidate: Some(IceCandidatePayload {
                candidate: "candidate:1 1 UDP 2122252543 198.51.100.7 54321 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_m_line_index: Some(0),
            }),
            dtls_fp_sig_b64: None,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"kind\":\"candidate\""));
        assert!(j.contains("\"sdpMid\""));
        assert!(j.contains("\"sdpMLineIndex\""));
        let back: SignalPayload = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
    }

    /// Pins forward-compat: a future
    /// `#[serde(deny_unknown_fields)]` on `SignalPayload` would
    /// reject bootstraps that add fields.
    #[test]
    fn payload_permissive_about_unknown_fields() {
        let j = r#"{"kind":"answer","sdp":"v=0\r\nanswer-sdp","future_extension":"hi"}"#;
        let parsed: SignalPayload = serde_json::from_str(j).unwrap();
        assert_eq!(parsed.kind, PayloadKind::Answer);
        assert_eq!(parsed.sdp.as_deref(), Some("v=0\r\nanswer-sdp"));
    }

    #[test]
    fn dtls_fp_signature_binds_session_and_peer() {
        // A signature for one session_id must not verify against
        // another, and must reject under a different signer's peer.
        let sk = SigningKey::generate();
        let peer = sk.peer_id();
        let fp = vec![0xABu8; 32];

        let sig_a = sign_dtls_fp(&sk, "session-A", FP_ALG_SHA256, &fp).unwrap();
        verify_dtls_fp(&peer, "session-A", FP_ALG_SHA256, &fp, &sig_a).expect("verify A");
        verify_dtls_fp(&peer, "session-B", FP_ALG_SHA256, &fp, &sig_a)
            .expect_err("session-B must reject A's signature");

        let other = SigningKey::generate().peer_id();
        verify_dtls_fp(&other, "session-A", FP_ALG_SHA256, &fp, &sig_a)
            .expect_err("other peer must reject");

        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_a.to_bytes());
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let bytes: [u8; 64] = raw.try_into().expect("64 bytes");
        let sig_back = ed25519_dalek_signature_from_bytes(bytes);
        verify_dtls_fp(&peer, "session-A", FP_ALG_SHA256, &fp, &sig_back).unwrap();

        let _: PeerId = peer;
    }

    fn ed25519_dalek_signature_from_bytes(bytes: [u8; 64]) -> p2claw_identity::Signature {
        p2claw_identity::Signature::from_bytes(&bytes)
    }

    #[tokio::test]
    async fn registry_ignores_native_visitor_kind() {
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let registry = Arc::new(SignalRegistry::new_no_stun(
            Arc::new(SigningKey::generate()),
            out_tx,
            test_forwarder(),
        ));
        registry
            .on_push("sid-native".into(), VisitorKind::Native)
            .await;
        tokio::task::yield_now().await;
        assert!(out_rx.try_recv().is_err(), "no outbound expected");
        assert!(registry.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn relay_for_unknown_session_is_silently_dropped() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let registry =
            SignalRegistry::new_no_stun(Arc::new(SigningKey::generate()), out_tx, test_forwarder());
        registry.on_relay("ghost", 0, "data".into()).await;
        registry.on_end("ghost", SignalEndReason::Aborted).await;
    }

    /// End-to-end loopback: drives the production [`SignalRegistry`]
    /// (box side) against an inline `RTCPeerConnection` (browser
    /// stand-in), exchanges signaling through in-memory channels,
    /// opens a data channel, and round-trips a translator POST. The
    /// empty forwarder + missing Host header returns `400 bad-Host`
    /// — observing that status proves bytes made it end-to-end
    /// through WebRTC + translator + handler.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn webrtc_loopback_signaling_to_translator() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::Duration;

        use p2claw_identity::verify_dtls_fp;

        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .try_init();

        // Box side.
        let identity = Arc::new(SigningKey::generate());
        let expected_peer = identity.peer_id();
        let (box_out_tx, mut box_out_rx) = mpsc::channel::<OutboundSignal>(64);
        let registry = Arc::new(SignalRegistry::new_no_stun(
            Arc::clone(&identity),
            box_out_tx,
            test_forwarder(),
        ));

        // Browser stand-in.
        let mut settings = SettingEngine::default();
        settings.detach_data_channels();
        let api = APIBuilder::new().with_setting_engine(settings).build();
        let browser_pc = Arc::new(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("browser pc"),
        );

        // Browser → box: candidates routed back via registry.on_relay,
        // matching what the real control conn does with signal_relay
        // frames.
        let session_id = "test-session-01".to_string();
        let browser_local_seq = Arc::new(AtomicU32::new(1));
        {
            let registry = Arc::clone(&registry);
            let sid = session_id.clone();
            let seq_gen = Arc::clone(&browser_local_seq);
            browser_pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
                let registry = Arc::clone(&registry);
                let sid = sid.clone();
                let seq_gen = Arc::clone(&seq_gen);
                Box::pin(async move {
                    let Some(c) = c else { return };
                    let init = match c.to_json() {
                        Ok(i) => i,
                        Err(_) => return,
                    };
                    let payload = SignalPayload {
                        kind: PayloadKind::Candidate,
                        sdp: None,
                        candidate: Some(IceCandidatePayload {
                            candidate: init.candidate,
                            sdp_mid: init.sdp_mid,
                            sdp_m_line_index: init.sdp_mline_index,
                        }),
                        dtls_fp_sig_b64: None,
                    };
                    let bytes = serde_json::to_vec(&payload).expect("encode");
                    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                    let seq = seq_gen.fetch_add(1, Ordering::Relaxed);
                    registry.on_relay(&sid, seq, b64).await;
                })
            }));
        }

        // Browser stand-in: on dc.onmessage, detach + spawn a
        // translator client and ship the response back via done_tx.
        let (done_tx, mut done_rx) = mpsc::channel::<String>(1);
        {
            let done_tx = done_tx.clone();
            browser_pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let done_tx = done_tx.clone();
                Box::pin(async move {
                    let dc_for_open = Arc::clone(&dc);
                    dc.on_open(Box::new(move || {
                        let dc = Arc::clone(&dc_for_open);
                        let done_tx = done_tx.clone();
                        Box::pin(async move {
                            let raw = match dc.detach().await {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("browser detach failed: {e}");
                                    return;
                                }
                            };
                            // PollDataChannel's default 8 KiB read
                            // buffer would error on any inbound SCTP
                            // message larger than that — bump on both
                            // sides to match the box's
                            // `bridge_to_translator` buffer.
                            let mut stream = PollDataChannel::new(raw);
                            stream.set_read_buf_capacity(64 * 1024);
                            let client = p2claw_translator::ClientConnection::spawn(stream);

                            // 32 KiB POST body: splits into 2 × 16 KiB
                            // DATA frames at translator's default
                            // chunk cap, exercising the box's
                            // matching read-buffer bump. With an
                            // 8 KiB box buffer the test times out
                            // — that's the regression this guards.
                            const POST_BODY_BYTES: usize = 32 * 1024;
                            let post_body = bytes::Bytes::from(vec![0xA5u8; POST_BODY_BYTES]);
                            let resp = match client
                                .request(p2claw_translator::ClientRequest::post(
                                    bytes::Bytes::from_static(b"/webrtc-hello"),
                                    p2claw_translator::OutgoingBody::once(post_body),
                                ))
                                .await
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("browser client.request failed: {e}");
                                    return;
                                }
                            };
                            // Empty forwarder + no Host header on the
                            // client request = 400 bad-Host. We
                            // assert on that shape in the outer task.
                            // The POST body itself isn't inspected by
                            // the empty forwarder; that the response
                            // came back at all proves the box's
                            // wire reader pulled the > 8 KiB DATA
                            // frame off PollDataChannel without
                            // erroring on the read buffer.
                            let body = resp.body.collect().await;
                            let s = std::str::from_utf8(&body).unwrap().to_string();
                            let _ = done_tx.send(format!("{}|{}", resp.status, s)).await;
                        })
                    }));
                })
            }));
        }

        // Pump: drain the box's outbound signaling and drive the
        // browser PC. Stands in for coord's relay.
        let pump = tokio::spawn({
            let pc = Arc::clone(&browser_pc);
            let registry = Arc::clone(&registry);
            let session_id = session_id.clone();
            async move {
                // Browsers reject `addIceCandidate` while
                // remoteDescription is null, so the offer must reach
                // the wire before any candidate — `run_session`
                // buffers candidates until the offer ships; this
                // flag asserts that buffer worked.
                let mut offer_seen = false;
                while let Some(out) = box_out_rx.recv().await {
                    match out {
                        OutboundSignal::Relay {
                            session_id: sid,
                            seq: _,
                            payload_b64,
                        } => {
                            assert_eq!(sid, session_id, "session_id mismatch on outbound");
                            let raw = base64::engine::general_purpose::STANDARD
                                .decode(&payload_b64)
                                .expect("decode outbound b64");
                            let payload: SignalPayload =
                                serde_json::from_slice(&raw).expect("decode outbound json");
                            if matches!(payload.kind, PayloadKind::Candidate) {
                                assert!(offer_seen, "candidate arrived before offer");
                            }
                            match payload.kind {
                                PayloadKind::Offer => {
                                    offer_seen = true;
                                    let sdp = payload.sdp.clone().expect("offer sdp");
                                    let sig_b64 = payload
                                        .dtls_fp_sig_b64
                                        .clone()
                                        .expect("offer must carry dtls_fp_sig");
                                    // Mirrors the fingerprint check
                                    // the real bootstrap performs.
                                    let sig_bytes: [u8; 64] =
                                        base64::engine::general_purpose::STANDARD
                                            .decode(&sig_b64)
                                            .expect("sig b64 decode")
                                            .try_into()
                                            .expect("sig is 64 bytes");
                                    let sig = p2claw_identity::Signature::from_bytes(&sig_bytes);
                                    let fp =
                                        extract_sha256_fingerprint(&sdp).expect("offer carries fp");
                                    verify_dtls_fp(&expected_peer, &sid, FP_ALG_SHA256, &fp, &sig)
                                        .expect("DTLS fp signature must verify");

                                    let offer =
                                        RTCSessionDescription::offer(sdp).expect("offer desc");
                                    pc.set_remote_description(offer).await.unwrap();
                                    let answer = pc.create_answer(None).await.unwrap();
                                    pc.set_local_description(answer.clone()).await.unwrap();

                                    let answer_payload = SignalPayload {
                                        kind: PayloadKind::Answer,
                                        sdp: Some(answer.sdp.clone()),
                                        candidate: None,
                                        dtls_fp_sig_b64: None,
                                    };
                                    let b64 = base64::engine::general_purpose::STANDARD
                                        .encode(serde_json::to_vec(&answer_payload).unwrap());
                                    registry.on_relay(&sid, 0, b64).await;
                                }
                                PayloadKind::Candidate => {
                                    let c = payload.candidate.clone().expect("candidate payload");
                                    let init = RTCIceCandidateInit {
                                        candidate: c.candidate,
                                        sdp_mid: c.sdp_mid,
                                        sdp_mline_index: c.sdp_m_line_index,
                                        username_fragment: None,
                                    };
                                    if let Err(e) = pc.add_ice_candidate(init).await {
                                        eprintln!(
                                            "browser add_ice_candidate failed: {e} \
                                             (likely benign trickle race)"
                                        );
                                    }
                                }
                                PayloadKind::Answer => {
                                    panic!("box should not send answer");
                                }
                            }
                        }
                        OutboundSignal::End { .. } => {
                            return;
                        }
                    }
                }
            }
        });

        registry
            .on_push(session_id.clone(), VisitorKind::Browser)
            .await;

        let resp_str = tokio::time::timeout(Duration::from_secs(20), done_rx.recv())
            .await
            .expect("timeout waiting for translator round-trip")
            .expect("browser-side task dropped its sender");

        // Response shape: "<status>|<body>". 400 bad-Host is the
        // expected response from the empty forwarder.
        assert!(
            resp_str.starts_with("400|"),
            "expected 400 from empty forwarder on Host-less request: {resp_str}"
        );
        assert!(
            resp_str.to_ascii_lowercase().contains("host"),
            "body should mention the missing Host header: {resp_str}"
        );

        registry
            .on_end(&session_id, SignalEndReason::Connected)
            .await;
        browser_pc.close().await.ok();
        pump.abort();
        let _ = pump.await;
    }

    /// Open a session through the full WebRTC + signaling path, wait
    /// for the DC to open + bridge to start, then fire End from coord
    /// and assert the box surfaces its OutboundSignal::End within a
    /// small bounded time. Guards against the bug where
    /// `bridge_to_translator.await` inside a select arm starves the
    /// inbound handler — pre-fix, this test would have hung until the
    /// session lifetime cap fired (150 s).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mid_bridge_end_from_coord_tears_session_down_promptly() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::Duration;

        let identity = Arc::new(SigningKey::generate());
        let (box_out_tx, mut box_out_rx) = mpsc::channel::<OutboundSignal>(64);
        let registry = Arc::new(SignalRegistry::new_no_stun(
            Arc::clone(&identity),
            box_out_tx,
            test_forwarder(),
        ));

        // Browser stand-in: open a peer connection + relay candidates
        // back through the registry. The browser doesn't drive any
        // traffic over the DC; once the DC opens, the box's bridge
        // sits idle waiting for translator frames. Fire End at that
        // point and assert teardown is bounded.
        let mut settings = SettingEngine::default();
        settings.detach_data_channels();
        let api = APIBuilder::new().with_setting_engine(settings).build();
        let browser_pc = Arc::new(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("browser pc"),
        );

        let session_id = "mid-bridge-end-session".to_string();
        let browser_local_seq = Arc::new(AtomicU32::new(1));
        {
            let registry = Arc::clone(&registry);
            let sid = session_id.clone();
            let seq_gen = Arc::clone(&browser_local_seq);
            browser_pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
                let registry = Arc::clone(&registry);
                let sid = sid.clone();
                let seq_gen = Arc::clone(&seq_gen);
                Box::pin(async move {
                    let Some(c) = c else { return };
                    let init = match c.to_json() {
                        Ok(i) => i,
                        Err(_) => return,
                    };
                    let payload = SignalPayload {
                        kind: PayloadKind::Candidate,
                        sdp: None,
                        candidate: Some(IceCandidatePayload {
                            candidate: init.candidate,
                            sdp_mid: init.sdp_mid,
                            sdp_m_line_index: init.sdp_mline_index,
                        }),
                        dtls_fp_sig_b64: None,
                    };
                    let bytes = serde_json::to_vec(&payload).expect("encode");
                    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                    let seq = seq_gen.fetch_add(1, Ordering::Relaxed);
                    registry.on_relay(&sid, seq, b64).await;
                })
            }));
        }

        // Signal the box: bridge will be spawned once the DC opens.
        let (dc_open_tx, dc_open_rx) = tokio::sync::oneshot::channel::<()>();
        let dc_open_tx = Arc::new(Mutex::new(Some(dc_open_tx)));
        {
            let dc_open_tx = Arc::clone(&dc_open_tx);
            browser_pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let dc_open_tx = Arc::clone(&dc_open_tx);
                Box::pin(async move {
                    let dc_open_tx = Arc::clone(&dc_open_tx);
                    dc.on_open(Box::new(move || {
                        let dc_open_tx = Arc::clone(&dc_open_tx);
                        Box::pin(async move {
                            if let Some(tx) = dc_open_tx.lock().await.take() {
                                let _ = tx.send(());
                            }
                        })
                    }));
                })
            }));
        }

        // Pump: relay box → browser, exactly the shape used in
        // `webrtc_loopback_signaling_to_translator`.
        let pump = tokio::spawn({
            let pc = Arc::clone(&browser_pc);
            let registry = Arc::clone(&registry);
            let session_id = session_id.clone();
            async move {
                while let Some(out) = box_out_rx.recv().await {
                    match out {
                        OutboundSignal::Relay {
                            session_id: _,
                            seq: _,
                            payload_b64,
                        } => {
                            let raw = base64::engine::general_purpose::STANDARD
                                .decode(&payload_b64)
                                .expect("decode outbound b64");
                            let payload: SignalPayload =
                                serde_json::from_slice(&raw).expect("decode outbound json");
                            match payload.kind {
                                PayloadKind::Offer => {
                                    let sdp = payload.sdp.expect("offer sdp");
                                    let offer =
                                        RTCSessionDescription::offer(sdp).expect("offer parse");
                                    pc.set_remote_description(offer).await.expect("set offer");
                                    let answer = pc.create_answer(None).await.expect("answer");
                                    pc.set_local_description(answer.clone())
                                        .await
                                        .expect("set local answer");
                                    let answer_payload = SignalPayload {
                                        kind: PayloadKind::Answer,
                                        sdp: Some(answer.sdp),
                                        candidate: None,
                                        dtls_fp_sig_b64: None,
                                    };
                                    let bytes =
                                        serde_json::to_vec(&answer_payload).expect("encode answer");
                                    let b64 =
                                        base64::engine::general_purpose::STANDARD.encode(bytes);
                                    let seq = browser_local_seq.fetch_add(1, Ordering::Relaxed);
                                    registry.on_relay(&session_id, seq, b64).await;
                                }
                                PayloadKind::Candidate => {
                                    let cand = payload.candidate.expect("cand payload");
                                    let init = RTCIceCandidateInit {
                                        candidate: cand.candidate,
                                        sdp_mid: cand.sdp_mid,
                                        sdp_mline_index: cand.sdp_m_line_index,
                                        ..Default::default()
                                    };
                                    if pc.add_ice_candidate(init).await.is_err() {
                                        // Tolerable race during shutdown.
                                    }
                                }
                                _ => {}
                            }
                        }
                        OutboundSignal::End { .. } => {
                            // Echoed back to the test below via a
                            // separate observer; do nothing here.
                        }
                    }
                }
            }
        });

        // Kick off the session.
        registry
            .on_push(session_id.clone(), VisitorKind::Browser)
            .await;

        // Wait for the DC to actually open. If this doesn't happen,
        // ICE never converged on loopback — outside the scope of
        // this test.
        tokio::time::timeout(Duration::from_secs(10), dc_open_rx)
            .await
            .expect("DC open within 10s")
            .expect("DC open sender dropped");

        // Bridge is now running. Fire End from coord and time how
        // long it takes for the box's session task to surface its
        // own OutboundSignal::End on the outbound channel.
        let teardown_start = std::time::Instant::now();
        registry.on_end(&session_id, SignalEndReason::Aborted).await;

        // Drain the outbound channel for the End frame the session
        // task emits on exit. Pump consumed everything before the
        // teardown_start; pump is still running, but we need a
        // dedicated receiver. Re-derive: the pump task already
        // forwarded earlier traffic; pull the end from session_tx
        // by waiting on the sessions map to clear.
        let teardown_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if registry.sessions.lock().await.is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= teardown_deadline {
                panic!(
                    "session did not tear down within 2s of End — pre-fix \
                     the select! starvation would block until the 150s \
                     lifetime cap"
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let teardown_elapsed = teardown_start.elapsed();
        assert!(
            teardown_elapsed < Duration::from_secs(2),
            "teardown took {teardown_elapsed:?}; expected sub-2s"
        );

        browser_pc.close().await.ok();
        pump.abort();
        let _ = pump.await;
    }

    /// `wait_for_bridge` with an empty slot must yield Pending forever
    /// — otherwise the select arm would resolve as soon as the loop
    /// is entered and we'd never poll the other arms.
    #[tokio::test]
    async fn wait_for_bridge_with_no_handle_stays_pending() {
        let mut slot: Option<JoinHandle<Result<(), BridgeError>>> = None;
        let res = tokio::time::timeout(Duration::from_millis(50), wait_for_bridge(&mut slot)).await;
        assert!(res.is_err(), "expected wait_for_bridge to stay pending");
        assert!(slot.is_none(), "no handle should be installed by waiting");
    }

    /// On a clean join, `wait_for_bridge` returns the bridge's
    /// Ok(Ok(())) and clears the slot so a re-poll won't double-await.
    #[tokio::test]
    async fn wait_for_bridge_returns_clean_join_and_clears_slot() {
        let mut slot: Option<JoinHandle<Result<(), BridgeError>>> =
            Some(tokio::spawn(async { Ok(()) }));
        let res = wait_for_bridge(&mut slot).await;
        assert!(matches!(res, Ok(Ok(()))), "got {res:?}");
        assert!(slot.is_none(), "slot must be cleared after successful join");
    }

    /// When the bridge returns `Err(_)`, `wait_for_bridge` propagates
    /// the inner error so the session loop can classify it as
    /// `SignalEndReason::Error` instead of `Connected`. This is the
    /// classification gap the previous `JoinHandle<()>` shape papered
    /// over.
    #[tokio::test]
    async fn wait_for_bridge_propagates_bridge_error_to_caller() {
        let mut slot: Option<JoinHandle<Result<(), BridgeError>>> = Some(tokio::spawn(async {
            Err(BridgeError::Translator(
                p2claw_translator::TranslatorError::ConnectionClosed,
            ))
        }));
        let res = wait_for_bridge(&mut slot).await;
        match res {
            Ok(Err(BridgeError::Translator(
                p2claw_translator::TranslatorError::ConnectionClosed,
            ))) => {}
            other => panic!("expected Translator(ConnectionClosed), got {other:?}"),
        }
        assert!(slot.is_none(), "slot must clear even on inner error");
    }

    /// `abort_bridge` on an empty slot is a no-op; on a live task it
    /// aborts and awaits termination so the slot is empty and the
    /// task is settled by the time the caller continues.
    #[tokio::test]
    async fn abort_bridge_aborts_and_awaits_termination() {
        let mut slot: Option<JoinHandle<Result<(), BridgeError>>> = None;
        abort_bridge(&mut slot).await;
        assert!(slot.is_none());

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        slot = Some(tokio::spawn(async move {
            // Sit on the receiver forever; only abort can end us.
            let _ = rx.await;
            Ok(())
        }));
        let start = std::time::Instant::now();
        abort_bridge(&mut slot).await;
        let elapsed = start.elapsed();
        assert!(slot.is_none(), "slot must be cleared after abort");
        assert!(
            elapsed < Duration::from_millis(500),
            "abort_bridge must not block on the spawned task: took {elapsed:?}"
        );
        drop(tx);
    }

    // -----------------------------------------------------------------
    // `on_end` must not silently drop the End signal when the
    // inbound channel is at capacity.
    // -----------------------------------------------------------------

    /// Fill the per-session inbound channel to capacity and prove that
    /// a subsequent `on_end` still lands in the queue once a slot
    /// frees, instead of being silently dropped by `try_send`.
    #[tokio::test]
    async fn on_end_backpressures_when_inbound_full_and_still_delivers() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let registry = Arc::new(SignalRegistry::new_no_stun(
            Arc::new(SigningKey::generate()),
            out_tx,
            test_forwarder(),
        ));

        // Install a session handle whose receiver this test holds.
        // Skips the on_push path so we don't spin up a real PC.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        {
            let mut sessions = registry.sessions.lock().await;
            sessions.insert(
                "stuck".to_string(),
                SessionHandle {
                    inbound_tx,
                    started_at: Instant::now(),
                    transport: Arc::new(std::sync::Mutex::new(SessionTransport::Unknown)),
                },
            );
        }

        // Saturate: INBOUND_CAP relays sit in the queue undrained.
        for seq in 0..INBOUND_CAP as u32 {
            registry.on_relay("stuck", seq, "x".into()).await;
        }
        assert_eq!(
            inbound_rx.capacity(),
            0,
            "queue must be full to exercise the bug"
        );

        // `on_end` should backpressure-await for a slot, not drop.
        let registry_for_end = Arc::clone(&registry);
        let end_task = tokio::spawn(async move {
            registry_for_end
                .on_end("stuck", SignalEndReason::Aborted)
                .await;
        });

        // Give the on_end task a beat to enqueue on the full channel
        // — under the pre-fix `try_send` it would have returned
        // immediately and we'd never see the End below.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !end_task.is_finished(),
            "on_end must not return while the channel is full"
        );

        // Drain the relays to make room for the pending End.
        for _ in 0..INBOUND_CAP {
            let drained = inbound_rx.recv().await.expect("relay drained");
            assert!(matches!(drained, SessionInbound::Relay { .. }));
        }

        // Now the End must arrive within a small bounded time.
        let next = tokio::time::timeout(Duration::from_secs(1), inbound_rx.recv())
            .await
            .expect("End didn't arrive within 1s — likely dropped silently")
            .expect("inbound channel closed before End landed");
        assert!(
            matches!(
                next,
                SessionInbound::End {
                    reason: SignalEndReason::Aborted
                }
            ),
            "expected SessionInbound::End, got {next:?}",
        );
        end_task.await.unwrap();
    }

    /// When the session task has already exited (receiver dropped),
    /// `on_end` returns cleanly without hanging — the receiver-closed
    /// error is the only legitimate failure mode for the new
    /// `send().await` shape.
    #[tokio::test]
    async fn on_end_returns_when_receiver_dropped() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let registry = Arc::new(SignalRegistry::new_no_stun(
            Arc::new(SigningKey::generate()),
            out_tx,
            test_forwarder(),
        ));

        let (inbound_tx, inbound_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        {
            let mut sessions = registry.sessions.lock().await;
            sessions.insert(
                "gone".to_string(),
                SessionHandle {
                    inbound_tx,
                    started_at: Instant::now(),
                    transport: Arc::new(std::sync::Mutex::new(SessionTransport::Unknown)),
                },
            );
        }
        // Simulate the session task exiting before End arrives.
        drop(inbound_rx);

        // Must not hang or panic; the debug log is the only side effect.
        tokio::time::timeout(
            Duration::from_secs(1),
            registry.on_end("gone", SignalEndReason::Aborted),
        )
        .await
        .expect("on_end must return promptly when the receiver is gone");
    }

    // -----------------------------------------------------------------
    // SessionCleanup's Drop impl must fire `summary` on abort,
    // and `finish()` must fire it exactly once on the happy path.
    // -----------------------------------------------------------------

    /// Drop without `finish()` still runs the summary callback —
    /// matches the abort path where the bridge task is cancelled
    /// before its post-`serve_with` cleanup block.
    #[tokio::test]
    async fn session_cleanup_drop_fires_summary_on_abort_path() {
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter_for_summary = Arc::clone(&counter);

        let (cancel_tx, _cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let sampler = tokio::spawn(async move {
            // Sit forever; abort path doesn't await us.
            std::future::pending::<()>().await;
        });

        let cleanup = SessionCleanup::new(cancel_tx, sampler, move || {
            counter_for_summary.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        // Drop without calling finish() — analogous to JoinHandle::abort
        // during serve_with.
        drop(cleanup);

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "Drop must fire summary on abort path",
        );
    }

    /// `finish()` runs the summary callback exactly once; Drop on the
    /// returned-by-value `self` after `finish()` consumes it must not
    /// double-fire.
    #[tokio::test]
    async fn session_cleanup_finish_fires_summary_exactly_once() {
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter_for_summary = Arc::clone(&counter);

        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let sampler = tokio::spawn(async move {
            // Exit on cancel so `finish()`'s await resolves promptly.
            let _ = (&mut cancel_rx).await;
        });

        let cleanup = SessionCleanup::new(cancel_tx, sampler, move || {
            counter_for_summary.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        cleanup.finish().await;

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "summary must fire exactly once when finish() runs",
        );
    }
}
