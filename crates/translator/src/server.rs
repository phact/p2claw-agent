use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use p2claw_wire::{DataFlags, ErrorCode, Frame, ResFlags, StreamId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::codec::Framed;
use tracing::{debug, warn};

use crate::body::{IncomingBody, OutgoingBody};
use crate::codec_io::FrameCodec;
use crate::error::TranslatorError;
use crate::ws::{WsConnection, WsInboundEvent};
use crate::{ServerRequest, ServerResponse, ServerWsUpgrade, WsUpgradeDecision};

/// A request handler. One invocation per inbound REQ; runs to
/// completion (response sent) for each stream.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: ServerRequest) -> Pin<Box<dyn Future<Output = ServerResponse> + Send>>;
}

impl<F, Fut> Handler for F
where
    F: Fn(ServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ServerResponse> + Send + 'static,
{
    fn handle(&self, req: ServerRequest) -> Pin<Box<dyn Future<Output = ServerResponse> + Send>> {
        Box::pin(self(req))
    }
}

/// A WebSocket-upgrade handler.
///
/// `decide` is called with the upgrade request's path + headers; it
/// returns either an [`WsUpgradeDecision::Accept`] (in which case
/// `serve` invokes [`WsHandler::run`] with the original upgrade,
/// the decision's `upstream_headers` payload, plus a
/// [`WsConnection`]) or a [`WsUpgradeDecision::Reject`] which is
/// mapped to a `RES`.
///
/// `run` re-receives the upgrade because route resolution / upstream
/// dial may need the original path + headers — `decide` typically
/// can't dial yet (an upstream-bound `decide` would delay the
/// WS_ACCEPT and stall the visitor), so the work happens in `run`.
///
/// The wire passes the `upstream_headers` list verbatim from the
/// decision into `run`. It exists so a handler that runs auth in
/// `decide` (e.g. the agent's `WsForwarder`) can hand its injected
/// identity headers to the upstream-dial code in `run` without
/// needing per-stream side state.
pub trait WsHandler: Send + Sync + 'static {
    fn decide(
        &self,
        upgrade: &ServerWsUpgrade,
    ) -> Pin<Box<dyn Future<Output = WsUpgradeDecision> + Send + '_>>;

    fn run(
        &self,
        upgrade: ServerWsUpgrade,
        upstream_headers: Vec<(Bytes, Bytes)>,
        conn: WsConnection,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Per-frame send-side tap. Fired *before* each [`Frame`] is
/// serialized to bytes and pushed to the underlying I/O sink by
/// [`writer_task`]. Hosts wire this to surface DC-level send activity
/// for production debugging — see the agent's `signal_handler` (WebRTC
/// path), which logs per-emission `[p2claw:dc.tx]` lines correlated
/// with browser-side receive counters.
///
/// Implementations must be cheap (a few atomics + one structured
/// `tracing` event at most): the hook runs on the writer task's
/// critical path and blocking it directly throttles the wire.
///
/// Translator itself emits no tracing of its own; the hook is a
/// no-op when [`ServeOptions::tx_observer`] is `None`, so unaffected
/// callers (forwarder unit tests, edge tunnel, etc.) see no change.
pub type TxFrameHook = Arc<dyn Fn(&Frame) + Send + Sync + 'static>;

/// Path-capacity probe options. When set on
/// [`ServeOptions::probe`], `serve_with` sends one [`Frame::Probe`]
/// at start and writes `cap_on_ack` into
/// [`ServeOptions::max_data_frame_payload_cell`] on the matching
/// [`Frame::ProbeAck`] within `ack_window`.
#[derive(Clone, Debug)]
pub struct ProbeOptions {
    pub payload_size: usize,
    pub cap_on_ack: usize,
    pub ack_window: std::time::Duration,
}

/// Tunables for [`serve_with`]. Defaults: PING every 25s, drop the
/// connection after two missed intervals.
#[derive(Clone)]
pub struct ServeOptions {
    /// Interval between server-initiated PINGs. `None` disables
    /// outbound PINGs entirely; the server still PONGs anything the
    /// peer sends.
    pub ping_interval: Option<std::time::Duration>,
    /// Tear the transport down if no PONG (or any frame) has arrived
    /// within this window. `None` disables liveness enforcement.
    pub ping_timeout: Option<std::time::Duration>,
    /// Optional WebSocket upgrade handler.
    pub ws_handler: Option<Arc<dyn WsHandler>>,
    /// Optional per-frame send-side tap (see [`TxFrameHook`]).
    pub tx_observer: Option<TxFrameHook>,
    /// Maximum body length of a single emitted DATA frame.
    /// `stream_outgoing_body` splits larger response chunks across
    /// successive DATA frames; only the final split carries
    /// `END_STREAM` (or none if trailers follow).
    ///
    /// Default is [`DEFAULT_MAX_DATA_FRAME_PAYLOAD`] (16 KiB).
    /// Hosts on tighter transports (low-MTU tunneled DTLS, etc.)
    /// dial this down to keep each DATA frame within a single
    /// SCTP user message.
    ///
    /// Ignored if [`Self::max_data_frame_payload_cell`] is `Some`.
    pub max_data_frame_payload: usize,
    /// Optional shared cap cell. When `Some`, every chunk-split reads
    /// from this atomic instead of [`Self::max_data_frame_payload`].
    pub max_data_frame_payload_cell: Option<Arc<AtomicUsize>>,
    /// Optional path-capacity probe; see [`ProbeOptions`].
    pub probe: Option<ProbeOptions>,
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("ping_interval", &self.ping_interval)
            .field("ping_timeout", &self.ping_timeout)
            .field("ws_handler", &self.ws_handler.as_ref().map(|_| "<set>"))
            .field("tx_observer", &self.tx_observer.as_ref().map(|_| "<set>"))
            .field("max_data_frame_payload", &self.max_data_frame_payload)
            .field(
                "max_data_frame_payload_cell",
                &self
                    .max_data_frame_payload_cell
                    .as_ref()
                    .map(|c| c.load(Ordering::Relaxed)),
            )
            .field("probe", &self.probe)
            .finish()
    }
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            ping_interval: Some(std::time::Duration::from_secs(25)),
            ping_timeout: Some(std::time::Duration::from_secs(60)),
            ws_handler: None,
            tx_observer: None,
            max_data_frame_payload: DEFAULT_MAX_DATA_FRAME_PAYLOAD,
            max_data_frame_payload_cell: None,
            probe: None,
        }
    }
}

/// Serve translator requests over `io` by dispatching each to
/// `handler`. Returns when the transport closes or a fatal protocol
/// error occurs.
pub async fn serve<IO, H>(io: IO, handler: H) -> Result<(), TranslatorError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: Handler,
{
    serve_with(io, handler, ServeOptions::default()).await
}

/// Like [`serve`] but with explicit options (ping cadence, optional
/// WebSocket handler).
pub async fn serve_with<IO, H>(
    io: IO,
    handler: H,
    options: ServeOptions,
) -> Result<(), TranslatorError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: Handler,
{
    let framed = Framed::new(io, FrameCodec);
    let (sink, mut stream) = framed.split();

    // Two-lane outbound path. The writer task drains both with a
    // priority bias toward `ctrl_rx` so session-control frames
    // (PING/PONG/GOAWAY/PROBE/PROBEACK/REQ-time STREAM_REFUSED)
    // can never queue behind a backed-up body backlog. Without
    // this split, sustained sink backpressure that keeps
    // `body_tx` full also delays the periodic `Ping`; the peer
    // stops replying with `Pong`; `last_frame_ms` ages out;
    // `ping_timeout` fires a spurious `Goaway` (which would
    // itself queue behind the body backlog) and long-lived streams
    // jam after roughly one ping-timeout.
    //
    // Per-stream frame order MUST stay total — only session-
    // global control frames route via `ctrl_tx`. Every per-stream
    // frame (REQ/RES/DATA/END/ERR/TRAILERS for HTTP, WSACCEPT/
    // WSMSG/WSCLOSE for WS) routes via `body_tx`.
    //
    // Body capacity: sized for two concurrent never-ending streams
    // plus typical control-frame interleave under sustained sink
    // backpressure. At the 16 KiB default per-frame cap the worst-
    // case heap reservation is bounded (≤ 8 MiB), well within
    // budget. No single stream can occupy more than
    // [`STREAM_CREDIT_BYTES`] of it (see [`StreamSender`]), so a
    // heavy stream's backlog can't head-of-line-block the others.
    // Ctrl is tiny — at most one outstanding PING + a
    // GOAWAY + the at-session-start PROBE — but kept >1 so a slow
    // PONG/PROBEACK can interleave without back-pressuring the
    // reader loop that produced them.
    let (body_tx, body_rx) = mpsc::channel::<BodyFrame>(512);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<Frame>(16);
    let tx_observer = options.tx_observer.clone();
    tokio::spawn(writer_task(sink, ctrl_rx, body_rx, tx_observer));

    let handler = Arc::new(handler);
    let ws_handler = options.ws_handler.clone();

    // Per-DATA-frame cap. Resolve to a single `Arc<AtomicUsize>` so
    // `stream_outgoing_body` always reads from one type. Hosts that
    // want runtime mutation supply the cell themselves.
    let max_data_frame_payload_cell: Arc<AtomicUsize> = options
        .max_data_frame_payload_cell
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicUsize::new(options.max_data_frame_payload)));

    // Probe state captured for the reader loop: (id, cap_on_ack,
    // deadline). `None` when probing is disabled.
    let probe_state: Option<(u32, usize, std::time::Instant)> = options.probe.as_ref().map(|p| {
        (
            next_probe_id(),
            p.cap_on_ack,
            std::time::Instant::now() + p.ack_window,
        )
    });

    // Outbound probe — fire-and-forget at session start. Session-
    // global control frame → ctrl lane.
    if let (Some(probe_opts), Some((id, _, _))) = (options.probe.clone(), probe_state) {
        let ctrl_tx = ctrl_tx.clone();
        tokio::spawn(async move {
            // Payload contents are irrelevant — only the size matters.
            let payload = Bytes::from(vec![0u8; probe_opts.payload_size]);
            if ctrl_tx.send(Frame::Probe { id, payload }).await.is_err() {
                debug!("server: probe send dropped — writer task already gone");
            }
        });
    }

    let open: Arc<Mutex<HashMap<StreamId, OpenStream>>> = Arc::new(Mutex::new(HashMap::new()));
    let going_away = Arc::new(AtomicBool::new(false));

    // Liveness: kick off a periodic PING task and a PONG-deadline
    // watcher. Both are cheap no-ops when the corresponding option is
    // None.
    //
    // Coarse liveness clock: milliseconds since `epoch`, stored
    // atomically so the per-frame hot path avoids a mutex.
    let epoch = std::time::Instant::now();
    let last_frame_ms = Arc::new(AtomicU64::new(0));
    if let Some(interval) = options.ping_interval {
        // PING is the load-bearing liveness signal — must NEVER
        // queue behind body frames or the connection looks dead
        // from the peer's POV. Ctrl lane mandatory.
        let ctrl_tx = ctrl_tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // First tick is immediate; skip it so we don't ping before
            // the connection has had a chance to do real work.
            tick.tick().await;
            loop {
                tick.tick().await;
                let nonce = rand_nonce();
                if ctrl_tx.send(Frame::Ping { nonce }).await.is_err() {
                    return;
                }
            }
        });
    }
    if let Some(timeout) = options.ping_timeout {
        // GOAWAY teardown signal — ctrl lane so the peer learns
        // we're going away even when body backlog is huge.
        let ctrl_tx = ctrl_tx.clone();
        let last_frame_ms = Arc::clone(&last_frame_ms);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(timeout / 4).await;
                let now_ms = epoch.elapsed().as_millis() as u64;
                let elapsed_ms = now_ms.saturating_sub(last_frame_ms.load(Ordering::Relaxed));
                if elapsed_ms > timeout.as_millis() as u64 {
                    let _ = ctrl_tx
                        .send(Frame::Goaway {
                            last_accepted_stream_id: StreamId(0),
                            code: ErrorCode::TRANSPORT_CLOSED,
                            message: Bytes::from_static(b"liveness timeout"),
                        })
                        .await;
                    return;
                }
            }
        });
    }

    while let Some(frame) = stream.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                warn!("server reader: decode error: {e}");
                return Err(TranslatorError::Io(e));
            }
        };
        last_frame_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);

        match frame {
            Frame::Req {
                stream_id,
                flags,
                method,
                path,
                headers,
            } => {
                if going_away.load(Ordering::Acquire) {
                    // Already promised the peer we won't service new
                    // streams. Refuse with ERR(STREAM_REFUSED). The
                    // stream has zero body frames in flight — nothing
                    // for this ERR to order against — so ctrl lane is
                    // both correct and important (don't queue this
                    // refusal behind the body backlog that triggered
                    // going-away in the first place).
                    let _ = ctrl_tx
                        .send(Frame::Err {
                            stream_id,
                            code: ErrorCode::STREAM_REFUSED,
                            message: Bytes::from_static(b"server is going away"),
                        })
                        .await;
                    continue;
                }

                // Per-stream INBOUND body channel — separate from
                // the outbound `body_tx` lane the writer drains.
                // Renamed to avoid shadowing the outer outbound
                // sender now that the writer is split into two
                // priority lanes.
                let (in_body_tx, trailers_tx, error_tx, body_rx) = IncomingBody::channel(32);
                let cancel = Arc::new(AtomicBool::new(false));
                if !flags.end_stream() {
                    open.lock().await.insert(
                        stream_id,
                        OpenStream {
                            body_tx: Some(in_body_tx),
                            trailers_tx: Some(trailers_tx),
                            error_tx: Some(error_tx),
                            cancel: Arc::clone(&cancel),
                            kind: StreamKind::Http,
                        },
                    );
                } else {
                    // Track the stream (no body channel) so ERR mid-handler
                    // can still flip the cancel flag. The handler-facing
                    // IncomingBody is wired up but its trailers oneshot
                    // is dropped with body_tx — there's no body and no
                    // trailers to deliver. error_tx likewise drops:
                    // no body means no mid-body Err to surface.
                    drop((in_body_tx, trailers_tx, error_tx));
                    open.lock().await.insert(
                        stream_id,
                        OpenStream {
                            body_tx: None,
                            trailers_tx: None,
                            error_tx: None,
                            cancel: Arc::clone(&cancel),
                            kind: StreamKind::Http,
                        },
                    );
                }

                let request = ServerRequest {
                    method,
                    path,
                    headers,
                    body: body_rx,
                };

                let handler = Arc::clone(&handler);
                // Per-stream response frames (RES/DATA/END/ERR/
                // TRAILERS) → body lane, through a fresh per-stream
                // credit handle. Order MUST stay total per stream —
                // never split these across lanes.
                let body_tx_for_task = StreamSender::new(body_tx.clone());
                let open_for_task = Arc::clone(&open);
                let cancel_for_task = Arc::clone(&cancel);
                let cap_for_task = Arc::clone(&max_data_frame_payload_cell);
                tokio::spawn(async move {
                    let response = handler.handle(request).await;
                    if cancel_for_task.load(Ordering::Acquire) {
                        // Peer ERR'd us before we finished — drop the
                        // response on the floor; we already de-registered
                        // when the ERR arrived.
                        return;
                    }
                    if let Err(e) = send_response(
                        stream_id,
                        response,
                        body_tx_for_task,
                        cancel_for_task,
                        Arc::clone(&cap_for_task),
                    )
                    .await
                    {
                        warn!(?stream_id, "response send failed: {e}");
                    }
                    // Done — release the entry.
                    open_for_task.lock().await.remove(&stream_id);
                });
            }
            Frame::Data {
                stream_id,
                flags,
                body,
            } => {
                // Backpressure note: `body_tx` is the receive
                // end of `IncomingBody::channel(32)` — bounded.
                // `tx.send(body).await` below blocks the wire reader
                // when the per-stream receive queue fills, which
                // transitively credits-back-pressures the peer at
                // the QUIC stream's recv-window. Per-stream peak ≈
                // 32 × DEFAULT_MAX_DATA_FRAME_PAYLOAD = 512 KiB queued
                // (hosts with a smaller per-frame cap queue
                // proportionally less).
                //
                // Critical: clone the sender (or `take` on END_STREAM)
                // OUTSIDE the lock-held region, then drop the guard
                // BEFORE awaiting send. Awaiting `tx.send` while
                // holding the global `open` Mutex would head-of-line-
                // block every unrelated stream's frame handling
                // (other DATA, REQ, ERR, PING, response-handler
                // cleanup). Per-stream backpressure must not
                // serialize the multiplexer.
                let tx_for_send = {
                    let mut open_guard = open.lock().await;
                    match open_guard.get_mut(&stream_id) {
                        None => None,
                        Some(state) => {
                            if flags.end_stream() {
                                // Take so dropping the sender after
                                // send closes the receiver's stream
                                // (next `recv` returns None). Also
                                // drop the trailers oneshot in the
                                // same critical section: DATA with
                                // END_STREAM is a terminal frame
                                // equivalent to bare END, so callers
                                // awaiting `incoming.trailers()`
                                // must see the "no trailers" signal
                                // (oneshot sender dropped → recv
                                // returns Err → trailers() yields
                                // None) instead of blocking forever.
                                // Without this, every request body
                                // delivered via the common DATA-
                                // END_STREAM shape stalls
                                // `pump_incoming_to_hyper` at the
                                // trailers().await, hanging the
                                // upstream's body read.
                                state.trailers_tx = None;
                                state.body_tx.take()
                            } else {
                                state.body_tx.clone()
                            }
                        }
                    }
                };
                if let Some(tx) = tx_for_send {
                    if !body.is_empty() && tx.send(body).await.is_err() {
                        // Receiver gone (handler dropped the body
                        // mid-stream). Best-effort de-register; the
                        // entry may already be gone if the handler
                        // task removed it on completion.
                        open.lock().await.remove(&stream_id);
                    }
                    // If end_stream, dropping the taken `tx` here
                    // closes the channel — receiver sees None on
                    // next recv. If !end_stream, this is a clone;
                    // the OpenStream's original sender stays alive.
                }
            }
            Frame::End { stream_id } => {
                if let Some(state) = open.lock().await.get_mut(&stream_id) {
                    state.body_tx = None;
                    // No trailers — receiver's `trailers()` resolves
                    // to `None` once we drop the oneshot sender.
                    state.trailers_tx = None;
                }
            }
            Frame::Trailers { stream_id, headers } => {
                // Trailers implicitly end the stream (SPEC: no
                // subsequent END or DATA(END_STREAM) for this id).
                // Drop body_tx so `next_chunk()` returns None on the
                // receiver's next poll, and fire the trailers oneshot
                // so `trailers()` resolves to `Some(headers)`.
                let mut open_guard = open.lock().await;
                if let Some(state) = open_guard.get_mut(&stream_id) {
                    state.body_tx = None;
                    if let Some(tx) = state.trailers_tx.take() {
                        // `Err` here means the receiver was dropped
                        // (handler discarded the body). Best-effort —
                        // there's no recovery action.
                        let _ = tx.send(headers);
                    }
                }
            }
            Frame::Err {
                stream_id,
                code,
                message,
            } => {
                if stream_id.0 == 0 {
                    debug!(?code, "server: connection-level ERR; closing");
                    return Ok(());
                }
                if let Some(state) = open.lock().await.remove(&stream_id) {
                    state.cancel.store(true, Ordering::Release);
                    drop(state.body_tx);
                    // ERR pre-empts trailers — drop the sender so the
                    // receiver's `trailers()` returns None promptly.
                    drop(state.trailers_tx);
                    // Surface the abort cause to the handler-side
                    // `IncomingBody::error()` so request-body readers
                    // can distinguish "visitor cancelled cleanly"
                    // from "visitor's transport died mid-stream".
                    // Drops the sender if no error_tx (WS streams or
                    // body-less REQ).
                    if let Some(tx) = state.error_tx {
                        let _ = tx.send((code, message));
                    }
                }
            }
            Frame::Ping { nonce } => {
                // PONG is a session-control reply — ctrl lane so
                // the peer's liveness signal isn't HOL-blocked
                // behind our body backlog. Symmetric to the
                // outbound PING path.
                if ctrl_tx.send(Frame::Pong { nonce }).await.is_err() {
                    return Ok(());
                }
            }
            Frame::Pong { .. } => {
                // last_frame_ms update above is enough.
            }
            Frame::Probe { id, payload } => {
                // Symmetric: any peer that sends a Probe gets an ACK
                // echoing the matching id.
                debug!(
                    probe_id = id,
                    probe_bytes = payload.len(),
                    "server: inbound Probe — sending ProbeAck"
                );
                // PROBE_ACK is session-control — same lane as PONG.
                if ctrl_tx.send(Frame::ProbeAck { id }).await.is_err() {
                    return Ok(());
                }
            }
            Frame::ProbeAck { id } => match probe_state {
                Some((expected_id, cap, deadline)) if id == expected_id => {
                    if std::time::Instant::now() <= deadline {
                        let prev = max_data_frame_payload_cell.swap(cap, Ordering::Release);
                        if prev != cap {
                            debug!(
                                prev_cap = prev,
                                new_cap = cap,
                                ack_id = id,
                                "server: ProbeAck — DATA cap upgraded"
                            );
                        }
                    } else {
                        debug!(
                            ack_id = id,
                            "server: ProbeAck arrived after the ack window — cap stays at current value"
                        );
                    }
                }
                Some((expected_id, _, _)) => {
                    debug!(
                        ack_id = id,
                        expected_id,
                        "server: ProbeAck id mismatch — ignoring (stale from a prior probe?)"
                    );
                }
                None => {
                    debug!(ack_id = id, "server: unsolicited ProbeAck — ignoring");
                }
            },
            Frame::Goaway {
                code,
                message,
                last_accepted_stream_id: _,
            } => {
                debug!(?code, ?message, "server: peer GOAWAY received");
                going_away.store(true, Ordering::Release);
                // Continue draining frames so the peer's in-flight
                // requests can complete; they'll naturally finish and
                // we'll exit when the transport closes.
            }
            Frame::WsUpgrade {
                stream_id,
                path,
                headers,
            } => {
                let Some(ws) = ws_handler.clone() else {
                    // 501 is the upgrade reply — per-stream → body
                    // lane. Total order with the (non-existent) WS
                    // frames that would have followed.
                    let _ = body_tx
                        .send(BodyFrame::uncredited(Frame::Res {
                            stream_id,
                            flags: ResFlags::END_STREAM,
                            status: 501,
                            headers: vec![(
                                Bytes::from_static(b"content-type"),
                                Bytes::from_static(b"text/plain"),
                            )],
                        }))
                        .await;
                    continue;
                };
                let upgrade = ServerWsUpgrade { path, headers };
                // WS frames (WS_ACCEPT/WS_MSG/WS_CLOSE) are per-
                // stream — body lane so order stays total, through
                // this stream's credit handle so a chatty WS can't
                // monopolize the lane.
                let body_tx = StreamSender::new(body_tx.clone());
                let open_for_task = Arc::clone(&open);
                tokio::spawn(async move {
                    let decision = ws.decide(&upgrade).await;
                    match decision {
                        WsUpgradeDecision::Reject { status, headers } => {
                            let _ = body_tx
                                .send(Frame::Res {
                                    stream_id,
                                    flags: ResFlags::END_STREAM,
                                    status,
                                    headers,
                                })
                                .await;
                        }
                        WsUpgradeDecision::Accept {
                            headers: accept_headers,
                            upstream_headers,
                        } => {
                            let (in_tx, in_rx) = mpsc::channel::<WsInboundEvent>(32);
                            let cancel = Arc::new(AtomicBool::new(false));
                            open_for_task.lock().await.insert(
                                stream_id,
                                OpenStream {
                                    body_tx: None,
                                    // WS streams don't carry HTTP
                                    // trailers (the WS frame layer
                                    // closes via WS_CLOSE, not
                                    // TRAILERS).
                                    trailers_tx: None,
                                    // WS streams surface errors via
                                    // WS_CLOSE, not Frame::Err on a
                                    // body.
                                    error_tx: None,
                                    cancel: Arc::clone(&cancel),
                                    kind: StreamKind::Ws { events: in_tx },
                                },
                            );
                            if body_tx
                                .send(Frame::WsAccept {
                                    stream_id,
                                    headers: accept_headers,
                                })
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let conn = WsConnection {
                                stream_id,
                                out: body_tx.clone(),
                                inbox: tokio::sync::Mutex::new(in_rx),
                                closed_local: AtomicBool::new(false),
                                peer_close_code: std::sync::atomic::AtomicU16::new(0),
                                peer_close_reason: tokio::sync::Mutex::new(Bytes::new()),
                            };
                            ws.run(upgrade, upstream_headers, conn).await;
                            open_for_task.lock().await.remove(&stream_id);
                        }
                    }
                });
            }
            Frame::WsMsg {
                stream_id,
                opcode,
                payload,
            } => {
                // Clone the events sender inside the lock, drop the
                // guard before the bounded send — same rationale as
                // the DATA arm above.
                let events_tx = {
                    let open_guard = open.lock().await;
                    open_guard
                        .get(&stream_id)
                        .and_then(|state| match &state.kind {
                            StreamKind::Ws { events } => Some(events.clone()),
                            _ => None,
                        })
                };
                if let Some(events) = events_tx {
                    let _ = events
                        .send(WsInboundEvent::Msg(crate::ws::WsMessage {
                            opcode,
                            payload,
                        }))
                        .await;
                }
            }
            Frame::WsClose {
                stream_id,
                code,
                reason,
            } => {
                let events_tx = {
                    let open_guard = open.lock().await;
                    open_guard
                        .get(&stream_id)
                        .and_then(|state| match &state.kind {
                            StreamKind::Ws { events } => Some(events.clone()),
                            _ => None,
                        })
                };
                if let Some(events) = events_tx {
                    let _ = events.send(WsInboundEvent::Close { code, reason }).await;
                }
            }
            other => {
                debug!(
                    "server reader: ignoring unhandled frame type {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    // Transport went away: notify any open WS sessions so their
    // `recv` returns `None`.
    let mut open_guard = open.lock().await;
    for (_, state) in open_guard.drain() {
        state.cancel.store(true, Ordering::Release);
        if let StreamKind::Ws { events } = state.kind {
            let _ = events.send(WsInboundEvent::Transport).await;
        }
    }
    Ok(())
}

struct OpenStream {
    body_tx: Option<mpsc::Sender<Bytes>>,
    /// Producer side of the inbound body's `IncomingBody::error`
    /// oneshot. Fired on inbound `Frame::Err` for an in-flight
    /// stream that has body in flight (request body case). Lets a
    /// server-side handler reading `req.body.next_chunk()` see the
    /// abort cause via `req.body.error().await` after `next_chunk`
    /// returns `None`. WS streams leave this `None`.
    error_tx: Option<oneshot::Sender<(crate::ErrorCode, Bytes)>>,
    /// Producer side of the [`IncomingBody`] trailers oneshot.
    /// `Some` until either a `Frame::Trailers` arrives (we send
    /// the headers) or the stream ends without trailers (we drop
    /// the sender → receiver's `trailers()` returns `None`). Same
    /// `Option<_>` discipline as `body_tx` — `take()` to consume.
    trailers_tx: Option<oneshot::Sender<crate::body::Trailers>>,
    cancel: Arc<AtomicBool>,
    kind: StreamKind,
}

enum StreamKind {
    Http,
    Ws {
        events: mpsc::Sender<WsInboundEvent>,
    },
}

/// Byte budget a single stream may hold inside the shared body lane
/// at once. The lane is a FIFO shared by every stream on the session;
/// without a per-stream bound, one heavy producer (a large download,
/// a fast SSE feed) fills the whole channel and every other stream's
/// frames queue behind it — cross-stream head-of-line blocking.
///
/// Sizing: at the 16 KiB default frame cap this admits 8 full frames
/// in flight per stream. The original 32 KiB (2 frames) starved the
/// writer's batch loop — the lane went empty after almost every
/// feed, costing a flush + pump↔writer wakeup per frame on a
/// single-stream download. 8 frames keeps batching effective while
/// still bounding the head-of-line cost a heavy stream can impose on
/// a sibling to ~128 KiB of wire time.
pub(crate) const STREAM_CREDIT_BYTES: usize = 128 * 1024;

/// Floor for a frame's credit cost. Payload-light frames (RES
/// headers, END, small SSE ticks) still occupy a channel slot and a
/// writer iteration, so charging raw payload bytes would let a
/// tiny-frame stream hold hundreds of slots. The floor bounds any
/// stream to `STREAM_CREDIT_BYTES / MIN_FRAME_COST` = 256 in-flight
/// frames regardless of payload size.
const MIN_FRAME_COST: usize = 512;

fn frame_credit_cost(frame: &Frame) -> u32 {
    frame_payload_len(frame).clamp(MIN_FRAME_COST, STREAM_CREDIT_BYTES) as u32
}

/// A frame in the shared body lane, optionally carrying the sending
/// stream's credit permit. The writer task drops the permit right
/// after `sink.feed()` accepts the frame, returning the credit to
/// that stream's pump.
#[derive(Debug)]
pub(crate) struct BodyFrame {
    pub(crate) frame: Frame,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl BodyFrame {
    /// Envelope for one-shot per-stream frames sent outside a
    /// [`StreamSender`] (REQ, WS_UPGRADE, cancel ERR). These are
    /// single frames per stream — they can't build a backlog, so
    /// they skip the credit accounting.
    pub(crate) fn uncredited(frame: Frame) -> Self {
        Self {
            frame,
            permit: None,
        }
    }
}

/// Per-stream handle onto the shared body lane. Every sustained
/// producer (response bodies, WS traffic) sends through one of
/// these; `send` charges the frame against the stream's byte credit
/// before enqueueing, so no single stream can occupy more than
/// [`STREAM_CREDIT_BYTES`] of the shared FIFO. Clones share the same
/// credit pool — one budget per stream, however many senders.
#[derive(Clone)]
pub(crate) struct StreamSender {
    tx: mpsc::Sender<BodyFrame>,
    credit: Arc<tokio::sync::Semaphore>,
}

impl StreamSender {
    pub(crate) fn new(tx: mpsc::Sender<BodyFrame>) -> Self {
        Self {
            tx,
            credit: Arc::new(tokio::sync::Semaphore::new(STREAM_CREDIT_BYTES)),
        }
    }

    /// Enqueue a frame, waiting for both stream credit and channel
    /// capacity. Errs when the writer task is gone.
    pub(crate) async fn send(&self, frame: Frame) -> Result<(), mpsc::error::SendError<Frame>> {
        let cost = frame_credit_cost(&frame);
        let permit = Arc::clone(&self.credit)
            .acquire_many_owned(cost)
            .await
            .expect("stream credit semaphore is never closed");
        self.tx
            .send(BodyFrame {
                frame,
                permit: Some(permit),
            })
            .await
            .map_err(|e| mpsc::error::SendError(e.0.frame))
    }
}

async fn send_response(
    stream_id: StreamId,
    resp: ServerResponse,
    body_tx: StreamSender,
    cancel: Arc<AtomicBool>,
    max_data_frame_payload: Arc<AtomicUsize>,
) -> Result<(), TranslatorError> {
    let is_body_empty = matches!(resp.body, OutgoingBody::Empty);
    // A deferred-trailers oneshot also blocks END_STREAM on RES — at
    // RES-send time we don't yet know whether the sender will deliver
    // trailers or drop, but we can't reverse the flag once it's on
    // the wire. Treat the rx as "may have trailers".
    let has_trailers = resp.trailers.is_some() || resp.trailers_rx.is_some();
    // The RES frame can carry END_STREAM only when there's nothing
    // more to send: empty body AND no trailers. Trailers always
    // arrive in their own terminal Frame::Trailers, so a trailers-
    // attached response must clear the END_STREAM flag on RES even
    // for an empty-body case.
    let res_end_stream = is_body_empty && !has_trailers;
    body_tx
        .send(Frame::Res {
            stream_id,
            flags: if res_end_stream {
                ResFlags::END_STREAM
            } else {
                ResFlags::NONE
            },
            status: resp.status,
            headers: resp.headers,
        })
        .await
        .map_err(|_| TranslatorError::ConnectionClosed)?;

    if !res_end_stream {
        // Stream the body (if any), then the trailers (if any). The
        // body-streaming function picks the right terminal frame
        // (DATA(END_STREAM) / bare END / TRAILERS) based on whether
        // trailers are attached.
        stream_outgoing_body(
            stream_id,
            resp.body,
            body_tx,
            Some(cancel),
            resp.trailers,
            resp.trailers_rx,
            resp.error_rx,
            max_data_frame_payload,
        )
        .await?;
    }
    Ok(())
}

/// Default per-DATA-frame payload cap used by [`ServeOptions::default`].
/// `webrtc-sctp` rejects messages over 64 KiB, and upstream bodies
/// can hand us multi-MB chunks, so the translator has to split
/// before the wire. 16 KiB leaves headroom for framing overhead on
/// every transport. Callers on tighter transports override via
/// [`ServeOptions::max_data_frame_payload`].
pub const DEFAULT_MAX_DATA_FRAME_PAYLOAD: usize = 16 * 1024;

/// Drain an [`OutgoingBody`] into DATA frames, then close the stream
/// with the right terminal frame:
///
/// - If neither `trailers` nor `trailers_rx` is set: the last DATA
///   frame carries `END_STREAM`; a zero-chunk body sends a bare `END`.
/// - If `trailers` is `Some(headers)`: DATA frames are emitted
///   without `END_STREAM` and a `Frame::Trailers` (with the supplied
///   headers, even if the vec is empty) closes the stream. Receivers
///   read trailers via [`IncomingBody::trailers`]. Empty body +
///   trailers → just one TRAILERS frame, no DATA, no END.
/// - If `trailers_rx` is set (and `trailers` is `None`): DATA frames
///   stay `END_STREAM`-free; the wire awaits the oneshot after the
///   body drains. The receiver's outcome picks the terminator —
///   `Ok(headers)` → `Frame::Trailers(headers)`, `Err` (sender
///   dropped without sending) → bare `Frame::End`. Used by the agent's
///   forwarder for HTTP/1.1 chunked-trailer responses, where trailers
///   only arrive after the upstream body has fully streamed.
///
/// Body chunks larger than `max_data_frame_payload` are split across
/// multiple frames; the wire reader already coalesces fragmented
/// DATA frames, so the split is invisible to the client.
///
/// `max_data_frame_payload` is the per-frame body cap. Hosts pick the
/// value via [`ServeOptions::max_data_frame_payload`]; the default
/// ([`DEFAULT_MAX_DATA_FRAME_PAYLOAD`] = 16 KiB) suits TCP / QUIC /
/// Chromium-WebRTC, the WebRTC visitor host dials it to ~1200 B for
/// iOS Safari SCTP-reassembly compatibility.
///
/// If `cancel` is `Some` and gets flipped to `true` mid-body, the
/// remaining body and any pending trailers are dropped.
// Each parameter carries a distinct, orthogonal piece of streaming
// state — bundling them into a struct just shifts the noise without
// reducing it. The boundary is internal to the crate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn stream_outgoing_body(
    stream_id: StreamId,
    mut body: OutgoingBody,
    body_tx: StreamSender,
    cancel: Option<Arc<AtomicBool>>,
    mut trailers: Option<crate::body::Trailers>,
    mut trailers_rx: Option<tokio::sync::oneshot::Receiver<crate::body::Trailers>>,
    mut error_rx: Option<tokio::sync::oneshot::Receiver<(p2claw_wire::ErrorCode, Bytes)>>,
    max_data_frame_payload: Arc<AtomicUsize>,
) -> Result<(), TranslatorError> {
    // Read the cap fresh on every chunk-split so a host that
    // mutates the cell mid-session takes effect on the next outbound
    // frame. Acquire pairs with the Release store on cell update.
    let read_cap = move || max_data_frame_payload.load(Ordering::Acquire).max(1);
    let cancelled = || cancel.as_ref().is_some_and(|c| c.load(Ordering::Acquire));
    // Static `trailers` and any `trailers_rx` both forbid END_STREAM
    // on the last DATA — the terminator moves to a Frame::Trailers
    // (or bare End if the rx ultimately yields nothing). A deferred
    // `error_rx` also forbids END_STREAM: the terminal might be
    // Frame::Err (sender fires) or fall through to trailers/End
    // (sender drops). Receivers treat DATA(END_STREAM) as
    // stream-close and remove pending state, so a stale END_STREAM
    // here would race the Frame::Err onto a no-longer-tracked
    // stream — dropping the error silently.
    let has_trailers = trailers.is_some() || trailers_rx.is_some();
    let has_deferred_error = error_rx.is_some();
    let mut pending: Option<Bytes> = None;
    loop {
        if cancelled() {
            return Ok(());
        }
        if pending.is_none() {
            pending = next_chunk(&mut body).await;
        }
        let Some(mut current) = pending.take() else {
            // Body exhausted. Pick the right terminal frame:
            //   deferred-error rx        → await; if Ok(code, msg) → Frame::Err,
            //                              else fall through to trailers/end
            //   static trailers          → Frame::Trailers
            //   deferred-trailers rx     → await; rx yields Ok(headers) → Trailers, else End
            //   neither                  → bare Frame::End
            //
            // The error path supersedes any trailer terminator on
            // purpose — a forwarder signalling a mid-stream upstream
            // failure should surface to the visitor as an explicit
            // Err, not get masked behind a benign trailers block.
            let aborted = if let Some(rx) = error_rx.take() {
                rx.await.ok()
            } else {
                None
            };
            let terminal = if let Some((code, message)) = aborted {
                Frame::Err {
                    stream_id,
                    code,
                    message,
                }
            } else if let Some(headers) = trailers.take() {
                Frame::Trailers { stream_id, headers }
            } else if let Some(rx) = trailers_rx.take() {
                match rx.await {
                    Ok(headers) => Frame::Trailers { stream_id, headers },
                    Err(_) => Frame::End { stream_id },
                }
            } else {
                Frame::End { stream_id }
            };
            body_tx
                .send(terminal)
                .await
                .map_err(|_| TranslatorError::ConnectionClosed)?;
            return Ok(());
        };

        // Peek the next body chunk so we know whether `current` is
        // the last piece of user data. Critical ordering: the
        // END_STREAM flag belongs on the very last *wire* frame, so
        // we drain `current` down below the cap with NONE-flagged
        // frames and save the flag for the final sub-slice.
        //
        // With trailers attached, the END_STREAM bit moves from the
        // last DATA to the TRAILERS frame — so the last DATA stays
        // NONE-flagged in that branch.
        pending = next_chunk(&mut body).await;
        let is_last_logical_chunk = pending.is_none();

        loop {
            // Re-read on each split so a runtime cap change takes
            // effect on the next sub-frame.
            let cap_now = read_cap();
            if current.len() <= cap_now {
                break;
            }
            if cancelled() {
                return Ok(());
            }
            let head = current.split_to(cap_now);
            body_tx
                .send(Frame::Data {
                    stream_id,
                    flags: DataFlags::NONE,
                    body: head,
                })
                .await
                .map_err(|_| TranslatorError::ConnectionClosed)?;
        }

        let flags = if is_last_logical_chunk && !has_trailers && !has_deferred_error {
            DataFlags::END_STREAM
        } else {
            DataFlags::NONE
        };
        body_tx
            .send(Frame::Data {
                stream_id,
                flags,
                body: current,
            })
            .await
            .map_err(|_| TranslatorError::ConnectionClosed)?;
        if is_last_logical_chunk {
            // Body fully sent. Pick the right terminator. A
            // deferred error supersedes both trailers and the
            // END_STREAM-on-last-DATA path (which we also
            // suppressed via `has_deferred_error` above).
            if let Some(rx) = error_rx.take() {
                let terminal = match rx.await {
                    Ok((code, message)) => Frame::Err {
                        stream_id,
                        code,
                        message,
                    },
                    Err(_) => {
                        // Sender dropped without firing — fall
                        // through to the trailers/End path below.
                        if let Some(headers) = trailers.take() {
                            Frame::Trailers { stream_id, headers }
                        } else if let Some(rx) = trailers_rx.take() {
                            match rx.await {
                                Ok(headers) => Frame::Trailers { stream_id, headers },
                                Err(_) => Frame::End { stream_id },
                            }
                        } else {
                            Frame::End { stream_id }
                        }
                    }
                };
                body_tx
                    .send(terminal)
                    .await
                    .map_err(|_| TranslatorError::ConnectionClosed)?;
            } else if let Some(headers) = trailers.take() {
                // No deferred error → original trailers-attached
                // path. (END_STREAM on last DATA already closed
                // the stream in the no-trailers / no-error case.)
                body_tx
                    .send(Frame::Trailers { stream_id, headers })
                    .await
                    .map_err(|_| TranslatorError::ConnectionClosed)?;
            }
            return Ok(());
        }
    }
}

async fn next_chunk(body: &mut OutgoingBody) -> Option<Bytes> {
    futures_util::future::poll_fn(|cx: &mut Context<'_>| -> Poll<Option<Bytes>> {
        body.poll_next(cx)
    })
    .await
}

pub(crate) async fn writer_task<Si>(
    mut sink: Si,
    mut ctrl_rx: mpsc::Receiver<Frame>,
    mut body_rx: mpsc::Receiver<BodyFrame>,
    tx_observer: Option<TxFrameHook>,
) where
    Si: futures_util::Sink<Frame, Error = std::io::Error> + Unpin + Send,
{
    // Multi-stream head-of-line diagnostic: every `sink.feed().await`
    // serializes one frame onto the single DC sink. Long feeds fill
    // the upstream `mpsc::channel::<Frame>` and back-pressure every
    // stream's pump behind them. Emit one INFO line whenever a feed
    // takes >= `SLOW_SEND_THRESHOLD`, and tag the stream id (when
    // resolvable) so per-stream-id stalls can be correlated against
    // the box's per-frame `[p2claw:dc.tx] frame` logs. Threshold
    // chosen to surface sustained backpressure (100 ms) without
    // logging every routine cold-cache TCP send (typically < 20 ms).
    //
    // The companion `SUMMARY_INTERVAL` log emits aggregate writer
    // stats every N seconds — count of slow sends, max wait
    // observed, current `mpsc` slot occupancy — so dashboards can
    // plot sustained pressure even when no single send crosses the
    // per-event threshold.
    const SLOW_SEND_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(100);
    const SUMMARY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
    // Greedy drain: after awaiting one frame, feed every frame the
    // lanes already hold without flushing between them, then flush
    // once when both lanes are momentarily empty. The budget caps
    // how many payload bytes a single batch can defer before an
    // explicit flush, bounding worst-case delivery latency under a
    // steady producer.
    const FLUSH_BYTE_BUDGET: usize = 256 * 1024;
    let mut summary_window_start = std::time::Instant::now();
    let mut slow_sends_in_window: u64 = 0;
    let mut frames_in_window: u64 = 0;
    let mut max_wait_in_window: std::time::Duration = std::time::Duration::ZERO;
    let mut max_backlog_in_window: usize = 0;
    // Drain both lanes with `biased` so a ready ctrl frame ALWAYS
    // wins a tie against a ready body frame. tokio's `select!`
    // default is pseudo-random pick; `biased` makes "control beats
    // body" the load-bearing invariant — PING must reach the wire
    // even when body is steadily backlogged, so the peer's
    // liveness deadline never spuriously fires from HOL alone.
    // Loop exits when BOTH lanes' senders are dropped (every per-
    // stream `body_tx.clone()` + every control task's `ctrl_tx`
    // gone).
    loop {
        let mut envelope = tokio::select! {
            biased;
            f = ctrl_rx.recv() => match f {
                Some(f) => BodyFrame::uncredited(f),
                None => {
                    // Ctrl senders all gone — defer to body until
                    // it's drained too, then exit.
                    match body_rx.recv().await {
                        Some(f) => f,
                        None => break,
                    }
                }
            },
            f = body_rx.recv() => match f {
                Some(f) => f,
                None => {
                    // Body senders all gone — keep ctrl draining
                    // until its senders close too.
                    match ctrl_rx.recv().await {
                        Some(f) => BodyFrame::uncredited(f),
                        None => break,
                    }
                }
            },
        };

        let mut batched_bytes = 0usize;
        loop {
            let BodyFrame { frame, permit } = envelope;
            // Fire the host's observer *before* the feed so the host
            // can (a) snapshot a high-resolution timestamp adjacent
            // to the wire emission, and (b) read the underlying
            // transport's `bufferedAmount` (or equivalent
            // backpressure proxy) right at the point we're about to
            // push. Hook must not block — it runs on the writer
            // task's critical path.
            if let Some(obs) = tx_observer.as_ref() {
                obs(&frame);
            }
            let frame_stream_id = frame_stream_id(&frame);
            batched_bytes += frame_payload_len(&frame);
            let pre_send = std::time::Instant::now();
            // `feed` = poll_ready + start_send: it still awaits sink
            // readiness (transport backpressure) per frame, but skips
            // the per-frame flush — that happens once per batch below.
            let send_outcome = sink.feed(frame).await;
            // Sink accepted the frame — return the byte credit to the
            // sending stream so its pump can enqueue the next frame.
            drop(permit);
            let elapsed = pre_send.elapsed();

            // Per-event slow-send log (high-signal, low-volume).
            if elapsed >= SLOW_SEND_THRESHOLD {
                // The receiver's current backlog is the HOL evidence:
                // `len()` ≈ frames already queued behind this slow send
                // that ALSO had to wait. Reading `len` is cheap (one
                // atomic load) and runs off the writer's hot path only
                // when we've already crossed the slow threshold.
                // Body backlog is the HOL signature; ctrl backlog is
                // bounded tiny (≤16) and irrelevant for the wedge
                // analysis.
                tracing::info!(
                    target: "p2claw::translator::writer",
                    stream_id = ?frame_stream_id,
                    elapsed_ms = elapsed.as_millis() as u64,
                    queued_behind = body_rx.len(),
                    ctrl_queued = ctrl_rx.len(),
                    "writer_task: slow sink.feed — frame stalled HOL"
                );
            }

            // Rolling aggregate for the periodic summary log.
            frames_in_window += 1;
            if elapsed >= SLOW_SEND_THRESHOLD {
                slow_sends_in_window += 1;
            }
            if elapsed > max_wait_in_window {
                max_wait_in_window = elapsed;
            }
            let backlog_now = body_rx.len();
            if backlog_now > max_backlog_in_window {
                max_backlog_in_window = backlog_now;
            }

            if let Err(e) = send_outcome {
                warn!("writer_task: {e}");
                return;
            }
            if batched_bytes >= FLUSH_BYTE_BUDGET {
                break;
            }
            // Same ctrl-over-body bias as the blocking select above,
            // but non-blocking: an empty ctrl lane falls through to
            // body, and both empty ends the batch.
            envelope = match ctrl_rx.try_recv() {
                Ok(f) => BodyFrame::uncredited(f),
                Err(_) => match body_rx.try_recv() {
                    Ok(f) => f,
                    Err(_) => break,
                },
            };
        }

        let pre_flush = std::time::Instant::now();
        if let Err(e) = sink.flush().await {
            warn!("writer_task: {e}");
            return;
        }
        let flush_elapsed = pre_flush.elapsed();
        if flush_elapsed >= SLOW_SEND_THRESHOLD {
            tracing::info!(
                target: "p2claw::translator::writer",
                elapsed_ms = flush_elapsed.as_millis() as u64,
                queued_behind = body_rx.len(),
                ctrl_queued = ctrl_rx.len(),
                "writer_task: slow sink.flush — batch stalled HOL"
            );
            slow_sends_in_window += 1;
        }
        if flush_elapsed > max_wait_in_window {
            max_wait_in_window = flush_elapsed;
        }

        if summary_window_start.elapsed() >= SUMMARY_INTERVAL {
            // Only emit a summary line when there's something
            // interesting in the window — keeps dashboards clean
            // on idle sessions but still surfaces sustained
            // pressure that never crossed the per-event threshold.
            if slow_sends_in_window > 0 || max_backlog_in_window > 0 {
                tracing::info!(
                    target: "p2claw::translator::writer",
                    frames = frames_in_window,
                    slow_sends = slow_sends_in_window,
                    max_wait_ms = max_wait_in_window.as_millis() as u64,
                    max_backlog = max_backlog_in_window,
                    "writer_task: 5s summary"
                );
            }
            summary_window_start = std::time::Instant::now();
            slow_sends_in_window = 0;
            frames_in_window = 0;
            max_wait_in_window = std::time::Duration::ZERO;
            max_backlog_in_window = 0;
        }
    }
    let _ = sink.close().await;
}

/// Stream id carried by a wire frame, if any. Control frames (PING,
/// PONG, PROBE, PROBE_ACK, GOAWAY) carry no stream id; everything
/// else is per-stream. Used by writer-side diagnostics to attribute
/// slow sends to a specific stream so operators can correlate
/// against per-frame logs.
fn frame_stream_id(frame: &Frame) -> Option<StreamId> {
    match frame {
        Frame::Req { stream_id, .. }
        | Frame::Res { stream_id, .. }
        | Frame::Data { stream_id, .. }
        | Frame::End { stream_id }
        | Frame::Err { stream_id, .. }
        | Frame::Trailers { stream_id, .. }
        | Frame::WsUpgrade { stream_id, .. }
        | Frame::WsAccept { stream_id, .. }
        | Frame::WsMsg { stream_id, .. }
        | Frame::WsClose { stream_id, .. } => Some(*stream_id),
        Frame::Ping { .. }
        | Frame::Pong { .. }
        | Frame::Probe { .. }
        | Frame::ProbeAck { .. }
        | Frame::Goaway { .. } => None,
    }
}

/// Approximate wire size of a frame's payload, used to bound how many
/// bytes a writer batch may defer before flushing. Bulk frames report
/// their body length; everything else is header-dominated and counted
/// as a small constant.
fn frame_payload_len(frame: &Frame) -> usize {
    const HEADER_ESTIMATE: usize = 64;
    match frame {
        Frame::Data { body, .. } => body.len() + HEADER_ESTIMATE,
        Frame::WsMsg { payload, .. } | Frame::Probe { payload, .. } => {
            payload.len() + HEADER_ESTIMATE
        }
        _ => HEADER_ESTIMATE,
    }
}

/// Monotonically-increasing probe id. Wrap is benign: ids are only
/// compared against the in-flight probe within a single session.
fn next_probe_id() -> u32 {
    static CTR: AtomicU32 = AtomicU32::new(1);
    CTR.fetch_add(1, Ordering::Relaxed)
}

fn rand_nonce() -> [u8; 8] {
    // Cheap deterministic nonce: each PING just needs to be
    // distinguishable from in-flight stragglers. We use the
    // monotonically-increasing counter rather than pulling in a CSPRNG;
    // PING nonces are not security-sensitive.
    static CTR: AtomicU32 = AtomicU32::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&n.to_be_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    out[4..].copy_from_slice(&now.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body that exceeds the smallest real-world transport cap
    /// (`webrtc-sctp`'s 64 KiB default) must be split into multiple
    /// DATA frames, none of which exceeds the per-call cap.
    /// Regression for the 4 MB marriott-HTML round-trip that surfaced
    /// this bug: a single oversized DATA frame tripped SCTP and closed
    /// the stream mid-response.
    #[tokio::test]
    async fn large_body_is_chunked_below_the_cap() {
        const BODY_LEN: usize = 200 * 1024; // 200 KiB — >> 64 KiB SCTP cap.
        let payload = vec![0xABu8; BODY_LEN];
        let body = OutgoingBody::once(Bytes::from(payload.clone()));

        let (tx, mut rx) = mpsc::channel::<BodyFrame>(64);
        let send_handle = tokio::spawn(async move {
            stream_outgoing_body(
                StreamId(1),
                body,
                StreamSender::new(tx),
                None,
                None,
                None,
                None,
                Arc::new(AtomicUsize::new(DEFAULT_MAX_DATA_FRAME_PAYLOAD)),
            )
            .await
            .unwrap();
        });

        let mut reassembled = Vec::with_capacity(BODY_LEN);
        let mut data_frames = 0usize;
        let mut got_end_stream = false;
        while let Some(BodyFrame { frame, .. }) = rx.recv().await {
            match frame {
                Frame::Data {
                    stream_id,
                    flags,
                    body,
                } => {
                    assert_eq!(stream_id, StreamId(1));
                    assert!(
                        body.len() <= DEFAULT_MAX_DATA_FRAME_PAYLOAD,
                        "DATA frame ({} bytes) exceeds cap ({})",
                        body.len(),
                        DEFAULT_MAX_DATA_FRAME_PAYLOAD,
                    );
                    data_frames += 1;
                    if flags.end_stream() {
                        got_end_stream = true;
                    }
                    reassembled.extend_from_slice(&body);
                }
                Frame::End { .. } => {
                    // For a non-empty body the terminal marker rides
                    // on the final DATA as END_STREAM; a bare END is
                    // reserved for the zero-chunk path.
                    panic!("unexpected bare END for a non-empty body");
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }

        send_handle.await.unwrap();
        assert!(data_frames > 1, "large body should span multiple frames");
        assert!(got_end_stream, "last DATA frame must carry END_STREAM");
        assert_eq!(reassembled, payload, "body bytes must round-trip exactly");
    }

    /// Per-call cap is honored — narrower than the default.
    #[tokio::test]
    async fn stream_outgoing_body_honors_per_call_cap() {
        const TINY_CAP: usize = 1200;
        const BODY_LEN: usize = 8 * 1024; // mimics the trace body that broke iPad.
        let payload = vec![0xCDu8; BODY_LEN];
        let body = OutgoingBody::once(Bytes::from(payload.clone()));

        let (tx, mut rx) = mpsc::channel::<BodyFrame>(64);
        let send_handle = tokio::spawn(async move {
            stream_outgoing_body(
                StreamId(7),
                body,
                StreamSender::new(tx),
                None,
                None,
                None,
                None,
                Arc::new(AtomicUsize::new(TINY_CAP)),
            )
            .await
            .unwrap();
        });

        let mut reassembled = Vec::with_capacity(BODY_LEN);
        let mut data_frames = 0usize;
        let mut got_end_stream = false;
        let mut max_seen = 0usize;
        while let Some(BodyFrame { frame, .. }) = rx.recv().await {
            let Frame::Data {
                stream_id,
                flags,
                body,
            } = frame
            else {
                panic!("unexpected non-DATA frame");
            };
            assert_eq!(stream_id, StreamId(7));
            assert!(
                body.len() <= TINY_CAP,
                "DATA frame ({} bytes) exceeds the per-call cap ({TINY_CAP})",
                body.len(),
            );
            max_seen = max_seen.max(body.len());
            data_frames += 1;
            if flags.end_stream() {
                got_end_stream = true;
            }
            reassembled.extend_from_slice(&body);
        }

        send_handle.await.unwrap();
        // 8 KiB / 1200 B = 7 chunks (with 800 B remainder), so we
        // expect 7 DATA frames + the last one carrying END_STREAM.
        assert!(
            data_frames >= 7,
            "expected >= 7 DATA frames for {BODY_LEN}-byte body at cap {TINY_CAP}, got {data_frames}",
        );
        assert_eq!(
            max_seen, TINY_CAP,
            "at least one DATA frame should be at the cap"
        );
        assert!(got_end_stream, "last DATA frame must carry END_STREAM");
        assert_eq!(reassembled, payload, "body bytes must round-trip exactly");
    }

    /// Writing a new cap into the shared cell mid-stream affects the
    /// next DATA-frame split rather than waiting for the next
    /// response. Drives the cell from 256 → 8 KiB after the first
    /// frame; asserts we see at least one tiny frame (pre-flip), at
    /// least one wide frame (post-flip), and that the body
    /// round-trips byte-for-byte.
    #[tokio::test]
    async fn stream_outgoing_body_picks_up_mid_stream_cap_increase() {
        const TINY: usize = 256;
        const WIDE: usize = 8 * 1024;
        const BODY_LEN: usize = 64 * 1024;
        let payload = vec![0xEFu8; BODY_LEN];
        let body = OutgoingBody::once(Bytes::from(payload.clone()));

        let cap = Arc::new(AtomicUsize::new(TINY));
        let cap_writer = Arc::clone(&cap);

        // mpsc(1) — back-pressure the sender so we can flip the cap
        // between the first DATA frame and the rest.
        let (tx, mut rx) = mpsc::channel::<BodyFrame>(1);
        let send_handle = tokio::spawn(async move {
            stream_outgoing_body(
                StreamId(9),
                body,
                StreamSender::new(tx),
                None,
                None,
                None,
                None,
                cap,
            )
            .await
        });

        // Drain the first frame at TINY, then ratchet up — the
        // sender will already be blocked on the bounded channel.
        let first = rx.recv().await.expect("first frame").frame;
        let first_len = match &first {
            Frame::Data { body, .. } => body.len(),
            other => panic!("expected DATA first, got {other:?}"),
        };
        assert!(
            first_len <= TINY,
            "pre-flip frame should be <= TINY ({TINY}), got {first_len}"
        );
        cap_writer.store(WIDE, Ordering::Release);

        let mut max_seen_post_flip = 0usize;
        let mut total = first_len;
        let mut reassembled = Vec::with_capacity(BODY_LEN);
        match &first {
            Frame::Data { body, .. } => reassembled.extend_from_slice(body),
            _ => unreachable!(),
        }
        while let Some(BodyFrame { frame, .. }) = rx.recv().await {
            let Frame::Data { body, .. } = frame else {
                panic!("non-DATA frame mid-stream");
            };
            total += body.len();
            max_seen_post_flip = max_seen_post_flip.max(body.len());
            reassembled.extend_from_slice(&body);
        }
        send_handle.await.expect("send task").expect("send result");

        assert_eq!(total, BODY_LEN, "byte total mismatch");
        assert_eq!(reassembled, payload, "round-trip bytes");
        assert!(
            max_seen_post_flip > TINY,
            "expected at least one post-flip frame larger than the pre-flip cap ({TINY}); largest was {max_seen_post_flip}"
        );
        assert!(
            max_seen_post_flip <= WIDE,
            "post-flip frames should not exceed the new cap ({WIDE}); largest was {max_seen_post_flip}"
        );
    }

    /// Backpressure regression: pushing 100 MB through an
    /// `IncomingBody::channel(N)` to a slow consumer must keep the
    /// in-flight chunk count bounded by N. The wire reader's
    /// Frame::Data handler in `serve_with` awaits on this same
    /// `tx.send` — so this regression also covers the wire-reader
    /// stall behavior that credit-back-pressures the QUIC peer.
    ///
    /// Without a bounded channel the producer would race ahead and
    /// queue the entire 100 MB in memory before the consumer drained
    /// the first chunk. Test asserts max_inflight ≤ CAP + small
    /// scheduler slop.
    ///
    /// If a future change swaps `IncomingBody::channel` for an
    /// unbounded sender (`mpsc::unbounded_channel`), this test
    /// fires immediately on the bound assertion (and would also
    /// OOM-or-balloon at this scale).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incoming_body_backpressure_keeps_inflight_bounded_under_slow_consumer() {
        use std::sync::atomic::AtomicUsize;
        const CAP: usize = 32;
        const CHUNK: usize = 1024;
        const TOTAL: usize = 100 * 1024 * 1024; // 100 MB
        const N_CHUNKS: usize = TOTAL / CHUNK;

        let (tx, _trailers_tx, _error_tx, mut body) = crate::body::IncomingBody::channel(CAP);

        let inflight = Arc::new(AtomicUsize::new(0));
        let max_inflight = Arc::new(AtomicUsize::new(0));

        let inflight_p = Arc::clone(&inflight);
        let max_p = Arc::clone(&max_inflight);
        let producer = tokio::spawn(async move {
            // Pre-allocated chunk; clones are cheap (refcount bump).
            let chunk = Bytes::from(vec![0u8; CHUNK]);
            for _ in 0..N_CHUNKS {
                // Increment BEFORE the bounded send. The send may
                // suspend until the consumer drains a slot — until
                // then this future doesn't make progress, which is
                // exactly the wire-reader stall behaviour we're
                // pinning. Track the running max.
                let n = inflight_p.fetch_add(1, Ordering::SeqCst) + 1;
                let mut m = max_p.load(Ordering::SeqCst);
                while n > m {
                    match max_p.compare_exchange_weak(m, n, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break,
                        Err(prev) => m = prev,
                    }
                }
                tx.send(chunk.clone()).await.expect("send should succeed");
            }
        });

        let inflight_c = Arc::clone(&inflight);
        let consumer = tokio::spawn(async move {
            let mut received = 0usize;
            while let Some(c) = body.next_chunk().await {
                received += c.len();
                inflight_c.fetch_sub(1, Ordering::SeqCst);
                // Slow consumer: yield to the scheduler after every
                // chunk so the producer regularly hits the bounded-
                // channel cap. Without this the scheduler may
                // happily drain the channel between each producer
                // send, masking the backpressure path.
                tokio::task::yield_now().await;
            }
            received
        });

        let received = consumer.await.unwrap();
        producer.await.unwrap();

        assert_eq!(received, TOTAL, "all bytes must round-trip");

        // Pipeline-depth bound: at most CAP chunks queued in the
        // channel + 1 in producer's about-to-send future + 1 in
        // the consumer's current handle = CAP + 2. Pad for
        // multi-threaded scheduler slop (the increment-before-send
        // ordering allows brief overshoot before the send actually
        // suspends).
        let max = max_inflight.load(Ordering::SeqCst);
        let bound = CAP + 4;
        assert!(
            max <= bound,
            "in-flight chunks exceeded the bounded-channel pipeline depth: \
             max={max}, cap={CAP}, bound={bound} — backpressure regression?",
        );
    }

    /// Priority-lane invariant: a ctrl frame enqueued while body
    /// has a deep backlog must reach the sink BEFORE the bulk of
    /// the body backlog drains. Directly exercises `writer_task`
    /// — bypasses the codec / wire / duplex so the only variable
    /// is the writer's drain policy.
    ///
    /// Setup: pre-fill body lane with `BODY_BACKLOG` frames. Sink
    /// is slow (forces backpressure into the channel layer where
    /// the priority decision actually lives). Enqueue a `Ping`
    /// on the ctrl lane AFTER the body backlog is already
    /// established. Observe the order frames hit the sink: the
    /// PING's position must be early (≤ `EARLY_THRESHOLD`), not
    /// after most/all body frames.
    ///
    /// Without the priority lane (single shared mpsc + writer
    /// draining FIFO), the PING would land at position
    /// `BODY_BACKLOG + 1`. With the priority lane + biased
    /// select, it lands at position 1 or 2.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ctrl_lane_bypasses_body_backlog() {
        use std::sync::Mutex;

        const BODY_BACKLOG: usize = 200;
        // PING must reach the sink within the first
        // `EARLY_THRESHOLD` frames. Generous slack (≈ 5% of the
        // backlog) accommodates the bias-resolution latency on
        // multi-thread runtimes; without the priority lane the
        // PING lands at position `BODY_BACKLOG + 1`, well
        // outside this bound.
        const EARLY_THRESHOLD: usize = 20;

        // Slow sink: records every frame in arrival order, awaits
        // 1 ms per send to model real-transport backpressure.
        // Boxed-pinned (not stack `tokio::pin!`) because writer_task
        // owns the sink across a `tokio::spawn` boundary.
        let recorded: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_sink = Arc::clone(&recorded);
        let sink = futures_util::sink::unfold((), move |(), frame: Frame| {
            let recorded = Arc::clone(&recorded_for_sink);
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                recorded.lock().unwrap().push(frame);
                Ok::<_, std::io::Error>(())
            }
        });
        let sink = Box::pin(sink);

        let (body_tx, body_rx) = mpsc::channel::<BodyFrame>(512);
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<Frame>(16);

        // Pre-fill body lane BEFORE the writer task starts so the
        // backlog is fully established. 200 frames into a 512-cap
        // channel — no producer blocking. Uncredited envelopes keep
        // this test about lane priority, not per-stream credit.
        for i in 0..BODY_BACKLOG {
            body_tx
                .send(BodyFrame::uncredited(Frame::Data {
                    stream_id: StreamId(7),
                    flags: DataFlags(0),
                    body: Bytes::from(format!("body-{i}").into_bytes()),
                }))
                .await
                .expect("body pre-fill should not block");
        }

        // Spawn the writer. It begins draining immediately.
        let writer = tokio::spawn(writer_task(sink, ctrl_rx, body_rx, None));

        // Give the writer a moment to start draining (1 frame ~ 1 ms,
        // so 5 ms ≈ 5 body frames sent before the PING arrives —
        // the PING enters with the bulk of the body still queued).
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // Enqueue PING on ctrl lane.
        ctrl_tx
            .send(Frame::Ping {
                nonce: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
            })
            .await
            .expect("ctrl enqueue");

        // Drop senders so the writer eventually exits after
        // draining everything.
        drop(body_tx);
        drop(ctrl_tx);
        writer.await.unwrap();

        // Find the PING's position in the arrival order.
        let recorded = recorded.lock().unwrap();
        let ping_pos = recorded
            .iter()
            .position(|f| {
                matches!(
                    f,
                    Frame::Ping {
                        nonce: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
                    }
                )
            })
            .expect("PING must reach the sink");

        // Must be within the early window — not buried behind
        // most of the body backlog.
        assert!(
            ping_pos < EARLY_THRESHOLD,
            "PING reached sink at position {ping_pos}/{BODY_BACKLOG} — \
             priority lane broken; ctrl frames are HOL-blocked behind body backlog. \
             Expected position < {EARLY_THRESHOLD}.",
        );

        // Sanity: all body frames + the PING delivered.
        assert_eq!(recorded.len(), BODY_BACKLOG + 1);
    }

    /// Cross-stream fairness invariant: a heavy stream pumping
    /// through a [`StreamSender`] can only occupy its credit's worth
    /// of the shared body lane, so another stream's frame is never
    /// buried behind a channel-deep monopoly. Without per-stream
    /// credit, the heavy producer fills all 512 slots and the light
    /// frame lands at position 513 — the "two SSE streams jam"
    /// head-of-line shape.
    #[tokio::test]
    async fn stream_credit_bounds_one_streams_share_of_the_body_lane() {
        const FRAME_BODY: usize = 800; // the WebRTC-path DATA cap
                                       // Worst case one stream can hold: every frame at max cost.
        const MAX_FRAMES_PER_STREAM: usize = STREAM_CREDIT_BYTES / MIN_FRAME_COST;

        let (tx, mut rx) = mpsc::channel::<BodyFrame>(512);
        let heavy = StreamSender::new(tx.clone());
        let light = StreamSender::new(tx);

        // Heavy stream pumps far more than its credit with nothing
        // draining the lane — it must stall on credit, not run until
        // the channel is full.
        let heavy_task = tokio::spawn(async move {
            for _ in 0..512usize {
                if heavy
                    .send(Frame::Data {
                        stream_id: StreamId(1),
                        flags: DataFlags::NONE,
                        body: Bytes::from(vec![0u8; FRAME_BODY]),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        // Let the heavy producer run until it blocks on credit.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let queued_by_heavy = rx.len();
        assert!(
            queued_by_heavy <= MAX_FRAMES_PER_STREAM,
            "heavy stream queued {queued_by_heavy} frames — exceeds its \
             credit bound of {MAX_FRAMES_PER_STREAM}; per-stream credit broken",
        );

        // The light stream's frame must be admitted promptly — the
        // lane has free slots because the heavy stream is capped.
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            light.send(Frame::Data {
                stream_id: StreamId(2),
                flags: DataFlags::END_STREAM,
                body: Bytes::from_static(b"light"),
            }),
        )
        .await
        .expect("light stream HOL-blocked behind heavy stream's backlog")
        .expect("send failed");

        // And it sits at a bounded position: right after the heavy
        // stream's credit-limited backlog, not after 512 frames.
        let mut position = 0usize;
        loop {
            position += 1;
            let envelope = rx.recv().await.expect("lane closed early");
            if matches!(
                envelope.frame,
                Frame::Data {
                    stream_id: StreamId(2),
                    ..
                }
            ) {
                break;
            }
            assert!(
                position <= MAX_FRAMES_PER_STREAM + 1,
                "light frame buried {position} deep — fairness bound broken",
            );
        }

        drop(rx);
        heavy_task.await.unwrap();
    }
}
