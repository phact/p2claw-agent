use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::body::Trailers;
use bytes::Bytes;
use futures_util::StreamExt;
use p2claw_wire::{ErrorCode, Frame, ReqFlags, StreamId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::codec::Framed;
use tracing::{debug, warn};

use crate::body::{IncomingBody, OutgoingBody};
use crate::codec_io::FrameCodec;
use crate::error::TranslatorError;
use crate::ws::{WsConnection, WsInboundEvent};
use crate::{ClientRequest, ClientResponse, ClientWsUpgrade};

/// Tunables for [`ClientConnection::spawn_with`]. Defaults: PING every
/// 25s, drop the connection after two missed intervals.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub ping_interval: Option<Duration>,
    pub ping_timeout: Option<Duration>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            ping_interval: Some(Duration::from_secs(25)),
            ping_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// A multiplexed translator connection from a visitor to a box.
///
/// Spawn once per transport. Issue requests with
/// [`ClientConnection::request`]; the future resolves when the
/// response headers (RES) arrive. The body continues to stream on
/// the returned [`ClientResponse`] after that.
#[derive(Clone)]
pub struct ClientConnection {
    shared: Arc<Shared>,
}

struct Shared {
    next_stream_id: AtomicU32,
    pending: Mutex<HashMap<StreamId, StreamState>>,
    out_tx: mpsc::Sender<crate::server::BodyFrame>,
    /// Priority lane for session-control frames (PING/PONG/GOAWAY).
    /// See the two-lane split in `spawn_with`.
    ctrl_tx: mpsc::Sender<Frame>,
    /// Set once the peer has sent GOAWAY. New requests beyond
    /// `last_accepted` (or all new requests, if last_accepted is None)
    /// fail synchronously with `GoingAway`.
    going_away: Mutex<Option<GoawayState>>,
    /// Flipped when the reader exits — every subsequent request fails
    /// fast with `ConnectionClosed`.
    closed: AtomicBool,
}

#[derive(Debug, Clone)]
struct GoawayState {
    last_accepted: StreamId,
    code: ErrorCode,
    message: String,
}

struct StreamState {
    /// `Some` before RES arrives; `None` afterwards.
    response_tx: Option<oneshot::Sender<Result<ClientResponse, TranslatorError>>>,
    /// `Some` while the response body is still being streamed in.
    body_tx: Option<mpsc::Sender<Bytes>>,
    /// Producer side of the response body's [`IncomingBody`] trailers
    /// oneshot. `Some` until either a `Frame::Trailers` arrives (we
    /// send the headers) or the stream ends without trailers (we
    /// drop the sender → receiver's `trailers()` returns `None`).
    /// Mirrors the server-side `OpenStream::trailers_tx`.
    trailers_tx: Option<oneshot::Sender<Trailers>>,
    /// Producer side of the response body's [`IncomingBody::error`]
    /// oneshot. Fired on inbound `Frame::Err` arriving for an
    /// in-flight stream (response head already landed, body
    /// streaming). Lets edge tunneling distinguish "box's upstream
    /// closed cleanly" from "box's upstream errored mid-stream" so
    /// the visitor sees a visible abort instead of silent FIN.
    error_tx: Option<oneshot::Sender<(ErrorCode, Bytes)>>,
    kind: PendingKind,
}

enum PendingKind {
    Http,
    Ws {
        events: mpsc::Sender<WsInboundEvent>,
    },
}

impl ClientConnection {
    /// Run the connection. Background reader + writer tasks drive
    /// the transport; the returned handle is cheap to clone.
    pub fn spawn<IO>(io: IO) -> Self
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::spawn_with(io, ClientOptions::default())
    }

    pub fn spawn_with<IO>(io: IO, options: ClientOptions) -> Self
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let framed = Framed::new(io, FrameCodec);
        let (sink, stream) = framed.split();

        let (out_tx, out_rx) = mpsc::channel::<crate::server::BodyFrame>(64);
        // Two-lane writer, mirroring the server (see the split in
        // `server::serve_with`): session-control frames (PING, the
        // PONG reply, GOAWAY) route via `ctrl_tx` so a sustained
        // upload body streaming through `out_tx` can't delay them
        // past the peer's liveness window. Per-stream frames stay on
        // `out_tx` to keep per-stream order total.
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<Frame>(16);
        let shared = Arc::new(Shared {
            next_stream_id: AtomicU32::new(1),
            pending: Mutex::new(HashMap::new()),
            out_tx,
            ctrl_tx,
            going_away: Mutex::new(None),
            closed: AtomicBool::new(false),
        });

        // Coarse liveness clock: milliseconds since `epoch`, stored
        // atomically so the per-frame hot path avoids a mutex.
        let epoch = std::time::Instant::now();
        let last_frame_ms = Arc::new(AtomicU64::new(0));

        // Client side never wires the box-only `tx_observer` hook —
        // pass `None` so writer_task takes the no-op branch on every
        // frame. The hook is exclusively for box-side (server-role)
        // DC instrumentation; see server::TxFrameHook.
        tokio::spawn(crate::server::writer_task(sink, ctrl_rx, out_rx, None));
        tokio::spawn(reader_task(
            stream,
            Arc::clone(&shared),
            epoch,
            Arc::clone(&last_frame_ms),
        ));

        if let Some(interval) = options.ping_interval {
            let ctrl_tx = shared.ctrl_tx.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let mut nonce = [0u8; 8];
                    let n = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    nonce.copy_from_slice(&n.to_be_bytes());
                    if ctrl_tx.send(Frame::Ping { nonce }).await.is_err() {
                        return;
                    }
                }
            });
        }

        if let Some(timeout) = options.ping_timeout {
            let shared_for_watch = Arc::clone(&shared);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(timeout / 4).await;
                    let now_ms = epoch.elapsed().as_millis() as u64;
                    let elapsed_ms = now_ms.saturating_sub(last_frame_ms.load(Ordering::Relaxed));
                    if elapsed_ms > timeout.as_millis() as u64 {
                        // Mark closed and fail every pending stream.
                        shared_for_watch.closed.store(true, Ordering::Release);
                        let mut pending = shared_for_watch.pending.lock().await;
                        for (_, state) in pending.drain() {
                            let mut state = state;
                            if let Some(tx) = state.response_tx.take() {
                                let _ = tx.send(Err(TranslatorError::ConnectionClosed));
                            }
                        }
                        return;
                    }
                }
            });
        }

        Self { shared }
    }

    /// Issue an HTTP request. Resolves once the RES frame arrives.
    /// The returned `ClientResponse`'s body streams after that.
    pub async fn request(&self, req: ClientRequest) -> Result<ClientResponse, TranslatorError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(TranslatorError::ConnectionClosed);
        }
        let stream_id = self.next_stream_id();
        self.check_goaway(stream_id).await?;
        debug!(?stream_id, ?req.path, "client: issuing request");

        let (response_tx, response_rx) = oneshot::channel();
        let (body_tx, trailers_tx, error_tx, body_rx) = IncomingBody::channel(32);

        {
            let mut pending = self.shared.pending.lock().await;
            pending.insert(
                stream_id,
                StreamState {
                    response_tx: Some(response_tx),
                    body_tx: Some(body_tx),
                    trailers_tx: Some(trailers_tx),
                    error_tx: Some(error_tx),
                    kind: PendingKind::Http,
                },
            );
        }

        let is_empty = matches!(req.body, OutgoingBody::Empty);
        let req_frame = Frame::Req {
            stream_id,
            flags: if is_empty {
                ReqFlags::END_STREAM
            } else {
                ReqFlags::NONE
            },
            method: req.method,
            path: req.path,
            headers: req.headers,
        };
        if self
            .shared
            .out_tx
            .send(crate::server::BodyFrame::uncredited(req_frame))
            .await
            .is_err()
        {
            self.shared.pending.lock().await.remove(&stream_id);
            return Err(TranslatorError::ConnectionClosed);
        }

        if !is_empty {
            // Use a fresh atomic per request; runtime-mutable caps
            // are a server-side concern only.
            let cap = Arc::new(std::sync::atomic::AtomicUsize::new(
                crate::server::DEFAULT_MAX_DATA_FRAME_PAYLOAD,
            ));
            crate::server::stream_outgoing_body(
                stream_id,
                req.body,
                crate::server::StreamSender::new(self.shared.out_tx.clone()),
                None,
                // Request trailers are not threaded through the
                // `ClientRequest` API; the receive side honors them
                // via IncomingBody::trailers.
                None,
                None,
                None,
                cap,
            )
            .await?;
        }

        // RAII guard so a dropped response future sends ERR(CANCEL) to
        // the peer rather than leaving the stream half-open. Two
        // phases:
        // 1. Before the response lands: guard sits on the local stack;
        //    drop fires CANCEL (handles request-future cancellation).
        // 2. After the response lands: guard moves into the response
        //    body via `set_drop_hook` — dropping the body now fires
        //    CANCEL too, so a caller that abandons a streaming
        //    response mid-flight tells the server to stop pumping
        //    instead of leaking. The reader cleans `pending` on any
        //    terminal frame (END/ERR/TRAILERS), so the guard's drop
        //    is a graceful no-op when the body is fully drained.
        let cancel_guard = StreamCancelGuard {
            shared: Arc::clone(&self.shared),
            stream_id,
            armed: true,
        };

        let result = response_rx.await;
        let mut body = body_rx;

        match result {
            Ok(Ok(mut resp)) => {
                // Hand the guard into the body so cancel-on-drop now
                // belongs to the body's lifetime, not this function's.
                body.set_drop_hook(Box::new(cancel_guard));
                resp.body = body;
                Ok(resp)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(TranslatorError::ConnectionClosed),
        }
    }

    /// Open a WebSocket. Resolves once `WS_ACCEPT` arrives.
    ///
    /// If the peer rejects the upgrade with a `RES(4xx, END_STREAM)`,
    /// the returned error is
    /// [`TranslatorError::Cancelled`] with code matching the rejection
    /// status (we don't surface a partial `ClientResponse` here — see
    /// [`ClientConnection::request`] for that path).
    pub async fn open_websocket(
        &self,
        req: ClientWsUpgrade,
    ) -> Result<WsConnection, TranslatorError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(TranslatorError::ConnectionClosed);
        }
        let stream_id = self.next_stream_id();
        self.check_goaway(stream_id).await?;

        let (accept_tx, accept_rx) = oneshot::channel::<Result<(), TranslatorError>>();
        let (events_tx, events_rx) = mpsc::channel::<WsInboundEvent>(32);

        // Reuse the existing StreamState by routing the accept-signal
        // through the response_tx channel: an `Ok(_)` from the reader
        // means WS_ACCEPT arrived, `Err(_)` means rejection or ERR.
        {
            let mut pending = self.shared.pending.lock().await;
            pending.insert(
                stream_id,
                StreamState {
                    response_tx: Some(map_accept_to_response_tx(accept_tx)),
                    body_tx: None,
                    // WS streams close via WS_CLOSE, not TRAILERS;
                    // no oneshot needed.
                    trailers_tx: None,
                    // WS streams surface errors via WS_CLOSE; no
                    // body-side error oneshot needed.
                    error_tx: None,
                    kind: PendingKind::Ws { events: events_tx },
                },
            );
        }

        let frame = Frame::WsUpgrade {
            stream_id,
            path: req.path,
            headers: req.headers,
        };
        if self
            .shared
            .out_tx
            .send(crate::server::BodyFrame::uncredited(frame))
            .await
            .is_err()
        {
            self.shared.pending.lock().await.remove(&stream_id);
            return Err(TranslatorError::ConnectionClosed);
        }

        let cancel_guard = StreamCancelGuard {
            shared: Arc::clone(&self.shared),
            stream_id,
            armed: true,
        };

        match accept_rx.await {
            Ok(Ok(())) => {
                let mut cancel_guard = cancel_guard;
                cancel_guard.armed = false;
                Ok(WsConnection {
                    stream_id,
                    out: crate::server::StreamSender::new(self.shared.out_tx.clone()),
                    inbox: tokio::sync::Mutex::new(events_rx),
                    closed_local: AtomicBool::new(false),
                    peer_close_code: std::sync::atomic::AtomicU16::new(0),
                    peer_close_reason: tokio::sync::Mutex::new(Bytes::new()),
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(TranslatorError::ConnectionClosed),
        }
    }

    /// Send GOAWAY to the peer and stop accepting new streams locally
    /// (further calls to [`Self::request`] / [`Self::open_websocket`]
    /// fail with [`TranslatorError::ConnectionClosed`]). In-flight
    /// streams continue to drain.
    pub async fn goaway(
        &self,
        code: ErrorCode,
        message: impl Into<Bytes>,
    ) -> Result<(), TranslatorError> {
        let last = StreamId(
            self.shared
                .next_stream_id
                .load(Ordering::Acquire)
                .saturating_sub(1),
        );
        self.shared.closed.store(true, Ordering::Release);
        // Teardown signal — ctrl lane so the peer learns we're going
        // away even when the body lane is backlogged.
        self.shared
            .ctrl_tx
            .send(Frame::Goaway {
                last_accepted_stream_id: last,
                code,
                message: message.into(),
            })
            .await
            .map_err(|_| TranslatorError::ConnectionClosed)
    }

    fn next_stream_id(&self) -> StreamId {
        StreamId(self.shared.next_stream_id.fetch_add(1, Ordering::Relaxed))
    }

    async fn check_goaway(&self, stream_id: StreamId) -> Result<(), TranslatorError> {
        let guard = self.shared.going_away.lock().await;
        if let Some(g) = guard.as_ref() {
            if stream_id.0 > g.last_accepted.0 {
                return Err(TranslatorError::GoingAway {
                    code: g.code,
                    message: g.message.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Convert the WS-upgrade accept-signal oneshot to the existing
/// `response_tx` shape. We synthesize a tiny `ClientResponse` for
/// "accepted" so the reader's RES/Err handling path can be reused
/// — the caller never observes the synthesized value.
fn map_accept_to_response_tx(
    accept_tx: oneshot::Sender<Result<(), TranslatorError>>,
) -> oneshot::Sender<Result<ClientResponse, TranslatorError>> {
    // Adapter: spawn a task that converts the response-tx output into
    // the accept-tx semantics.
    let (response_tx, response_rx) = oneshot::channel();
    tokio::spawn(async move {
        match response_rx.await {
            Ok(Ok(_resp)) => {
                let _ = accept_tx.send(Ok(()));
            }
            Ok(Err(e)) => {
                let _ = accept_tx.send(Err(e));
            }
            Err(_) => {
                let _ = accept_tx.send(Err(TranslatorError::ConnectionClosed));
            }
        }
    });
    response_tx
}

/// RAII handle that ERRs the stream if it's still open when dropped
/// without being explicitly disarmed. Used to translate "caller
/// dropped the response future" into an outbound `ERR(CANCEL)`
/// so the box doesn't keep computing a response no one's
/// listening for.
struct StreamCancelGuard {
    shared: Arc<Shared>,
    stream_id: StreamId,
    armed: bool,
}

impl Drop for StreamCancelGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let stream_id = self.stream_id;
        tokio::spawn(async move {
            let mut pending = shared.pending.lock().await;
            if pending.remove(&stream_id).is_some() {
                drop(pending);
                let _ = shared
                    .out_tx
                    .send(crate::server::BodyFrame::uncredited(Frame::Err {
                        stream_id,
                        code: ErrorCode::CANCEL,
                        message: Bytes::from_static(b"caller dropped"),
                    }))
                    .await;
            }
        });
    }
}

async fn reader_task<St>(
    mut stream: St,
    shared: Arc<Shared>,
    epoch: std::time::Instant,
    last_frame_ms: Arc<AtomicU64>,
) where
    St: futures_util::Stream<Item = Result<Frame, std::io::Error>> + Unpin,
{
    while let Some(frame) = stream.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                warn!("client reader: decode error: {e}");
                break;
            }
        };
        last_frame_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);

        match frame {
            Frame::Res {
                stream_id,
                flags,
                status,
                headers,
            } => {
                let mut pending = shared.pending.lock().await;
                let Some(state) = pending.get_mut(&stream_id) else {
                    warn!(?stream_id, "RES for unknown stream");
                    continue;
                };

                // WS path: a RES on a WS stream means the peer
                // rejected the upgrade. Surface as a
                // Cancelled-with-status error to the caller.
                if matches!(state.kind, PendingKind::Ws { .. }) {
                    if let Some(response_tx) = state.response_tx.take() {
                        let code = ErrorCode(status);
                        let _ = response_tx.send(Err(TranslatorError::Cancelled(code)));
                    }
                    pending.remove(&stream_id);
                    continue;
                }

                if let Some(response_tx) = state.response_tx.take() {
                    let resp = ClientResponse {
                        status,
                        headers,
                        // Caller provides the real IncomingBody;
                        // this placeholder gets overwritten in
                        // `request` after the oneshot resolves.
                        body: IncomingBody::empty(),
                    };
                    let _ = response_tx.send(Ok(resp));
                }
                if flags.end_stream() {
                    state.body_tx.take();
                    // RES with END_STREAM means no body and no
                    // trailers — drop the trailers oneshot so the
                    // receiver's `trailers()` resolves to None.
                    state.trailers_tx.take();
                    pending.remove(&stream_id);
                }
            }
            Frame::Data {
                stream_id,
                flags,
                body,
            } => {
                // Clone (or take, on END_STREAM) the per-stream sender
                // inside the lock, then drop the guard BEFORE awaiting
                // the bounded send. Awaiting while holding the global
                // `pending` Mutex would head-of-line-block every other
                // stream's frame handling behind one slow body
                // consumer.
                let tx_for_send = {
                    let mut pending = shared.pending.lock().await;
                    match pending.get_mut(&stream_id) {
                        None => {
                            warn!(?stream_id, "DATA for unknown stream");
                            continue;
                        }
                        Some(state) => {
                            if flags.end_stream() {
                                // DATA(END_STREAM) terminates the
                                // stream without trailers — drop the
                                // oneshot and take the sender so
                                // dropping it after send closes the
                                // receiver's stream.
                                state.trailers_tx.take();
                                let tx = state.body_tx.take();
                                pending.remove(&stream_id);
                                tx
                            } else {
                                state.body_tx.clone()
                            }
                        }
                    }
                };
                if let Some(tx) = tx_for_send {
                    if !body.is_empty() && tx.send(body).await.is_err() {
                        // Caller dropped the body; cancel stream.
                        shared.pending.lock().await.remove(&stream_id);
                    }
                }
            }
            Frame::End { stream_id } => {
                let mut pending = shared.pending.lock().await;
                if let Some(mut state) = pending.remove(&stream_id) {
                    state.body_tx.take();
                    state.trailers_tx.take();
                }
            }
            Frame::Trailers { stream_id, headers } => {
                // TRAILERS implicitly closes the stream. Drop body_tx
                // so `next_chunk()` returns None on the receiver, and
                // fire the trailers oneshot so `trailers()` resolves
                // to `Some(headers)`.
                let mut pending = shared.pending.lock().await;
                if let Some(mut state) = pending.remove(&stream_id) {
                    state.body_tx.take();
                    if let Some(tx) = state.trailers_tx.take() {
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
                    debug!(?code, "client: connection-level ERR; closing");
                    break;
                }
                let mut pending = shared.pending.lock().await;
                if let Some(mut state) = pending.remove(&stream_id) {
                    if let Some(response_tx) = state.response_tx.take() {
                        // Response head hadn't landed yet — surface
                        // the abort to the in-flight `request()`
                        // future as a `Cancelled` error.
                        let _ = response_tx.send(Err(TranslatorError::Cancelled(code)));
                    } else if let Some(tx) = state.error_tx.take() {
                        // Response head already landed; body is
                        // streaming. Surface the abort to
                        // `IncomingBody::error()` so consumers
                        // (edge tunneling, etc.) can distinguish
                        // clean End from mid-stream Err and emit a
                        // visible abort to the visitor instead of
                        // silent FIN-after-truncation.
                        let _ = tx.send((code, message));
                    }
                    state.body_tx.take();
                    state.trailers_tx.take();
                    if let PendingKind::Ws { events } = state.kind {
                        let _ = events.send(WsInboundEvent::Transport).await;
                    }
                }
            }
            Frame::WsAccept { stream_id, .. } => {
                let mut pending = shared.pending.lock().await;
                let Some(state) = pending.get_mut(&stream_id) else {
                    warn!(?stream_id, "WS_ACCEPT for unknown stream");
                    continue;
                };
                if let Some(response_tx) = state.response_tx.take() {
                    let resp = ClientResponse {
                        status: 101,
                        headers: Vec::new(),
                        body: IncomingBody::empty(),
                    };
                    let _ = response_tx.send(Ok(resp));
                }
            }
            Frame::WsMsg {
                stream_id,
                opcode,
                payload,
            } => {
                // Clone the events sender inside the lock, drop the
                // guard before the bounded send — same rationale as
                // the DATA arm.
                let events_tx = {
                    let pending = shared.pending.lock().await;
                    pending.get(&stream_id).and_then(|state| match &state.kind {
                        PendingKind::Ws { events } => Some(events.clone()),
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
                    let pending = shared.pending.lock().await;
                    pending.get(&stream_id).and_then(|state| match &state.kind {
                        PendingKind::Ws { events } => Some(events.clone()),
                        _ => None,
                    })
                };
                if let Some(events) = events_tx {
                    let _ = events.send(WsInboundEvent::Close { code, reason }).await;
                }
            }
            Frame::Ping { nonce } => {
                // PONG is a session-control reply — ctrl lane so our
                // liveness signal isn't HOL-blocked behind an upload
                // body backlog on `out_tx`.
                if shared.ctrl_tx.send(Frame::Pong { nonce }).await.is_err() {
                    break;
                }
            }
            Frame::Pong { .. } => {
                // last_frame_ms update above is enough.
            }
            Frame::Goaway {
                last_accepted_stream_id,
                code,
                message,
            } => {
                debug!(?code, "client: peer GOAWAY received");
                let mut g = shared.going_away.lock().await;
                *g = Some(GoawayState {
                    last_accepted: last_accepted_stream_id,
                    code,
                    message: String::from_utf8_lossy(&message).into_owned(),
                });
                // Fail any pending streams beyond last_accepted.
                let mut pending = shared.pending.lock().await;
                let to_drop: Vec<StreamId> = pending
                    .keys()
                    .copied()
                    .filter(|sid| sid.0 > last_accepted_stream_id.0)
                    .collect();
                for sid in to_drop {
                    if let Some(mut state) = pending.remove(&sid) {
                        if let Some(tx) = state.response_tx.take() {
                            let _ = tx.send(Err(TranslatorError::GoingAway {
                                code,
                                message: String::from_utf8_lossy(&Bytes::copy_from_slice(
                                    b"peer going away",
                                ))
                                .into_owned(),
                            }));
                        }
                    }
                }
            }
            other => {
                debug!(
                    "client reader: ignoring unhandled frame type {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    // Transport closed — fail every pending stream.
    shared.closed.store(true, Ordering::Release);
    let mut pending = shared.pending.lock().await;
    for (_, state) in pending.drain() {
        let mut state = state;
        if let Some(tx) = state.response_tx.take() {
            let _ = tx.send(Err(TranslatorError::ConnectionClosed));
        }
        if let PendingKind::Ws { events } = state.kind {
            let _ = events.send(WsInboundEvent::Transport).await;
        }
    }
}
