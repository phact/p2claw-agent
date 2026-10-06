use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use tokio::sync::{mpsc, oneshot};

/// Trailing HTTP headers carried by a `Frame::Trailers` after the
/// body has streamed. Same shape as the request/response header
/// vectors elsewhere in the translator API.
pub type Trailers = Vec<(Bytes, Bytes)>;

/// Producer-side handles paired with an [`IncomingBody`]: a body
/// chunk channel, a trailers oneshot, and an error oneshot. The wire
/// reader holds these in its per-stream open-state table; the
/// `IncomingBody` is handed back to the consumer.
pub(crate) type IncomingBodyChannel = (
    mpsc::Sender<Bytes>,
    oneshot::Sender<Trailers>,
    oneshot::Sender<(crate::ErrorCode, Bytes)>,
    IncomingBody,
);

/// Receive-end of a request or response body. Produces `Bytes`
/// chunks as they arrive on the wire; yields `None` at end-of-stream.
///
/// **Trailers**: after `next_chunk` returns `None` (body exhausted),
/// callers that care about trailing headers (gRPC `grpc-status`,
/// HTTP/1.1 chunked-trailer extensions) can call
/// [`IncomingBody::trailers`] to retrieve them. The future resolves
/// to `Some(headers)` if a `Frame::Trailers` arrived, or `None` if
/// the stream ended via `DATA(END_STREAM)` / bare `END` without
/// trailers. Calling `trailers` before the body has fully drained is
/// supported but the returned future won't resolve until the
/// terminal frame arrives.
pub struct IncomingBody {
    rx: mpsc::Receiver<Bytes>,
    /// `Some` until [`Self::trailers`] is called or the stream
    /// terminates without trailers. The producer-side
    /// `oneshot::Sender` is held by the wire reader's open-stream
    /// table; on TRAILERS arrival the reader sends headers and on
    /// any other terminal it drops the sender so the receiver
    /// returns `None`.
    trailers_rx: Option<oneshot::Receiver<Trailers>>,
    /// Optional drop-time hook. Client-side response bodies use this
    /// to fire `Frame::Err { code: CANCEL }` on the wire when the
    /// body is dropped before the stream has finished — so the
    /// peer can abort its outbound pump promptly instead of waiting
    /// for the (potentially never-ending) stream to time out. Server-
    /// side request bodies leave this `None`; the visitor can't
    /// "cancel" an inbound request body the server is already
    /// reading.
    on_drop: Option<Box<dyn Send + Sync>>,
    /// `Some` until [`Self::error`] is called or the wire reader
    /// resolves the oneshot. The wire reader sends `(code, message)`
    /// on inbound `Frame::Err` for an in-flight stream so the
    /// receiver can distinguish abort-with-cause from clean
    /// end-of-stream after `next_chunk` returns `None`. Mirror of
    /// [`crate::OutgoingBody`]'s `with_deferred_error` surface on
    /// the sender side.
    error_rx: Option<oneshot::Receiver<(crate::ErrorCode, Bytes)>>,
}

impl IncomingBody {
    pub(crate) fn channel(capacity: usize) -> IncomingBodyChannel {
        let (body_tx, body_rx) = mpsc::channel(capacity);
        let (trailers_tx, trailers_rx) = oneshot::channel();
        let (error_tx, error_rx) = oneshot::channel();
        (
            body_tx,
            trailers_tx,
            error_tx,
            Self {
                rx: body_rx,
                trailers_rx: Some(trailers_rx),
                on_drop: None,
                error_rx: Some(error_rx),
            },
        )
    }

    /// Attach a drop-time hook. The boxed value is held by the body
    /// for its entire lifetime; when the body drops, the hook drops
    /// too. Used by `client::request` to install a `StreamCancelGuard`
    /// so dropping a response body that hasn't reached end-of-stream
    /// emits `Frame::Err { code: CANCEL }` on the wire.
    pub(crate) fn set_drop_hook(&mut self, hook: Box<dyn Send + Sync>) {
        self.on_drop = Some(hook);
    }

    /// Construct an empty body. Promoted to `pub` for downstream
    /// callers (e.g., `p2claw_agent::oauth::middleware` unit
    /// tests) that need to build a `ServerRequest` shell without
    /// driving the full transport. The internal `channel` builder
    /// is `pub(crate)` because consumers shouldn't be poking the
    /// trailers oneshot directly, but the empty no-body case is a
    /// reasonable test surface.
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel(1);
        Self {
            rx,
            // No trailers will ever arrive — `trailers()` resolves
            // to `None` immediately. Set to `None` rather than
            // hand-rolling a closed oneshot because that's what
            // [`Self::trailers`] checks for the never-going-to-have-
            // trailers case.
            trailers_rx: None,
            on_drop: None,
            // Same posture: no error will ever arrive on an empty
            // body — `error()` resolves to `None`.
            error_rx: None,
        }
    }

    /// Next body chunk, or `None` if the stream has ended.
    pub async fn next_chunk(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }

    /// Poll-form of [`Self::next_chunk`], for callers that adapt the
    /// body into a `Stream`/`Body` impl without a pump task.
    /// `Ready(None)` = end-of-stream.
    pub fn poll_next_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.rx.poll_recv(cx)
    }

    /// Poll-form of [`Self::trailers`]. Resolves `Some(headers)` if a
    /// `Frame::Trailers` arrived, `None` if the stream ended without
    /// trailers. Idempotent like [`Self::trailers`]: once resolved,
    /// always `Ready(None)`.
    pub fn poll_trailers(&mut self, cx: &mut Context<'_>) -> Poll<Option<Trailers>> {
        let Some(rx) = self.trailers_rx.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(rx).poll(cx) {
            Poll::Ready(res) => {
                self.trailers_rx = None;
                Poll::Ready(res.ok())
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Wait for trailing headers. Returns `Some(headers)` if a
    /// `Frame::Trailers` arrived for this stream, or `None` if the
    /// stream ended without trailers (or trailers were already
    /// consumed by a prior call).
    ///
    /// Idempotent: a second call always returns `None`.
    ///
    /// **Ordering**: callers SHOULD drain the body via `next_chunk`
    /// first; calling `trailers` before the body has finished still
    /// works but the future blocks until the terminal frame arrives.
    /// After the body has been fully drained (`next_chunk` returned
    /// `None`), check whether the stream ended via clean
    /// end-of-stream or was aborted by an inbound `Frame::Err`.
    /// Returns `Some((code, message))` if a peer `Frame::Err`
    /// arrived for this stream, `None` otherwise (clean End /
    /// Trailers terminator, or error already consumed).
    ///
    /// Edge tunneling uses this to distinguish "box's upstream
    /// closed cleanly" from "box's upstream errored mid-stream" so
    /// the visitor sees a visible abort (axum body-stream Err →
    /// HTTP/1.1 truncated-chunked / HTTP/2 RST_STREAM) instead of
    /// silent FIN-after-truncation. Mirrors the sender-side
    /// `OutgoingBody::with_deferred_error` surface.
    pub async fn error(&mut self) -> Option<(crate::ErrorCode, Bytes)> {
        let rx = self.error_rx.take()?;
        rx.await.ok()
    }

    pub async fn trailers(&mut self) -> Option<Trailers> {
        let rx = self.trailers_rx.take()?;
        // `Err` from a closed oneshot means the sender was dropped
        // without sending — which is exactly the "stream ended
        // without trailers" signal the wire reader emits.
        rx.await.ok()
    }

    /// Collect the entire body into a single `Bytes`. Convenient for
    /// tests and small-body callers; prefer `next_chunk` for
    /// streaming. Trailers (if any) are discarded — call
    /// [`Self::trailers`] before `collect` if you need them.
    pub async fn collect(mut self) -> Bytes {
        let mut pieces = Vec::new();
        let mut total = 0usize;
        while let Some(chunk) = self.rx.recv().await {
            total += chunk.len();
            pieces.push(chunk);
        }
        if pieces.len() == 1 {
            return pieces.pop().unwrap();
        }
        let mut out = bytes::BytesMut::with_capacity(total);
        for p in pieces {
            out.extend_from_slice(&p);
        }
        out.freeze()
    }
}

impl fmt::Debug for IncomingBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingBody").finish_non_exhaustive()
    }
}

/// Send-end of a request or response body, consumed by the
/// translator.
pub enum OutgoingBody {
    /// No body at all. REQ/RES will carry the END_STREAM flag.
    Empty,
    /// The entire body fits in one chunk. Translator sends a single
    /// DATA frame with END_STREAM.
    Once(Bytes),
    /// Arbitrary streaming body. Translator drains and emits DATA
    /// frames until the stream ends, then sends END.
    Stream(Pin<Box<dyn Stream<Item = Bytes> + Send>>),
}

impl OutgoingBody {
    pub fn empty() -> Self {
        Self::Empty
    }

    pub fn once(data: impl Into<Bytes>) -> Self {
        let b = data.into();
        if b.is_empty() {
            Self::Empty
        } else {
            Self::Once(b)
        }
    }

    pub fn stream<S>(s: S) -> Self
    where
        S: Stream<Item = Bytes> + Send + 'static,
    {
        Self::Stream(Box::pin(s))
    }

    pub(crate) fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        match self {
            Self::Empty => Poll::Ready(None),
            Self::Once(b) => {
                let taken = std::mem::take(b);
                *self = Self::Empty;
                if taken.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(taken))
                }
            }
            Self::Stream(s) => s.as_mut().poll_next(cx),
        }
    }
}

impl fmt::Debug for OutgoingBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "OutgoingBody::Empty"),
            Self::Once(b) => write!(f, "OutgoingBody::Once({} bytes)", b.len()),
            Self::Stream(_) => write!(f, "OutgoingBody::Stream(..)"),
        }
    }
}
