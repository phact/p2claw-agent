//! p2claw translator: bidirectional bridge between the wire protocol
//! ([`p2claw_wire`]) and HTTP request/response objects.
//!
//! Scope: HTTP (GET/POST/etc.) with streaming request and response
//! bodies. WebSocket upgrades, PING/PONG liveness, and graceful
//! GOAWAY are layered on top via the [`ws`] module and the
//! [`ServeOptions`] / [`ClientOptions`] knobs.
//!
//! Transport-agnostic: operates over any `AsyncRead + AsyncWrite`
//! byte stream — TCP for tests, Iroh QUIC streams, WebRTC data
//! channels (indirectly).

#![deny(rust_2018_idioms)]

mod body;
mod client;
mod codec_io;
mod error;
mod server;
pub mod ws;

pub use body::{IncomingBody, OutgoingBody, Trailers};
pub use client::{ClientConnection, ClientOptions};
pub use error::TranslatorError;
pub use server::{serve, serve_with, Handler, ProbeOptions, ServeOptions, TxFrameHook, WsHandler};
pub use ws::{WsConnection, WsMessage};

use bytes::Bytes;
pub use p2claw_wire::ErrorCode;

/// A request **to be sent** by a client.
#[derive(Debug)]
pub struct ClientRequest {
    pub method: Bytes,
    pub path: Bytes,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: OutgoingBody,
}

impl ClientRequest {
    pub fn get(path: impl Into<Bytes>) -> Self {
        Self {
            method: Bytes::from_static(b"GET"),
            path: path.into(),
            headers: Vec::new(),
            body: OutgoingBody::empty(),
        }
    }

    pub fn post(path: impl Into<Bytes>, body: OutgoingBody) -> Self {
        Self {
            method: Bytes::from_static(b"POST"),
            path: path.into(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A WebSocket-upgrade request, distinguished from a plain HTTP
/// request by the upgrade verb at the wire layer (`WS_UPGRADE`
/// instead of `REQ`).
#[derive(Debug)]
pub struct ClientWsUpgrade {
    pub path: Bytes,
    pub headers: Vec<(Bytes, Bytes)>,
}

impl ClientWsUpgrade {
    pub fn new(path: impl Into<Bytes>) -> Self {
        Self {
            path: path.into(),
            headers: Vec::new(),
        }
    }

    pub fn header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A response **received** by a client. Headers are already here;
/// the body streams in via [`IncomingBody::next_chunk`].
#[derive(Debug)]
pub struct ClientResponse {
    pub status: u16,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: IncomingBody,
}

/// A request **received** by a server-side handler.
#[derive(Debug)]
pub struct ServerRequest {
    pub method: Bytes,
    pub path: Bytes,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: IncomingBody,
}

/// A response **to be sent** by a server-side handler.
#[derive(Debug)]
pub struct ServerResponse {
    pub status: u16,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: OutgoingBody,
    /// Static trailing headers known at construction time. `None`
    /// (default) means the stream ends on the last DATA frame's
    /// `END_STREAM` flag (or a bare `END` for zero-chunk bodies).
    /// `Some(_)` — even an empty `Vec` — switches the terminator to
    /// TRAILERS, which gRPC and HTTP-trailer-aware clients can read
    /// via [`IncomingBody::trailers`] on their receiving side.
    ///
    /// Mutually exclusive with [`Self::trailers_rx`] — if a handler
    /// sets both, the static block wins.
    pub trailers: Option<Trailers>,
    /// Deferred trailers — the wire awaits this oneshot **after** the
    /// body stream finishes. Used by the agent's forwarder for
    /// HTTP/1.1 chunked-trailer responses, where trailers only arrive
    /// after the upstream body has fully drained. If the sender is
    /// dropped without ever sending, the wire emits a bare `END`
    /// instead of `Frame::Trailers`. Has no effect when
    /// [`Self::trailers`] is already set.
    pub trailers_rx: Option<tokio::sync::oneshot::Receiver<Trailers>>,
    /// Deferred mid-stream error — the wire polls this oneshot **after
    /// the body stream finishes** to decide whether to emit a clean
    /// `Frame::End` or abort with `Frame::Err`. Used by the agent's
    /// forwarder when the loopback upstream's HTTP body errors part-
    /// way through: the body stream returns `None` (no error item
    /// possible on `Stream<Item = Bytes>`), but we still want the
    /// visitor to see an explicit failure code (e.g.
    /// `ErrorCode::LOCAL_APP_DOWN`) instead of a clean EOF that looks
    /// indistinguishable from a complete response. Dropping the sender
    /// without sending falls back to the clean `End` terminator.
    /// Higher precedence than [`Self::trailers`] / [`Self::trailers_rx`]
    /// — an explicit error supersedes any trailing-header terminator.
    pub error_rx: Option<tokio::sync::oneshot::Receiver<(ErrorCode, Bytes)>>,
}

impl ServerResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: OutgoingBody::empty(),
            trailers: None,
            trailers_rx: None,
            error_rx: None,
        }
    }

    pub fn with_body(mut self, body: OutgoingBody) -> Self {
        self.body = body;
        self
    }

    pub fn header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Replace the trailers block. Pass `Some(vec![..])` to attach
    /// trailers (the wire emits `Frame::Trailers` after the body);
    /// pass `None` to fall back to the default end-of-stream-via-DATA
    /// terminator.
    pub fn with_trailers(mut self, trailers: Option<Trailers>) -> Self {
        self.trailers = trailers;
        self
    }

    /// Attach a deferred-trailers oneshot. The wire emits a
    /// `Frame::Trailers` (or bare `END` if the sender is dropped
    /// without sending) **after** the body stream completes. Used
    /// when trailers only become available once the body has fully
    /// streamed — e.g. the agent's forwarder reading an HTTP/1.1
    /// chunked-trailer upstream response.
    pub fn with_deferred_trailers(mut self, rx: tokio::sync::oneshot::Receiver<Trailers>) -> Self {
        self.trailers_rx = Some(rx);
        self
    }

    /// Attach a deferred-error oneshot. After the body stream
    /// finishes, the wire awaits this rx — if it yields a code, the
    /// stream terminates with `Frame::Err { code, message }` instead
    /// of the usual clean `Frame::End`. Lets a streaming body that
    /// can't natively signal errors (`Stream<Item = Bytes>`) report
    /// a late failure — e.g. forwarder seeing the upstream hyper
    /// body error mid-stream. Dropping the sender without sending
    /// falls back to the clean `End` terminator.
    pub fn with_deferred_error(
        mut self,
        rx: tokio::sync::oneshot::Receiver<(ErrorCode, Bytes)>,
    ) -> Self {
        self.error_rx = Some(rx);
        self
    }

    /// Append a single trailing header. First call promotes
    /// `trailers` from `None` → `Some(vec![])`; subsequent calls
    /// push onto the existing vec. The stream terminator switches
    /// from DATA(END_STREAM) to TRAILERS the moment the first
    /// trailer is set.
    pub fn trailer(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.trailers
            .get_or_insert_with(Vec::new)
            .push((name.into(), value.into()));
        self
    }
}

/// A WS_UPGRADE **received** by a server-side WS handler.
#[derive(Debug)]
pub struct ServerWsUpgrade {
    pub path: Bytes,
    pub headers: Vec<(Bytes, Bytes)>,
}

/// Handler decision for a WS_UPGRADE: either accept (the handler is
/// then invoked with a [`WsConnection`] for the lifetime of the
/// session) or reject with an HTTP-style status. A rejection goes on
/// the wire as `RES(status=4xx, END_STREAM)`, not `ERR`.
#[derive(Debug)]
pub enum WsUpgradeDecision {
    Accept {
        /// Headers to send with the WS_ACCEPT (e.g. selected
        /// `Sec-WebSocket-Protocol`).
        headers: Vec<(Bytes, Bytes)>,
        /// Handler-private payload threaded by the wire from
        /// [`WsHandler::decide`] through to [`WsHandler::run`].
        /// the agent's `WsForwarder` uses this to carry the OAuth
        /// middleware's injected identity headers
        /// (`X-P2claw-User`, `X-P2claw-Email`, etc.) into the
        /// upstream WebSocket dial in `run`. The translator wire
        /// itself never inspects this list.
        upstream_headers: Vec<(Bytes, Bytes)>,
    },
    Reject {
        status: u16,
        headers: Vec<(Bytes, Bytes)>,
    },
}
