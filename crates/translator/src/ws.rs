//! WebSocket plumbing on top of the translator.
//!
//! [`WsConnection`] is the post-upgrade handle returned by the client
//! once a `WS_UPGRADE` is accepted, and the same shape the server-side
//! WS handler is given to drive an upgraded stream. Both sides are
//! symmetrical: either may send WS_MSG, send WS_CLOSE, or observe the
//! peer's WS_CLOSE.
//!
//! The connection is **not** clone-able because it owns the receive
//! half of the per-stream channel; clone the sender separately if you
//! need to fan out writes.

use std::sync::atomic::AtomicU16;

use bytes::Bytes;
use p2claw_wire::{Frame, StreamId, WsOpcode};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::error::TranslatorError;

/// A WS_MSG payload alongside its opcode. Text/Binary carry the
/// application payload; Ping/Pong are control frames per RFC 6455.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMessage {
    pub opcode: WsOpcode,
    pub payload: Bytes,
}

impl WsMessage {
    pub fn text(s: impl Into<Bytes>) -> Self {
        Self {
            opcode: WsOpcode::Text,
            payload: s.into(),
        }
    }
    pub fn binary(b: impl Into<Bytes>) -> Self {
        Self {
            opcode: WsOpcode::Binary,
            payload: b.into(),
        }
    }
    pub fn ping(b: impl Into<Bytes>) -> Self {
        Self {
            opcode: WsOpcode::Ping,
            payload: b.into(),
        }
    }
    pub fn pong(b: impl Into<Bytes>) -> Self {
        Self {
            opcode: WsOpcode::Pong,
            payload: b.into(),
        }
    }
}

/// Reason a [`WsConnection::recv`] returned `None`.
#[derive(Debug, Clone)]
pub enum WsClose {
    /// Peer sent WS_CLOSE with the given code/reason.
    Peer { code: u16, reason: Bytes },
    /// The transport went away or the stream was ERR'd.
    Transport,
}

/// A bidirectional WebSocket carried over a translator stream.
///
/// Receive arriving messages with [`WsConnection::recv`]; send with
/// [`WsConnection::send`]. The control-message split (Ping/Pong) is
/// surfaced verbatim — the translator does **not** auto-reply to WS
/// pings on behalf of the application: fragmentation is collapsed but
/// opcodes are preserved.
pub struct WsConnection {
    pub(crate) stream_id: StreamId,
    pub(crate) out: crate::server::StreamSender,
    pub(crate) inbox: Mutex<mpsc::Receiver<WsInboundEvent>>,
    /// Set once we've sent WS_CLOSE locally. Subsequent sends fail
    /// with `ConnectionClosed`.
    pub(crate) closed_local: std::sync::atomic::AtomicBool,
    /// Set when the peer's WS_CLOSE arrives, so [`Self::peer_close`]
    /// can return the code/reason after `recv` returns `None`.
    pub(crate) peer_close_code: AtomicU16,
    pub(crate) peer_close_reason: Mutex<Bytes>,
}

#[derive(Debug)]
pub(crate) enum WsInboundEvent {
    Msg(WsMessage),
    Close { code: u16, reason: Bytes },
    Transport,
}

impl std::fmt::Debug for WsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnection")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl WsConnection {
    /// Send a WebSocket frame. Returns `ConnectionClosed` if the
    /// underlying connection has gone away or the local side has
    /// already sent WS_CLOSE.
    pub async fn send(&self, msg: WsMessage) -> Result<(), TranslatorError> {
        if self.closed_local.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TranslatorError::ConnectionClosed);
        }
        self.out
            .send(Frame::WsMsg {
                stream_id: self.stream_id,
                opcode: msg.opcode,
                payload: msg.payload,
            })
            .await
            .map_err(|_| TranslatorError::ConnectionClosed)
    }

    /// Receive the next inbound message. Returns `Ok(Some(msg))` for
    /// data/control frames and `Ok(None)` once the stream has closed
    /// (either side's WS_CLOSE, or transport teardown). After `None`,
    /// [`Self::peer_close`] returns the close code/reason if the peer
    /// initiated the close.
    pub async fn recv(&self) -> Result<Option<WsMessage>, TranslatorError> {
        let mut inbox = self.inbox.lock().await;
        match inbox.recv().await {
            Some(WsInboundEvent::Msg(m)) => Ok(Some(m)),
            Some(WsInboundEvent::Close { code, reason }) => {
                self.peer_close_code
                    .store(code, std::sync::atomic::Ordering::Release);
                *self.peer_close_reason.lock().await = reason;
                Ok(None)
            }
            Some(WsInboundEvent::Transport) | None => Ok(None),
        }
    }

    /// Close code + reason from the peer's WS_CLOSE, if one arrived.
    /// Returns `None` if the connection ended for a different reason
    /// (transport teardown, ERR, local close).
    pub async fn peer_close(&self) -> Option<(u16, Bytes)> {
        let code = self
            .peer_close_code
            .load(std::sync::atomic::Ordering::Acquire);
        if code == 0 {
            return None;
        }
        Some((code, self.peer_close_reason.lock().await.clone()))
    }

    /// Send WS_CLOSE; idempotent. After this returns Ok, no further
    /// sends are permitted on this connection.
    pub async fn close(&self, code: u16, reason: impl Into<Bytes>) -> Result<(), TranslatorError> {
        if self
            .closed_local
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Ok(());
        }
        self.out
            .send(Frame::WsClose {
                stream_id: self.stream_id,
                code,
                reason: reason.into(),
            })
            .await
            .map_err(|_| TranslatorError::ConnectionClosed)
    }
}
