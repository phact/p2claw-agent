//! Sans-I/O WebSocket-shape shim driven over the peer wire protocol.
//!
//! Mirrors the browser bootstrap's `P2clawWebSocket` lifecycle but as
//! a pure state machine. The caller feeds in wire frames received off
//! a DataChannel plus application calls (`send`, `close`); the
//! machine drains a queue of frames to write back out and events to
//! deliver to the application.
//!
//! Lifecycle states match the WHATWG WebSocket `readyState` model:
//!
//! ```text
//!   Connecting ──[WsAccept]──▶ Open ──[close()]──▶ Closing ──[WsClose]──▶ Closed
//!         │                      │                                       ▲
//!         │                      └───────[WsClose from box]──────────────┤
//!         └────────[Err / unexpected frame / send()-pre-open]────────────┘
//! ```

use std::sync::Mutex;

use crate::codec::{frame_kind_of, Frame, Header, WireOpcode};

/// WHATWG-aligned readyState for the shim.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReadyState {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
}

/// Event delivered up to the application as the state machine advances.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum WsEvent {
    /// Box accepted the upgrade. Carries any sub-protocol or response
    /// headers the box returned on the WsAccept frame.
    Open { headers: Vec<Header> },
    /// Inbound text or binary message from the box.
    Message { binary: bool, data: Vec<u8> },
    /// Either side closed cleanly. `code`/`reason` follow RFC 6455.
    Close { code: u16, reason: Vec<u8> },
    /// Protocol error — message describes the cause.
    Error { message: String },
}

#[derive(Debug)]
struct WsState {
    state: ReadyState,
    outbox: Vec<Frame>,
    events: Vec<WsEvent>,
}

/// Sans-I/O state for one WebSocket-shape stream. Internally
/// mutex-guarded so the FFI surface can hand out `Arc<WsShim>` and the
/// foreign callers can drive it from any thread.
#[derive(Debug, uniffi::Object)]
pub struct WsShim {
    stream_id: u32,
    inner: Mutex<WsState>,
}

#[uniffi::export]
impl WsShim {
    /// Open a new shim, emitting the [`Frame::WsUpgrade`] the caller
    /// must transmit. `path` and `headers` go on the upgrade frame
    /// verbatim — see the wire spec for the `Sec-WebSocket-Protocol`
    /// and related headers expected by the forwarder.
    #[uniffi::constructor]
    pub fn open(stream_id: u32, path: Vec<u8>, headers: Vec<Header>) -> Self {
        let outbox = vec![Frame::WsUpgrade {
            stream_id,
            path,
            headers,
        }];
        Self {
            stream_id,
            inner: Mutex::new(WsState {
                state: ReadyState::Connecting,
                outbox,
                events: Vec::new(),
            }),
        }
    }

    /// Current readyState. Mirrors the WHATWG `WebSocket.readyState`
    /// numeric encoding for predictable FFI mapping.
    pub fn ready_state(&self) -> ReadyState {
        self.inner.lock().unwrap().state
    }

    /// Stream id this shim manages on the multiplexed transport.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// App action: send a text message (UTF-8 already validated by
    /// caller — the wire is opaque about charset).
    pub fn send_text(&self, payload: Vec<u8>) {
        self.send(WireOpcode::Text, payload);
    }

    /// App action: send a binary message.
    pub fn send_binary(&self, payload: Vec<u8>) {
        self.send(WireOpcode::Binary, payload);
    }

    /// App action: initiate a clean close. `code` follows RFC 6455
    /// (1000 = normal, 1001 = going away, etc.). The shim emits a
    /// [`Frame::WsClose`] and moves to [`ReadyState::Closing`]; the
    /// state machine settles to [`ReadyState::Closed`] when the box's
    /// matching `WsClose` arrives via [`Self::handle_frame`].
    pub fn close(&self, code: u16, reason: Vec<u8>) {
        let mut s = self.inner.lock().unwrap();
        match s.state {
            ReadyState::Open => {
                s.outbox.push(Frame::WsClose {
                    stream_id: self.stream_id,
                    code,
                    reason,
                });
                s.state = ReadyState::Closing;
            }
            ReadyState::Connecting => {
                // No upgrade yet, no Close to send.
                s.state = ReadyState::Closed;
                s.events.push(WsEvent::Close { code, reason });
            }
            ReadyState::Closing | ReadyState::Closed => {
                // Idempotent: re-issuing close() in these states is a no-op.
            }
        }
    }

    /// Feed an inbound wire frame received on the transport. Returns
    /// `true` when the frame belonged to this shim, `false` when the
    /// stream_id didn't match (caller is multiplexing several streams
    /// over one transport).
    pub fn handle_frame(&self, frame: Frame) -> bool {
        if frame_stream(&frame) != Some(self.stream_id) {
            return false;
        }
        let mut s = self.inner.lock().unwrap();
        match (s.state, frame) {
            (ReadyState::Connecting, Frame::WsAccept { headers, .. }) => {
                s.state = ReadyState::Open;
                s.events.push(WsEvent::Open { headers });
            }
            (
                ReadyState::Open,
                Frame::WsMsg {
                    opcode, payload, ..
                },
            ) => {
                if matches!(opcode, WireOpcode::Text | WireOpcode::Binary) {
                    let binary = matches!(opcode, WireOpcode::Binary);
                    s.events.push(WsEvent::Message {
                        binary,
                        data: payload,
                    });
                }
                // Ping/Pong opcodes are handled by lower layers (the
                // wire-level PING / PONG frames) and shouldn't appear
                // as WsMsg payloads — drop silently if they do.
            }
            (ReadyState::Open | ReadyState::Closing, Frame::WsClose { code, reason, .. }) => {
                s.state = ReadyState::Closed;
                s.events.push(WsEvent::Close { code, reason });
            }
            (_, Frame::Err { code, message, .. }) => {
                s.state = ReadyState::Closed;
                s.events.push(WsEvent::Error {
                    message: format!(
                        "stream error 0x{:04x}: {}",
                        code,
                        String::from_utf8_lossy(&message)
                    ),
                });
            }
            (_, Frame::End { .. }) => {
                // END terminates the stream without a Close opcode; the
                // browser shim treats this as an abnormal close (1006).
                if !matches!(s.state, ReadyState::Closed) {
                    s.state = ReadyState::Closed;
                    s.events.push(WsEvent::Close {
                        code: 1006,
                        reason: b"transport ended".to_vec(),
                    });
                }
            }
            (state, frame) => {
                // A `Res` while still Connecting carries the box's HTTP
                // refusal — surface the status so callers see why the
                // upgrade was rejected instead of a flat "unexpected".
                let message = match &frame {
                    Frame::Res { status, .. } => {
                        format!("ws upgrade rejected: HTTP {status} (state {state:?})")
                    }
                    other => {
                        let kind = frame_kind_of(other);
                        format!("unexpected {kind:?} in state {state:?}")
                    }
                };
                if !matches!(s.state, ReadyState::Closed) {
                    s.state = ReadyState::Closed;
                    s.events.push(WsEvent::Error { message });
                }
            }
        }
        true
    }

    /// Drain pending frames the caller must transmit on the transport.
    pub fn take_outgoing(&self) -> Vec<Frame> {
        std::mem::take(&mut self.inner.lock().unwrap().outbox)
    }

    /// Drain pending application-level events.
    pub fn take_events(&self) -> Vec<WsEvent> {
        std::mem::take(&mut self.inner.lock().unwrap().events)
    }
}

impl WsShim {
    fn send(&self, opcode: WireOpcode, payload: Vec<u8>) {
        let mut s = self.inner.lock().unwrap();
        match s.state {
            ReadyState::Open => {
                s.outbox.push(Frame::WsMsg {
                    stream_id: self.stream_id,
                    opcode,
                    payload,
                });
            }
            _ => {
                let prev = s.state;
                if !matches!(s.state, ReadyState::Closed) {
                    s.state = ReadyState::Closed;
                    s.events.push(WsEvent::Error {
                        message: format!("send while readyState={prev:?}; ignored"),
                    });
                }
            }
        }
    }
}

fn frame_stream(frame: &Frame) -> Option<u32> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(stream_id: u32) -> WsShim {
        WsShim::open(
            stream_id,
            b"/chat".to_vec(),
            vec![Header::new(
                b"sec-websocket-protocol".to_vec(),
                b"chat.v1".to_vec(),
            )],
        )
    }

    #[test]
    fn open_emits_upgrade_and_stays_connecting() {
        let shim = fresh(1);
        let out = shim.take_outgoing();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Frame::WsUpgrade { .. }));
        assert_eq!(shim.ready_state(), ReadyState::Connecting);
    }

    #[test]
    fn accept_transitions_to_open() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        let consumed = shim.handle_frame(Frame::WsAccept {
            stream_id: 1,
            headers: vec![Header::new(
                b"sec-websocket-protocol".to_vec(),
                b"chat.v1".to_vec(),
            )],
        });
        assert!(consumed);
        assert_eq!(shim.ready_state(), ReadyState::Open);
        let events = shim.take_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], WsEvent::Open { .. }));
    }

    #[test]
    fn send_after_open_emits_wsmsg() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        shim.handle_frame(Frame::WsAccept {
            stream_id: 1,
            headers: Vec::new(),
        });
        shim.take_events();

        shim.send_text(b"hello".to_vec());
        let out = shim.take_outgoing();
        assert_eq!(out.len(), 1);
        match &out[0] {
            Frame::WsMsg {
                opcode, payload, ..
            } => {
                assert!(matches!(opcode, WireOpcode::Text));
                assert_eq!(payload, b"hello");
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }

    #[test]
    fn inbound_message_is_delivered_as_event() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        shim.handle_frame(Frame::WsAccept {
            stream_id: 1,
            headers: Vec::new(),
        });
        shim.take_events();

        shim.handle_frame(Frame::WsMsg {
            stream_id: 1,
            opcode: WireOpcode::Binary,
            payload: vec![1, 2, 3],
        });
        let events = shim.take_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            WsEvent::Message { binary, data } => {
                assert!(*binary);
                assert_eq!(data, &[1, 2, 3]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn close_flow_sends_wsclose_and_settles_on_inbound_close() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        shim.handle_frame(Frame::WsAccept {
            stream_id: 1,
            headers: Vec::new(),
        });
        shim.take_events();

        shim.close(1000, b"goodbye".to_vec());
        let out = shim.take_outgoing();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Frame::WsClose { code: 1000, .. }));
        assert_eq!(shim.ready_state(), ReadyState::Closing);

        shim.handle_frame(Frame::WsClose {
            stream_id: 1,
            code: 1000,
            reason: b"goodbye".to_vec(),
        });
        assert_eq!(shim.ready_state(), ReadyState::Closed);
        let events = shim.take_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], WsEvent::Close { code: 1000, .. }));
    }

    #[test]
    fn err_frame_transitions_to_closed_with_error_event() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        shim.handle_frame(Frame::WsAccept {
            stream_id: 1,
            headers: Vec::new(),
        });
        shim.take_events();

        shim.handle_frame(Frame::Err {
            stream_id: 1,
            code: 0x0001,
            message: b"bad frame".to_vec(),
        });
        assert_eq!(shim.ready_state(), ReadyState::Closed);
        let events = shim.take_events();
        assert!(matches!(&events[0], WsEvent::Error { .. }));
    }

    #[test]
    fn end_without_close_yields_abnormal_1006() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        shim.handle_frame(Frame::WsAccept {
            stream_id: 1,
            headers: Vec::new(),
        });
        shim.take_events();

        shim.handle_frame(Frame::End { stream_id: 1 });
        assert_eq!(shim.ready_state(), ReadyState::Closed);
        let events = shim.take_events();
        match &events[0] {
            WsEvent::Close { code, .. } => assert_eq!(*code, 1006),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn frame_for_other_stream_is_not_consumed() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        let consumed = shim.handle_frame(Frame::WsAccept {
            stream_id: 99,
            headers: Vec::new(),
        });
        assert!(!consumed);
        assert_eq!(shim.ready_state(), ReadyState::Connecting);
    }

    #[test]
    fn send_before_open_fails_the_shim() {
        let shim = fresh(1);
        let _ = shim.take_outgoing();
        shim.send_text(b"too early".to_vec());
        assert_eq!(shim.ready_state(), ReadyState::Closed);
        let events = shim.take_events();
        assert!(matches!(&events[0], WsEvent::Error { .. }));
    }
}
