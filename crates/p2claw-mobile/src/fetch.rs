//! Sans-I/O plain-HTTP fetch shim driven over the peer wire protocol.
//!
//! Analogous to [`crate::ws::WsShim`] but for the request/response
//! cycle the box's forwarder exposes (`Frame::Req` outbound, then
//! `Frame::Res` + zero or more `Frame::Data` + optional
//! `Frame::Trailers` + `Frame::End` inbound).
//!
//! The state machine is one-shot from the caller's side: a request
//! is constructed with its full body up front. The response side
//! streams — callers receive headers, then a series of body chunks,
//! then a terminal event. This matches the typical mobile-app
//! pattern of "I send a request and read the response" without
//! requiring the FFI surface to model bidirectional streaming.

use std::sync::Mutex;

use crate::codec::{frame_kind_of, Frame, Header};

/// Sequence of states a fetch progresses through. Exposed so callers
/// can assert progress in tests; not normally observed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FetchState {
    /// Request sent; awaiting [`Frame::Res`].
    AwaitingResponse,
    /// `Res` arrived; receiving zero or more body chunks until `End`.
    Receiving,
    /// Stream completed cleanly (`End` received).
    Done,
    /// Stream failed (`Err` from box or transport/state-machine error).
    Failed,
}

/// Event delivered to the application as the response unfolds.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FetchEvent {
    /// Response headers — fires exactly once per fetch on success.
    Head { status: u16, headers: Vec<Header> },
    /// One body chunk. Multiple chunks are typical for streaming
    /// responses; a single fetch may emit `Chunk` zero times for
    /// empty bodies and many times for streamed ones.
    Chunk { data: Vec<u8> },
    /// Optional trailer headers received after the body.
    Trailers { headers: Vec<Header> },
    /// Stream completed cleanly.
    End,
    /// Stream failed — `code` follows the wire's `ErrorCode`
    /// inventory, `message` is the optional human-readable detail.
    Error { code: u16, message: Vec<u8> },
}

/// Wire-level protocol-error code surfaced when the box sends frames
/// out of the expected order. Matches `p2claw_wire::ErrorCode::PROTOCOL_ERROR`.
const PROTOCOL_ERROR_CODE: u16 = 0x0001;

#[derive(Debug)]
struct FetchInner {
    state: FetchState,
    outbox: Vec<Frame>,
    events: Vec<FetchEvent>,
}

/// Sans-I/O state for one HTTP-shape fetch.
#[derive(Debug, uniffi::Object)]
pub struct FetchShim {
    stream_id: u32,
    inner: Mutex<FetchInner>,
}

#[uniffi::export]
impl FetchShim {
    /// Start a fetch. Emits the `Req` frame plus, if `body` is
    /// non-empty, a `Data` frame carrying the body with the
    /// END_STREAM flag set. The fetch is fully request-side complete
    /// once construction returns — no further app calls drive the
    /// request side.
    #[uniffi::constructor]
    pub fn request(
        stream_id: u32,
        method: Vec<u8>,
        path: Vec<u8>,
        headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Self {
        let body_empty = body.is_empty();
        // END_STREAM on Req signals "no body following" — the box
        // forwarder skips waiting on DATA. For non-empty bodies we
        // clear the flag and emit a Data frame with END_STREAM
        // instead.
        let mut outbox = vec![Frame::Req {
            stream_id,
            end_stream: body_empty,
            method,
            path,
            headers,
        }];
        if !body_empty {
            outbox.push(Frame::Data {
                stream_id,
                end_stream: true,
                body,
            });
        }
        Self {
            stream_id,
            inner: Mutex::new(FetchInner {
                state: FetchState::AwaitingResponse,
                outbox,
                events: Vec::new(),
            }),
        }
    }

    /// Stream id this fetch occupies on the multiplexed transport.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Current state.
    pub fn state(&self) -> FetchState {
        self.inner.lock().unwrap().state
    }

    /// Feed an inbound wire frame received on the transport. Returns
    /// `true` when the frame belonged to this fetch, `false` when the
    /// stream_id didn't match.
    pub fn handle_frame(&self, frame: Frame) -> bool {
        if frame_stream(&frame) != Some(self.stream_id) {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        match (inner.state, frame) {
            (
                FetchState::AwaitingResponse,
                Frame::Res {
                    status, headers, ..
                },
            ) => {
                inner.state = FetchState::Receiving;
                inner.events.push(FetchEvent::Head { status, headers });
            }
            (FetchState::Receiving, Frame::Data { body, .. }) => {
                if !body.is_empty() {
                    inner.events.push(FetchEvent::Chunk { data: body });
                }
            }
            (FetchState::Receiving, Frame::Trailers { headers, .. }) => {
                inner.events.push(FetchEvent::Trailers { headers });
            }
            (FetchState::Receiving, Frame::End { .. }) => {
                inner.state = FetchState::Done;
                inner.events.push(FetchEvent::End);
            }
            (_, Frame::Err { code, message, .. }) => {
                inner.state = FetchState::Failed;
                inner.events.push(FetchEvent::Error { code, message });
            }
            (state, frame) => {
                let kind = frame_kind_of(&frame);
                if !matches!(inner.state, FetchState::Failed | FetchState::Done) {
                    inner.state = FetchState::Failed;
                    inner.events.push(FetchEvent::Error {
                        code: PROTOCOL_ERROR_CODE,
                        message: format!("unexpected {kind:?} in state {state:?}").into_bytes(),
                    });
                }
            }
        }
        true
    }

    /// Drain pending outbound frames.
    pub fn take_outgoing(&self) -> Vec<Frame> {
        std::mem::take(&mut self.inner.lock().unwrap().outbox)
    }

    /// Drain pending application events.
    pub fn take_events(&self) -> Vec<FetchEvent> {
        std::mem::take(&mut self.inner.lock().unwrap().events)
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

    fn get(stream_id: u32, path: &str) -> FetchShim {
        FetchShim::request(
            stream_id,
            b"GET".to_vec(),
            path.as_bytes().to_vec(),
            vec![Header::new(b"accept", b"application/json")],
            Vec::new(),
        )
    }

    #[test]
    fn empty_body_request_emits_req_with_end_stream() {
        let shim = get(1, "/api/items");
        let out = shim.take_outgoing();
        assert_eq!(out.len(), 1, "no DATA frame for empty body");
        match &out[0] {
            Frame::Req {
                end_stream, method, ..
            } => {
                assert_eq!(method, b"GET");
                assert!(*end_stream);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn non_empty_body_emits_req_then_data_end_stream() {
        let shim = FetchShim::request(
            2,
            b"POST".to_vec(),
            b"/api/items".to_vec(),
            Vec::new(),
            b"{\"name\":\"alpha\"}".to_vec(),
        );
        let out = shim.take_outgoing();
        assert_eq!(out.len(), 2);
        match &out[0] {
            Frame::Req { end_stream, .. } => assert!(!*end_stream),
            other => panic!("unexpected {other:?}"),
        }
        match &out[1] {
            Frame::Data {
                end_stream, body, ..
            } => {
                assert!(*end_stream);
                assert_eq!(body, b"{\"name\":\"alpha\"}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn res_then_data_then_end_yields_full_response() {
        let shim = get(1, "/api/items");
        shim.take_outgoing();

        assert!(shim.handle_frame(Frame::Res {
            stream_id: 1,
            end_stream: false,
            status: 200,
            headers: vec![Header::new(b"content-type", b"text/plain")],
        }));
        assert!(shim.handle_frame(Frame::Data {
            stream_id: 1,
            end_stream: false,
            body: b"chunk-a".to_vec(),
        }));
        assert!(shim.handle_frame(Frame::Data {
            stream_id: 1,
            end_stream: false,
            body: b"chunk-b".to_vec(),
        }));
        assert!(shim.handle_frame(Frame::End { stream_id: 1 }));

        assert_eq!(shim.state(), FetchState::Done);
        let events = shim.take_events();
        assert_eq!(events.len(), 4);
        assert!(matches!(&events[0], FetchEvent::Head { status: 200, .. }));
        assert!(matches!(&events[1], FetchEvent::Chunk { data } if data == b"chunk-a"));
        assert!(matches!(&events[2], FetchEvent::Chunk { data } if data == b"chunk-b"));
        assert!(matches!(&events[3], FetchEvent::End));
    }

    #[test]
    fn trailers_arrive_after_body() {
        let shim = get(1, "/grpc/route");
        shim.take_outgoing();
        shim.handle_frame(Frame::Res {
            stream_id: 1,
            end_stream: false,
            status: 200,
            headers: Vec::new(),
        });
        shim.handle_frame(Frame::Trailers {
            stream_id: 1,
            headers: vec![Header::new(b"grpc-status", b"0")],
        });
        shim.handle_frame(Frame::End { stream_id: 1 });

        let events = shim.take_events();
        assert!(
            matches!(&events[1], FetchEvent::Trailers { headers } if headers[0].name == b"grpc-status")
        );
        assert_eq!(shim.state(), FetchState::Done);
    }

    #[test]
    fn empty_data_chunks_are_dropped() {
        let shim = get(1, "/keep-alive");
        shim.take_outgoing();
        shim.handle_frame(Frame::Res {
            stream_id: 1,
            end_stream: false,
            status: 200,
            headers: Vec::new(),
        });
        shim.handle_frame(Frame::Data {
            stream_id: 1,
            end_stream: false,
            body: Vec::new(),
        });
        shim.handle_frame(Frame::End { stream_id: 1 });
        let events = shim.take_events();
        // Head + End only — empty Chunk filtered out.
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn err_frame_settles_to_failed() {
        let shim = get(1, "/fail");
        shim.take_outgoing();
        // 0x0002 = INTERNAL_ERROR per the wire's ErrorCode inventory.
        shim.handle_frame(Frame::Err {
            stream_id: 1,
            code: 0x0002,
            message: b"upstream down".to_vec(),
        });
        assert_eq!(shim.state(), FetchState::Failed);
        let events = shim.take_events();
        assert!(matches!(&events[0], FetchEvent::Error { code, .. } if *code == 0x0002));
    }

    #[test]
    fn unexpected_frame_order_fails_stream() {
        let shim = get(1, "/strict");
        shim.take_outgoing();
        // Data before Res is illegal — must trigger protocol error.
        shim.handle_frame(Frame::Data {
            stream_id: 1,
            end_stream: false,
            body: b"out of order".to_vec(),
        });
        assert_eq!(shim.state(), FetchState::Failed);
        let events = shim.take_events();
        assert!(
            matches!(&events[0], FetchEvent::Error { code, .. } if *code == PROTOCOL_ERROR_CODE)
        );
    }

    #[test]
    fn frame_for_other_stream_is_not_consumed() {
        let shim = get(1, "/iso");
        shim.take_outgoing();
        let consumed = shim.handle_frame(Frame::Res {
            stream_id: 99,
            end_stream: false,
            status: 200,
            headers: Vec::new(),
        });
        assert!(!consumed);
        assert_eq!(shim.state(), FetchState::AwaitingResponse);
    }
}
