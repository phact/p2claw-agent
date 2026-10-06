//! Wire-frame codec adapters.
//!
//! `p2claw_wire` is the single source of truth for the on-wire byte
//! layout. Its public types use [`bytes::Bytes`] for zero-copy body
//! handles and several newtype wrappers (`StreamId`, `ReqFlags`,
//! `WsOpcode`) that have no obvious FFI peer. This module mirrors the
//! `Frame` enum with primitive fields so the public surface maps
//! directly to Kotlin / Swift via UniFFI — no custom-type adapters,
//! no per-field conversion glue on the consumer side.
//!
//! Conversion between [`Frame`] and [`p2claw_wire::Frame`] happens at
//! the codec boundary. The only flag bit the wire actually emits is
//! `FLAG_END_STREAM`, surfaced here as `end_stream: bool`.

use bytes::{Bytes, BytesMut};

/// One header pair on a request, response, or trailer block.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Header {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// WebSocket payload opcode. Wire-byte values match RFC 6455 verbatim
/// (the same encoding `p2claw_wire::WsOpcode` uses).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WireOpcode {
    Text = 0x1,
    Binary = 0x2,
    Ping = 0x9,
    Pong = 0xA,
}

impl WireOpcode {
    fn from_wire(opcode: p2claw_wire::WsOpcode) -> Self {
        match opcode {
            p2claw_wire::WsOpcode::Text => Self::Text,
            p2claw_wire::WsOpcode::Binary => Self::Binary,
            p2claw_wire::WsOpcode::Ping => Self::Ping,
            p2claw_wire::WsOpcode::Pong => Self::Pong,
        }
    }

    fn to_wire(self) -> p2claw_wire::WsOpcode {
        match self {
            Self::Text => p2claw_wire::WsOpcode::Text,
            Self::Binary => p2claw_wire::WsOpcode::Binary,
            Self::Ping => p2claw_wire::WsOpcode::Ping,
            Self::Pong => p2claw_wire::WsOpcode::Pong,
        }
    }
}

/// Decoded wire frame. Field types are primitives plus [`Header`] /
/// [`WireOpcode`] so the enum maps cleanly to a UniFFI sealed-class
/// hierarchy on Kotlin / discriminated union on Swift.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Frame {
    Req {
        stream_id: u32,
        end_stream: bool,
        method: Vec<u8>,
        path: Vec<u8>,
        headers: Vec<Header>,
    },
    Res {
        stream_id: u32,
        end_stream: bool,
        status: u16,
        headers: Vec<Header>,
    },
    Data {
        stream_id: u32,
        end_stream: bool,
        body: Vec<u8>,
    },
    End {
        stream_id: u32,
    },
    Err {
        stream_id: u32,
        code: u16,
        message: Vec<u8>,
    },
    Trailers {
        stream_id: u32,
        headers: Vec<Header>,
    },
    WsUpgrade {
        stream_id: u32,
        path: Vec<u8>,
        headers: Vec<Header>,
    },
    WsAccept {
        stream_id: u32,
        headers: Vec<Header>,
    },
    WsMsg {
        stream_id: u32,
        opcode: WireOpcode,
        payload: Vec<u8>,
    },
    WsClose {
        stream_id: u32,
        code: u16,
        reason: Vec<u8>,
    },
    Ping {
        nonce: Vec<u8>,
    },
    Pong {
        nonce: Vec<u8>,
    },
    Probe {
        id: u32,
        payload: Vec<u8>,
    },
    ProbeAck {
        id: u32,
    },
    Goaway {
        last_accepted_stream_id: u32,
        code: u16,
        message: Vec<u8>,
    },
}

/// Codec failure surface. `Wire` wraps a [`p2claw_wire::WireError`] —
/// the underlying error already carries enough detail (frame type,
/// length expectations, payload offsets).
///
/// Field is `detail`, not `message`, because UniFFI's Kotlin codegen
/// emits Error enum variants as subclasses of `kotlin.Exception` and
/// a struct-variant field literally named `message` clashes with
/// `Throwable.message` without an `override` modifier the codegen
/// doesn't emit. Tuple variants escape this because they pass the
/// arg straight through to the superclass constructor.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum CodecError {
    #[error("wire: {detail}")]
    Wire { detail: String },
}

impl From<p2claw_wire::WireError> for CodecError {
    fn from(err: p2claw_wire::WireError) -> Self {
        Self::Wire {
            detail: err.to_string(),
        }
    }
}

/// Encode `frame` to its on-wire byte form.
#[uniffi::export]
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let wire = to_wire(frame);
    let mut out = BytesMut::new();
    p2claw_wire::encode(&wire, &mut out);
    out.to_vec()
}

/// Streaming frame decoder. Owns an internal buffer; callers feed
/// transport bytes via [`Decoder::push`] (typically as they arrive on
/// a DataChannel) and drain complete frames with
/// [`Decoder::next_frame`].
#[derive(Debug, Default, uniffi::Object)]
pub struct Decoder {
    inner: std::sync::Mutex<BytesMut>,
}

#[uniffi::export]
impl Decoder {
    /// Fresh decoder with an empty buffer.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append received transport bytes to the buffer.
    pub fn push(&self, bytes: Vec<u8>) {
        self.inner.lock().unwrap().extend_from_slice(&bytes);
    }

    /// Pop the next fully-buffered frame, or `None` if the buffer
    /// does not yet contain one complete frame.
    pub fn next_frame(&self) -> Result<Option<Frame>, CodecError> {
        let mut guard = self.inner.lock().unwrap();
        match p2claw_wire::decode(&mut guard)? {
            Some(wire) => Ok(Some(from_wire(wire))),
            None => Ok(None),
        }
    }

    /// Bytes currently buffered but not yet forming a complete frame.
    pub fn buffered(&self) -> u32 {
        self.inner.lock().unwrap().len() as u32
    }
}

/// Wire-byte discriminator for a [`Frame`]. Mirrors
/// [`p2claw_wire::FrameType`] verbatim so consumers can switch on a
/// stable repr-`u8` value without depending on the wire crate.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum FrameKind {
    Req = 0x01,
    Res = 0x02,
    Data = 0x03,
    End = 0x04,
    Err = 0x05,
    Trailers = 0x06,
    WsUpgrade = 0x10,
    WsAccept = 0x11,
    WsMsg = 0x12,
    WsClose = 0x13,
    Ping = 0x20,
    Pong = 0x21,
    Probe = 0x30,
    ProbeAck = 0x31,
    Goaway = 0x7F,
}

/// Classify a [`Frame`] by its on-wire byte.
#[uniffi::export]
pub fn frame_kind_of(frame: &Frame) -> FrameKind {
    match frame {
        Frame::Req { .. } => FrameKind::Req,
        Frame::Res { .. } => FrameKind::Res,
        Frame::Data { .. } => FrameKind::Data,
        Frame::End { .. } => FrameKind::End,
        Frame::Err { .. } => FrameKind::Err,
        Frame::Trailers { .. } => FrameKind::Trailers,
        Frame::WsUpgrade { .. } => FrameKind::WsUpgrade,
        Frame::WsAccept { .. } => FrameKind::WsAccept,
        Frame::WsMsg { .. } => FrameKind::WsMsg,
        Frame::WsClose { .. } => FrameKind::WsClose,
        Frame::Ping { .. } => FrameKind::Ping,
        Frame::Pong { .. } => FrameKind::Pong,
        Frame::Probe { .. } => FrameKind::Probe,
        Frame::ProbeAck { .. } => FrameKind::ProbeAck,
        Frame::Goaway { .. } => FrameKind::Goaway,
    }
}

fn headers_to_wire(headers: &[Header]) -> Vec<(Bytes, Bytes)> {
    headers
        .iter()
        .map(|h| {
            (
                Bytes::copy_from_slice(&h.name),
                Bytes::copy_from_slice(&h.value),
            )
        })
        .collect()
}

fn headers_from_wire(headers: Vec<(Bytes, Bytes)>) -> Vec<Header> {
    headers
        .into_iter()
        .map(|(name, value)| Header {
            name: name.to_vec(),
            value: value.to_vec(),
        })
        .collect()
}

fn req_flags(end_stream: bool) -> p2claw_wire::ReqFlags {
    p2claw_wire::ReqFlags(if end_stream {
        p2claw_wire::FLAG_END_STREAM
    } else {
        0
    })
}

fn res_flags(end_stream: bool) -> p2claw_wire::ResFlags {
    p2claw_wire::ResFlags(if end_stream {
        p2claw_wire::FLAG_END_STREAM
    } else {
        0
    })
}

fn data_flags(end_stream: bool) -> p2claw_wire::DataFlags {
    p2claw_wire::DataFlags(if end_stream {
        p2claw_wire::FLAG_END_STREAM
    } else {
        0
    })
}

fn nonce_array(nonce: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let n = nonce.len().min(8);
    out[..n].copy_from_slice(&nonce[..n]);
    out
}

fn to_wire(frame: &Frame) -> p2claw_wire::Frame {
    use p2claw_wire::Frame as W;
    match frame {
        Frame::Req {
            stream_id,
            end_stream,
            method,
            path,
            headers,
        } => W::Req {
            stream_id: p2claw_wire::StreamId(*stream_id),
            flags: req_flags(*end_stream),
            method: Bytes::copy_from_slice(method),
            path: Bytes::copy_from_slice(path),
            headers: headers_to_wire(headers),
        },
        Frame::Res {
            stream_id,
            end_stream,
            status,
            headers,
        } => W::Res {
            stream_id: p2claw_wire::StreamId(*stream_id),
            flags: res_flags(*end_stream),
            status: *status,
            headers: headers_to_wire(headers),
        },
        Frame::Data {
            stream_id,
            end_stream,
            body,
        } => W::Data {
            stream_id: p2claw_wire::StreamId(*stream_id),
            flags: data_flags(*end_stream),
            body: Bytes::copy_from_slice(body),
        },
        Frame::End { stream_id } => W::End {
            stream_id: p2claw_wire::StreamId(*stream_id),
        },
        Frame::Err {
            stream_id,
            code,
            message,
        } => W::Err {
            stream_id: p2claw_wire::StreamId(*stream_id),
            code: p2claw_wire::ErrorCode(*code),
            message: Bytes::copy_from_slice(message),
        },
        Frame::Trailers { stream_id, headers } => W::Trailers {
            stream_id: p2claw_wire::StreamId(*stream_id),
            headers: headers_to_wire(headers),
        },
        Frame::WsUpgrade {
            stream_id,
            path,
            headers,
        } => W::WsUpgrade {
            stream_id: p2claw_wire::StreamId(*stream_id),
            path: Bytes::copy_from_slice(path),
            headers: headers_to_wire(headers),
        },
        Frame::WsAccept { stream_id, headers } => W::WsAccept {
            stream_id: p2claw_wire::StreamId(*stream_id),
            headers: headers_to_wire(headers),
        },
        Frame::WsMsg {
            stream_id,
            opcode,
            payload,
        } => W::WsMsg {
            stream_id: p2claw_wire::StreamId(*stream_id),
            opcode: opcode.to_wire(),
            payload: Bytes::copy_from_slice(payload),
        },
        Frame::WsClose {
            stream_id,
            code,
            reason,
        } => W::WsClose {
            stream_id: p2claw_wire::StreamId(*stream_id),
            code: *code,
            reason: Bytes::copy_from_slice(reason),
        },
        Frame::Ping { nonce } => W::Ping {
            nonce: nonce_array(nonce),
        },
        Frame::Pong { nonce } => W::Pong {
            nonce: nonce_array(nonce),
        },
        Frame::Probe { id, payload } => W::Probe {
            id: *id,
            payload: Bytes::copy_from_slice(payload),
        },
        Frame::ProbeAck { id } => W::ProbeAck { id: *id },
        Frame::Goaway {
            last_accepted_stream_id,
            code,
            message,
        } => W::Goaway {
            last_accepted_stream_id: p2claw_wire::StreamId(*last_accepted_stream_id),
            code: p2claw_wire::ErrorCode(*code),
            message: Bytes::copy_from_slice(message),
        },
    }
}

fn from_wire(frame: p2claw_wire::Frame) -> Frame {
    use p2claw_wire::Frame as W;
    let end_stream = |bits: u8| bits & p2claw_wire::FLAG_END_STREAM == p2claw_wire::FLAG_END_STREAM;
    match frame {
        W::Req {
            stream_id,
            flags,
            method,
            path,
            headers,
        } => Frame::Req {
            stream_id: stream_id.0,
            end_stream: end_stream(flags.0),
            method: method.to_vec(),
            path: path.to_vec(),
            headers: headers_from_wire(headers),
        },
        W::Res {
            stream_id,
            flags,
            status,
            headers,
        } => Frame::Res {
            stream_id: stream_id.0,
            end_stream: end_stream(flags.0),
            status,
            headers: headers_from_wire(headers),
        },
        W::Data {
            stream_id,
            flags,
            body,
        } => Frame::Data {
            stream_id: stream_id.0,
            end_stream: end_stream(flags.0),
            body: body.to_vec(),
        },
        W::End { stream_id } => Frame::End {
            stream_id: stream_id.0,
        },
        W::Err {
            stream_id,
            code,
            message,
        } => Frame::Err {
            stream_id: stream_id.0,
            code: code.0,
            message: message.to_vec(),
        },
        W::Trailers { stream_id, headers } => Frame::Trailers {
            stream_id: stream_id.0,
            headers: headers_from_wire(headers),
        },
        W::WsUpgrade {
            stream_id,
            path,
            headers,
        } => Frame::WsUpgrade {
            stream_id: stream_id.0,
            path: path.to_vec(),
            headers: headers_from_wire(headers),
        },
        W::WsAccept { stream_id, headers } => Frame::WsAccept {
            stream_id: stream_id.0,
            headers: headers_from_wire(headers),
        },
        W::WsMsg {
            stream_id,
            opcode,
            payload,
        } => Frame::WsMsg {
            stream_id: stream_id.0,
            opcode: WireOpcode::from_wire(opcode),
            payload: payload.to_vec(),
        },
        W::WsClose {
            stream_id,
            code,
            reason,
        } => Frame::WsClose {
            stream_id: stream_id.0,
            code,
            reason: reason.to_vec(),
        },
        W::Ping { nonce } => Frame::Ping {
            nonce: nonce.to_vec(),
        },
        W::Pong { nonce } => Frame::Pong {
            nonce: nonce.to_vec(),
        },
        W::Probe { id, payload } => Frame::Probe {
            id,
            payload: payload.to_vec(),
        },
        W::ProbeAck { id } => Frame::ProbeAck { id },
        W::Goaway {
            last_accepted_stream_id,
            code,
            message,
        } => Frame::Goaway {
            last_accepted_stream_id: last_accepted_stream_id.0,
            code: code.0,
            message: message.to_vec(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let bytes = encode_frame(&frame);
        let decoder = Decoder::new();
        decoder.push(bytes);
        let decoded = decoder
            .next_frame()
            .expect("decode succeeds")
            .expect("frame is complete");
        assert_eq!(frame, decoded);
        assert_eq!(decoder.buffered(), 0, "decoder fully drained");
    }

    #[test]
    fn req_roundtrip() {
        roundtrip(Frame::Req {
            stream_id: 7,
            end_stream: true,
            method: b"GET".to_vec(),
            path: b"/api/v1/items".to_vec(),
            headers: vec![Header::new(b"host".to_vec(), b"example.test".to_vec())],
        });
    }

    #[test]
    fn data_roundtrip() {
        roundtrip(Frame::Data {
            stream_id: 42,
            end_stream: true,
            body: b"hello world".to_vec(),
        });
    }

    #[test]
    fn end_roundtrip() {
        roundtrip(Frame::End { stream_id: 11 });
    }

    #[test]
    fn ws_msg_text_roundtrip() {
        roundtrip(Frame::WsMsg {
            stream_id: 3,
            opcode: WireOpcode::Text,
            payload: b"hi".to_vec(),
        });
    }

    #[test]
    fn ws_close_roundtrip() {
        roundtrip(Frame::WsClose {
            stream_id: 3,
            code: 1000,
            reason: b"bye".to_vec(),
        });
    }

    #[test]
    fn ping_pong_roundtrip() {
        roundtrip(Frame::Ping {
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
        });
        roundtrip(Frame::Pong {
            nonce: vec![9, 8, 7, 6, 5, 4, 3, 2],
        });
    }

    #[test]
    fn decoder_handles_split_pushes() {
        let frame = Frame::Data {
            stream_id: 1,
            end_stream: false,
            body: b"chunked transport".to_vec(),
        };
        let bytes = encode_frame(&frame);
        let decoder = Decoder::new();
        decoder.push(bytes[..3].to_vec());
        assert!(decoder.next_frame().expect("ok").is_none());
        decoder.push(bytes[3..].to_vec());
        let decoded = decoder
            .next_frame()
            .expect("ok")
            .expect("complete after second push");
        assert_eq!(frame, decoded);
    }

    #[test]
    fn decoder_yields_multiple_frames_from_one_push() {
        let a = Frame::End { stream_id: 1 };
        let b = Frame::End { stream_id: 2 };
        let mut buf = encode_frame(&a);
        buf.extend(encode_frame(&b));
        let decoder = Decoder::new();
        decoder.push(buf);
        assert_eq!(decoder.next_frame().unwrap().unwrap(), a);
        assert_eq!(decoder.next_frame().unwrap().unwrap(), b);
        assert!(decoder.next_frame().unwrap().is_none());
    }

    #[test]
    fn frame_kind_classification() {
        assert_eq!(frame_kind_of(&Frame::End { stream_id: 1 }), FrameKind::End);
        assert_eq!(FrameKind::End as u8, 0x04);
        assert_eq!(FrameKind::WsMsg as u8, 0x12);
    }
}
