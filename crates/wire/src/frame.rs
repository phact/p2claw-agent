use bytes::Bytes;

/// A stream identifier. Allocated by the initiating peer (visitor);
/// the box never originates streams. ID 0 is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

/// Flag bit: final frame in this direction for the stream.
pub const FLAG_END_STREAM: u8 = 0x01;

/// Maximum total payload length (including type + flags) the decoder
/// will accept. Receivers must accept frames up to 16 MiB.
pub const MAX_FRAME_BODY: u32 = 16 * 1024 * 1024;

/// Frame-type discriminants as they appear on the wire.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Req = 0x01,
    Res = 0x02,
    Data = 0x03,
    End = 0x04,
    Err = 0x05,
    /// Trailing HTTP headers carrying end-of-stream. Used for
    /// gRPC `grpc-status` / `grpc-message` and any HTTP trailer
    /// extension. TRAILERS implicitly closes the stream — peers MUST
    /// NOT send a subsequent END or DATA(END_STREAM) for the same
    /// stream after sending TRAILERS.
    Trailers = 0x06,
    WsUpgrade = 0x10,
    WsAccept = 0x11,
    WsMsg = 0x12,
    WsClose = 0x13,
    Ping = 0x20,
    Pong = 0x21,
    /// Path-capacity probe: a single large frame the box (server)
    /// sends on DC open to test whether the underlying transport
    /// tolerates multi-chunk SCTP user messages. The receiver
    /// replies with `ProbeAck`. Used to swap a session's outbound
    /// DATA cap from a conservative tunneled-path default up to the
    /// full server default once the path is shown to work — see
    /// `crates/agent/src/signal_handler.rs` for the WebRTC
    /// integration.
    Probe = 0x30,
    /// Reply to a `Probe` — payload-less acknowledgement.
    ProbeAck = 0x31,
    Goaway = 0x7F,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::Req,
            0x02 => Self::Res,
            0x03 => Self::Data,
            0x04 => Self::End,
            0x05 => Self::Err,
            0x06 => Self::Trailers,
            0x10 => Self::WsUpgrade,
            0x11 => Self::WsAccept,
            0x12 => Self::WsMsg,
            0x13 => Self::WsClose,
            0x20 => Self::Ping,
            0x21 => Self::Pong,
            0x30 => Self::Probe,
            0x31 => Self::ProbeAck,
            0x7F => Self::Goaway,
            _ => return None,
        })
    }
}

/// REQ / RES / DATA frame flags. A single bit today (`END_STREAM`);
/// additional flags in future versions will land here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReqFlags(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResFlags(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataFlags(pub u8);

macro_rules! flag_impl {
    ($ty:ident) => {
        impl $ty {
            pub const NONE: Self = Self(0);
            pub const END_STREAM: Self = Self(FLAG_END_STREAM);

            pub fn end_stream(self) -> bool {
                self.0 & FLAG_END_STREAM != 0
            }

            pub fn bits(self) -> u8 {
                self.0
            }
        }
    };
}
flag_impl!(ReqFlags);
flag_impl!(ResFlags);
flag_impl!(DataFlags);

/// A single HTTP-style header. Names are lowercase ASCII on the wire.
pub type Header = (Bytes, Bytes);

/// Ordered collection of headers. Duplicates (e.g. multiple
/// `set-cookie`) are preserved in insertion order.
pub type Headers = Vec<Header>;

/// WebSocket opcode carried in `WS_MSG` frames. Numeric values match
/// RFC 6455.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    Text = 0x1,
    Binary = 0x2,
    Ping = 0x9,
    Pong = 0xA,
}

impl WsOpcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => return None,
        })
    }
}

/// Protocol-level error code carried in ERR and GOAWAY.
///
/// Codes 0x0000–0x00FF are reserved; 0x0100+ available for
/// translator-specific use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode(pub u16);

impl ErrorCode {
    pub const NO_ERROR: Self = Self(0x0000);
    pub const PROTOCOL_ERROR: Self = Self(0x0001);
    pub const INTERNAL_ERROR: Self = Self(0x0002);
    pub const FRAME_TOO_LARGE: Self = Self(0x0003);
    pub const STREAM_REFUSED: Self = Self(0x0004);
    pub const CANCEL: Self = Self(0x0005);
    pub const LOCAL_APP_DOWN: Self = Self(0x0006);
    pub const LOCAL_APP_TIMEOUT: Self = Self(0x0007);
    pub const TRANSPORT_CLOSED: Self = Self(0x0008);
    pub const UNSUPPORTED: Self = Self(0x0009);
}

/// A fully-decoded frame. Zero-copy where the layout allows: body
/// bytes, header values, and free-form strings live in [`Bytes`]
/// rather than owned `Vec`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Req {
        stream_id: StreamId,
        flags: ReqFlags,
        method: Bytes,
        path: Bytes,
        headers: Headers,
    },
    Res {
        stream_id: StreamId,
        flags: ResFlags,
        status: u16,
        headers: Headers,
    },
    Data {
        stream_id: StreamId,
        flags: DataFlags,
        body: Bytes,
    },
    End {
        stream_id: StreamId,
    },
    Err {
        stream_id: StreamId,
        code: ErrorCode,
        message: Bytes,
    },
    /// Trailing headers + end-of-stream marker. Mutually exclusive
    /// with a final `Data { flags: END_STREAM }` and with a bare
    /// `End` for the same stream. Producers send DATA frames without
    /// END_STREAM, then a TRAILERS frame; receivers MUST treat
    /// TRAILERS as both end-of-body and end-of-stream.
    ///
    /// Use cases: gRPC trailers (`grpc-status`, `grpc-message`),
    /// HTTP/1.1 chunked-trailer extensions, any protocol that
    /// surfaces metadata after the body has streamed.
    Trailers {
        stream_id: StreamId,
        headers: Headers,
    },
    WsUpgrade {
        stream_id: StreamId,
        path: Bytes,
        headers: Headers,
    },
    WsAccept {
        stream_id: StreamId,
        headers: Headers,
    },
    WsMsg {
        stream_id: StreamId,
        opcode: WsOpcode,
        payload: Bytes,
    },
    WsClose {
        stream_id: StreamId,
        code: u16,
        reason: Bytes,
    },
    Ping {
        nonce: [u8; 8],
    },
    Pong {
        nonce: [u8; 8],
    },
    /// Path-capacity probe. `payload` is opaque to the
    /// receiver — the box picks a size meant to trigger multi-chunk
    /// SCTP fragmentation on tight tunneled paths (currently ~8 KiB).
    /// On receipt, the wrapper sends back a `ProbeAck` with a
    /// matching `id`; the box uses that round-trip as the signal to
    /// upgrade its per-session DATA cap from the conservative
    /// default. The `id` lets the sender ignore stragglers from a
    /// previous probe in the (rare) case that more than one round
    /// is in flight on the same session.
    Probe {
        id: u32,
        payload: Bytes,
    },
    /// Acknowledgement of a `Probe`. Echoes the probe's `id`; no
    /// payload — the round-trip is the signal.
    ProbeAck {
        id: u32,
    },
    Goaway {
        last_accepted_stream_id: StreamId,
        code: ErrorCode,
        message: Bytes,
    },
}
