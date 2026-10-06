use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("frame length {0} exceeds maximum {1}")]
    FrameTooLarge(u32, u32),

    #[error("frame length {0} below minimum of 2 (must include type+flags)")]
    FrameTooShort(u32),

    #[error("unknown frame type 0x{0:02x}")]
    UnknownFrameType(u8),

    #[error("truncated frame payload: expected {expected} bytes, got {got}")]
    TruncatedPayload { expected: usize, got: usize },

    #[error("invalid UTF-8 in length-prefixed string")]
    InvalidUtf8,

    #[error("header block exceeds maximum size")]
    HeaderBlockTooLarge,

    #[error("invalid status code {0}")]
    InvalidStatus(u16),

    #[error("unknown WebSocket opcode 0x{0:02x}")]
    UnknownWsOpcode(u8),
}
