use thiserror::Error;

#[derive(Debug, Error)]
pub enum TranslatorError {
    #[error("wire: {0}")]
    Wire(#[from] p2claw_wire::WireError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("unexpected frame for this stream state")]
    ProtocolViolation,

    #[error("stream cancelled: code={0:?}")]
    Cancelled(p2claw_wire::ErrorCode),

    /// Peer sent GOAWAY and refuses to accept new streams. The
    /// connection is still serving any streams the peer already
    /// accepted; only newly-issued requests beyond
    /// `last_accepted_stream_id` see this error.
    #[error("peer is going away (code={code:?}): {message}")]
    GoingAway {
        code: p2claw_wire::ErrorCode,
        message: String,
    },
}
