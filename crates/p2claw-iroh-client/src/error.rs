//! Error types for the native client.

use thiserror::Error;

use crate::url::UrlParseError;

/// Top-level error returned by the [`crate::PeerClient`] API.
#[derive(Debug, Error)]
pub enum PeerClientError {
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] UrlParseError),

    /// Coordination service returned an error, or the HTTP call
    /// failed before we got a response.
    #[error("coordination: {0}")]
    Coord(String),

    #[error("coordination: no such peer")]
    NoSuchPeer,

    #[error("coordination: peer revoked")]
    PeerRevoked,

    #[error("coordination: box offline")]
    BoxOffline,

    #[error("coordination: rate limited; retry after {0}s")]
    RateLimited(u64),

    #[error("iroh: {0}")]
    Iroh(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("translator: {0}")]
    Translator(#[from] p2claw_translator::TranslatorError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("timed out after {secs}s")]
    Timeout { secs: u64 },
}
