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

    /// Coordination's answer for the target isn't signed by the
    /// trusted root key, so the peer it names can't be trusted.
    #[error("coordination: untrusted answer: {0}")]
    UntrustedResolution(String),

    /// No coordination root key to check answers against: the
    /// coordination service isn't the default and
    /// `ClientOptions::coord_root` is unset.
    #[error("no coordination root key configured for {0}")]
    NoCoordRoot(String),

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
