use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity key file is not 32 bytes (got {0})")]
    KeyFileWrongSize(usize),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("z-base-32 input length {got} does not match expected {expected}")]
    Z32WrongLength { got: usize, expected: usize },

    #[error("invalid z-base-32 character: 0x{0:02x}")]
    Z32InvalidChar(u8),

    #[error("z-base-32 padding bits must be zero")]
    Z32NonZeroPadding,

    #[error("signature verification failed")]
    BadSignature,

    #[error("timestamp out of skew window: |now - ts| = {skew}s, max {max}s")]
    ClockSkew { skew: u64, max: u64 },

    #[error("coordination domain too long (>65535 bytes)")]
    CoordDomainTooLong,

    #[error("session_id too long (>65535 bytes)")]
    SessionIdTooLong,

    #[error("signed field too long (>65535 bytes)")]
    FieldTooLong,

    #[error("alias too long (>65535 bytes)")]
    AliasTooLong,
}
