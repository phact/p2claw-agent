//! p2claw identity: Ed25519 keys, `PeerId`, z-base-32 encoding,
//! registration and DTLS-fingerprint signature helpers.

#![deny(rust_2018_idioms)]

pub mod alias_label;
mod error;
mod keypair;
mod peer_id;
mod proofs;
mod zbase32;

pub use alias_label::{
    is_reserved_alias, is_valid_alias_label, is_valid_haiku_label, is_valid_vanity_label,
    ALIAS_LABEL_MAX_LEN, HAIKU_NUM_MIN_DIGITS, RESERVED_TOKENS,
};
pub use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
pub use error::IdentityError;
pub use keypair::{SecretKey, SigningKey, VerifyingKey};
pub use peer_id::{PeerId, ALIAS_BASE_LEN, ALIAS_MAX_LEN, PEER_ID_Z32_LEN};
pub use proofs::{
    build_alias_binding_payload, build_alias_upgrade_payload, build_box_request_payload,
    build_dtls_fp_payload, build_registration_payload, sign_alias_binding, sign_alias_upgrade,
    sign_box_request, sign_dtls_fp, sign_registration, verify_alias_binding, verify_alias_upgrade,
    verify_box_request, verify_dtls_fp, verify_registration, ALIAS_BINDING_DOMAIN_SEP,
    ALIAS_UPGRADE_DOMAIN_SEP, ALIAS_UPGRADE_MAX_SKEW_SECS, BOX_REQUEST_DOMAIN_SEP,
    BOX_REQUEST_MAX_SKEW_SECS, BOX_REQUEST_PEER_HEADER, BOX_REQUEST_SIGNATURE_HEADER,
    BOX_REQUEST_TIMESTAMP_HEADER, DTLS_FP_DOMAIN_SEP, REGISTRATION_DOMAIN_SEP,
    REGISTRATION_MAX_SKEW_SECS,
};
pub use zbase32::{decode as zbase32_decode, encode as zbase32_encode, Z32_ALPHABET};
