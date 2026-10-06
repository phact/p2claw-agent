//! p2claw mobile-SDK protocol core.
//!
//! Sans-I/O. The crate carries the wire codec, a signaling client
//! against `coord.p2claw.com/v1/connect` + `/v1/signal/*`, and two
//! state machines: a WebSocket-shape shim and a plain-HTTP-fetch
//! shim. Both drive the peer wire protocol over an opaque byte
//! transport — typically a WebRTC data channel on the caller's side.
//!
//! Three deliberate non-goals:
//!
//! - **No WebRTC.** The caller owns the DataChannel; this crate only
//!   reads/writes its bytes.
//! - **No transport in-crate.** HTTPS and the signaling WS are
//!   platform-implemented via [`SignalingTransport`] + [`WsTransport`]
//!   trait callbacks. UniFFI binds them as foreign-implemented
//!   interfaces; the Rust core never touches sockets.
//! - **No platform glue.** Kotlin/Swift wrappers around UniFFI's
//!   generated bindings live in `mobile/android/sdk/` and
//!   `mobile/ios/sdk/`.
//!
//! UniFFI 0.31 codegen traps to keep in mind when adding public types
//! or trait methods to this surface:
//!
//! - A `uniffi::Error` struct variant must not have a field named
//!   `message` (or `cause`): the Kotlin exception subclass shadows
//!   `Throwable.message` and fails to compile. See [`CodecError`].
//! - Don't use `#[uniffi(flat_error)]` on an error whose variants carry
//!   payloads: a foreign-side throw panics at "Can't lift flat errors".
//!   See [`SignalingError`].
//! - A `with_foreign` async trait can't return another foreign trait
//!   object; return an id and look it up on a second trait instead.
//!   See [`SignalingTransport::open_ws`].

#![deny(rust_2018_idioms)]

uniffi::setup_scaffolding!();

pub mod codec;
pub mod device;
pub mod fetch;
pub mod signaling;
pub mod ws;

pub use device::{
    device_request_headers, enroll_request_json, generate_device_key, parse_enroll_response,
    sign_device_pop, DeviceError, DeviceKeypair, EnrolledCert,
};

pub use codec::{
    encode_frame, frame_kind_of, CodecError, Decoder, Frame, FrameKind, Header, WireOpcode,
};
pub use fetch::{FetchEvent, FetchShim, FetchState};
pub use signaling::{
    BrowserConnectResponse, EndReason, SignalingClient, SignalingConfig, SignalingError,
    SignalingEvent, SignalingSession, SignalingTransport, WsTransport,
};
pub use ws::{ReadyState, WsEvent, WsShim};
