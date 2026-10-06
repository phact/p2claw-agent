//! p2claw wire-protocol frame codec.
//!
//! Sans-I/O: encode appends to a [`BytesMut`]; decode reads from one.
//! Transport integration (tokio sockets, WebRTC data channels) lives
//! elsewhere and drives this codec with byte buffers.

#![deny(rust_2018_idioms)]

mod codec;
mod error;
mod frame;

pub use codec::{decode, encode};
pub use error::WireError;
pub use frame::{
    DataFlags, ErrorCode, Frame, FrameType, Header, Headers, ReqFlags, ResFlags, StreamId,
    WsOpcode, FLAG_END_STREAM, MAX_FRAME_BODY,
};
