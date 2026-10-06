//! Adapter: exposes the sans-I/O wire codec as a tokio_util Encoder +
//! Decoder so we can wrap an `AsyncRead + AsyncWrite` in a
//! `Framed<_, FrameCodec>`.

use bytes::BytesMut;
use p2claw_wire::{decode, encode, Frame, WireError};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Default)]
pub(crate) struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Frame>, Self::Error> {
        match decode(buf) {
            Ok(opt) => Ok(opt),
            Err(e) => Err(wire_err_to_io(e)),
        }
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: Frame, out: &mut BytesMut) -> Result<(), Self::Error> {
        encode(&frame, out);
        Ok(())
    }
}

fn wire_err_to_io(e: WireError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}
