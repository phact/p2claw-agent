use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::WireError;
use crate::frame::{
    DataFlags, ErrorCode, Frame, FrameType, Headers, ReqFlags, ResFlags, StreamId, WsOpcode,
    MAX_FRAME_BODY,
};

/// Serialize a frame to the end of `out`.
pub fn encode(frame: &Frame, out: &mut BytesMut) {
    // Reserve space for the length prefix; patch it once the payload
    // size is known.
    let length_pos = out.len();
    out.put_u32(0);
    let payload_start = out.len();

    match frame {
        Frame::Req {
            stream_id,
            flags,
            method,
            path,
            headers,
        } => {
            put_header(out, FrameType::Req, flags.bits());
            out.put_u32(stream_id.0);
            put_lp_u16(out, method);
            put_lp_u16(out, path);
            put_headers(out, headers);
        }
        Frame::Res {
            stream_id,
            flags,
            status,
            headers,
        } => {
            put_header(out, FrameType::Res, flags.bits());
            out.put_u32(stream_id.0);
            out.put_u16(*status);
            put_headers(out, headers);
        }
        Frame::Data {
            stream_id,
            flags,
            body,
        } => {
            put_header(out, FrameType::Data, flags.bits());
            out.put_u32(stream_id.0);
            out.put_slice(body);
        }
        Frame::End { stream_id } => {
            put_header(out, FrameType::End, 0);
            out.put_u32(stream_id.0);
        }
        Frame::Err {
            stream_id,
            code,
            message,
        } => {
            put_header(out, FrameType::Err, 0);
            out.put_u32(stream_id.0);
            out.put_u16(code.0);
            put_lp_u16(out, message);
        }
        Frame::Trailers { stream_id, headers } => {
            // Layout: stream_id (u32) + headers block. No status, no
            // flags semantics — TRAILERS implicitly carries end-of-
            // stream so a flags byte of 0 is the only valid value.
            put_header(out, FrameType::Trailers, 0);
            out.put_u32(stream_id.0);
            put_headers(out, headers);
        }
        Frame::WsUpgrade {
            stream_id,
            path,
            headers,
        } => {
            put_header(out, FrameType::WsUpgrade, 0);
            out.put_u32(stream_id.0);
            put_lp_u16(out, path);
            put_headers(out, headers);
        }
        Frame::WsAccept { stream_id, headers } => {
            put_header(out, FrameType::WsAccept, 0);
            out.put_u32(stream_id.0);
            put_headers(out, headers);
        }
        Frame::WsMsg {
            stream_id,
            opcode,
            payload,
        } => {
            put_header(out, FrameType::WsMsg, 0);
            out.put_u32(stream_id.0);
            out.put_u8(*opcode as u8);
            out.put_slice(payload);
        }
        Frame::WsClose {
            stream_id,
            code,
            reason,
        } => {
            put_header(out, FrameType::WsClose, 0);
            out.put_u32(stream_id.0);
            out.put_u16(*code);
            put_lp_u16(out, reason);
        }
        Frame::Ping { nonce } => {
            put_header(out, FrameType::Ping, 0);
            out.put_slice(nonce);
        }
        Frame::Pong { nonce } => {
            put_header(out, FrameType::Pong, 0);
            out.put_slice(nonce);
        }
        Frame::Probe { id, payload } => {
            // Header + 4-byte id + raw payload. No length prefix
            // beyond the outer frame-length envelope; decoder
            // reads the rest of the payload buffer.
            put_header(out, FrameType::Probe, 0);
            out.put_u32(*id);
            out.put_slice(payload);
        }
        Frame::ProbeAck { id } => {
            put_header(out, FrameType::ProbeAck, 0);
            out.put_u32(*id);
        }
        Frame::Goaway {
            last_accepted_stream_id,
            code,
            message,
        } => {
            put_header(out, FrameType::Goaway, 0);
            out.put_u32(last_accepted_stream_id.0);
            out.put_u16(code.0);
            put_lp_u16(out, message);
        }
    }

    // Patch the length prefix.
    let payload_len = (out.len() - payload_start) as u32;
    out[length_pos..length_pos + 4].copy_from_slice(&payload_len.to_be_bytes());
}

/// Try to decode one frame from the front of `buf`.
///
/// Returns:
/// - `Ok(Some(frame))` — one frame was decoded; its bytes are consumed from `buf`.
/// - `Ok(None)` — need more bytes; `buf` unchanged.
/// - `Err(_)` — malformed bytes; the connection must be treated as
///   poisoned. `buf` state is unspecified after an error.
pub fn decode(buf: &mut BytesMut) -> Result<Option<Frame>, WireError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    if frame_len < 2 {
        return Err(WireError::FrameTooShort(frame_len));
    }
    if frame_len > MAX_FRAME_BODY {
        return Err(WireError::FrameTooLarge(frame_len, MAX_FRAME_BODY));
    }
    let total = 4 + frame_len as usize;
    if buf.len() < total {
        return Ok(None);
    }

    // Split the frame off the front of `buf` without copying: the
    // payload is a refcounted view into the receive buffer. Decode
    // errors poison the connection, so consuming the bytes up front
    // is fine.
    let mut payload = buf.split_to(total).freeze().slice(4..);
    let type_byte = payload.get_u8();
    let flags = payload.get_u8();
    let ty = FrameType::from_u8(type_byte).ok_or(WireError::UnknownFrameType(type_byte))?;

    let frame = match ty {
        FrameType::Req => decode_req(&mut payload, flags)?,
        FrameType::Res => decode_res(&mut payload, flags)?,
        FrameType::Data => decode_data(&mut payload, flags)?,
        FrameType::End => decode_end(&mut payload)?,
        FrameType::Err => decode_err(&mut payload)?,
        FrameType::Trailers => decode_trailers(&mut payload)?,
        FrameType::WsUpgrade => decode_ws_upgrade(&mut payload)?,
        FrameType::WsAccept => decode_ws_accept(&mut payload)?,
        FrameType::WsMsg => decode_ws_msg(&mut payload)?,
        FrameType::WsClose => decode_ws_close(&mut payload)?,
        FrameType::Ping => decode_ping(&mut payload)?,
        FrameType::Pong => decode_pong(&mut payload)?,
        FrameType::Probe => decode_probe(&mut payload)?,
        FrameType::ProbeAck => decode_probe_ack(&mut payload)?,
        FrameType::Goaway => decode_goaway(&mut payload)?,
    };

    Ok(Some(frame))
}

// ---------- helpers ----------

fn put_header(out: &mut BytesMut, ty: FrameType, flags: u8) {
    out.put_u8(ty as u8);
    out.put_u8(flags);
}

fn put_lp_u16(out: &mut BytesMut, s: &[u8]) {
    // Length-prefixed string / byte sequence with a u16 length prefix.
    out.put_u16(s.len() as u16);
    out.put_slice(s);
}

fn put_headers(out: &mut BytesMut, headers: &Headers) {
    out.put_u16(headers.len() as u16);
    for (name, value) in headers {
        put_lp_u16(out, name);
        put_lp_u16(out, value);
    }
}

fn take_lp_u16(p: &mut Bytes) -> Result<Bytes, WireError> {
    if p.len() < 2 {
        return Err(WireError::TruncatedPayload {
            expected: 2,
            got: p.len(),
        });
    }
    let len = p.get_u16() as usize;
    if p.len() < len {
        return Err(WireError::TruncatedPayload {
            expected: len,
            got: p.len(),
        });
    }
    Ok(p.split_to(len))
}

fn take_stream_id(p: &mut Bytes) -> Result<StreamId, WireError> {
    if p.len() < 4 {
        return Err(WireError::TruncatedPayload {
            expected: 4,
            got: p.len(),
        });
    }
    Ok(StreamId(p.get_u32()))
}

fn take_headers(p: &mut Bytes) -> Result<Headers, WireError> {
    if p.len() < 2 {
        return Err(WireError::TruncatedPayload {
            expected: 2,
            got: p.len(),
        });
    }
    let count = p.get_u16() as usize;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let name = take_lp_u16(p)?;
        let value = take_lp_u16(p)?;
        headers.push((name, value));
    }
    Ok(headers)
}

// ---------- per-type decoders ----------

fn decode_req(p: &mut Bytes, flags: u8) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    let method = take_lp_u16(p)?;
    let path = take_lp_u16(p)?;
    let headers = take_headers(p)?;
    Ok(Frame::Req {
        stream_id,
        flags: ReqFlags(flags),
        method,
        path,
        headers,
    })
}

fn decode_res(p: &mut Bytes, flags: u8) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    if p.len() < 2 {
        return Err(WireError::TruncatedPayload {
            expected: 2,
            got: p.len(),
        });
    }
    let status = p.get_u16();
    if !(100..=599).contains(&status) {
        return Err(WireError::InvalidStatus(status));
    }
    let headers = take_headers(p)?;
    Ok(Frame::Res {
        stream_id,
        flags: ResFlags(flags),
        status,
        headers,
    })
}

fn decode_data(p: &mut Bytes, flags: u8) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    let body = std::mem::take(p);
    Ok(Frame::Data {
        stream_id,
        flags: DataFlags(flags),
        body,
    })
}

fn decode_end(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    Ok(Frame::End { stream_id })
}

fn decode_err(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    if p.len() < 2 {
        return Err(WireError::TruncatedPayload {
            expected: 2,
            got: p.len(),
        });
    }
    let code = ErrorCode(p.get_u16());
    let message = take_lp_u16(p)?;
    Ok(Frame::Err {
        stream_id,
        code,
        message,
    })
}

fn decode_trailers(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    let headers = take_headers(p)?;
    Ok(Frame::Trailers { stream_id, headers })
}

fn decode_ws_upgrade(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    let path = take_lp_u16(p)?;
    let headers = take_headers(p)?;
    Ok(Frame::WsUpgrade {
        stream_id,
        path,
        headers,
    })
}

fn decode_ws_accept(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    let headers = take_headers(p)?;
    Ok(Frame::WsAccept { stream_id, headers })
}

fn decode_ws_msg(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    if p.is_empty() {
        return Err(WireError::TruncatedPayload {
            expected: 1,
            got: 0,
        });
    }
    let opcode_byte = p.get_u8();
    let opcode = WsOpcode::from_u8(opcode_byte).ok_or(WireError::UnknownWsOpcode(opcode_byte))?;
    let payload = std::mem::take(p);
    Ok(Frame::WsMsg {
        stream_id,
        opcode,
        payload,
    })
}

fn decode_ws_close(p: &mut Bytes) -> Result<Frame, WireError> {
    let stream_id = take_stream_id(p)?;
    if p.len() < 2 {
        return Err(WireError::TruncatedPayload {
            expected: 2,
            got: p.len(),
        });
    }
    let code = p.get_u16();
    let reason = take_lp_u16(p)?;
    Ok(Frame::WsClose {
        stream_id,
        code,
        reason,
    })
}

fn decode_ping(p: &mut Bytes) -> Result<Frame, WireError> {
    if p.len() < 8 {
        return Err(WireError::TruncatedPayload {
            expected: 8,
            got: p.len(),
        });
    }
    let mut nonce = [0u8; 8];
    p.copy_to_slice(&mut nonce);
    Ok(Frame::Ping { nonce })
}

fn decode_pong(p: &mut Bytes) -> Result<Frame, WireError> {
    if p.len() < 8 {
        return Err(WireError::TruncatedPayload {
            expected: 8,
            got: p.len(),
        });
    }
    let mut nonce = [0u8; 8];
    p.copy_to_slice(&mut nonce);
    Ok(Frame::Pong { nonce })
}

fn decode_probe(p: &mut Bytes) -> Result<Frame, WireError> {
    if p.len() < 4 {
        return Err(WireError::TruncatedPayload {
            expected: 4,
            got: p.len(),
        });
    }
    let id = p.get_u32();
    // Probe carries an opaque payload; the receiver doesn't inspect
    // contents (only ACKs). Empty payload is legal — useful for
    // tests, though production probes are sized to force SCTP
    // fragmentation.
    let payload = std::mem::take(p);
    Ok(Frame::Probe { id, payload })
}

fn decode_probe_ack(p: &mut Bytes) -> Result<Frame, WireError> {
    if p.len() < 4 {
        return Err(WireError::TruncatedPayload {
            expected: 4,
            got: p.len(),
        });
    }
    let id = p.get_u32();
    Ok(Frame::ProbeAck { id })
}

fn decode_goaway(p: &mut Bytes) -> Result<Frame, WireError> {
    let last = take_stream_id(p)?;
    if p.len() < 2 {
        return Err(WireError::TruncatedPayload {
            expected: 2,
            got: p.len(),
        });
    }
    let code = ErrorCode(p.get_u16());
    let message = take_lp_u16(p)?;
    Ok(Frame::Goaway {
        last_accepted_stream_id: last,
        code,
        message,
    })
}
