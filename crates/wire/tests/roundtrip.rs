use bytes::{Bytes, BytesMut};
use p2claw_wire::*;

fn roundtrip(frame: Frame) {
    let mut buf = BytesMut::new();
    encode(&frame, &mut buf);
    let decoded = decode(&mut buf).expect("decode ok").expect("decode some");
    assert_eq!(decoded, frame, "roundtrip mismatch");
    assert!(buf.is_empty(), "decoder left bytes behind");
}

fn hdr(k: &'static str, v: &'static str) -> Header {
    (
        Bytes::from_static(k.as_bytes()),
        Bytes::from_static(v.as_bytes()),
    )
}

#[test]
fn req_roundtrip_bodyless() {
    roundtrip(Frame::Req {
        stream_id: StreamId(1),
        flags: ReqFlags::END_STREAM,
        method: Bytes::from_static(b"GET"),
        path: Bytes::from_static(b"/api/items"),
        headers: vec![
            hdr("user-agent", "p2claw-iroh-client/0.0.0"),
            hdr("accept", "application/json"),
        ],
    });
}

#[test]
fn req_roundtrip_streaming() {
    roundtrip(Frame::Req {
        stream_id: StreamId(42),
        flags: ReqFlags::NONE,
        method: Bytes::from_static(b"POST"),
        path: Bytes::from_static(b"/api/upload"),
        headers: vec![hdr("content-type", "application/octet-stream")],
    });
}

#[test]
fn res_roundtrip() {
    roundtrip(Frame::Res {
        stream_id: StreamId(1),
        flags: ResFlags::NONE,
        status: 200,
        headers: vec![
            hdr("content-type", "application/json"),
            hdr("content-length", "42"),
        ],
    });
}

#[test]
fn res_with_dup_headers() {
    // Multiple `set-cookie` values must survive as separate entries.
    roundtrip(Frame::Res {
        stream_id: StreamId(7),
        flags: ResFlags::END_STREAM,
        status: 204,
        headers: vec![
            hdr("set-cookie", "a=1; Path=/"),
            hdr("set-cookie", "b=2; Path=/; HttpOnly"),
        ],
    });
}

#[test]
fn data_roundtrip() {
    roundtrip(Frame::Data {
        stream_id: StreamId(3),
        flags: DataFlags::END_STREAM,
        body: Bytes::from_static(b"hello, world"),
    });
    roundtrip(Frame::Data {
        stream_id: StreamId(3),
        flags: DataFlags::NONE,
        body: Bytes::from_static(&[0xAA; 1024]),
    });
    // Zero-length DATA is legal.
    roundtrip(Frame::Data {
        stream_id: StreamId(3),
        flags: DataFlags::END_STREAM,
        body: Bytes::new(),
    });
}

#[test]
fn end_roundtrip() {
    roundtrip(Frame::End {
        stream_id: StreamId(99),
    });
}

#[test]
fn err_roundtrip() {
    roundtrip(Frame::Err {
        stream_id: StreamId(0),
        code: ErrorCode::PROTOCOL_ERROR,
        message: Bytes::from_static(b"malformed REQ frame"),
    });
}

#[test]
fn trailers_roundtrip() {
    // gRPC-shaped: the canonical use case is grpc-status / grpc-message
    // surfaced after the response body has streamed. Pin the dup-name
    // shape too — HTTP trailers can repeat (rare but legal).
    roundtrip(Frame::Trailers {
        stream_id: StreamId(7),
        headers: vec![hdr("grpc-status", "0"), hdr("grpc-message", "OK")],
    });
    // Empty trailers block: still a valid end-of-stream marker
    // (some receivers want the explicit terminal frame to distinguish
    // "we sent body and we're done" from "we sent body and we're
    // stalled mid-stream"). Producers should normally send DATA with
    // END_STREAM in the empty-trailers case, but the wire MUST accept
    // a trailer-less Trailers frame so a forwarder can pass it through
    // without inventing trailers it doesn't have.
    roundtrip(Frame::Trailers {
        stream_id: StreamId(1),
        headers: vec![],
    });
}

#[test]
fn ws_upgrade_accept_msg_close() {
    roundtrip(Frame::WsUpgrade {
        stream_id: StreamId(5),
        path: Bytes::from_static(b"/ws"),
        headers: vec![hdr("sec-websocket-protocol", "chat")],
    });
    roundtrip(Frame::WsAccept {
        stream_id: StreamId(5),
        headers: vec![hdr("sec-websocket-protocol", "chat")],
    });
    roundtrip(Frame::WsMsg {
        stream_id: StreamId(5),
        opcode: WsOpcode::Text,
        payload: Bytes::from_static(b"hello"),
    });
    roundtrip(Frame::WsMsg {
        stream_id: StreamId(5),
        opcode: WsOpcode::Binary,
        payload: Bytes::from_static(&[0x01, 0x02, 0x03]),
    });
    roundtrip(Frame::WsClose {
        stream_id: StreamId(5),
        code: 1000,
        reason: Bytes::from_static(b"bye"),
    });
}

#[test]
fn ping_pong_roundtrip() {
    roundtrip(Frame::Ping {
        nonce: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
    });
    roundtrip(Frame::Pong {
        nonce: [0, 0, 0, 0, 0, 0, 0, 0],
    });
}

#[test]
fn probe_and_probe_ack_roundtrip() {
    // Empty payload (legal — the receiver doesn't inspect contents).
    roundtrip(Frame::Probe {
        id: 1,
        payload: Bytes::new(),
    });
    // Small fixed payload.
    roundtrip(Frame::Probe {
        id: 42,
        payload: Bytes::from_static(b"probe-marker"),
    });
    // ~8 KiB payload — the production size used by the box-side
    // WebRTC visitor host to force multi-chunk SCTP fragmentation
    // on tunneled paths. Sanity-check the length-prefix path
    // handles 4-digit sizes cleanly.
    let big = vec![0xCDu8; 8 * 1024];
    roundtrip(Frame::Probe {
        id: u32::MAX,
        payload: Bytes::from(big),
    });
    // ProbeAck echoes the probe id; round-trip both ends of the
    // range to catch any endianness drift in the codec.
    roundtrip(Frame::ProbeAck { id: 0 });
    roundtrip(Frame::ProbeAck { id: 42 });
    roundtrip(Frame::ProbeAck { id: u32::MAX });
}

#[test]
fn goaway_roundtrip() {
    roundtrip(Frame::Goaway {
        last_accepted_stream_id: StreamId(100),
        code: ErrorCode::NO_ERROR,
        message: Bytes::from_static(b"draining"),
    });
}

#[test]
fn decode_partial_returns_none() {
    let frame = Frame::End {
        stream_id: StreamId(1),
    };
    let mut full = BytesMut::new();
    encode(&frame, &mut full);

    // Feed the bytes one at a time; decode should return None until
    // the final byte arrives.
    let mut buf = BytesMut::new();
    for &byte in &full[..full.len() - 1] {
        buf.extend_from_slice(&[byte]);
        assert!(decode(&mut buf).unwrap().is_none(), "premature decode");
    }
    buf.extend_from_slice(&[full[full.len() - 1]]);
    let decoded = decode(&mut buf).unwrap().expect("decode some");
    assert_eq!(decoded, frame);
    assert!(buf.is_empty());
}

#[test]
fn decode_multiple_frames_from_one_buffer() {
    let frames = vec![
        Frame::Ping {
            nonce: [1, 2, 3, 4, 5, 6, 7, 8],
        },
        Frame::End {
            stream_id: StreamId(2),
        },
        Frame::Pong {
            nonce: [9, 8, 7, 6, 5, 4, 3, 2],
        },
    ];
    let mut buf = BytesMut::new();
    for f in &frames {
        encode(f, &mut buf);
    }

    let mut decoded = vec![];
    while let Some(f) = decode(&mut buf).unwrap() {
        decoded.push(f);
    }
    assert_eq!(decoded, frames);
    assert!(buf.is_empty());
}

#[test]
fn unknown_frame_type_errors() {
    // frame_len=2, type=0xFE, flags=0
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0, 0, 0, 2, 0xFE, 0x00]);
    match decode(&mut buf) {
        Err(WireError::UnknownFrameType(0xFE)) => {}
        other => panic!("expected UnknownFrameType, got {other:?}"),
    }
}

#[test]
fn frame_too_short_errors() {
    // Claimed length = 1, which is below the 2-byte minimum.
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0, 0, 0, 1, 0x01]);
    assert!(matches!(decode(&mut buf), Err(WireError::FrameTooShort(1))));
}

#[test]
fn invalid_status_errors() {
    // Manually build a RES with status=42. Payload layout:
    //   type=0x02, flags=0, stream_id=u32, status=u16, header_count=u16
    // length = 2 + 4 + 2 + 2 = 10
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0, 0, 0, 10]); // length
    buf.extend_from_slice(&[0x02, 0x00]); // type, flags
    buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id
    buf.extend_from_slice(&[0, 42]); // status = 42 (invalid)
    buf.extend_from_slice(&[0, 0]); // header_count = 0
    assert!(matches!(
        decode(&mut buf),
        Err(WireError::InvalidStatus(42))
    ));
}
