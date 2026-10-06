//! Generate the wire-codec test vectors shared by the TypeScript and mobile ports.
//!
//! Run:   cargo run -p p2claw-wire --example dump_wire_vectors
//!
//! Prints one JSON object to stdout — a list of
//! `{name, description, hex}` entries. Pipe into
//! `crates/wire/test-vectors.json`.

use bytes::{Bytes, BytesMut};
use p2claw_wire::*;

fn main() {
    let cases: Vec<(&str, &str, Frame)> = vec![
        (
            "req_get_end_stream",
            "REQ stream=1 END_STREAM method=GET path=/api/items headers=[]",
            Frame::Req {
                stream_id: StreamId(1),
                flags: ReqFlags::END_STREAM,
                method: Bytes::from_static(b"GET"),
                path: Bytes::from_static(b"/api/items"),
                headers: vec![],
            },
        ),
        (
            "req_post_streaming",
            "REQ stream=42 no-flags method=POST path=/api/upload headers=[content-type:application/octet-stream]",
            Frame::Req {
                stream_id: StreamId(42),
                flags: ReqFlags::NONE,
                method: Bytes::from_static(b"POST"),
                path: Bytes::from_static(b"/api/upload"),
                headers: vec![(
                    Bytes::from_static(b"content-type"),
                    Bytes::from_static(b"application/octet-stream"),
                )],
            },
        ),
        (
            "res_200_streaming",
            "RES stream=1 no-flags status=200 headers=[content-type:text/event-stream]",
            Frame::Res {
                stream_id: StreamId(1),
                flags: ResFlags::NONE,
                status: 200,
                headers: vec![(
                    Bytes::from_static(b"content-type"),
                    Bytes::from_static(b"text/event-stream"),
                )],
            },
        ),
        (
            "res_204_end_stream",
            "RES stream=7 END_STREAM status=204 headers=[]",
            Frame::Res {
                stream_id: StreamId(7),
                flags: ResFlags::END_STREAM,
                status: 204,
                headers: vec![],
            },
        ),
        (
            "res_dup_set_cookie",
            "RES stream=7 END_STREAM status=200 headers=[set-cookie:a=1; Path=/, set-cookie:b=2; Path=/; HttpOnly]",
            Frame::Res {
                stream_id: StreamId(7),
                flags: ResFlags::END_STREAM,
                status: 200,
                headers: vec![
                    (
                        Bytes::from_static(b"set-cookie"),
                        Bytes::from_static(b"a=1; Path=/"),
                    ),
                    (
                        Bytes::from_static(b"set-cookie"),
                        Bytes::from_static(b"b=2; Path=/; HttpOnly"),
                    ),
                ],
            },
        ),
        (
            "data_end_stream",
            "DATA stream=3 END_STREAM body=\"hello, world\"",
            Frame::Data {
                stream_id: StreamId(3),
                flags: DataFlags::END_STREAM,
                body: Bytes::from_static(b"hello, world"),
            },
        ),
        (
            "data_empty_end_stream",
            "DATA stream=3 END_STREAM body=[]",
            Frame::Data {
                stream_id: StreamId(3),
                flags: DataFlags::END_STREAM,
                body: Bytes::new(),
            },
        ),
        (
            "end",
            "END stream=99",
            Frame::End {
                stream_id: StreamId(99),
            },
        ),
        (
            "err_protocol_error",
            "ERR stream=0 code=PROTOCOL_ERROR(0x0001) message=\"malformed REQ frame\"",
            Frame::Err {
                stream_id: StreamId(0),
                code: ErrorCode::PROTOCOL_ERROR,
                message: Bytes::from_static(b"malformed REQ frame"),
            },
        ),
        (
            "trailers_grpc_status",
            "TRAILERS stream=7 headers=[grpc-status:0, grpc-message:OK]",
            Frame::Trailers {
                stream_id: StreamId(7),
                headers: vec![
                    (
                        Bytes::from_static(b"grpc-status"),
                        Bytes::from_static(b"0"),
                    ),
                    (
                        Bytes::from_static(b"grpc-message"),
                        Bytes::from_static(b"OK"),
                    ),
                ],
            },
        ),
        (
            "trailers_empty",
            "TRAILERS stream=1 headers=[]",
            Frame::Trailers {
                stream_id: StreamId(1),
                headers: vec![],
            },
        ),
        (
            "ws_upgrade",
            "WS_UPGRADE stream=5 path=/ws headers=[sec-websocket-protocol:chat]",
            Frame::WsUpgrade {
                stream_id: StreamId(5),
                path: Bytes::from_static(b"/ws"),
                headers: vec![(
                    Bytes::from_static(b"sec-websocket-protocol"),
                    Bytes::from_static(b"chat"),
                )],
            },
        ),
        (
            "ws_accept",
            "WS_ACCEPT stream=5 headers=[sec-websocket-protocol:chat]",
            Frame::WsAccept {
                stream_id: StreamId(5),
                headers: vec![(
                    Bytes::from_static(b"sec-websocket-protocol"),
                    Bytes::from_static(b"chat"),
                )],
            },
        ),
        (
            "ws_msg_text",
            "WS_MSG stream=5 opcode=0x1 (text) payload=\"hello\"",
            Frame::WsMsg {
                stream_id: StreamId(5),
                opcode: WsOpcode::Text,
                payload: Bytes::from_static(b"hello"),
            },
        ),
        (
            "ws_msg_binary",
            "WS_MSG stream=5 opcode=0x2 (binary) payload=[0x01,0x02,0x03]",
            Frame::WsMsg {
                stream_id: StreamId(5),
                opcode: WsOpcode::Binary,
                payload: Bytes::from_static(&[0x01, 0x02, 0x03]),
            },
        ),
        (
            "ws_close",
            "WS_CLOSE stream=5 code=1000 reason=\"bye\"",
            Frame::WsClose {
                stream_id: StreamId(5),
                code: 1000,
                reason: Bytes::from_static(b"bye"),
            },
        ),
        (
            "ping",
            "PING nonce=DEADBEEF01020304",
            Frame::Ping {
                nonce: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            },
        ),
        (
            "pong",
            "PONG nonce=0000000000000000",
            Frame::Pong {
                nonce: [0, 0, 0, 0, 0, 0, 0, 0],
            },
        ),
        (
            "goaway",
            "GOAWAY last=100 code=NO_ERROR(0x0000) message=\"draining\"",
            Frame::Goaway {
                last_accepted_stream_id: StreamId(100),
                code: ErrorCode::NO_ERROR,
                message: Bytes::from_static(b"draining"),
            },
        ),
    ];

    println!("{{");
    println!("  \"spec_version\": \"0.1\",");
    println!("  \"note\": \"Generated by crates/wire/examples/dump_wire_vectors.rs. Do not edit by hand; re-run the example to update.\",");
    println!("  \"vectors\": [");
    let n = cases.len();
    for (i, (name, desc, frame)) in cases.into_iter().enumerate() {
        let mut buf = BytesMut::new();
        encode(&frame, &mut buf);
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        let comma = if i + 1 == n { "" } else { "," };
        println!("    {{");
        println!("      \"name\": {},", json_string(name));
        println!("      \"description\": {},", json_string(desc));
        println!("      \"hex\": {}", json_string(&hex));
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}

/// Minimal JSON-string escaping — enough for ASCII `name`, `desc`,
/// and `hex`.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
