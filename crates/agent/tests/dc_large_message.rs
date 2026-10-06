//! A frame larger than the SCTP max message size must still cross a
//! WebRTC data channel intact, and frames after it must keep flowing.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use p2claw_agent::dc_stream::MessageSizeCap;
use p2claw_wire::{Frame, StreamId, WsOpcode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data::data_channel::{DataChannel, PollDataChannel};
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::RTCPeerConnection;

const BIG: usize = 200 * 1024;

async fn new_pc() -> Arc<RTCPeerConnection> {
    let mut settings = SettingEngine::default();
    settings.detach_data_channels();
    let api = APIBuilder::new().with_setting_engine(settings).build();
    Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    )
}

/// Two peer connections joined over loopback. The connections are kept
/// here so they outlive the detached channels.
struct Pair {
    _pcs: [Arc<RTCPeerConnection>; 2],
    offerer: Arc<DataChannel>,
    answerer: Arc<DataChannel>,
}

async fn dc_pair() -> Pair {
    let a = new_pc().await;
    let b = new_pc().await;

    let (a_tx, a_rx) = oneshot::channel();
    let dc = a.create_data_channel("p2claw", None).await.unwrap();
    let dc_open = Arc::clone(&dc);
    let a_tx = std::sync::Mutex::new(Some(a_tx));
    dc.on_open(Box::new(move || {
        let dc = Arc::clone(&dc_open);
        let tx = a_tx.lock().unwrap().take();
        Box::pin(async move {
            let raw = dc.detach().await.unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(raw);
            }
        })
    }));

    let (b_tx, b_rx) = oneshot::channel();
    let b_tx = Arc::new(std::sync::Mutex::new(Some(b_tx)));
    b.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let b_tx = Arc::clone(&b_tx);
        Box::pin(async move {
            let dc_open = Arc::clone(&dc);
            dc.on_open(Box::new(move || {
                let dc = Arc::clone(&dc_open);
                let tx = b_tx.lock().unwrap().take();
                Box::pin(async move {
                    let raw = dc.detach().await.unwrap();
                    if let Some(tx) = tx {
                        let _ = tx.send(raw);
                    }
                })
            }));
        })
    }));

    let offer = a.create_offer(None).await.unwrap();
    let mut a_gathered = a.gathering_complete_promise().await;
    a.set_local_description(offer).await.unwrap();
    let _ = a_gathered.recv().await;
    b.set_remote_description(a.local_description().await.unwrap())
        .await
        .unwrap();
    let answer = b.create_answer(None).await.unwrap();
    let mut b_gathered = b.gathering_complete_promise().await;
    b.set_local_description(answer).await.unwrap();
    let _ = b_gathered.recv().await;
    a.set_remote_description(b.local_description().await.unwrap())
        .await
        .unwrap();

    let timeout = Duration::from_secs(20);
    let a_dc = tokio::time::timeout(timeout, a_rx).await.unwrap().unwrap();
    let b_dc = tokio::time::timeout(timeout, b_rx).await.unwrap().unwrap();
    Pair {
        _pcs: [a, b],
        offerer: a_dc,
        answerer: b_dc,
    }
}

fn big_ws_msg() -> Frame {
    let payload: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
    Frame::WsMsg {
        stream_id: StreamId(1),
        opcode: WsOpcode::Binary,
        payload: Bytes::from(payload),
    }
}

fn encode(frames: &[Frame]) -> BytesMut {
    let mut out = BytesMut::new();
    for f in frames {
        p2claw_wire::encode(f, &mut out);
    }
    out
}

#[tokio::test]
async fn frame_larger_than_max_message_size_arrives_intact() {
    let pair = dc_pair().await;

    let big = big_ws_msg();
    let small = Frame::Ping { nonce: [7; 8] };
    let bytes = encode(&[big.clone(), small.clone()]);

    let mut tx = MessageSizeCap::new(PollDataChannel::new(Arc::clone(&pair.offerer)));
    tx.write_all(&bytes).await.unwrap();
    tx.flush().await.unwrap();

    let mut rx = PollDataChannel::new(Arc::clone(&pair.answerer));
    rx.set_read_buf_capacity(64 * 1024);
    let mut buf = BytesMut::new();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while got.len() < 2 {
            while let Some(f) = p2claw_wire::decode(&mut buf).unwrap() {
                got.push(f);
            }
            if got.len() < 2 {
                let n = rx.read_buf(&mut buf).await.unwrap();
                assert!(n > 0, "data channel closed early");
            }
        }
    })
    .await
    .expect("frames did not arrive");

    assert_eq!(got, vec![big, small]);
}

#[tokio::test]
async fn uncapped_write_of_large_frame_fails() {
    let pair = dc_pair().await;
    let bytes = encode(&[big_ws_msg()]);
    let mut tx = PollDataChannel::new(Arc::clone(&pair.offerer));
    let err = tx.write_all(&bytes).await.unwrap_err();
    assert!(
        err.to_string().contains("larger than maximum message size"),
        "{err}"
    );
}
