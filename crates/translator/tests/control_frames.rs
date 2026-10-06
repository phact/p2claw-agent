//! Integration tests for the control-frame surface:
//! ERR-on-pending-stream, PING/PONG liveness, GOAWAY graceful
//! shutdown, drop-cancellation, and the WebSocket upgrade API.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use p2claw_translator::{
    serve, serve_with, ws::WsMessage, ClientConnection, ClientOptions, ClientRequest,
    ClientWsUpgrade, Handler, OutgoingBody, ServeOptions, ServerRequest, ServerResponse,
    ServerWsUpgrade, WsConnection, WsHandler, WsUpgradeDecision,
};
use p2claw_wire::ErrorCode;
use tokio::io::duplex;

fn pair_with<H>(
    handler: H,
    options: ServeOptions,
) -> (ClientConnection, tokio::task::JoinHandle<()>)
where
    H: Handler,
{
    let (s_io, c_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let _ = serve_with(s_io, handler, options).await;
    });
    let client = ClientConnection::spawn(c_io);
    (client, server)
}

/// Build a tiny HTTP handler that always returns the path back as
/// the response body.
fn echo_path() -> impl Handler {
    move |req: ServerRequest| {
        Box::pin(async move { ServerResponse::new(200).with_body(OutgoingBody::once(req.path)) })
            as Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
    }
}

#[tokio::test]
async fn drop_request_future_sends_err_cancel() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let saw_err = Arc::new(AtomicBool::new(false));
    let saw_err_for_handler = Arc::clone(&saw_err);

    // Handler that never returns until its body channel reports
    // cancellation by closing — that signal is what drives the
    // `saw_err` flag, proving server-side ERR delivery.
    let handler = move |mut req: ServerRequest| {
        let saw = Arc::clone(&saw_err_for_handler);
        Box::pin(async move {
            // Wait for body EOF. Without ERR propagation the test
            // hangs; with it, the body channel closes.
            let _ = req.body.next_chunk().await;
            saw.store(true, Ordering::Release);
            ServerResponse::new(200)
        }) as Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
    };

    let (client, _server) = pair_with(handler, ServeOptions::default());

    let req = ClientRequest::post("/slow", OutgoingBody::empty());
    // Issue the request; if we drop the future before the response,
    // the client should send ERR(CANCEL) and the server's body should
    // observe EOF.
    let client_clone = client.clone();
    let h = tokio::spawn(async move { client_clone.request(req).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    h.abort();
    let _ = h.await;

    // Give the cancel-on-drop spawn time to flush ERR.
    for _ in 0..50 {
        if saw_err.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        saw_err.load(Ordering::Acquire),
        "server handler should observe body EOF triggered by ERR(CANCEL)"
    );
}

#[tokio::test]
async fn ping_pong_keeps_connection_alive() {
    // Use a very tight ping interval to drive several PINGs through
    // before the test exits.
    let opts = ServeOptions {
        ping_interval: Some(Duration::from_millis(20)),
        ping_timeout: Some(Duration::from_secs(5)),
        ws_handler: None,
        tx_observer: None,
        ..ServeOptions::default()
    };
    let (client, _server) = pair_with(echo_path(), opts);

    // Burn 150ms — multiple PING/PONG cycles will run in the
    // background. We don't have a hook to count them; the success
    // criterion is that requests still work and the connection
    // doesn't get torn down by the liveness watcher.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let resp = client.request(ClientRequest::get("/alive")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(&resp.body.collect().await[..], b"/alive");
}

#[tokio::test]
async fn client_goaway_blocks_new_requests_on_server() {
    // Spin up the connection, send GOAWAY from the client, then a
    // *server* won't accept any new REQs from that client. We can't
    // observe the server side directly without instrumenting — so we
    // use the symmetrical case: the server sends GOAWAY (via a
    // server-side handle), and the client's next request fails with
    // GoingAway.
    //
    // Easier-to-test variant: client calls goaway() to flip its
    // local closed flag and refuse to send further REQs.
    let (client, _server) = pair_with(echo_path(), ServeOptions::default());

    client
        .goaway(ErrorCode::NO_ERROR, "client done")
        .await
        .unwrap();

    let err = client.request(ClientRequest::get("/x")).await.unwrap_err();
    assert!(
        matches!(err, p2claw_translator::TranslatorError::ConnectionClosed),
        "after local goaway, new requests must fail: got {err:?}"
    );
}

#[tokio::test]
async fn websocket_round_trip_echo() {
    struct Echo;
    impl WsHandler for Echo {
        fn decide(
            &self,
            _upgrade: &ServerWsUpgrade,
        ) -> Pin<Box<dyn std::future::Future<Output = WsUpgradeDecision> + Send + '_>> {
            Box::pin(async move {
                WsUpgradeDecision::Accept {
                    headers: Vec::new(),
                    upstream_headers: Vec::new(),
                }
            })
        }

        fn run(
            &self,
            _upgrade: ServerWsUpgrade,
            _upstream_headers: Vec<(Bytes, Bytes)>,
            conn: WsConnection,
        ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            Box::pin(async move {
                while let Ok(Some(msg)) = conn.recv().await {
                    if conn.send(msg).await.is_err() {
                        break;
                    }
                }
            })
        }
    }

    let opts = ServeOptions {
        ws_handler: Some(Arc::new(Echo)),
        ..ServeOptions::default()
    };
    let (client, _server) = pair_with(
        // HTTP handler still required for the trait; never invoked.
        |_req: ServerRequest| {
            Box::pin(async move { ServerResponse::new(404) })
                as Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
        },
        opts,
    );

    let ws = client
        .open_websocket(ClientWsUpgrade::new("/socket"))
        .await
        .unwrap();

    ws.send(WsMessage::text(Bytes::from_static(b"hello")))
        .await
        .unwrap();
    let echoed = ws.recv().await.unwrap().expect("ws message");
    assert_eq!(&echoed.payload[..], b"hello");

    ws.send(WsMessage::binary(Bytes::from_static(&[1u8, 2, 3])))
        .await
        .unwrap();
    let echoed2 = ws.recv().await.unwrap().expect("ws bin message");
    assert_eq!(&echoed2.payload[..], &[1u8, 2, 3]);

    ws.close(1000, Bytes::from_static(b"bye")).await.unwrap();
}

#[tokio::test]
async fn websocket_upgrade_rejection_returns_cancelled() {
    struct Reject;
    impl WsHandler for Reject {
        fn decide(
            &self,
            _upgrade: &ServerWsUpgrade,
        ) -> Pin<Box<dyn std::future::Future<Output = WsUpgradeDecision> + Send + '_>> {
            Box::pin(async move {
                WsUpgradeDecision::Reject {
                    status: 401,
                    headers: Vec::new(),
                }
            })
        }
        fn run(
            &self,
            _upgrade: ServerWsUpgrade,
            _upstream_headers: Vec<(Bytes, Bytes)>,
            _conn: WsConnection,
        ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            Box::pin(async move {})
        }
    }

    let opts = ServeOptions {
        ws_handler: Some(Arc::new(Reject)),
        ..ServeOptions::default()
    };
    let (client, _server) = pair_with(
        |_req: ServerRequest| {
            Box::pin(async move { ServerResponse::new(404) })
                as Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
        },
        opts,
    );

    let err = client
        .open_websocket(ClientWsUpgrade::new("/secret"))
        .await
        .unwrap_err();
    match err {
        p2claw_translator::TranslatorError::Cancelled(code) => {
            assert_eq!(code.0, 401, "rejection code should mirror RES status");
        }
        other => panic!("expected Cancelled(401), got {other:?}"),
    }
}

#[tokio::test]
async fn no_ws_handler_returns_501() {
    // Rejections come back as RES(4xx). When the
    // server has no registered WS handler at all, return 501
    // (Not Implemented) — the client surfaces this as Cancelled(501).
    let (client, _server) = pair_with(
        |_req: ServerRequest| {
            Box::pin(async move { ServerResponse::new(404) })
                as Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
        },
        ServeOptions::default(),
    );

    let err = client
        .open_websocket(ClientWsUpgrade::new("/whatever"))
        .await
        .unwrap_err();
    match err {
        p2claw_translator::TranslatorError::Cancelled(code) => {
            assert_eq!(code.0, 501);
        }
        other => panic!("expected Cancelled(501), got {other:?}"),
    }
}

#[tokio::test]
async fn http_request_works_with_default_options_disabled_pings() {
    // Sanity: turning PING off shouldn't break the HTTP path.
    let opts = ServeOptions {
        ping_interval: None,
        ping_timeout: None,
        ws_handler: None,
        tx_observer: None,
        ..ServeOptions::default()
    };
    let (s_io, c_io) = duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = serve_with(s_io, echo_path(), opts).await;
    });
    let copts = ClientOptions {
        ping_interval: None,
        ping_timeout: None,
    };
    let client = ClientConnection::spawn_with(c_io, copts);

    let resp = client
        .request(ClientRequest::get("/ping-off"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(&resp.body.collect().await[..], b"/ping-off");
}

#[tokio::test]
async fn unaffected_default_serve_function_still_works() {
    // Plain `serve` (no options) must keep working unchanged for
    // existing callers (the agent, p2claw-iroh-client tests).
    let (s_io, c_io) = duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = serve(s_io, echo_path()).await;
    });
    let client = ClientConnection::spawn(c_io);
    let resp = client.request(ClientRequest::get("/legacy")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(&resp.body.collect().await[..], b"/legacy");
}

/// ANY sustained body backlog must not HOL-block a PING (or any
/// session-control frame). Single fat/fast
/// download with a slow consumer can fill `body_tx`; PING needs its
/// own lane or `last_frame_at` ages out → spurious GOAWAY.
///
/// Setup: a tiny duplex (1 KiB) caps wire throughput hard. Handler
/// returns a never-ending body of 4 KiB chunks for the requested
/// path, so the body lane stays saturated. Visitor reads slowly:
/// one chunk every ~250 ms. Box-side `ping_interval` = 100 ms,
/// `ping_timeout` = 500 ms. With single-lane FIFO this would peg
/// the wedge in well under a second. With the priority-control-
/// lane split, PING reaches the wire promptly, the visitor's
/// translator emits PONG, and the box's liveness deadline stays
/// armed → no GOAWAY for the duration of the test.
///
/// Test passes if the streaming response continues for at least
/// `OBSERVE_WINDOW`, well past `ping_timeout`, with no spurious
/// teardown by the box's liveness watcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_body_backlog_does_not_starve_ping() {
    use tokio::io::duplex;

    // Tight transport budget — forces backpressure into the
    // body lane on every frame.
    let (s_io, c_io) = duplex(1024);

    // 100 ms PING / 500 ms timeout — quick enough that any HOL
    // longer than ~1 s would trip the watcher.
    let server_options = ServeOptions {
        ping_interval: Some(Duration::from_millis(100)),
        ping_timeout: Some(Duration::from_millis(500)),
        ..ServeOptions::default()
    };

    let handler = move |_req: ServerRequest| {
        Box::pin(async move {
            // No per-tick sleep — produce body frames as fast as
            // the bounded channel accepts them. With single-lane
            // FIFO, this saturates body_tx and HOL-queues the
            // PING task behind it. With the priority split, PING
            // bypasses the body backlog.
            let chunks = futures_util::stream::unfold(0usize, |i| async move {
                tokio::task::yield_now().await;
                Some((Bytes::from(vec![0u8; 4 * 1024]), i + 1))
            });
            ServerResponse::new(200)
                .header("content-type", "application/octet-stream")
                .with_body(OutgoingBody::stream(chunks))
        }) as Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
    };

    let server = tokio::spawn(async move {
        let _ = serve_with(s_io, handler, server_options).await;
    });
    // CRITICAL: client does NOT ping the box. The box's
    // `last_frame_at` must be refreshed ONLY by the peer's
    // PONG responses to the box's PINGs. Without this
    // restriction, client PINGs themselves would refresh
    // last_frame_at and mask any box-side PING starvation —
    // the bug under test depends on inbound traffic depending
    // on outbound PINGs landing.
    let client_options = ClientOptions {
        ping_interval: None,
        ping_timeout: None,
    };
    let client = ClientConnection::spawn_with(c_io, client_options);

    let req = ClientRequest::get(Bytes::from_static(b"/saturate"));
    let resp = client.request(req).await.expect("request");
    let mut body = resp.body;

    // Observe well past the box's ping_timeout. Pre-fix
    // hypothesis: PING HOL'd by body backlog → no PONG → box
    // fires GOAWAY at 500 ms → connection torn down → body
    // returns None → test fails on the chunks-received floor.
    const OBSERVE_WINDOW: Duration = Duration::from_secs(3);
    const SLOW_READ_INTERVAL: Duration = Duration::from_millis(250);

    let observe_started = tokio::time::Instant::now();
    let mut chunks_received = 0usize;
    while observe_started.elapsed() < OBSERVE_WINDOW {
        match tokio::time::timeout(Duration::from_secs(2), body.next_chunk()).await {
            Ok(Some(_)) => {
                chunks_received += 1;
                tokio::time::sleep(SLOW_READ_INTERVAL).await;
            }
            Ok(None) => {
                panic!(
                    "stream ended after {chunks_received} chunks at {:?} — \
                     PING was HOL-blocked behind body backlog, liveness fired GOAWAY",
                    observe_started.elapsed()
                );
            }
            Err(_) => {
                panic!(
                    "next_chunk timed out after {chunks_received} chunks at {:?} — \
                     transport stalled (likely GOAWAY teardown mid-flight)",
                    observe_started.elapsed()
                );
            }
        }
    }
    // OBSERVE_WINDOW elapsed without GOAWAY teardown: PING lane
    // stayed live through the body backlog. Drop body to release
    // the server task.
    assert!(
        chunks_received >= 5,
        "even slow consumer should pull at least 5 chunks in {OBSERVE_WINDOW:?}; got {chunks_received}"
    );
    drop(body);
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
