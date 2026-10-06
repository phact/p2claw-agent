//! Integration tests: two translators talking over a loopback TCP
//! socket. Exercises the HTTP path (REQ/RES/DATA/END), streaming
//! bodies, and stream multiplexing.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream;
use p2claw_translator::{
    serve, ClientConnection, ClientRequest, OutgoingBody, ServerRequest, ServerResponse,
};
use tokio::net::{TcpListener, TcpStream};

/// Spin up a loopback server running `handler` and return a
/// connected `ClientConnection` pointing at it.
async fn pair<H>(handler: H) -> ClientConnection
where
    H: Fn(
            ServerRequest,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ServerResponse> + Send>>
        + Send
        + Sync
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handler = Arc::new(handler);
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let h = Arc::clone(&handler);
        serve(sock, move |req| h(req)).await.unwrap();
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    ClientConnection::spawn(sock)
}

#[tokio::test]
async fn simple_get() {
    let client = pair(|req| {
        Box::pin(async move {
            ServerResponse::new(200)
                .header("content-type", "text/plain")
                .with_body(OutgoingBody::once(req.path))
        })
    })
    .await;

    let resp = client.request(ClientRequest::get("/hello")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp
        .headers
        .iter()
        .any(|(k, v)| &k[..] == b"content-type" && &v[..] == b"text/plain"));
    let body = resp.body.collect().await;
    assert_eq!(&body[..], b"/hello");
}

#[tokio::test]
async fn empty_body_roundtrip() {
    let client = pair(|_req| Box::pin(async move { ServerResponse::new(204) })).await;

    let resp = client.request(ClientRequest::get("/")).await.unwrap();
    assert_eq!(resp.status, 204);
    let body = resp.body.collect().await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn post_with_body_echoed() {
    let client = pair(|req| {
        Box::pin(async move {
            let body = req.body.collect().await;
            ServerResponse::new(200)
                .header("content-type", "application/octet-stream")
                .with_body(OutgoingBody::once(body))
        })
    })
    .await;

    let payload = Bytes::from_static(b"the quick brown fox jumps over the lazy dog");
    let req = ClientRequest::post("/echo", OutgoingBody::once(payload.clone()))
        .header("content-type", "application/octet-stream");
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(&resp.body.collect().await[..], &payload[..]);
}

#[tokio::test]
async fn streaming_response_body() {
    let client = pair(|_req| {
        Box::pin(async move {
            let chunks = vec![
                Bytes::from_static(b"chunk-1 "),
                Bytes::from_static(b"chunk-2 "),
                Bytes::from_static(b"chunk-3"),
            ];
            let s = stream::iter(chunks);
            ServerResponse::new(200)
                .header("content-type", "text/event-stream")
                .with_body(OutgoingBody::stream(s))
        })
    })
    .await;

    let mut resp = client.request(ClientRequest::get("/events")).await.unwrap();
    assert_eq!(resp.status, 200);

    let mut seen = Vec::<Bytes>::new();
    while let Some(chunk) = resp.body.next_chunk().await {
        seen.push(chunk);
    }
    let joined: Vec<u8> = seen.iter().flat_map(|b| b.iter().copied()).collect();
    assert_eq!(&joined[..], b"chunk-1 chunk-2 chunk-3");
    // The chunks should arrive separately (wire layer emits one DATA
    // per stream chunk when bodies are sourced as discrete chunks).
    assert!(
        seen.len() >= 2,
        "expected multiple chunks, got {}",
        seen.len()
    );
}

/// Regression: a response body larger than the smallest real-world
/// transport message cap (`webrtc-sctp`'s 64 KiB
/// `DEFAULT_MAX_MESSAGE_SIZE`) must round-trip byte-for-byte. The
/// server chunks the body into ≤16 KiB DATA frames; the client must
/// reassemble them transparently.
///
/// This bug surfaced end-to-end serving a 4 MB static HTML page
/// through the the agent's forwarder — the upstream handed hyper a
/// single giant chunk, the translator emitted it as one DATA frame,
/// and SCTP refused the message and closed the stream mid-response.
#[tokio::test]
async fn large_body_roundtrips_across_multiple_data_frames() {
    // Use a deterministic but non-constant pattern so a buggy
    // reassembly that drops or reorders frames is visible at the
    // mismatching index rather than silently comparing equal.
    const BODY_LEN: usize = 200 * 1024; // 200 KiB, well past 64 KiB.
    let payload: Bytes = (0..BODY_LEN)
        .map(|i| (i & 0xff) as u8)
        .collect::<Vec<u8>>()
        .into();

    let body_for_handler = payload.clone();
    let client = pair(move |_req| {
        let body = body_for_handler.clone();
        Box::pin(async move {
            ServerResponse::new(200)
                .header("content-type", "application/octet-stream")
                .with_body(OutgoingBody::once(body))
        })
    })
    .await;

    let resp = client.request(ClientRequest::get("/big")).await.unwrap();
    assert_eq!(resp.status, 200);
    let got = resp.body.collect().await;
    assert_eq!(got.len(), payload.len(), "body length mismatch");
    assert_eq!(&got[..], &payload[..], "body bytes must round-trip exactly");
}

#[tokio::test]
async fn multiplexed_concurrent_requests() {
    // Handler echoes the path back, after a short stagger so
    // responses clearly interleave.
    let client = pair(|req| {
        Box::pin(async move {
            let path = req.path.clone();
            // Stagger by last path char so fewer concurrent-same
            // responses come back in request order.
            if path.ends_with(b"2") {
                tokio::time::sleep(Duration::from_millis(40)).await;
            } else if path.ends_with(b"3") {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            ServerResponse::new(200).with_body(OutgoingBody::once(path))
        })
    })
    .await;

    let mut handles = vec![];
    for i in 1..=5 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let path = format!("/item-{i}");
            let resp = client
                .request(ClientRequest::get(Bytes::from(path.clone())))
                .await
                .unwrap();
            assert_eq!(resp.status, 200);
            let body = resp.body.collect().await;
            assert_eq!(std::str::from_utf8(&body).unwrap(), path);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn response_trailers_round_trip_with_body() {
    // gRPC-shaped trailers: a non-empty body followed by a TRAILERS
    // frame carrying grpc-status / grpc-message. The receiver reads
    // the body via `collect`, then `trailers()` resolves to the
    // sent headers. Verifies wire round-trip + IncomingBody plumbing.
    let client = pair(|_req| {
        Box::pin(async move {
            ServerResponse::new(200)
                .header("content-type", "application/grpc")
                .with_body(OutgoingBody::once(Bytes::from_static(b"protobuf bytes")))
                .trailer("grpc-status", "0")
                .trailer("grpc-message", "OK")
        })
    })
    .await;

    let resp = client
        .request(ClientRequest::get("/say-hello"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let mut body = resp.body;
    // Drain the body first; trailers arrive after the terminal
    // TRAILERS frame which the receiver only emits once next_chunk
    // returns None.
    let mut bytes = bytes::BytesMut::new();
    while let Some(chunk) = body.next_chunk().await {
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(&bytes[..], b"protobuf bytes");

    let trailers = body.trailers().await.expect("server attached trailers");
    assert_eq!(trailers.len(), 2);
    assert_eq!(&trailers[0].0[..], b"grpc-status");
    assert_eq!(&trailers[0].1[..], b"0");
    assert_eq!(&trailers[1].0[..], b"grpc-message");
    assert_eq!(&trailers[1].1[..], b"OK");

    // Idempotent: a second call returns None — receivers shouldn't
    // be able to retrieve the same trailers twice (catches
    // accidental reuse in long-lived consumers).
    assert!(body.trailers().await.is_none());
}

#[tokio::test]
async fn response_trailers_round_trip_empty_body() {
    // Trailers without a body — empty `OutgoingBody::Empty` plus
    // `.trailer(..)`. The wire emits ONE Frame::Trailers, no DATA,
    // no END. Receiver sees an empty body + populated trailers.
    let client = pair(|_req| {
        Box::pin(async move {
            ServerResponse::new(200).trailer("grpc-status", "5") // NOT_FOUND in gRPC
        })
    })
    .await;

    let resp = client.request(ClientRequest::get("/")).await.unwrap();
    assert_eq!(resp.status, 200);
    let mut body = resp.body;
    assert!(body.next_chunk().await.is_none(), "body should be empty");
    let trailers = body.trailers().await.expect("server attached trailers");
    assert_eq!(trailers.len(), 1);
    assert_eq!(&trailers[0].0[..], b"grpc-status");
    assert_eq!(&trailers[0].1[..], b"5");
}

#[tokio::test]
async fn response_without_trailers_returns_none() {
    // Regression: a stream that ends via DATA(END_STREAM) — the
    // non-trailers termination shape — must surface `trailers() == None`
    // rather than blocking forever. The wire reader drops the
    // trailers oneshot when it sees END_STREAM, so the receiver's
    // recv() returns Err and we map that to None.
    let client = pair(|_req| {
        Box::pin(async move {
            ServerResponse::new(200).with_body(OutgoingBody::once(Bytes::from_static(b"hi")))
        })
    })
    .await;

    let resp = client.request(ClientRequest::get("/")).await.unwrap();
    let mut body = resp.body;
    drain_body(&mut body).await;
    assert!(body.trailers().await.is_none());
}

/// Non-consuming drain helper. `IncomingBody::collect` takes self
/// by value — to drain-then-call-trailers in one test, we walk
/// `next_chunk` here instead.
async fn drain_body(body: &mut p2claw_translator::IncomingBody) -> bytes::Bytes {
    let mut out = bytes::BytesMut::new();
    while let Some(chunk) = body.next_chunk().await {
        out.extend_from_slice(&chunk);
    }
    out.freeze()
}

#[tokio::test]
async fn response_with_duplicate_headers() {
    // Duplicate `set-cookie` headers must survive the round trip.
    let client = pair(|_req| {
        Box::pin(async move {
            ServerResponse::new(200)
                .header("set-cookie", "a=1; Path=/")
                .header("set-cookie", "b=2; Path=/; HttpOnly")
        })
    })
    .await;

    let resp = client.request(ClientRequest::get("/")).await.unwrap();
    let set_cookies: Vec<_> = resp
        .headers
        .iter()
        .filter(|(k, _)| &k[..] == b"set-cookie")
        .map(|(_, v)| v.clone())
        .collect();
    assert_eq!(set_cookies.len(), 2);
    assert_eq!(&set_cookies[0][..], b"a=1; Path=/");
    assert_eq!(&set_cookies[1][..], b"b=2; Path=/; HttpOnly");
}

/// Two concurrent never-ending response streams sharing one
/// translator. Verifies under bench-grade fairness that the writer
/// does NOT permanently wedge either stream — both receive at least
/// `MIN_CHUNKS_PER_STREAM` within the deadline. The concern is that
/// the single bounded `mpsc::channel::<Frame>(64)` + single-writer
/// pipeline could HOL one stream's frames behind the other's slow
/// drain. tokio's mpsc semantics make a permanent
/// wedge unlikely (multiple senders share fairly under FIFO wake),
/// but a path that LOOKS wedged can still emerge from severe rate
/// degradation; this test pins the no-wedge property explicitly.
///
/// The test runs in real time with `tokio::time::sleep(50ms)`
/// between chunks (deterministic-enough at this scale; not a
/// `pause()` test because the sleep is also acting as the
/// "natural-rate" SSE-event generator).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_streams_both_progress() {
    use std::time::Instant;

    // Per-stream chunk count we'll demand each stream produces.
    // Production SSE: an "event" arrives every ~tens of ms; this
    // mirrors that.
    const MIN_CHUNKS_PER_STREAM: usize = 20;
    // Chunks per stream the handler will emit. Higher than the
    // assertion floor so each stream has headroom to keep producing
    // while the other catches up.
    const HANDLER_CHUNKS: usize = 40;
    const CHUNK_INTERVAL: Duration = Duration::from_millis(20);

    let client = pair(|req| {
        Box::pin(async move {
            // Per-stream body: emits CHUNK every 20ms, tagged with
            // the request path so the client can attribute by stream.
            let path = req.path.clone();
            let chunks = stream::unfold(0usize, move |i| {
                let path = path.clone();
                async move {
                    if i >= HANDLER_CHUNKS {
                        return None;
                    }
                    tokio::time::sleep(CHUNK_INTERVAL).await;
                    let payload = format!(
                        "stream={} chunk={i}\n",
                        std::str::from_utf8(&path).unwrap_or("?")
                    );
                    Some((Bytes::from(payload), i + 1))
                }
            });
            ServerResponse::new(200)
                .header("content-type", "text/event-stream")
                .with_body(OutgoingBody::stream(chunks))
        })
    })
    .await;

    let client = Arc::new(client);

    // Two concurrent never-ending requests.
    let stream_a = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let req = ClientRequest::get(Bytes::from_static(b"/a"));
            let resp = client.request(req).await.expect("request a");
            let mut chunks = Vec::new();
            let mut body = resp.body;
            let start = Instant::now();
            while let Some(c) = body.next_chunk().await {
                chunks.push((c, start.elapsed()));
                if chunks.len() >= MIN_CHUNKS_PER_STREAM {
                    break;
                }
            }
            chunks
        })
    };
    let stream_b = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let req = ClientRequest::get(Bytes::from_static(b"/b"));
            let resp = client.request(req).await.expect("request b");
            let mut chunks = Vec::new();
            let mut body = resp.body;
            let start = Instant::now();
            while let Some(c) = body.next_chunk().await {
                chunks.push((c, start.elapsed()));
                if chunks.len() >= MIN_CHUNKS_PER_STREAM {
                    break;
                }
            }
            chunks
        })
    };

    // Deadline: each stream emits MIN_CHUNKS at 20ms intervals →
    // 400 ms minimum. Allow generous headroom for scheduler +
    // translator framing latency without hiding a permanent wedge.
    let deadline = Duration::from_secs(8);

    let chunks_a = tokio::time::timeout(deadline, stream_a)
        .await
        .expect("stream a must not wedge")
        .expect("stream a task panicked");
    let chunks_b = tokio::time::timeout(deadline, stream_b)
        .await
        .expect("stream b must not wedge")
        .expect("stream b task panicked");

    assert!(
        chunks_a.len() >= MIN_CHUNKS_PER_STREAM,
        "stream a delivered only {}/{} chunks",
        chunks_a.len(),
        MIN_CHUNKS_PER_STREAM
    );
    assert!(
        chunks_b.len() >= MIN_CHUNKS_PER_STREAM,
        "stream b delivered only {}/{} chunks",
        chunks_b.len(),
        MIN_CHUNKS_PER_STREAM
    );

    // Per-stream max inter-chunk gap: if HOL happens, one stream
    // sees a large gap while the other races. Threshold = 5× the
    // source 20 ms cadence; anything larger indicates head-of-line
    // stalling.
    let max_gap = |chunks: &[(Bytes, Duration)]| -> Duration {
        chunks
            .windows(2)
            .map(|w| w[1].1.saturating_sub(w[0].1))
            .max()
            .unwrap_or(Duration::ZERO)
    };
    let gap_a = max_gap(&chunks_a);
    let gap_b = max_gap(&chunks_b);
    assert!(
        gap_a < Duration::from_millis(500),
        "stream a hit a {gap_a:?} inter-chunk gap — head-of-line stall?"
    );
    assert!(
        gap_b < Duration::from_millis(500),
        "stream b hit a {gap_b:?} inter-chunk gap — head-of-line stall?"
    );
}

/// The load-bearing experiment: **healthy stream's chunks must keep
/// arriving while a sibling stream's consumer is completely
/// stalled.** The user-visible symptom is "two SSE streams jam";
/// the failure mode requires that one stream's downstream
/// consumer is slow/stalled (the SSE page reading one stream and
/// ignoring the other, or the wrapper's per-stream queue stuck).
///
/// On the box's side, the `IncomingBody::channel(N)` per-stream
/// receive queue on the CLIENT (visitor) end is what fills first.
/// Once full, the client's wire reader stops calling
/// `body_tx.send().await` for that stream → the BOX'S writer
/// senses pressure only indirectly (no inbound DATA frames clearing
/// flow-control credits). On the OUTBOUND side, the box's
/// `stream_outgoing_body` for the stalled stream's response body
/// keeps trying to push frames; those queue into the shared
/// `out_tx`. The healthy stream's pump shares that same `out_tx`.
/// If mpsc fairness holds, the healthy stream still gets its
/// share of slots when the writer drains. If it doesn't — or if a
/// future change breaks the shared-channel semantics — this test
/// catches it.
///
/// Pre-fix: BOTH streams must still progress (no permanent wedge
/// of the healthy stream behind the stalled one). The healthy
/// stream's `MIN_CHUNKS` floor is what asserts that property
/// directly. The stalled stream is deliberately read-once-then-
/// dropped, then re-asserted not-to-have-blocked sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_on_one_stream_does_not_wedge_sibling() {
    use std::time::Instant;

    const MIN_HEALTHY_CHUNKS: usize = 20;
    const HANDLER_CHUNKS: usize = 200;
    const CHUNK_INTERVAL: Duration = Duration::from_millis(10);

    let client = pair(|req| {
        Box::pin(async move {
            let path = req.path.clone();
            let chunks = stream::unfold(0usize, move |i| {
                let path = path.clone();
                async move {
                    if i >= HANDLER_CHUNKS {
                        return None;
                    }
                    tokio::time::sleep(CHUNK_INTERVAL).await;
                    // Payload size is meaningful: > the typical
                    // IncomingBody::channel cap × frame slot, so a
                    // stalled consumer pegs the per-stream queue.
                    let payload = vec![b'X'; 8 * 1024];
                    let mut buf = Vec::with_capacity(payload.len() + 32);
                    buf.extend_from_slice(
                        format!(
                            "stream={} chunk={i}: ",
                            std::str::from_utf8(&path).unwrap_or("?")
                        )
                        .as_bytes(),
                    );
                    buf.extend_from_slice(&payload);
                    Some((Bytes::from(buf), i + 1))
                }
            });
            ServerResponse::new(200)
                .header("content-type", "text/event-stream")
                .with_body(OutgoingBody::stream(chunks))
        })
    })
    .await;

    let client = Arc::new(client);

    // STALLED stream: take exactly one chunk, then drop the body
    // without further reads. The per-stream `IncomingBody::channel`
    // will fill; subsequent body deliveries on the wire credit-
    // back-pressure the box-side pump for THIS stream id only.
    let stalled = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let req = ClientRequest::get(Bytes::from_static(b"/stalled"));
            let resp = client.request(req).await.expect("request stalled");
            let mut body = resp.body;
            let _first = body
                .next_chunk()
                .await
                .expect("at least one chunk for stalled");
            // DO NOT drain further. Hold the body alive (preventing
            // a clean cancel) but never call `next_chunk` again,
            // simulating a page reading SSE then becoming
            // unresponsive (paused tab, full ReadableStream queue,
            // etc.). Sleep covers the healthy stream's full run.
            tokio::time::sleep(Duration::from_secs(4)).await;
            drop(body);
        })
    };

    // HEALTHY stream: drain at line rate. Must complete in real
    // time despite the stalled sibling.
    let healthy = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let req = ClientRequest::get(Bytes::from_static(b"/healthy"));
            let resp = client.request(req).await.expect("request healthy");
            let mut body = resp.body;
            let mut chunks = Vec::new();
            let start = Instant::now();
            while let Some(c) = body.next_chunk().await {
                chunks.push((c, start.elapsed()));
                if chunks.len() >= MIN_HEALTHY_CHUNKS {
                    break;
                }
            }
            chunks
        })
    };

    // Healthy stream's natural runtime ≈ MIN_HEALTHY_CHUNKS × 10ms
    // = 200 ms. Allow 6s headroom — anything beyond is a real wedge.
    let healthy_deadline = Duration::from_secs(6);
    let healthy_chunks = tokio::time::timeout(healthy_deadline, healthy)
        .await
        .expect("healthy stream must not wedge when sibling consumer stalls")
        .expect("healthy task panicked");
    assert!(
        healthy_chunks.len() >= MIN_HEALTHY_CHUNKS,
        "healthy stream delivered only {}/{} chunks while sibling was stalled",
        healthy_chunks.len(),
        MIN_HEALTHY_CHUNKS
    );

    // Wait for the stalled task to release the body so the wire
    // can fully tear down before the test exits.
    let _ = tokio::time::timeout(Duration::from_secs(8), stalled).await;
}

/// POST with a request body whose handler reads it to completion
/// must observe end-of-body. If the box's wire reader closed the
/// body channel on DATA(END_STREAM) but left the trailers oneshot
/// alive, any handler awaiting trailers after draining the body —
/// e.g. the agent's `pump_incoming_to_hyper` translating the request
/// body into a hyper StreamBody — would block forever on
/// `trailers().await`, and every body-reading POST would hang until
/// the gateway timeout.
///
/// This test reproduces the path: client sends a POST whose body
/// terminates with the canonical DATA(END_STREAM) shape (a non-
/// empty DATA chunk followed by an empty DATA frame with the
/// END_STREAM flag — exactly what `bootstrap/src/translator/
/// client.ts::pumpRequestBody` emits). The handler reads the
/// body via `next_chunk` until `None`, then calls
/// `trailers().await` and asserts it resolves to `None` within a
/// bounded deadline.
///
/// Pre-fix: trailers().await hangs forever → test timeouts.
/// Post-fix: trailers() resolves promptly to None.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_body_terminator_completes_trailers_to_none() {
    use bytes::BytesMut;

    let body_done = Arc::new(tokio::sync::Notify::new());
    let trailers_done = Arc::new(tokio::sync::Notify::new());
    let received_body = Arc::new(tokio::sync::Mutex::new(BytesMut::new()));
    let trailers_value = Arc::new(tokio::sync::Mutex::new(None));

    let body_done_h = Arc::clone(&body_done);
    let trailers_done_h = Arc::clone(&trailers_done);
    let received_body_h = Arc::clone(&received_body);
    let trailers_value_h = Arc::clone(&trailers_value);

    let client = pair(move |mut req| {
        let body_done_h = Arc::clone(&body_done_h);
        let trailers_done_h = Arc::clone(&trailers_done_h);
        let received_body_h = Arc::clone(&received_body_h);
        let trailers_value_h = Arc::clone(&trailers_value_h);
        Box::pin(async move {
            // Drain the request body — the load-bearing call that
            // hangs pre-fix.
            let mut buf = BytesMut::new();
            while let Some(chunk) = req.body.next_chunk().await {
                buf.extend_from_slice(&chunk);
            }
            *received_body_h.lock().await = buf;
            body_done_h.notify_one();
            // Now await trailers — the call that *actually* hangs
            // pre-fix because trailers_tx isn't dropped on
            // DATA(END_STREAM).
            let trailers = req.body.trailers().await;
            *trailers_value_h.lock().await = trailers;
            trailers_done_h.notify_one();
            ServerResponse::new(200).with_body(OutgoingBody::once(Bytes::from_static(b"ok")))
        })
    })
    .await;

    // Build a POST with a body so the bootstrap client's
    // body-pump shape exercises DATA + DATA(END_STREAM).
    let payload = Bytes::from_static(b"hello chat backend");
    let payload_for_assert = payload.clone();
    let client_arc = Arc::new(client);
    let client_for_task = Arc::clone(&client_arc);
    // Drive the request in a separate task: pre-fix the handler
    // hangs on `trailers().await`, which blocks `send_response`,
    // which blocks `client.request().await`. The test must check
    // handler-side liveness independently of whether the response
    // ever arrives.
    let req_handle = tokio::spawn(async move {
        let req = ClientRequest::post(
            Bytes::from_static(b"/api/chat"),
            OutgoingBody::once(payload),
        );
        client_for_task.request(req).await
    });

    // Both notifications must fire within a tight deadline. Pre-
    // fix, `trailers_done` never fires — discriminating
    // assertion.
    tokio::time::timeout(Duration::from_secs(2), body_done.notified())
        .await
        .expect("handler body drain must complete promptly");
    tokio::time::timeout(Duration::from_secs(2), trailers_done.notified())
        .await
        .expect("handler trailers().await must resolve promptly (pre-fix: hangs forever)");

    // Sanity: body fully delivered, no spurious trailers.
    assert_eq!(
        received_body.lock().await.as_ref(),
        payload_for_assert.as_ref()
    );
    assert!(trailers_value.lock().await.is_none());

    // Sanity: response also flows — only reachable post-fix
    // because the handler now actually returns.
    let resp = tokio::time::timeout(Duration::from_secs(2), req_handle)
        .await
        .expect("request must complete after fix unblocks the handler")
        .expect("request task join")
        .expect("request error");
    assert_eq!(resp.status, 200);
    let mut body = resp.body;
    let chunk = body.next_chunk().await.expect("response body");
    assert_eq!(chunk.as_ref(), b"ok");
}

/// Box side of a visitor-initiated stream cancel:
/// `Frame::Err { code: CANCEL }` stops the box's response pump
/// promptly and tears down the handler task (no leak). Box-side
/// wire shape for the visitor's runaway-stream rescue: when a
/// client drops the `ClientResponse`, `StreamCancelGuard` emits
/// `Frame::Err { stream_id, code: ErrorCode::CANCEL, message }`;
/// the box must abort `stream_outgoing_body` mid-pump and let
/// the handler-task complete so the upstream connection (and
/// any per-stream resources) clean up.
///
/// Test shape: handler emits chunks at a steady cadence and
/// increments a counter per chunk produced. Client reads a few
/// chunks then drops the response → CANCEL fires on the wire.
/// Assert the producer counter stops climbing within a bounded
/// window — proof the pump observed cancel and stopped pulling
/// from the body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visitor_cancel_stops_outbound_response_pump() {
    use std::sync::atomic::{AtomicUsize as StdAtomicUsize, Ordering as StdOrdering};

    let produced = Arc::new(StdAtomicUsize::new(0));
    let produced_h = Arc::clone(&produced);

    let client = pair(move |_req| {
        let produced_h = Arc::clone(&produced_h);
        Box::pin(async move {
            // Never-ending stream; each chunk bumps the producer
            // counter. Sleep simulates a real backend's per-event
            // cadence (SSE-shape).
            let chunks = stream::unfold(produced_h, |counter| async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                counter.fetch_add(1, StdOrdering::SeqCst);
                Some((Bytes::from_static(b"x"), counter))
            });
            ServerResponse::new(200)
                .header("content-type", "text/event-stream")
                .with_body(OutgoingBody::stream(chunks))
        })
    })
    .await;

    let req = ClientRequest::get(Bytes::from_static(b"/stream"));
    let resp = client.request(req).await.expect("request");

    // Read a few chunks to confirm the stream is live.
    let mut body = resp.body;
    for _ in 0..3 {
        let chunk = tokio::time::timeout(Duration::from_secs(2), body.next_chunk())
            .await
            .expect("first chunks must arrive promptly")
            .expect("body chunk");
        assert_eq!(chunk.as_ref(), b"x");
    }

    // Drop the response → `StreamCancelGuard` emits CANCEL on
    // the wire → box's Frame::Err handler flips the per-stream
    // cancel atomic → pump returns at the next iteration check.
    drop(body);

    // Wait for any in-flight production to finish, then snapshot.
    // The pump checks `cancelled()` once per loop iteration
    // (i.e. between body chunks), so allow up to ~3 chunk
    // intervals + scheduler slop for the abort to land.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after_cancel = produced.load(StdOrdering::SeqCst);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after_wait = produced.load(StdOrdering::SeqCst);

    assert_eq!(
        after_cancel,
        after_wait,
        "producer should have stopped after CANCEL; it produced {} more chunks \
         in the 500ms post-cancel window (cancel atomic not propagating)",
        after_wait - after_cancel
    );
    // Sanity: producer actually ran before cancel.
    assert!(
        after_cancel >= 3,
        "producer only ran {after_cancel} times — test setup broken"
    );
}

/// Server emits a few body chunks then a deferred-error → wire emits
/// `Frame::Err` mid-body. Client's `IncomingBody::next_chunk` drains
/// the chunks, returns `None`, and then `IncomingBody::error()`
/// resolves to `Some((code, message))` — distinguishing this from a
/// clean end-of-stream. The edge tunnel consumes this signal to emit
/// a visible abort to the visitor instead of silent FIN-after-
/// truncation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_stream_frame_err_surfaces_via_incoming_body_error() {
    use p2claw_translator::ErrorCode;

    let client = pair(|_req| {
        Box::pin(async move {
            // Three known chunks, then deferred error fires.
            let chunks = vec![
                Bytes::from_static(b"chunk-1"),
                Bytes::from_static(b"chunk-2"),
                Bytes::from_static(b"chunk-3"),
            ];
            let body_stream = stream::iter(chunks);

            let (err_tx, err_rx) = tokio::sync::oneshot::channel::<(ErrorCode, Bytes)>();
            // Fire the error after a short delay so the body chunks
            // race ahead and the receiver hits next_chunk None →
            // error() resolves to Some, not the response-tx Cancelled
            // path.
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = err_tx.send((
                    ErrorCode::LOCAL_APP_DOWN,
                    Bytes::from_static(b"simulated upstream death"),
                ));
            });

            ServerResponse::new(200)
                .header("content-type", "application/octet-stream")
                .with_body(OutgoingBody::stream(body_stream))
                .with_deferred_error(err_rx)
        })
    })
    .await;

    let resp = client
        .request(ClientRequest::get(Bytes::from_static(b"/stream")))
        .await
        .expect("response head should land before deferred-error fires");
    assert_eq!(resp.status, 200);

    // Drain body — all three chunks must arrive, then None.
    let mut body = resp.body;
    let mut chunks_received = Vec::new();
    while let Some(c) = tokio::time::timeout(Duration::from_secs(2), body.next_chunk())
        .await
        .expect("body drain must not hang")
    {
        chunks_received.push(c);
    }
    assert_eq!(
        chunks_received.len(),
        3,
        "all three body chunks must arrive"
    );
    assert_eq!(chunks_received[0].as_ref(), b"chunk-1");

    // Body is exhausted — error() resolves to Some((code, message)).
    let err = tokio::time::timeout(Duration::from_secs(2), body.error())
        .await
        .expect("error() must resolve")
        .expect("body should report mid-stream Frame::Err, got None (clean End)");
    assert_eq!(err.0, ErrorCode::LOCAL_APP_DOWN);
    assert_eq!(err.1.as_ref(), b"simulated upstream death");

    // Idempotent: second call returns None (oneshot already consumed).
    assert!(body.error().await.is_none(), "error() must be idempotent");
}

/// Symmetric to the test above but proves the *clean* path stays
/// quiet — a body that ends naturally (no deferred error fired) must
/// have `error()` return `None`, not Some. Pins the regression that
/// the edge unfold doesn't spuriously abort clean responses just
/// because the oneshot exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_end_of_stream_leaves_incoming_body_error_none() {
    let client = pair(|_req| {
        Box::pin(async move {
            ServerResponse::new(200).with_body(OutgoingBody::once(Bytes::from_static(b"done")))
        })
    })
    .await;

    let resp = client
        .request(ClientRequest::get(Bytes::from_static(b"/")))
        .await
        .expect("request");

    let mut body = resp.body;
    let mut all = Vec::new();
    while let Some(c) = body.next_chunk().await {
        all.extend_from_slice(&c);
    }
    assert_eq!(&all[..], b"done");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), body.error())
            .await
            .expect("error() must resolve")
            .is_none(),
        "clean End must leave error() returning None"
    );
}
