//! Perf smoke measurements for the multiplexed writer path. Not run
//! in CI — invoke explicitly:
//!
//! ```sh
//! cargo test --release -p p2claw-translator --test perf_smoke -- --ignored --nocapture
//! ```
//!
//! Two scenarios:
//! - `single_stream_throughput`: one stream pushing a large body over
//!   an unthrottled in-memory transport. Regression guard for
//!   per-frame overhead on the hot send path.
//! - `light_latency_under_heavy_load`: a heavy stream saturating a
//!   rate-limited transport while small requests measure end-to-end
//!   latency — the cross-stream head-of-line number.

use std::time::{Duration, Instant};

use bytes::Bytes;
use p2claw_translator::{serve, ClientConnection, OutgoingBody, ServerRequest, ServerResponse};

const HEAVY_BODY: usize = 64 * 1024 * 1024; // 64 MiB
const LIGHT_BODY: usize = 512;

async fn handler(req: ServerRequest) -> ServerResponse {
    let body = if req.path.starts_with(b"/heavy") {
        OutgoingBody::once(Bytes::from(vec![0xAAu8; HEAVY_BODY]))
    } else {
        OutgoingBody::once(Bytes::from(vec![0xBBu8; LIGHT_BODY]))
    };
    ServerResponse {
        status: 200,
        headers: vec![],
        body,
        trailers: None,
        trailers_rx: None,
        error_rx: None,
    }
}

async fn drain(resp: &mut p2claw_translator::ClientResponse) -> usize {
    let mut total = 0;
    while let Some(chunk) = resp.body.next_chunk().await {
        total += chunk.len();
    }
    total
}

/// Copy bytes between two duplex halves at a capped rate, modeling a
/// slow transport so the writer's body lane actually backs up.
async fn rate_limited_pump(
    mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    bytes_per_10ms: usize,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; bytes_per_10ms];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf measurement, run explicitly"]
async fn single_stream_throughput() {
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let _ = serve(server_io, handler).await;
    });
    let client = ClientConnection::spawn(client_io);

    // Warm-up.
    let mut resp = client
        .request(p2claw_translator::ClientRequest::get("/light"))
        .await
        .unwrap();
    drain(&mut resp).await;

    let start = Instant::now();
    let mut resp = client
        .request(p2claw_translator::ClientRequest::get("/heavy"))
        .await
        .unwrap();
    let got = drain(&mut resp).await;
    let elapsed = start.elapsed();
    assert_eq!(got, HEAVY_BODY);

    let mbps = (HEAVY_BODY as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    println!("single_stream_throughput: {HEAVY_BODY} bytes in {elapsed:?} = {mbps:.0} MiB/s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf measurement, run explicitly"]
async fn light_latency_under_heavy_load() {
    // server <-> pump <-> client, pump caps the server->client
    // direction at ~3 MiB/s so the writer's lane fills.
    let (server_io, pump_side_a) = tokio::io::duplex(64 * 1024);
    let (pump_side_b, client_io) = tokio::io::duplex(64 * 1024);
    let (a_read, a_write) = tokio::io::split(pump_side_a);
    let (b_read, b_write) = tokio::io::split(pump_side_b);
    tokio::spawn(rate_limited_pump(a_read, b_write, 32 * 1024)); // server->client throttled
    tokio::spawn(rate_limited_pump(b_read, a_write, 32 * 1024)); // client->server (requests are tiny)

    tokio::spawn(async move {
        let _ = serve(server_io, handler).await;
    });
    let client = ClientConnection::spawn(client_io);

    // Warm-up.
    let mut resp = client
        .request(p2claw_translator::ClientRequest::get("/light"))
        .await
        .unwrap();
    drain(&mut resp).await;

    // Kick off the heavy stream and let it saturate the pipe.
    let heavy_client = client.clone();
    let heavy = tokio::spawn(async move {
        let mut resp = heavy_client
            .request(p2claw_translator::ClientRequest::get("/heavy"))
            .await
            .unwrap();
        drain(&mut resp).await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Measure light request latency while the heavy stream runs.
    let mut latencies = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let mut resp = client
            .request(p2claw_translator::ClientRequest::get("/light"))
            .await
            .unwrap();
        let got = drain(&mut resp).await;
        assert_eq!(got, LIGHT_BODY);
        latencies.push(start.elapsed());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(heavy); // don't wait for the 64 MiB to finish at 3 MiB/s

    let max = latencies.iter().max().unwrap();
    let avg: Duration = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    println!("light_latency_under_heavy_load: samples={latencies:?}");
    println!("light_latency_under_heavy_load: avg={avg:?} max={max:?}");
}
