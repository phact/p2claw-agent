//! Client side of the `email` stream the box opens on its coord
//! connection: one request frame, one response frame, and for `fetch`
//! the sealed bytes as raw length-prefixed frames after the response.
//!
//! Generic over the stream halves so the protocol can be exercised
//! against an in-memory peer; production hands it iroh's QUIC streams.

use p2claw_control_proto::{
    decode_frame_length, encode_frame, EmailRejections, EmailRequest, EmailResponse, QueuedEmail,
    StreamHelloEnvelope, StreamKind,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest sealed message the box will buffer: Cloudflare caps mail
/// at 25 MiB, plus sealing overhead.
pub const MAX_SEALED_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing: {0}")]
    Framing(#[from] p2claw_control_proto::FramingError),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("coord: {0}")]
    Coord(String),
    #[error("sealed message of {0} bytes exceeds the {MAX_SEALED_BYTES}-byte cap")]
    TooLarge(u64),
}

pub struct EmailStream<R, W> {
    recv: R,
    send: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> EmailStream<R, W> {
    /// Wrap a freshly opened bidirectional stream and send the stream
    /// hello that names it an email stream.
    pub async fn open(send: W, recv: R) -> Result<Self, StreamError> {
        let mut s = Self { recv, send };
        s.write_frame(
            StreamHelloEnvelope::new(StreamKind::Email)
                .to_json()
                .as_bytes(),
        )
        .await?;
        Ok(s)
    }

    pub async fn list(&mut self) -> Result<Vec<QueuedEmail>, StreamError> {
        match self.call(&EmailRequest::List).await? {
            EmailResponse::List { items } => Ok(items),
            other => Err(unexpected("list", &other)),
        }
    }

    /// The sealed bytes queued under `id`.
    pub async fn fetch(&mut self, id: &str) -> Result<Vec<u8>, StreamError> {
        let size = match self
            .call(&EmailRequest::Fetch { id: id.to_string() })
            .await?
        {
            EmailResponse::Fetch { id: got, size } if got == id => size,
            EmailResponse::Fetch { id: got, .. } => {
                return Err(StreamError::Protocol(format!(
                    "fetch answered for `{got}`, asked for `{id}`"
                )))
            }
            other => return Err(unexpected("fetch", &other)),
        };
        if size > MAX_SEALED_BYTES {
            return Err(StreamError::TooLarge(size));
        }
        let mut blob = Vec::with_capacity(size as usize);
        while (blob.len() as u64) < size {
            let frame = self.read_frame().await?;
            if blob.len() as u64 + frame.len() as u64 > size {
                return Err(StreamError::Protocol(format!(
                    "fetch body overran the announced {size} bytes"
                )));
            }
            if frame.is_empty() {
                return Err(StreamError::Protocol(
                    "empty frame inside fetch body".into(),
                ));
            }
            blob.extend_from_slice(&frame);
        }
        Ok(blob)
    }

    pub async fn ack(&mut self, id: &str) -> Result<(), StreamError> {
        match self.call(&EmailRequest::Ack { id: id.to_string() }).await? {
            EmailResponse::Ack { id: got } if got == id => Ok(()),
            EmailResponse::Ack { id: got } => Err(StreamError::Protocol(format!(
                "ack answered for `{got}`, asked for `{id}`"
            ))),
            other => Err(unexpected("ack", &other)),
        }
    }

    pub async fn rejected(&mut self) -> Result<EmailRejections, StreamError> {
        match self.call(&EmailRequest::Rejected).await? {
            EmailResponse::Rejected(r) => Ok(r),
            other => Err(unexpected("rejected", &other)),
        }
    }

    /// Close the sending half; coord ends its side after the last
    /// response.
    pub async fn finish(mut self) -> Result<(), StreamError> {
        self.send.shutdown().await?;
        Ok(())
    }

    async fn call(&mut self, req: &EmailRequest) -> Result<EmailResponse, StreamError> {
        let json = serde_json::to_vec(req).map_err(|e| StreamError::Protocol(e.to_string()))?;
        self.write_frame(&json).await?;
        let frame = self.read_frame().await?;
        let resp: EmailResponse = serde_json::from_slice(&frame)
            .map_err(|e| StreamError::Protocol(format!("response: {e}")))?;
        if let EmailResponse::Error { message } = resp {
            return Err(StreamError::Coord(message));
        }
        Ok(resp)
    }

    async fn write_frame(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        let frame = encode_frame(payload)?;
        self.send.write_all(&frame).await?;
        self.send.flush().await?;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>, StreamError> {
        let mut hdr = [0u8; 4];
        self.recv.read_exact(&mut hdr).await?;
        let len = decode_frame_length(hdr)?;
        let mut buf = vec![0u8; len];
        self.recv.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

fn unexpected(op: &str, got: &EmailResponse) -> StreamError {
    let kind = match got {
        EmailResponse::List { .. } => "list",
        EmailResponse::Fetch { .. } => "fetch",
        EmailResponse::Ack { .. } => "ack",
        EmailResponse::Rejected(_) => "rejected",
        EmailResponse::Error { .. } => "error",
    };
    StreamError::Protocol(format!("{op} answered with a {kind} response"))
}

/// An in-memory stand-in for coord's side of the email stream, for
/// tests of the client and the drain loop.
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use p2claw_control_proto::{
        decode_frame_length, encode_frame, EmailRejections, EmailRequest, EmailResponse,
        QueuedEmail, StreamHelloEnvelope, StreamKind, MAX_FRAME_BYTES,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// What coord holds for the box: queued items plus their sealed
    /// bytes, and a log of every request it answered.
    #[derive(Default)]
    pub struct Queue {
        pub items: Vec<QueuedEmail>,
        pub blobs: BTreeMap<String, Vec<u8>>,
        pub rejections: EmailRejections,
        pub acked: Vec<String>,
        pub requests: Vec<EmailRequest>,
        /// Frame size for fetch bodies; defaults to the protocol max.
        pub chunk: usize,
        /// Answer `fetch` for these ids with an error frame.
        pub fail_fetch: Vec<String>,
    }

    pub type Shared = Arc<Mutex<Queue>>;

    /// Serve one email stream over a duplex pair; returns the box's
    /// halves. The server task runs until the box closes its send
    /// side.
    pub fn serve(queue: Shared) -> (DuplexStream, DuplexStream) {
        let (box_send, mut srv_recv) = tokio::io::duplex(64 * 1024);
        let (mut srv_send, box_recv) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let hello = read_frame(&mut srv_recv).await.expect("stream hello");
            let hello = StreamHelloEnvelope::from_json(std::str::from_utf8(&hello).unwrap())
                .expect("hello json");
            assert_eq!(hello.kind, StreamKind::Email);
            while let Ok(frame) = read_frame(&mut srv_recv).await {
                let req: EmailRequest = serde_json::from_slice(&frame).expect("request json");
                let (resp, body) = {
                    let mut q = queue.lock().unwrap();
                    q.requests.push(req.clone());
                    match req {
                        EmailRequest::List => (
                            EmailResponse::List {
                                items: q
                                    .items
                                    .iter()
                                    .filter(|i| !q.acked.contains(&i.id))
                                    .cloned()
                                    .collect(),
                            },
                            None,
                        ),
                        EmailRequest::Fetch { id } => {
                            if q.fail_fetch.contains(&id) {
                                (
                                    EmailResponse::Error {
                                        message: "storage".into(),
                                    },
                                    None,
                                )
                            } else {
                                match q.blobs.get(&id) {
                                    Some(b) => (
                                        EmailResponse::Fetch {
                                            id,
                                            size: b.len() as u64,
                                        },
                                        Some(b.clone()),
                                    ),
                                    None => (
                                        EmailResponse::Error {
                                            message: format!("no such message {id}"),
                                        },
                                        None,
                                    ),
                                }
                            }
                        }
                        EmailRequest::Ack { id } => {
                            q.acked.push(id.clone());
                            (EmailResponse::Ack { id }, None)
                        }
                        EmailRequest::Rejected => {
                            (EmailResponse::Rejected(q.rejections.clone()), None)
                        }
                    }
                };
                let chunk = {
                    let c = queue.lock().unwrap().chunk;
                    if c == 0 {
                        MAX_FRAME_BYTES
                    } else {
                        c
                    }
                };
                write_frame(&mut srv_send, &serde_json::to_vec(&resp).unwrap()).await;
                if let Some(body) = body {
                    for part in body.chunks(chunk) {
                        write_frame(&mut srv_send, part).await;
                    }
                }
            }
        });
        (box_send, box_recv)
    }

    async fn read_frame(r: &mut DuplexStream) -> std::io::Result<Vec<u8>> {
        let mut hdr = [0u8; 4];
        r.read_exact(&mut hdr).await?;
        let len = decode_frame_length(hdr).map_err(std::io::Error::other)?;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn write_frame(w: &mut DuplexStream, payload: &[u8]) {
        w.write_all(&encode_frame(payload).unwrap()).await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{self, Queue};
    use super::*;
    use std::sync::{Arc, Mutex};

    fn queued(id: &str, size: u64) -> QueuedEmail {
        QueuedEmail {
            id: id.into(),
            received_at: 1,
            size,
            expired: false,
            summary_b64: String::new(),
        }
    }

    #[tokio::test]
    async fn list_fetch_ack_rejected_roundtrip() {
        let blob: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let q = Arc::new(Mutex::new(Queue {
            items: vec![queued("m_1", blob.len() as u64)],
            blobs: [("m_1".to_string(), blob.clone())].into(),
            chunk: 100_000,
            ..Default::default()
        }));
        q.lock().unwrap().rejections.admitted_today = 3;
        let (send, recv) = fake::serve(Arc::clone(&q));
        let mut s = EmailStream::open(send, recv).await.unwrap();

        let items = s.list().await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(s.fetch("m_1").await.unwrap(), blob);
        s.ack("m_1").await.unwrap();
        assert!(s.list().await.unwrap().is_empty());
        assert_eq!(s.rejected().await.unwrap().admitted_today, 3);
        s.finish().await.unwrap();

        let q = q.lock().unwrap();
        assert_eq!(q.acked, vec!["m_1"]);
        assert_eq!(q.requests.len(), 5);
    }

    #[tokio::test]
    async fn coord_error_frames_surface_as_coord_errors() {
        let q = Arc::new(Mutex::new(Queue::default()));
        let (send, recv) = fake::serve(Arc::clone(&q));
        let mut s = EmailStream::open(send, recv).await.unwrap();
        let err = s.fetch("m_missing").await.unwrap_err();
        assert!(matches!(err, StreamError::Coord(_)), "{err:?}");
    }

    #[tokio::test]
    async fn oversized_fetch_is_refused_before_reading() {
        let (mut peer_send, box_recv) = tokio::io::duplex(1024);
        let (box_send, _peer_recv) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let resp = EmailResponse::Fetch {
                id: "m_big".into(),
                size: MAX_SEALED_BYTES + 1,
            };
            peer_send
                .write_all(&encode_frame(&serde_json::to_vec(&resp).unwrap()).unwrap())
                .await
                .unwrap();
        });
        let mut s = EmailStream::open(box_send, box_recv).await.unwrap();
        let err = s.fetch("m_big").await.unwrap_err();
        assert!(matches!(err, StreamError::TooLarge(_)), "{err:?}");
        server.await.unwrap();
    }
}
