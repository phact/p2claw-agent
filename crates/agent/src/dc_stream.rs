//! Byte-stream adapter for WebRTC data channels.
//!
//! A data channel carries messages, not bytes: each `poll_write` on
//! `PollDataChannel` becomes one SCTP message, and SCTP refuses any
//! message larger than the association's max message size (64 KiB by
//! default, and less on some browsers). [`MessageSizeCap`] splits writes
//! so a single large frame is sent as several messages; receivers
//! decode frames from the concatenated byte stream, so frames may span
//! message boundaries.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest single data-channel message the box sends. 16 KiB is the
/// size every WebRTC implementation accepts without negotiation.
pub const DC_MAX_WRITE: usize = 16 * 1024;

/// Wraps a data-channel stream so no single write exceeds `max` bytes.
/// Reads pass through unchanged.
#[derive(Debug)]
pub struct MessageSizeCap<T> {
    inner: T,
    max: usize,
}

impl<T> MessageSizeCap<T> {
    /// Cap writes at [`DC_MAX_WRITE`].
    pub fn new(inner: T) -> Self {
        Self::with_max(inner, DC_MAX_WRITE)
    }

    /// Cap writes at `max` bytes (must be non-zero).
    pub fn with_max(inner: T, max: usize) -> Self {
        assert!(max > 0, "max write size must be non-zero");
        Self { inner, max }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for MessageSizeCap<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MessageSizeCap<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = buf.len().min(self.max);
        Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Records the size of every write it receives.
    #[derive(Default)]
    struct Recorder(Vec<usize>);

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.push(buf.len());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn large_write_is_split_into_capped_messages() {
        let mut w = MessageSizeCap::new(Recorder::default());
        w.write_all(&vec![0u8; 200 * 1024 + 5]).await.unwrap();
        let sizes = w.into_inner().0;
        assert!(sizes.iter().all(|&n| n <= DC_MAX_WRITE), "{sizes:?}");
        assert_eq!(sizes.iter().sum::<usize>(), 200 * 1024 + 5);
        assert_eq!(sizes.len(), 13);
    }

    #[tokio::test]
    async fn small_write_passes_through_whole() {
        let mut w = MessageSizeCap::new(Recorder::default());
        w.write_all(b"hello").await.unwrap();
        assert_eq!(w.into_inner().0, vec![5]);
    }
}
