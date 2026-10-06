//! Pull coord's queue into the inbox.
//!
//! Each queued item is fetched, opened with the box's X25519 secret
//! and stored, then acked so coord drops its copy. Expired items carry
//! only a sealed summary and become `expired` entries. An item that
//! can't be opened or parsed is acked anyway: it will never open
//! better later, and leaving it would block the queue. Only a local
//! storage failure stops the drain without acking, so the next
//! notification retries it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine as _;
use p2claw_email_proto::{open_message, open_summary, Kind};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use super::forwarding;
use super::inbox::{Inbox, InboxError};
use super::stream::{EmailStream, StreamError};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainReport {
    pub stored: usize,
    pub expired: usize,
    pub forwarding_requests: usize,
    /// Items acked without being stored (unopenable or malformed).
    pub dropped: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum DrainError {
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Inbox(#[from] InboxError),
}

/// Drain everything coord has queued. `secret` is the box's X25519
/// key; it is used here and never logged.
pub async fn drain<R, W>(
    stream: &mut EmailStream<R, W>,
    secret: &[u8; 32],
    inbox: &Inbox,
) -> Result<DrainReport, DrainError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut report = DrainReport::default();
    let items = stream.list().await?;
    for item in items {
        let id = item.id.as_str();
        if inbox.contains(id) {
            // Stored on an earlier pass whose ack never reached coord.
            stream.ack(id).await?;
            continue;
        }
        if item.expired {
            match B64_URL
                .decode(&item.summary_b64)
                .ok()
                .and_then(|blob| open_summary(secret, id, &blob).ok())
            {
                Some(summary) => {
                    inbox.record_expired(&summary).await?;
                    report.expired += 1;
                }
                None => {
                    warn!(id, "email: expired summary would not open; dropping");
                    report.dropped += 1;
                }
            }
            stream.ack(id).await?;
            continue;
        }

        let blob = match stream.fetch(id).await {
            Ok(b) => b,
            Err(e @ (StreamError::Coord(_) | StreamError::TooLarge(_))) => {
                warn!(id, error = %e, "email: fetch refused; dropping");
                report.dropped += 1;
                stream.ack(id).await?;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        match open_message(secret, id, &blob) {
            Ok((meta, raw)) if meta.id == id => match meta.kind {
                Kind::Message => {
                    inbox.store_message(&meta, &raw).await?;
                    report.stored += 1;
                }
                Kind::ForwardingRequest => {
                    let req = forwarding::request(id, meta.received_at, &raw, &meta.to);
                    if req.account.is_none() || req.link.is_none() {
                        warn!(
                            id,
                            has_account = req.account.is_some(),
                            has_link = req.link.is_some(),
                            "email: forwarding confirmation only partly understood"
                        );
                    }
                    inbox.store_forwarding_request(req).await?;
                    report.forwarding_requests += 1;
                }
            },
            Ok((meta, _)) => {
                warn!(id, inner = %meta.id, "email: sealed metadata names another id; dropping");
                report.dropped += 1;
            }
            Err(e) => {
                warn!(id, error = %e, "email: message would not open; dropping");
                report.dropped += 1;
            }
        }
        stream.ack(id).await?;
    }
    if report != DrainReport::default() {
        info!(
            stored = report.stored,
            expired = report.expired,
            forwarding_requests = report.forwarding_requests,
            dropped = report.dropped,
            "email: queue drained"
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::super::stream::fake::{self, Queue};
    use super::*;
    use p2claw_control_proto::QueuedEmail;
    use p2claw_email_proto::{
        generate_keypair, seal_message, seal_summary, Auth, Metadata, Summary,
    };
    use std::sync::{Arc, Mutex};

    fn meta(id: &str, kind: Kind) -> Metadata {
        Metadata {
            id: id.into(),
            kind,
            received_at: 1_791_126_131,
            to: "alias@p2claw.com".into(),
            envelope_from: "you@gmail.com".into(),
            from: "you@gmail.com".into(),
            forwarded_by: None,
            auth: Auth {
                dkim: "pass".into(),
                dkim_domain: Some("gmail.com".into()),
                arc: "none".into(),
            },
        }
    }

    fn summary(id: &str) -> Summary {
        Summary {
            id: id.into(),
            received_at: 1_791_000_000,
            from: "x@y.org".into(),
            subject: "missed".into(),
        }
    }

    fn queued(id: &str, size: u64, expired: bool, summary_b64: String) -> QueuedEmail {
        QueuedEmail {
            id: id.into(),
            received_at: 1,
            size,
            expired,
            summary_b64,
        }
    }

    const RAW: &[u8] = b"From: you@gmail.com\r\nSubject: hi\r\n\r\nbody\r\n";

    const CONFIRMATION: &str = "From: forwarding-noreply@google.com\r\n\
To: alias@p2claw.com\r\n\
Subject: Gmail Forwarding Confirmation - Receive Mail from acct@gmail.com\r\n\
X-Google-Address-Confirmation: 1\r\n\
\r\n\
acct@gmail.com has requested to automatically forward mail to alias@p2claw.com.\r\n\
https://mail-settings.google.com/mail/vf-secret-token\r\n";

    #[tokio::test]
    async fn drains_messages_expired_and_forwarding_requests() {
        let (sk, pk) = generate_keypair();
        let (_other_sk, other_pk) = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));

        let m1 = seal_message(&pk, &meta("m_1", Kind::Message), RAW).unwrap();
        let m2 = seal_message(
            &pk,
            &meta("m_2", Kind::ForwardingRequest),
            CONFIRMATION.as_bytes(),
        )
        .unwrap();
        // Sealed to someone else's key: must be dropped, not retried.
        let m3 = seal_message(&other_pk, &meta("m_3", Kind::Message), RAW).unwrap();
        let s4 = B64_URL.encode(seal_summary(&pk, &summary("m_4")).unwrap());
        let s5 = B64_URL.encode(seal_summary(&other_pk, &summary("m_5")).unwrap());

        let q = Arc::new(Mutex::new(Queue {
            items: vec![
                queued("m_1", m1.len() as u64, false, String::new()),
                queued("m_2", m2.len() as u64, false, String::new()),
                queued("m_3", m3.len() as u64, false, String::new()),
                queued("m_4", 0, true, s4),
                queued("m_5", 0, true, s5),
                queued("m_6", 10, false, String::new()),
            ],
            blobs: [
                ("m_1".to_string(), m1),
                ("m_2".to_string(), m2),
                ("m_3".to_string(), m3),
            ]
            .into(),
            chunk: 7,
            fail_fetch: vec!["m_6".into()],
            ..Default::default()
        }));
        let (send, recv) = fake::serve(Arc::clone(&q));
        let mut stream = EmailStream::open(send, recv).await.unwrap();

        let report = drain(&mut stream, &sk, &inbox).await.unwrap();
        assert_eq!(
            report,
            DrainReport {
                stored: 1,
                expired: 1,
                forwarding_requests: 1,
                dropped: 3,
            }
        );
        assert_eq!(
            q.lock().unwrap().acked,
            vec!["m_1", "m_2", "m_3", "m_4", "m_5", "m_6"],
            "everything is acked exactly once"
        );

        let ids: Vec<String> = inbox.list(false).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, ["m_1", "m_4"]);
        assert_eq!(inbox.raw("m_1").await.unwrap(), RAW);
        let reqs = inbox.forwarding_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].account.as_deref(), Some("acct@gmail.com"));
        assert_eq!(
            reqs[0].link.as_deref(),
            Some("https://mail-settings.google.com/mail/vf-secret-token")
        );

        // A second drain finds nothing and acks nothing.
        let report = drain(&mut stream, &sk, &inbox).await.unwrap();
        assert_eq!(report, DrainReport::default());
        assert_eq!(q.lock().unwrap().acked.len(), 6);
    }

    #[tokio::test]
    async fn already_stored_items_are_acked_without_fetching() {
        let (sk, pk) = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        let m = meta("m_1", Kind::Message);
        inbox.store_message(&m, RAW).await.unwrap();
        let blob = seal_message(&pk, &m, RAW).unwrap();
        let q = Arc::new(Mutex::new(Queue {
            items: vec![queued("m_1", blob.len() as u64, false, String::new())],
            blobs: [("m_1".to_string(), blob)].into(),
            ..Default::default()
        }));
        let (send, recv) = fake::serve(Arc::clone(&q));
        let mut stream = EmailStream::open(send, recv).await.unwrap();
        drain(&mut stream, &sk, &inbox).await.unwrap();
        let q = q.lock().unwrap();
        assert_eq!(q.acked, vec!["m_1"]);
        assert!(
            !q.requests
                .iter()
                .any(|r| matches!(r, p2claw_control_proto::EmailRequest::Fetch { .. })),
            "{:?}",
            q.requests
        );
    }
}
