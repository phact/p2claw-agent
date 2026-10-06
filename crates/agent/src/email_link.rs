//! Bridge between the local API and the coord connection for email:
//! the `email_config` / `email_config_ack` exchange and `rejected`
//! lookups over the email stream.
//!
//! Same shape as `route_announcer`: the local API drops a job on an
//! unbounded channel and optionally waits on a oneshot; the session
//! loop in `coord_conn` drains the jobs, so a request made while the
//! box is offline resolves to `Pending` and the next reconnect's
//! post-`hello_ack` snapshot re-syncs coord anyway.

use std::time::Duration;

use p2claw_control_proto::EmailRejections;
use tokio::sync::{mpsc, oneshot};

use p2claw_agent::email::{EmailSettings, Inbox};

/// Coord's answer to an `email_config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAck {
    pub addresses: Vec<String>,
    pub error: Option<String>,
}

pub enum EmailJob {
    /// Send the current settings snapshot. `reply` is `Some` when a
    /// local-API caller waits for the ack.
    SendConfig {
        reply: Option<oneshot::Sender<ConfigAck>>,
    },
    /// Ask coord for the rejection stats over an email stream.
    Rejected {
        reply: oneshot::Sender<Result<EmailRejections, String>>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum LinkError {
    /// No coord session took the job in time: the box is offline, or
    /// the session ended before the answer came back.
    Pending,
    /// Coord answered the request with an error.
    Coord(String),
}

/// The email state both the local API and the coord session share.
#[derive(Clone)]
pub struct EmailShared {
    pub settings: EmailSettings,
    pub inbox: Inbox,
}

impl EmailShared {
    /// Settings at `<data_dir>/email.json`, inbox under
    /// `<data_dir>/mail/`.
    pub fn load(data_dir: &std::path::Path) -> Self {
        Self {
            settings: EmailSettings::load_or_default(data_dir.join("email.json")),
            inbox: Inbox::load_or_empty(data_dir.join("mail")),
        }
    }
}

/// Producer side; cheap to clone.
#[derive(Clone)]
pub struct EmailLink {
    job_tx: mpsc::UnboundedSender<EmailJob>,
}

/// Consumer side, owned by the coord-connection loop.
pub struct EmailLinkInbox {
    pub job_rx: mpsc::UnboundedReceiver<EmailJob>,
}

impl EmailLink {
    pub fn new() -> (Self, EmailLinkInbox) {
        let (job_tx, job_rx) = mpsc::unbounded_channel();
        (Self { job_tx }, EmailLinkInbox { job_rx })
    }

    /// Send the settings snapshot and wait for coord's ack.
    pub async fn send_config_and_wait(&self, timeout: Duration) -> Result<ConfigAck, LinkError> {
        let (tx, rx) = oneshot::channel();
        if self
            .job_tx
            .send(EmailJob::SendConfig { reply: Some(tx) })
            .is_err()
        {
            return Err(LinkError::Pending);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(ack)) => Ok(ack),
            _ => Err(LinkError::Pending),
        }
    }

    /// Fetch coord's rejection stats for this box.
    pub async fn rejected(&self, timeout: Duration) -> Result<EmailRejections, LinkError> {
        let (tx, rx) = oneshot::channel();
        if self.job_tx.send(EmailJob::Rejected { reply: tx }).is_err() {
            return Err(LinkError::Pending);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(r))) => Ok(r),
            Ok(Ok(Err(e))) => Err(LinkError::Coord(e)),
            _ => Err(LinkError::Pending),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_resolves_with_the_ack() {
        let (link, mut inbox) = EmailLink::new();
        tokio::spawn(async move {
            match inbox.job_rx.recv().await.expect("job") {
                EmailJob::SendConfig { reply } => {
                    let _ = reply.unwrap().send(ConfigAck {
                        addresses: vec!["a@p2claw.com".into()],
                        error: None,
                    });
                }
                EmailJob::Rejected { .. } => panic!("wrong job"),
            }
        });
        let ack = link
            .send_config_and_wait(Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(ack.addresses, vec!["a@p2claw.com"]);
    }

    #[tokio::test]
    async fn pending_when_nobody_answers_or_inbox_gone() {
        let (link, inbox) = EmailLink::new();
        drop(inbox);
        assert_eq!(
            link.send_config_and_wait(Duration::from_millis(20)).await,
            Err(LinkError::Pending)
        );
        assert!(matches!(
            link.rejected(Duration::from_millis(20)).await,
            Err(LinkError::Pending)
        ));

        let (link, mut inbox) = EmailLink::new();
        let _hold = tokio::spawn(async move {
            let _job = inbox.job_rx.recv().await;
            std::future::pending::<()>().await;
        });
        assert_eq!(
            link.send_config_and_wait(Duration::from_millis(20)).await,
            Err(LinkError::Pending)
        );
    }

    #[tokio::test]
    async fn rejected_surfaces_coord_errors() {
        let (link, mut inbox) = EmailLink::new();
        tokio::spawn(async move {
            match inbox.job_rx.recv().await.expect("job") {
                EmailJob::Rejected { reply } => {
                    let _ = reply.send(Err("storage".into()));
                }
                EmailJob::SendConfig { .. } => panic!("wrong job"),
            }
        });
        assert_eq!(
            link.rejected(Duration::from_secs(1)).await,
            Err(LinkError::Coord("storage".into()))
        );
    }
}
