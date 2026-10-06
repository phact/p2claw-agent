//! Bridge between `local_api` (route mutations) and `control_conn`
//! (the persistent WebSocket to coordination) for the `route_announce`
//! / `route_announce_ack` exchange.
//!
//! Why this lives in its own module:
//!
//! - The local API mutates the route table and needs to know whether
//!   coord accepted the change *before* it returns to the operator.
//!   A direct call into `control_conn`
//!   would couple the request handler to an unrelated reconnect loop.
//! - The control connection re-emits a full snapshot on every
//!   (re)connect (right after `hello_ack`) and after every successful
//!   local mutation. Both of those events come from different parts
//!   of the agent and need a shared, lock-free fan-in.
//!
//! Wiring:
//!
//! ```text
//!   local_api ──┐
//!               │  AnnounceJob (mpsc, unbounded)
//!               ▼
//!         RouteAnnouncer ──┐
//!                          ▼   AnnouncerInbox (job_rx, latest_ack)
//!                     control_conn::session
//!                          │
//!                          ▼
//!                     coordination WebSocket
//! ```
//!
//! Per-job lifecycle: a [`RouteAnnouncer::request_and_wait`] caller
//! gets a `oneshot::Sender<AnnounceAck>` planted on the job; the
//! session loop pushes that sender onto a per-session FIFO when it
//! sends the announce, and the next inbound `route_announce_ack`
//! pops + fulfills it. Order is preserved because coord acks
//! announces in the order it received them. If the
//! session ends before the ack arrives, the sender is dropped and the
//! `request_and_wait` resolves to [`AnnounceWaitError::Pending`] —
//! the caller surfaces `pending_announce: true` to the operator and
//! the next reconnect's hello_ack-triggered announce re-syncs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, RwLock};

use p2claw_control_proto::{AcceptedRoute, DailyChanges, RejectedRoute};

/// Coord's verdict on a single `route_announce`. Mirrors
/// `Message::RouteAnnounceAck` minus the wire envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceAck {
    pub accepted: Vec<String>,
    pub rejected: Vec<RejectedRoute>,
    pub max_apps: u32,
    pub used_apps: u32,
    pub daily_changes: Option<DailyChanges>,
    /// Per-app coord-authoritative state. Empty when coord doesn't
    /// emit the field, or when no apps were accepted (e.g.
    /// daily-limit / quota-rejected paths). Daemons walk this in
    /// `coord_conn` to update local `RouteRecord.requires_auth` for
    /// any app coord echoed back with a different gate value.
    pub accepted_apps: Vec<AcceptedRoute>,
}

/// One unit of work pulled by `control_conn::session` from
/// [`AnnouncerInbox::job_rx`]. Always the same shape (snapshot the
/// current route table and send it); `reply` decides whether the
/// caller is blocked on the ack.
pub enum AnnounceJob {
    /// Build + send a fresh `route_announce`. The session loop
    /// snapshots the route table at send time, so every queued job
    /// emits the **current** state — duplicate jobs collapse
    /// naturally without us tracking diffs.
    Send {
        /// `Some` ⇒ a `request_and_wait` caller is awaiting the next
        /// `route_announce_ack`. `None` ⇒ fire-and-forget (post-
        /// `hello_ack` resync, post-`DELETE` notification, etc.).
        reply: Option<oneshot::Sender<AnnounceAck>>,
    },
}

/// Why a `request_and_wait` did not produce a fresh ack within its
/// budget. The caller's contract is to keep the local route and
/// surface `pending_announce: true`.
#[derive(Debug, PartialEq, Eq)]
pub enum AnnounceWaitError {
    /// Either the control connection's job receiver is gone (process
    /// is shutting down) or the per-session sender was dropped before
    /// the ack came back (session ended mid-flight, or coord timed
    /// out within our 2s budget). Indistinguishable from the caller's
    /// perspective; both degrade to "best-effort, will resync on
    /// reconnect".
    Pending,
}

/// Producer side. Cheap to clone (just two `Arc`s under the hood);
/// share between every part of the agent that wants to emit
/// announces.
#[derive(Clone)]
pub struct RouteAnnouncer {
    job_tx: mpsc::UnboundedSender<AnnounceJob>,
    // Surfaced via `latest_ack()` for a future `GET /v1/quota`;
    // kept behind `#[allow]` so the wire path is in place and the
    // read side adds zero protocol surface when it lands.
    #[allow(dead_code)]
    latest_ack: Arc<RwLock<Option<AnnounceAck>>>,
    /// Monotonic instant of the most recent `route_announce_ack`.
    /// Read by `GET /v1/status` as `coord.last_ack_age_secs` — a live
    /// signal that the control link is actually round-tripping.
    last_ack_at: Arc<RwLock<Option<Instant>>>,
}

/// Consumer side. Single-owner — held by the `control_conn::run` loop
/// across reconnects, borrowed `&mut` into each `session` call. Not
/// `Clone`.
pub struct AnnouncerInbox {
    pub job_rx: mpsc::UnboundedReceiver<AnnounceJob>,
    pub latest_ack: Arc<RwLock<Option<AnnounceAck>>>,
    last_ack_at: Arc<RwLock<Option<Instant>>>,
}

impl AnnouncerInbox {
    /// Replace the latest stored ack. Called by the session loop on
    /// every inbound `route_announce_ack` so a future
    /// `GET /v1/quota` can surface the
    /// current quota counters without round-tripping coord.
    pub async fn store_latest(&self, ack: AnnounceAck) {
        *self.latest_ack.write().await = Some(ack);
        *self.last_ack_at.write().await = Some(Instant::now());
    }
}

impl RouteAnnouncer {
    /// Build a new announcer + its matching inbox. Hand the announcer
    /// to every emit-side (local API, eventually a future
    /// CLI-trigger) and the inbox to the control-connection loop.
    pub fn new() -> (Self, AnnouncerInbox) {
        let (job_tx, job_rx) = mpsc::unbounded_channel();
        let latest_ack = Arc::new(RwLock::new(None));
        let last_ack_at = Arc::new(RwLock::new(None));
        (
            Self {
                job_tx,
                latest_ack: Arc::clone(&latest_ack),
                last_ack_at: Arc::clone(&last_ack_at),
            },
            AnnouncerInbox {
                job_rx,
                latest_ack,
                last_ack_at,
            },
        )
    }

    /// Seconds since the most recent `route_announce_ack`, or `None`
    /// if no ack has arrived this process lifetime. Read by
    /// `GET /v1/status`.
    pub async fn last_ack_age_secs(&self) -> Option<u64> {
        self.last_ack_at.read().await.map(|t| t.elapsed().as_secs())
    }

    /// Trigger an announce; do not wait for the ack. Send is
    /// non-blocking — the unbounded mpsc never backpressures, and the
    /// only way this fails is the control-connection task having
    /// dropped its receiver (process is winding down). We swallow that
    /// error: a failed announce-emit on shutdown is benign, the agent
    /// is exiting anyway.
    pub fn request_fire_and_forget(&self) {
        let _ = self.job_tx.send(AnnounceJob::Send { reply: None });
    }

    /// Trigger an announce and await coord's verdict. Returns
    /// [`AnnounceWaitError::Pending`] if the deadline elapses before
    /// the ack arrives or the control conn drops the reply slot mid-
    /// flight — caller surfaces `pending_announce: true`.
    pub async fn request_and_wait(
        &self,
        timeout: Duration,
    ) -> Result<AnnounceAck, AnnounceWaitError> {
        let (tx, rx) = oneshot::channel();
        if self
            .job_tx
            .send(AnnounceJob::Send { reply: Some(tx) })
            .is_err()
        {
            // Inbox is gone — control_conn task already exited.
            return Err(AnnounceWaitError::Pending);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(ack)) => Ok(ack),
            // Either the budget elapsed (Err timeout) or the per-
            // session sender was dropped (Ok(Err(_))). Both degrade
            // to Pending — coord didn't ack in time, the agent will
            // resync on the next reconnect.
            _ => Err(AnnounceWaitError::Pending),
        }
    }

    /// Latest stored ack — read by a future `GET /v1/quota`.
    /// `None` until the first ack arrives this process lifetime.
    #[allow(dead_code)] // Not yet wired to an endpoint; tests cover it.
    pub async fn latest_ack(&self) -> Option<AnnounceAck> {
        self.latest_ack.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn fire_and_forget_enqueues_send_with_no_reply() {
        let (announcer, mut inbox) = RouteAnnouncer::new();
        announcer.request_fire_and_forget();

        let job = inbox.job_rx.recv().await.expect("job arrives");
        match job {
            AnnounceJob::Send { reply } => assert!(reply.is_none()),
        }
    }

    #[tokio::test]
    async fn last_ack_age_is_none_until_stored_then_some() {
        let (announcer, inbox) = RouteAnnouncer::new();
        assert!(
            announcer.last_ack_age_secs().await.is_none(),
            "no ack yet → None"
        );
        inbox
            .store_latest(AnnounceAck {
                accepted: vec![],
                rejected: vec![],
                max_apps: 3,
                used_apps: 0,
                daily_changes: None,
                accepted_apps: vec![],
            })
            .await;
        assert!(
            announcer.last_ack_age_secs().await.is_some(),
            "after an ack → Some(age)"
        );
    }

    #[tokio::test]
    async fn request_and_wait_returns_ack_when_delivered() {
        let (announcer, mut inbox) = RouteAnnouncer::new();

        // Spawn a stand-in for the control-conn loop: pull the job,
        // grab the reply sender, fulfill with a canned ack.
        let receiver_task = tokio::spawn(async move {
            let job = inbox.job_rx.recv().await.expect("job arrives");
            match job {
                AnnounceJob::Send { reply } => {
                    let tx = reply.expect("reply sender present");
                    let ack = AnnounceAck {
                        accepted: vec!["recipes".into()],
                        rejected: vec![],
                        max_apps: 3,
                        used_apps: 1,
                        daily_changes: None,
                        accepted_apps: vec![],
                    };
                    tx.send(ack).expect("oneshot deliver");
                }
            }
        });

        let got = announcer
            .request_and_wait(Duration::from_secs(1))
            .await
            .expect("ack arrives");
        assert_eq!(got.accepted, vec!["recipes".to_string()]);
        assert_eq!(got.max_apps, 3);
        receiver_task.await.expect("receiver task");
    }

    #[tokio::test]
    async fn request_and_wait_returns_pending_when_inbox_dropped() {
        let (announcer, inbox) = RouteAnnouncer::new();
        // Simulate control-conn task having exited: drop the inbox.
        drop(inbox);

        let res = announcer.request_and_wait(Duration::from_millis(50)).await;
        assert_eq!(res, Err(AnnounceWaitError::Pending));
    }

    #[tokio::test]
    async fn request_and_wait_returns_pending_on_timeout() {
        let (announcer, mut inbox) = RouteAnnouncer::new();

        // Pull the job but never fulfill the reply — the ack budget
        // elapses and the caller gets Pending.
        let _stuck_task = tokio::spawn(async move {
            // Hold the reply sender forever.
            let _job = inbox.job_rx.recv().await;
            std::future::pending::<()>().await;
        });

        let res = announcer.request_and_wait(Duration::from_millis(50)).await;
        assert_eq!(res, Err(AnnounceWaitError::Pending));
    }

    #[tokio::test]
    async fn request_and_wait_returns_pending_when_reply_sender_dropped() {
        let (announcer, mut inbox) = RouteAnnouncer::new();

        // Pull the job and immediately drop the reply sender — this
        // models the session ending mid-flight before the ack arrived.
        tokio::spawn(async move {
            let job = inbox.job_rx.recv().await.expect("job");
            match job {
                AnnounceJob::Send { reply } => drop(reply),
            }
        });

        let res = announcer.request_and_wait(Duration::from_secs(1)).await;
        assert_eq!(res, Err(AnnounceWaitError::Pending));
    }

    #[tokio::test]
    async fn store_latest_then_read_via_announcer() {
        let (announcer, inbox) = RouteAnnouncer::new();
        let ack = AnnounceAck {
            accepted: vec!["a".into(), "b".into()],
            rejected: vec![],
            max_apps: 3,
            used_apps: 2,
            daily_changes: None,
            accepted_apps: vec![],
        };
        inbox.store_latest(ack.clone()).await;
        assert_eq!(announcer.latest_ack().await, Some(ack));
    }
}
