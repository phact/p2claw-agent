//! Subtask supervisor for the agent's auxiliary background loops
//! (local API, iroh listener, and any future helpers).
//!
//! The agent should not
//! wedge or exit if a single subtask hits a transient bug. Panics are
//! caught and the task is restarted with a fresh future. A second
//! panic for the same subtask within [`PANIC_WINDOW`] indicates a
//! deterministic bug that restart-looping will not fix, so the
//! supervisor surfaces a [`FatalReason`] and the agent exits non-zero.
//!
//! The control connection runs *outside* the supervisor — it owns
//! its own internal reconnect / re-register state machine and a
//! richer [`crate::control_conn::LoopOutcome`].
//!
//! Restart policy summary:
//!
//! | Subtask outcome              | Action                    |
//! |------------------------------|---------------------------|
//! | future returned cleanly      | log, do not restart       |
//! | future panicked, < limit     | log + restart from factory|
//! | future panicked, ≥ limit     | record `FatalReason`      |
//! | task cancelled (shutdown)    | log, do not restart       |
//!
//! Subtasks are expected to observe an external `shutdown` watch and
//! return cleanly when it flips; the supervisor itself does not push
//! any shutdown signal — see [`Supervisor::shutdown`].

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;
use tracing::{error, info, warn};

/// Window over which repeated panics for the same subtask are treated
/// as the *same* deterministic failure. Two panics inside this window
/// trip the fatal guard.
pub const PANIC_WINDOW: Duration = Duration::from_secs(60);
/// Number of panics inside [`PANIC_WINDOW`] that we tolerate before
/// declaring the subtask permanently broken. The N-th panic trips
/// the guard (so with `LIMIT = 2` the second panic exits the agent).
pub const PANIC_LIMIT: usize = 2;

/// Boxed future the supervisor owns and runs. `'static + Send` is
/// required so we can move it onto the JoinSet across restarts.
type Fut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
/// Factory invoked once per (re)start; `Fn` (not `FnOnce`) so the
/// supervisor can call it again after a panic. Closures in main pass
/// in cheaply-clonable handles (`Arc`, `watch::Receiver`, `Forwarder`)
/// or wrap non-`Clone` resources (`watch::Sender`) in
/// `Mutex<Option<_>>` and `.take()` on first call.
type Factory = Box<dyn Fn() -> Fut + Send + 'static>;

/// Why the supervisor gave up. Returned from [`Supervisor::next_fatal`]
/// so `wait_for_exit` in `main` can map it to a non-zero exit code.
#[derive(Debug, Clone)]
pub struct FatalReason {
    /// Logical name from [`Supervisor::spawn`].
    pub name: String,
    /// Human-readable explanation; goes into the error log.
    pub message: String,
}

struct Subtask {
    name: String,
    factory: Factory,
    /// Sliding window of recent panic timestamps for *this* subtask.
    /// Older-than-[`PANIC_WINDOW`] entries get evicted on each push.
    panics: VecDeque<Instant>,
}

/// Supervises a fixed set of named background subtasks. See module
/// docs for the restart contract.
pub struct Supervisor {
    subtasks: Vec<Subtask>,
    /// Each set entry yields `(idx, JoinHandle outcome)` so we can
    /// look the panicked subtask up in `subtasks` for restart.
    set: JoinSet<(usize, Result<(), JoinError>)>,
    /// Latched on the first fatal event; subsequent calls to
    /// [`Supervisor::next_fatal`] return it without re-driving the
    /// JoinSet. Cleared once observed.
    fatal: Option<FatalReason>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            subtasks: Vec::new(),
            set: JoinSet::new(),
            fatal: None,
        }
    }

    /// Register and immediately start a subtask. `factory` is invoked
    /// now (for the initial run) and on each restart.
    pub fn spawn<F, Fu>(&mut self, name: impl Into<String>, factory: F)
    where
        F: Fn() -> Fu + Send + 'static,
        Fu: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        let factory: Factory = Box::new(move || Box::pin(factory()));
        let idx = self.subtasks.len();
        self.subtasks.push(Subtask {
            name,
            factory,
            panics: VecDeque::new(),
        });
        self.start(idx);
    }

    /// Spawn the inner future under a private `tokio::spawn` so the
    /// JoinSet sees `Ok((idx, Err(JoinError {is_panic: true})))` when
    /// the subtask panics. (JoinSet's own panic propagation would
    /// drop the index and forced us to maintain a separate id→name
    /// map.)
    fn start(&mut self, idx: usize) {
        let fut = (self.subtasks[idx].factory)();
        self.set.spawn(async move {
            let inner = tokio::spawn(fut);
            let res = inner.await;
            (idx, res)
        });
    }

    /// Drive the JoinSet until a fatal event happens (panic-limit
    /// tripped) or — if every subtask exits cleanly — pend forever so
    /// the caller's `select!` keeps observing other arms (signals,
    /// the control-conn handle).
    pub async fn next_fatal(&mut self) -> FatalReason {
        if let Some(r) = self.fatal.take() {
            return r;
        }
        loop {
            match self.set.join_next().await {
                None => {
                    // Set drained. Don't return — wait_for_exit's
                    // other select arms (signals, cc_handle) will
                    // resolve. Returning here would cause a busy
                    // loop in the caller.
                    std::future::pending::<()>().await;
                    unreachable!();
                }
                Some(Ok((idx, Ok(())))) => {
                    let name = self.subtasks[idx].name.clone();
                    info!(
                        task = %name,
                        "supervisor: subtask exited cleanly; not restarting"
                    );
                }
                Some(Ok((idx, Err(join_err)))) => {
                    if let Some(r) = self.handle_join_failure(idx, join_err) {
                        return r;
                    }
                }
                Some(Err(outer_err)) => {
                    // Outer wrapper task can only fail if we panic in
                    // the wrapper itself — which we don't. Surface
                    // defensively rather than silently swallow.
                    error!(error = ?outer_err, "supervisor: outer task failed");
                    return FatalReason {
                        name: "supervisor".into(),
                        message: format!("outer wrapper task failed: {outer_err}"),
                    };
                }
            }
        }
    }

    /// Decide what to do about a JoinHandle failure for `subtasks[idx]`.
    /// Returns `Some(FatalReason)` iff the panic-limit guard tripped.
    fn handle_join_failure(&mut self, idx: usize, err: JoinError) -> Option<FatalReason> {
        let name = self.subtasks[idx].name.clone();
        if err.is_cancelled() {
            info!(task = %name, "supervisor: subtask cancelled; not restarting");
            return None;
        }
        if !err.is_panic() {
            warn!(task = %name, error = ?err, "supervisor: subtask join error");
            return None;
        }
        let panic_msg = panic_payload_string(&err);
        warn!(task = %name, panic = %panic_msg, "supervisor: subtask panicked");

        let now = Instant::now();
        let task = &mut self.subtasks[idx];
        record_panic(&mut task.panics, now);
        if task.panics.len() >= PANIC_LIMIT {
            let reason = FatalReason {
                name: name.clone(),
                message: format!(
                    "subtask panicked {} times within {:?}: {panic_msg}",
                    task.panics.len(),
                    PANIC_WINDOW
                ),
            };
            error!(
                task = %name,
                count = task.panics.len(),
                window_secs = PANIC_WINDOW.as_secs(),
                "supervisor: panic-limit tripped"
            );
            return Some(reason);
        }
        info!(task = %name, "supervisor: restarting subtask");
        self.start(idx);
        None
    }

    /// Drain in-flight subtasks, waiting up to `timeout` for them to
    /// observe the caller's external shutdown signal and return on
    /// their own. Anything still alive at the deadline gets aborted.
    /// Idempotent — safe to call after a fatal exit.
    pub async fn shutdown(&mut self, timeout: Duration) {
        let drain = async { while self.set.join_next().await.is_some() {} };
        if tokio::time::timeout(timeout, drain).await.is_err() {
            warn!(
                timeout_secs = timeout.as_secs(),
                "supervisor: subtasks did not drain in time; aborting"
            );
            self.set.shutdown().await;
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// Best-effort stringification of a panic payload for logging.
/// Tokio's `JoinError::into_panic` would give us the boxed payload
/// but consumes the error; we only want a label here, so peek by
/// formatting the `JoinError` itself (which embeds the payload's
/// `Display` when it's a string).
fn panic_payload_string(err: &JoinError) -> String {
    // `JoinError` formats as e.g. "task 12 panicked with message \"...\"".
    err.to_string()
}

/// Push `now`, evicting entries older than [`PANIC_WINDOW`]. Pulled
/// out for unit-testing the sliding-window logic without spinning up
/// a JoinSet.
fn record_panic(window: &mut VecDeque<Instant>, now: Instant) {
    while let Some(&front) = window.front() {
        if now.duration_since(front) > PANIC_WINDOW {
            window.pop_front();
        } else {
            break;
        }
    }
    window.push_back(now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn record_panic_evicts_stale_entries() {
        let mut w = VecDeque::new();
        let now = Instant::now();
        // Two stale entries just outside the window.
        w.push_back(now - PANIC_WINDOW - Duration::from_secs(5));
        w.push_back(now - PANIC_WINDOW - Duration::from_secs(2));
        record_panic(&mut w, now);
        assert_eq!(w.len(), 1, "stale entries must be evicted on push");
    }

    #[test]
    fn record_panic_keeps_in_window_entries() {
        let mut w = VecDeque::new();
        let now = Instant::now();
        w.push_back(now - Duration::from_secs(10));
        record_panic(&mut w, now);
        assert_eq!(w.len(), 2);
    }

    #[tokio::test]
    async fn panic_then_clean_run_does_not_trip_guard() {
        // First call panics; the supervisor restarts; the second
        // call exits cleanly. Single panic should not be fatal.
        let count = Arc::new(AtomicUsize::new(0));
        let mut sup = Supervisor::new();
        {
            let count = Arc::clone(&count);
            sup.spawn("flaky", move || {
                let count = Arc::clone(&count);
                async move {
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        panic!("first run panic");
                    }
                    // Subsequent runs return immediately (clean exit).
                }
            });
        }

        // Race the supervisor against a short timeout — `next_fatal`
        // should NOT resolve, because one panic is below the limit.
        let fatal = tokio::time::timeout(Duration::from_millis(500), sup.next_fatal()).await;
        assert!(fatal.is_err(), "single panic must not trip the guard");
        // Both the original run and the restart should have executed.
        assert!(count.load(Ordering::SeqCst) >= 2, "expected restart");

        sup.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn two_panics_in_window_trip_the_guard() {
        // Both runs panic — second panic should trip the panic-limit.
        let count = Arc::new(AtomicUsize::new(0));
        let mut sup = Supervisor::new();
        {
            let count = Arc::clone(&count);
            sup.spawn("always-panics", move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    panic!("boom");
                }
            });
        }

        let fatal = tokio::time::timeout(Duration::from_secs(2), sup.next_fatal())
            .await
            .expect("supervisor should surface a FatalReason");
        assert_eq!(fatal.name, "always-panics");
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "expected at least one restart"
        );

        sup.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn clean_exit_is_not_restarted() {
        // Subtask exits Ok immediately — should not be respawned.
        let count = Arc::new(AtomicUsize::new(0));
        let mut sup = Supervisor::new();
        {
            let count = Arc::clone(&count);
            sup.spawn("graceful", move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        // Give the JoinSet time to reap. next_fatal should pend
        // (not return a fatal) since clean exit is not fatal.
        let _ = tokio::time::timeout(Duration::from_millis(300), sup.next_fatal()).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "must not restart on clean exit"
        );

        sup.shutdown(Duration::from_secs(1)).await;
    }
}
