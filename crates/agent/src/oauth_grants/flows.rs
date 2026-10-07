//! Pending consent flows, in memory only.
//!
//! A flow is born when an app starts one, receives at most one
//! callback from the provider (relayed by coordination), and is
//! consumed by the first exchange. Restarting the agent drops every
//! flow: codes expire within minutes anyway, so the app starts again.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::watch;

/// How long a flow may wait for its callback.
pub const FLOW_TTL: Duration = Duration::from_secs(10 * 60);

/// Flows older than this are dropped from the table on the next
/// insert, so abandoned flows don't accumulate.
const SWEEP_AFTER: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowStatus {
    Pending,
    Ready,
    Error,
    Expired,
    Consumed,
}

impl FlowStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, FlowStatus::Pending)
    }
}

/// What a waiting app sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowView {
    pub flow_id: String,
    pub provider: String,
    pub status: FlowStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Everything the exchange needs once the callback is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyFlow {
    pub flow_id: String,
    pub provider: String,
    pub scopes: Vec<String>,
    pub nonce_hash: String,
    pub code: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeRefusal {
    Unknown,
    /// No callback yet.
    Pending,
    /// The provider sent an error instead of a code.
    Failed(String),
    Expired,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Pending,
    Ready { code: String, state: String },
    Error { error: String },
}

struct Flow {
    provider: String,
    scopes: Vec<String>,
    nonce_hash: String,
    created: Instant,
    outcome: Outcome,
    consumed: bool,
    /// Bumped on every transition so long-pollers wake up.
    version: watch::Sender<u64>,
}

impl Flow {
    fn status(&self, now: Instant) -> FlowStatus {
        if self.consumed {
            FlowStatus::Consumed
        } else if now.duration_since(self.created) > FLOW_TTL {
            FlowStatus::Expired
        } else {
            match self.outcome {
                Outcome::Pending => FlowStatus::Pending,
                Outcome::Ready { .. } => FlowStatus::Ready,
                Outcome::Error { .. } => FlowStatus::Error,
            }
        }
    }

    fn view(&self, flow_id: &str, now: Instant) -> FlowView {
        let status = self.status(now);
        let (code, state, error) = match (&status, &self.outcome) {
            (FlowStatus::Ready, Outcome::Ready { code, state }) => {
                (Some(code.clone()), Some(state.clone()), None)
            }
            (FlowStatus::Error, Outcome::Error { error }) => (None, None, Some(error.clone())),
            _ => (None, None, None),
        };
        FlowView {
            flow_id: flow_id.to_string(),
            provider: self.provider.clone(),
            status,
            code,
            state,
            error,
        }
    }
}

#[derive(Default)]
pub struct FlowRegistry {
    flows: Mutex<HashMap<String, Flow>>,
}

impl FlowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a flow id and register the flow as pending.
    pub fn start(&self, provider: &str, scopes: Vec<String>, nonce_hash: &str) -> String {
        let flow_id = format!("f_{}", ulid::Ulid::new());
        self.start_with_id(&flow_id, provider, scopes, nonce_hash);
        flow_id
    }

    fn start_with_id(&self, flow_id: &str, provider: &str, scopes: Vec<String>, nonce_hash: &str) {
        let now = Instant::now();
        let mut flows = self.lock();
        flows.retain(|_, f| now.duration_since(f.created) <= SWEEP_AFTER);
        flows.insert(
            flow_id.to_string(),
            Flow {
                provider: provider.to_string(),
                scopes,
                nonce_hash: nonce_hash.to_string(),
                created: now,
                outcome: Outcome::Pending,
                consumed: false,
                version: watch::channel(0).0,
            },
        );
    }

    /// Drop a flow the broker refused to start.
    pub fn abandon(&self, flow_id: &str) {
        self.lock().remove(flow_id);
    }

    /// Deliver the provider's callback. `false` when it was dropped:
    /// unknown, expired, consumed, or already answered.
    pub fn deliver(
        &self,
        flow_id: &str,
        code: Option<String>,
        error: Option<String>,
        state: String,
    ) -> bool {
        let mut flows = self.lock();
        let Some(flow) = flows.get_mut(flow_id) else {
            return false;
        };
        if flow.status(Instant::now()) != FlowStatus::Pending {
            return false;
        }
        flow.outcome = match (code, error) {
            (Some(code), _) if !code.is_empty() => Outcome::Ready { code, state },
            (_, Some(error)) => Outcome::Error {
                error: if error.is_empty() {
                    "unknown_error".into()
                } else {
                    error
                },
            },
            _ => Outcome::Error {
                error: "callback_without_code".into(),
            },
        };
        flow.version.send_modify(|v| *v += 1);
        true
    }

    pub fn get(&self, flow_id: &str) -> Option<FlowView> {
        let flows = self.lock();
        flows.get(flow_id).map(|f| f.view(flow_id, Instant::now()))
    }

    /// Current view, waiting up to `timeout` for the flow to leave
    /// `pending`. Returns the pending view on timeout.
    pub async fn wait(&self, flow_id: &str, timeout: Duration) -> Option<FlowView> {
        let deadline = Instant::now() + timeout;
        let mut rx = {
            let flows = self.lock();
            let flow = flows.get(flow_id)?;
            let view = flow.view(flow_id, Instant::now());
            if view.status.is_terminal() {
                return Some(view);
            }
            flow.version.subscribe()
        };
        loop {
            let now = Instant::now();
            let view = self.get(flow_id)?;
            if view.status.is_terminal() || now >= deadline {
                return Some(view);
            }
            // The flow can also expire while nobody bumps the version.
            let until_expiry = {
                let flows = self.lock();
                let flow = flows.get(flow_id)?;
                (flow.created + FLOW_TTL).saturating_duration_since(now)
            };
            let sleep = (deadline - now).min(until_expiry) + Duration::from_millis(5);
            tokio::select! {
                r = rx.changed() => {
                    if r.is_err() {
                        return self.get(flow_id);
                    }
                }
                _ = tokio::time::sleep(sleep) => {}
            }
        }
    }

    /// Mark the flow consumed and hand out what the exchange needs.
    /// Refuses anything but a ready flow; consumed is permanent even
    /// if the exchange then fails at the broker.
    pub fn consume(&self, flow_id: &str) -> Result<ReadyFlow, ExchangeRefusal> {
        let mut flows = self.lock();
        let Some(flow) = flows.get_mut(flow_id) else {
            return Err(ExchangeRefusal::Unknown);
        };
        match flow.status(Instant::now()) {
            FlowStatus::Pending => Err(ExchangeRefusal::Pending),
            FlowStatus::Expired => Err(ExchangeRefusal::Expired),
            FlowStatus::Consumed => Err(ExchangeRefusal::Consumed),
            FlowStatus::Error => match &flow.outcome {
                Outcome::Error { error } => Err(ExchangeRefusal::Failed(error.clone())),
                _ => Err(ExchangeRefusal::Unknown),
            },
            FlowStatus::Ready => {
                let Outcome::Ready { code, state } = &flow.outcome else {
                    return Err(ExchangeRefusal::Unknown);
                };
                let ready = ReadyFlow {
                    flow_id: flow_id.to_string(),
                    provider: flow.provider.clone(),
                    scopes: flow.scopes.clone(),
                    nonce_hash: flow.nonce_hash.clone(),
                    code: code.clone(),
                    state: state.clone(),
                };
                flow.consumed = true;
                flow.version.send_modify(|v| *v += 1);
                Ok(ready)
            }
        }
    }

    #[cfg(test)]
    fn age(&self, flow_id: &str, by: Duration) {
        if let Some(f) = self.lock().get_mut(flow_id) {
            f.created -= by;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Flow>> {
        self.flows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with_flow() -> (FlowRegistry, String) {
        let r = FlowRegistry::new();
        let id = r.start("google", vec!["calendar".into()], "nh");
        assert!(id.starts_with("f_") && id.len() == 28, "{id}");
        (r, id)
    }

    #[test]
    fn pending_until_the_callback_then_ready_then_consumed() {
        let (r, id) = registry_with_flow();
        assert_eq!(r.get(&id).unwrap().status, FlowStatus::Pending);
        assert!(matches!(r.consume(&id), Err(ExchangeRefusal::Pending)));

        assert!(r.deliver(&id, Some("c0de".into()), None, "s1.x.y".into()));
        let v = r.get(&id).unwrap();
        assert_eq!(v.status, FlowStatus::Ready);
        assert_eq!(v.code.as_deref(), Some("c0de"));
        assert_eq!(v.state.as_deref(), Some("s1.x.y"));

        // A second callback is dropped; the first wins.
        assert!(!r.deliver(&id, Some("other".into()), None, "s1.x.z".into()));
        assert_eq!(r.get(&id).unwrap().code.as_deref(), Some("c0de"));

        let ready = r.consume(&id).unwrap();
        assert_eq!(ready.code, "c0de");
        assert_eq!(ready.nonce_hash, "nh");
        assert_eq!(ready.scopes, vec!["calendar"]);
        let v = r.get(&id).unwrap();
        assert_eq!(v.status, FlowStatus::Consumed);
        assert!(v.code.is_none() && v.state.is_none());
        assert!(matches!(r.consume(&id), Err(ExchangeRefusal::Consumed)));
        assert!(!r.deliver(&id, Some("again".into()), None, "s".into()));
    }

    #[test]
    fn provider_error_is_surfaced_and_blocks_exchange() {
        let (r, id) = registry_with_flow();
        assert!(r.deliver(&id, None, Some("access_denied".into()), "s1.x.y".into()));
        let v = r.get(&id).unwrap();
        assert_eq!(v.status, FlowStatus::Error);
        assert_eq!(v.error.as_deref(), Some("access_denied"));
        assert!(matches!(
            r.consume(&id),
            Err(ExchangeRefusal::Failed(e)) if e == "access_denied"
        ));
        // A callback with neither code nor error still ends the flow.
        let id2 = r.start("google", vec![], "nh");
        assert!(r.deliver(&id2, None, None, "s".into()));
        assert_eq!(
            r.get(&id2).unwrap().error.as_deref(),
            Some("callback_without_code")
        );
    }

    #[test]
    fn unknown_and_expired_flows_drop_callbacks() {
        let (r, id) = registry_with_flow();
        assert!(!r.deliver("f_nope", Some("c".into()), None, "s".into()));
        assert!(r.get("f_nope").is_none());
        assert!(matches!(r.consume("f_nope"), Err(ExchangeRefusal::Unknown)));

        r.age(&id, FLOW_TTL + Duration::from_secs(1));
        assert_eq!(r.get(&id).unwrap().status, FlowStatus::Expired);
        assert!(!r.deliver(&id, Some("c".into()), None, "s".into()));
        assert!(matches!(r.consume(&id), Err(ExchangeRefusal::Expired)));
    }

    #[test]
    fn ready_flows_expire_too_and_old_ones_are_swept() {
        let (r, id) = registry_with_flow();
        assert!(r.deliver(&id, Some("c".into()), None, "s".into()));
        r.age(&id, FLOW_TTL + Duration::from_secs(1));
        assert_eq!(r.get(&id).unwrap().status, FlowStatus::Expired);
        r.age(&id, SWEEP_AFTER);
        let _ = r.start("google", vec![], "nh");
        assert!(r.get(&id).is_none());
    }

    #[test]
    fn abandon_forgets_the_flow() {
        let (r, id) = registry_with_flow();
        r.abandon(&id);
        assert!(r.get(&id).is_none());
    }

    #[tokio::test]
    async fn wait_returns_on_delivery_or_timeout() {
        let (r, id) = registry_with_flow();
        let r = std::sync::Arc::new(r);
        let v = r.wait(&id, Duration::from_millis(30)).await.unwrap();
        assert_eq!(v.status, FlowStatus::Pending);

        let waiter = {
            let r = r.clone();
            let id = id.clone();
            tokio::spawn(async move { r.wait(&id, Duration::from_secs(5)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(r.deliver(&id, Some("c0de".into()), None, "s".into()));
        let v = waiter.await.unwrap().unwrap();
        assert_eq!(v.status, FlowStatus::Ready);
        assert_eq!(v.code.as_deref(), Some("c0de"));

        // Already-terminal flows answer at once.
        let v = r.wait(&id, Duration::from_secs(5)).await.unwrap();
        assert_eq!(v.status, FlowStatus::Ready);
        assert!(r.wait("f_nope", Duration::from_millis(1)).await.is_none());
    }

    #[tokio::test]
    async fn wait_notices_expiry_without_a_callback() {
        let (r, id) = registry_with_flow();
        r.age(&id, FLOW_TTL - Duration::from_millis(20));
        let v = r.wait(&id, Duration::from_secs(5)).await.unwrap();
        assert_eq!(v.status, FlowStatus::Expired);
    }
}
