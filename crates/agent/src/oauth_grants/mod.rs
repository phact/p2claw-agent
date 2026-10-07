//! OAuth grants through p2claw Connect: an app on this box gets a
//! user's consent for a provider API without an OAuth client of its
//! own. The broker holds the client secret and does the code exchange
//! and refresh; the grant it returns is sealed to this box and lives
//! only here.
//!
//! Two storage modes, chosen per flow: app-managed (the app keeps the
//! grant and asks for refreshes) and agent-managed (the grant is kept
//! in [`store`] and the app asks for access tokens, which are cached
//! and refreshed behind the call).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use thiserror::Error;
use tracing::{debug, info, warn};

pub mod broker;
pub mod flows;
pub mod store;

pub use broker::{Broker, BrokerClient, BrokerError, Provider, TokenResponse};
pub use flows::{ExchangeRefusal, FlowRegistry, FlowStatus, FlowView, FLOW_TTL};
pub use store::{GrantStore, GrantSummary, StoreError, StoredGrant};

/// Access tokens are refreshed this long before they expire.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// How long the broker's provider list is reused.
const PROVIDERS_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("{0}")]
    BadRequest(String),
    #[error("no such grant")]
    NotFound,
    /// The provider rejected the grant; it has been dropped.
    #[error("the provider rejected the grant; consent again")]
    InvalidGrant,
    #[error(transparent)]
    Flow(FlowRefusal),
    #[error(transparent)]
    Broker(BrokerError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Why an exchange was refused before reaching the broker.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FlowRefusal {
    #[error("no such flow")]
    Unknown,
    #[error("the flow has no callback yet")]
    Pending,
    #[error("the provider returned an error: {0}")]
    Failed(String),
    #[error("the flow expired; start again")]
    Expired,
    #[error("the flow was already exchanged")]
    Consumed,
}

impl From<ExchangeRefusal> for FlowRefusal {
    fn from(r: ExchangeRefusal) -> Self {
        match r {
            ExchangeRefusal::Unknown => FlowRefusal::Unknown,
            ExchangeRefusal::Pending => FlowRefusal::Pending,
            ExchangeRefusal::Failed(e) => FlowRefusal::Failed(e),
            ExchangeRefusal::Expired => FlowRefusal::Expired,
            ExchangeRefusal::Consumed => FlowRefusal::Consumed,
        }
    }
}

impl From<BrokerError> for GrantError {
    fn from(e: BrokerError) -> Self {
        match e {
            BrokerError::InvalidGrant => GrantError::InvalidGrant,
            e => GrantError::Broker(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StartRequest {
    pub provider: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub nonce_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Started {
    pub flow_id: String,
    pub authorize_url: String,
}

/// Result of an exchange. `grant` is set in app-managed mode,
/// `grant_id` in agent-managed mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Exchanged {
    pub provider: String,
    pub access_token: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessToken {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revoked {
    pub id: String,
    pub provider: String,
    /// `true` when the provider accepted the revocation. The grant is
    /// dropped locally either way.
    pub provider_revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_error: Option<String>,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    scope: Option<String>,
    expires_at: Instant,
}

pub struct OauthGrants<B = BrokerClient> {
    broker: B,
    flows: FlowRegistry,
    store: GrantStore,
    tokens: Mutex<HashMap<String, CachedToken>>,
    /// One lock per grant so concurrent token requests share a single
    /// refresh.
    refresh_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    providers: Mutex<Option<(Instant, Vec<Provider>)>>,
}

impl<B: Broker> OauthGrants<B> {
    pub fn new(broker: B, store: GrantStore) -> Self {
        Self {
            broker,
            flows: FlowRegistry::new(),
            store,
            tokens: Mutex::new(HashMap::new()),
            refresh_locks: Mutex::new(HashMap::new()),
            providers: Mutex::new(None),
        }
    }

    pub fn flows(&self) -> &FlowRegistry {
        &self.flows
    }

    pub fn store(&self) -> &GrantStore {
        &self.store
    }

    /// Providers and scopes the Connect apps offer, cached briefly.
    pub async fn providers(&self) -> Result<Vec<Provider>, GrantError> {
        if let Some((at, list)) = &*lock(&self.providers) {
            if at.elapsed() < PROVIDERS_TTL {
                return Ok(list.clone());
            }
        }
        let list = self.broker.providers().await?;
        *lock(&self.providers) = Some((Instant::now(), list.clone()));
        Ok(list)
    }

    pub async fn start(&self, req: StartRequest) -> Result<Started, GrantError> {
        validate_start(&req)?;
        let flow_id = self
            .flows
            .start(&req.provider, req.scopes.clone(), &req.nonce_hash);
        let body = broker::StartFlowRequest {
            flow_id: flow_id.clone(),
            scopes: req.scopes,
            code_challenge: req.code_challenge,
            nonce_hash: req.nonce_hash,
        };
        match self.broker.start_flow(&req.provider, &body).await {
            Ok(authorize_url) => {
                debug!(%flow_id, provider = %req.provider, "oauth-grants: flow started");
                Ok(Started {
                    flow_id,
                    authorize_url,
                })
            }
            Err(e) => {
                self.flows.abandon(&flow_id);
                Err(e.into())
            }
        }
    }

    /// Exchange the code the callback delivered. The flow is consumed
    /// first, so a failure at the broker still spends it.
    pub async fn exchange(
        &self,
        flow_id: &str,
        code_verifier: &str,
        store: bool,
    ) -> Result<Exchanged, GrantError> {
        if code_verifier.is_empty() {
            return Err(GrantError::BadRequest("code_verifier is required".into()));
        }
        let ready = self
            .flows
            .consume(flow_id)
            .map_err(|r| GrantError::Flow(r.into()))?;
        let req = broker::ExchangeRequest {
            flow_id: ready.flow_id.clone(),
            code: ready.code,
            code_verifier: code_verifier.to_string(),
            state: ready.state,
            nonce_hash: ready.nonce_hash,
        };
        let mut tok = self.broker.exchange(&ready.provider, &req).await?;
        let Some(blob) = tok.grant.take() else {
            return Err(GrantError::Broker(BrokerError::BadResponse(
                "exchange response carried no grant".into(),
            )));
        };
        if !store {
            info!(%flow_id, provider = %ready.provider, "oauth-grants: exchanged (app-managed)");
            return Ok(Exchanged {
                provider: ready.provider,
                access_token: tok.access_token,
                expires_in: tok.expires_in,
                scope: tok.scope,
                grant: Some(blob),
                grant_id: None,
            });
        }
        let id = format!("gr_{}", ulid::Ulid::new());
        let scopes = match &tok.scope {
            Some(s) if !s.trim().is_empty() => s.split_whitespace().map(String::from).collect(),
            _ => ready.scopes,
        };
        self.store
            .insert(StoredGrant {
                id: id.clone(),
                provider: ready.provider.clone(),
                scopes,
                grant: blob,
                created_at: now_secs(),
            })
            .await?;
        self.cache_token(&id, &tok);
        info!(%flow_id, grant_id = %id, provider = %ready.provider, "oauth-grants: exchanged (agent-managed)");
        Ok(Exchanged {
            provider: ready.provider,
            access_token: tok.access_token,
            expires_in: tok.expires_in,
            scope: tok.scope,
            grant: None,
            grant_id: Some(id),
        })
    }

    /// Refresh an app-managed grant.
    pub async fn refresh(&self, provider: &str, grant: &str) -> Result<TokenResponse, GrantError> {
        if provider.is_empty() || grant.is_empty() {
            return Err(GrantError::BadRequest(
                "provider and grant are required".into(),
            ));
        }
        Ok(self.broker.refresh(provider, grant).await?)
    }

    pub fn list(&self) -> Vec<GrantSummary> {
        self.store.list()
    }

    /// Access token for a stored grant, refreshed when it is within
    /// [`REFRESH_MARGIN`] of expiry. On `invalid_grant` the grant is
    /// dropped and [`GrantError::InvalidGrant`] is returned.
    pub async fn token(&self, id: &str) -> Result<AccessToken, GrantError> {
        let grant = self.store.get(id).ok_or(GrantError::NotFound)?;
        let refresh_lock = self.refresh_lock(id);
        let _held = refresh_lock.lock().await;
        // The grant may have been dropped while waiting on the lock.
        let grant = self.store.get(id).unwrap_or(grant);
        if let Some(t) = self.cached_token(id) {
            return Ok(t);
        }
        match self.broker.refresh(&grant.provider, &grant.grant).await {
            Ok(tok) => {
                if let Some(blob) = &tok.grant {
                    if !self.store.replace_blob(id, blob.clone()).await? {
                        return Err(GrantError::NotFound);
                    }
                }
                self.cache_token(id, &tok);
                Ok(AccessToken {
                    access_token: tok.access_token,
                    expires_in: tok.expires_in,
                    scope: tok.scope,
                })
            }
            Err(BrokerError::InvalidGrant) => {
                warn!(grant_id = %id, provider = %grant.provider, "oauth-grants: grant rejected by the provider; dropping it");
                self.forget(id).await?;
                Err(GrantError::InvalidGrant)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Revoke at the provider, then drop the grant. The grant is
    /// dropped even when the provider call fails; the result says so.
    pub async fn revoke(&self, id: &str) -> Result<Revoked, GrantError> {
        let grant = self.store.get(id).ok_or(GrantError::NotFound)?;
        let mut result = Revoked {
            id: id.to_string(),
            provider: grant.provider.clone(),
            provider_revoked: false,
            provider_error: None,
        };
        match self.token(id).await {
            Ok(tok) => match self.revoke_url(&grant.provider).await {
                Ok(url) => match self
                    .broker
                    .revoke_at_provider(&url, &tok.access_token)
                    .await
                {
                    Ok(()) => result.provider_revoked = true,
                    Err(e) => result.provider_error = Some(e.to_string()),
                },
                Err(e) => result.provider_error = Some(e.to_string()),
            },
            Err(GrantError::InvalidGrant) => {
                result.provider_error = Some("the provider had already rejected the grant".into())
            }
            Err(e) => result.provider_error = Some(e.to_string()),
        }
        self.forget(id).await?;
        info!(grant_id = %id, provider_revoked = result.provider_revoked, "oauth-grants: grant revoked");
        Ok(result)
    }

    async fn revoke_url(&self, provider: &str) -> Result<String, GrantError> {
        let providers = self.providers().await?;
        providers
            .into_iter()
            .find(|p| p.name == provider)
            .map(|p| p.revoke_url)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                GrantError::Broker(BrokerError::BadResponse(format!(
                    "the broker lists no revoke endpoint for {provider}"
                )))
            })
    }

    async fn forget(&self, id: &str) -> Result<(), GrantError> {
        self.store.remove(id).await?;
        lock(&self.tokens).remove(id);
        lock(&self.refresh_locks).remove(id);
        Ok(())
    }

    fn refresh_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.refresh_locks)
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    fn cached_token(&self, id: &str) -> Option<AccessToken> {
        let tokens = lock(&self.tokens);
        let t = tokens.get(id)?;
        let remaining = t.expires_at.checked_duration_since(Instant::now())?;
        if remaining <= REFRESH_MARGIN {
            return None;
        }
        Some(AccessToken {
            access_token: t.access_token.clone(),
            expires_in: remaining.as_secs(),
            scope: t.scope.clone(),
        })
    }

    fn cache_token(&self, id: &str, tok: &TokenResponse) {
        lock(&self.tokens).insert(
            id.to_string(),
            CachedToken {
                access_token: tok.access_token.clone(),
                scope: tok.scope.clone(),
                expires_at: Instant::now() + Duration::from_secs(tok.expires_in),
            },
        );
    }
}

fn validate_start(req: &StartRequest) -> Result<(), GrantError> {
    let bad = |m: &str| Err(GrantError::BadRequest(m.into()));
    if req.provider.is_empty()
        || req.provider.len() > 32
        || !req
            .provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return bad("provider must be a short lowercase name");
    }
    if req.scopes.is_empty() || req.scopes.iter().any(|s| s.is_empty() || s.contains(' ')) {
        return bad("scopes must name at least one scope, none containing spaces");
    }
    if !is_base64url(&req.code_challenge) || req.code_challenge.len() != 43 {
        return bad("code_challenge must be the base64url SHA-256 of the verifier (43 chars)");
    }
    if !is_base64url(&req.nonce_hash) || req.nonce_hash.len() != 43 {
        return bad("nonce_hash must be the base64url SHA-256 of the nonce (43 chars)");
    }
    Ok(())
}

fn is_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const NONCE_HASH: &str = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg";

    /// In-process broker: canned answers, call counters, optional
    /// delay on refresh so single-flight can be observed.
    #[derive(Default)]
    struct MockBroker {
        refreshes: AtomicUsize,
        exchanges: AtomicUsize,
        provider_lists: AtomicUsize,
        revokes: Mutex<Vec<(String, String)>>,
        refresh_delay: Option<Duration>,
        /// Grant blobs the provider has revoked.
        dead_grants: Mutex<Vec<String>>,
        /// Blob to return from refresh (rotation), if any.
        rotate_to: Mutex<Option<String>>,
        /// Lifetime of the token the exchange hands out; refreshed
        /// tokens always live an hour.
        expires_in: u64,
        fail_revoke: bool,
    }

    impl MockBroker {
        fn new() -> Self {
            Self {
                expires_in: 3600,
                ..Default::default()
            }
        }
    }

    impl Broker for MockBroker {
        async fn providers(&self) -> Result<Vec<Provider>, BrokerError> {
            self.provider_lists.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Provider {
                name: "google".into(),
                scopes: vec!["calendar.app.created".into()],
                revoke_url: "https://oauth2.googleapis.com/revoke".into(),
            }])
        }
        async fn start_flow(
            &self,
            provider: &str,
            req: &broker::StartFlowRequest,
        ) -> Result<String, BrokerError> {
            if provider != "google" {
                return Err(BrokerError::Rejected {
                    status: 400,
                    detail: "unknown_provider".into(),
                });
            }
            Ok(format!(
                "https://accounts.google.com/o/oauth2/v2/auth?state=s1.{}",
                req.flow_id
            ))
        }
        async fn exchange(
            &self,
            _provider: &str,
            req: &broker::ExchangeRequest,
        ) -> Result<TokenResponse, BrokerError> {
            self.exchanges.fetch_add(1, Ordering::SeqCst);
            Ok(TokenResponse {
                access_token: format!("at-{}-{}", req.code, req.code_verifier),
                expires_in: self.expires_in,
                scope: Some("calendar.app.created".into()),
                grant: Some(format!("g1.k1.{}", req.flow_id)),
            })
        }
        async fn refresh(
            &self,
            _provider: &str,
            grant: &str,
        ) -> Result<TokenResponse, BrokerError> {
            if let Some(d) = self.refresh_delay {
                tokio::time::sleep(d).await;
            }
            let n = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
            if lock(&self.dead_grants).iter().any(|g| g == grant) {
                return Err(BrokerError::InvalidGrant);
            }
            Ok(TokenResponse {
                access_token: format!("fresh-{n}"),
                expires_in: 3600,
                scope: None,
                grant: lock(&self.rotate_to).clone(),
            })
        }
        async fn revoke_at_provider(
            &self,
            revoke_url: &str,
            access_token: &str,
        ) -> Result<(), BrokerError> {
            lock(&self.revokes).push((revoke_url.into(), access_token.into()));
            if self.fail_revoke {
                return Err(BrokerError::Provider {
                    detail: "revoke endpoint answered 500".into(),
                });
            }
            Ok(())
        }
    }

    fn manager(broker: MockBroker) -> (Arc<OauthGrants<MockBroker>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = GrantStore::load_or_empty(dir.path().join("oauth-grants.json"));
        (Arc::new(OauthGrants::new(broker, store)), dir)
    }

    fn start_req() -> StartRequest {
        StartRequest {
            provider: "google".into(),
            scopes: vec!["calendar.app.created".into()],
            code_challenge: CHALLENGE.into(),
            nonce_hash: NONCE_HASH.into(),
        }
    }

    async fn stored_grant(m: &OauthGrants<MockBroker>) -> String {
        let started = m.start(start_req()).await.unwrap();
        assert!(m
            .flows()
            .deliver(&started.flow_id, Some("c0de".into()), None, "s1.a.b".into()));
        let ex = m
            .exchange(&started.flow_id, "verifier", true)
            .await
            .unwrap();
        ex.grant_id.unwrap()
    }

    #[tokio::test]
    async fn start_validates_and_abandons_refused_flows() {
        let (m, _d) = manager(MockBroker::new());
        let mut bad = start_req();
        bad.code_challenge = "short".into();
        assert!(matches!(m.start(bad).await, Err(GrantError::BadRequest(_))));
        let mut bad = start_req();
        bad.scopes = vec![];
        assert!(matches!(m.start(bad).await, Err(GrantError::BadRequest(_))));
        let mut bad = start_req();
        bad.provider = "Google!".into();
        assert!(matches!(m.start(bad).await, Err(GrantError::BadRequest(_))));

        let mut refused = start_req();
        refused.provider = "github".into();
        assert!(matches!(
            m.start(refused).await,
            Err(GrantError::Broker(BrokerError::Rejected {
                status: 400,
                ..
            }))
        ));

        let started = m.start(start_req()).await.unwrap();
        assert!(started.authorize_url.contains(&started.flow_id));
        assert_eq!(
            m.flows().get(&started.flow_id).unwrap().status,
            FlowStatus::Pending
        );
    }

    #[tokio::test]
    async fn exchange_app_managed_returns_the_grant_and_stores_nothing() {
        let (m, _d) = manager(MockBroker::new());
        let started = m.start(start_req()).await.unwrap();
        assert!(matches!(
            m.exchange(&started.flow_id, "v", false).await,
            Err(GrantError::Flow(FlowRefusal::Pending))
        ));
        m.flows()
            .deliver(&started.flow_id, Some("c0de".into()), None, "s1.a.b".into());
        let ex = m
            .exchange(&started.flow_id, "verifier", false)
            .await
            .unwrap();
        assert_eq!(ex.access_token, "at-c0de-verifier");
        assert_eq!(
            ex.grant.as_deref(),
            Some(format!("g1.k1.{}", started.flow_id).as_str())
        );
        assert!(ex.grant_id.is_none());
        assert!(m.list().is_empty());
        assert!(matches!(
            m.exchange(&started.flow_id, "verifier", false).await,
            Err(GrantError::Flow(FlowRefusal::Consumed))
        ));
        assert!(matches!(
            m.exchange("f_nope", "verifier", false).await,
            Err(GrantError::Flow(FlowRefusal::Unknown))
        ));
    }

    #[tokio::test]
    async fn exchange_agent_managed_stores_and_caches() {
        let (m, dir) = manager(MockBroker::new());
        let id = stored_grant(&m).await;
        assert!(id.starts_with("gr_"));
        let list = m.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].provider, "google");
        assert_eq!(list[0].scopes, vec!["calendar.app.created"]);
        assert!(dir.path().join("oauth-grants.json").exists());

        // The exchange's access token is served from cache: no refresh.
        let t = m.token(&id).await.unwrap();
        assert_eq!(t.access_token, "at-c0de-verifier");
        assert!(t.expires_in > 3500 && t.expires_in <= 3600);
        assert_eq!(m.broker.refreshes.load(Ordering::SeqCst), 0);
        assert!(matches!(
            m.token("gr_nope").await,
            Err(GrantError::NotFound)
        ));
    }

    #[tokio::test]
    async fn token_refreshes_near_expiry_with_a_single_flight() {
        let (m, _d) = manager(MockBroker {
            refresh_delay: Some(Duration::from_millis(60)),
            // Within the margin as soon as it is issued.
            expires_in: 30,
            ..MockBroker::new()
        });
        let id = stored_grant(&m).await;
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let m = m.clone();
            let id = id.clone();
            tasks.push(tokio::spawn(async move { m.token(&id).await.unwrap() }));
        }
        let mut tokens = Vec::new();
        for t in tasks {
            tokens.push(t.await.unwrap().access_token);
        }
        // One refresh served every concurrent caller.
        assert_eq!(m.broker.refreshes.load(Ordering::SeqCst), 1);
        assert!(tokens.iter().all(|t| t == "fresh-1"), "{tokens:?}");
        let t = m.token(&id).await.unwrap();
        assert_eq!(t.access_token, "fresh-1");
        assert_eq!(m.broker.refreshes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn token_replaces_a_rotated_grant() {
        let (m, _d) = manager(MockBroker {
            expires_in: 10,
            ..MockBroker::new()
        });
        let id = stored_grant(&m).await;
        *lock(&m.broker.rotate_to) = Some("g1.k1.rotated".into());
        m.token(&id).await.unwrap();
        assert_eq!(m.store().get(&id).unwrap().grant, "g1.k1.rotated");
    }

    #[tokio::test]
    async fn invalid_grant_drops_the_stored_grant() {
        let (m, _d) = manager(MockBroker {
            expires_in: 10,
            ..MockBroker::new()
        });
        let id = stored_grant(&m).await;
        let blob = m.store().get(&id).unwrap().grant;
        lock(&m.broker.dead_grants).push(blob);
        assert!(matches!(m.token(&id).await, Err(GrantError::InvalidGrant)));
        assert!(m.list().is_empty());
        assert!(matches!(m.token(&id).await, Err(GrantError::NotFound)));
    }

    #[tokio::test]
    async fn refresh_app_managed_maps_invalid_grant() {
        let (m, _d) = manager(MockBroker::new());
        let t = m.refresh("google", "g1.k1.ok").await.unwrap();
        assert_eq!(t.access_token, "fresh-1");
        lock(&m.broker.dead_grants).push("g1.k1.dead".into());
        assert!(matches!(
            m.refresh("google", "g1.k1.dead").await,
            Err(GrantError::InvalidGrant)
        ));
        assert!(matches!(
            m.refresh("", "g").await,
            Err(GrantError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn revoke_calls_the_provider_then_drops() {
        let (m, _d) = manager(MockBroker::new());
        let id = stored_grant(&m).await;
        let r = m.revoke(&id).await.unwrap();
        assert!(r.provider_revoked && r.provider_error.is_none(), "{r:?}");
        assert_eq!(
            *lock(&m.broker.revokes),
            vec![(
                "https://oauth2.googleapis.com/revoke".to_string(),
                "at-c0de-verifier".to_string()
            )]
        );
        assert!(m.list().is_empty());
        assert!(matches!(m.revoke(&id).await, Err(GrantError::NotFound)));
    }

    #[tokio::test]
    async fn revoke_drops_locally_even_when_the_provider_fails() {
        let (m, _d) = manager(MockBroker {
            fail_revoke: true,
            ..MockBroker::new()
        });
        let id = stored_grant(&m).await;
        let r = m.revoke(&id).await.unwrap();
        assert!(!r.provider_revoked);
        assert!(r.provider_error.unwrap().contains("500"));
        assert!(m.list().is_empty());
    }

    #[tokio::test]
    async fn providers_are_cached() {
        let (m, _d) = manager(MockBroker::new());
        assert_eq!(m.providers().await.unwrap().len(), 1);
        assert_eq!(m.providers().await.unwrap().len(), 1);
        assert_eq!(m.broker.provider_lists.load(Ordering::SeqCst), 1);
    }
}
