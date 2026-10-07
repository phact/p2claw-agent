//! HTTP client for the Connect endpoints of the OAuth broker.
//!
//! Every call except the providers listing is signed with the box's
//! identity key over the host, method, path (with query), a timestamp
//! and the SHA-256 of the exact body bytes sent. The broker verifies
//! the signature against the `peer_id` header, so nothing here carries
//! a bearer credential.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine as _;
use p2claw_identity::{
    sign_box_request, SigningKey, BOX_REQUEST_PEER_HEADER, BOX_REQUEST_SIGNATURE_HEADER,
    BOX_REQUEST_TIMESTAMP_HEADER,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// One provider the Connect app covers, as the broker lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub revoke_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartFlowRequest {
    pub flow_id: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub nonce_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExchangeRequest {
    pub flow_id: String,
    pub code: String,
    pub code_verifier: String,
    pub state: String,
    pub nonce_hash: String,
}

/// What exchange and refresh return: a fresh access token and, at
/// exchange or when the provider rotated the refresh token, a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

#[derive(Debug, Error)]
pub enum BrokerError {
    /// The provider no longer honours the refresh token behind a
    /// grant; the caller drops the grant.
    #[error("the provider rejected the grant; consent again")]
    InvalidGrant,
    /// The broker could not complete the call at the provider.
    #[error("provider error: {detail}")]
    Provider { detail: String },
    /// The broker refused the request (bad signature, unknown
    /// provider, scopes outside the Connect app, ...).
    #[error("broker refused the request ({status}): {detail}")]
    Rejected { status: u16, detail: String },
    #[error("broker unreachable: {0}")]
    Unreachable(String),
    #[error("broker answered with an unexpected body: {0}")]
    BadResponse(String),
    #[error("could not build the request: {0}")]
    Request(String),
}

/// What the grant manager needs from a broker. Production uses
/// [`BrokerClient`]; tests substitute an in-process stand-in.
pub trait Broker: Send + Sync + 'static {
    fn providers(&self) -> impl Future<Output = Result<Vec<Provider>, BrokerError>> + Send;
    fn start_flow(
        &self,
        provider: &str,
        req: &StartFlowRequest,
    ) -> impl Future<Output = Result<String, BrokerError>> + Send;
    fn exchange(
        &self,
        provider: &str,
        req: &ExchangeRequest,
    ) -> impl Future<Output = Result<TokenResponse, BrokerError>> + Send;
    fn refresh(
        &self,
        provider: &str,
        grant: &str,
    ) -> impl Future<Output = Result<TokenResponse, BrokerError>> + Send;
    /// Revoke an access token at the provider's own endpoint.
    fn revoke_at_provider(
        &self,
        revoke_url: &str,
        access_token: &str,
    ) -> impl Future<Output = Result<(), BrokerError>> + Send;
}

/// Signed-request client against one broker URL.
pub struct BrokerClient {
    base: Url,
    /// Authority the signature binds to, as a `Host` header carries
    /// it (port only when it isn't the scheme default).
    host: String,
    identity: Arc<SigningKey>,
    http: reqwest::Client,
}

impl BrokerClient {
    pub fn new(broker_url: &str, identity: Arc<SigningKey>) -> Result<Self, BrokerError> {
        let base = Url::parse(broker_url.trim_end_matches('/'))
            .map_err(|e| BrokerError::Request(format!("broker url: {e}")))?;
        let host = signing_host(&base)
            .ok_or_else(|| BrokerError::Request("broker url has no host".into()))?;
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!(
                "p2claw-agent/",
                env!("CARGO_PKG_VERSION"),
                " (oauth-grants)"
            ))
            .build()
            .map_err(|e| BrokerError::Request(e.to_string()))?;
        Ok(Self {
            base,
            host,
            identity,
            http,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base
    }

    fn url(&self, path: &str) -> Url {
        let mut u = self.base.clone();
        u.set_path(&format!(
            "{}{}",
            self.base.path().trim_end_matches('/'),
            path
        ));
        u
    }

    async fn signed_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, BrokerError> {
        let bytes = serde_json::to_vec(body).map_err(|e| BrokerError::Request(e.to_string()))?;
        let url = self.url(path);
        let path_and_query = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let headers = signed_headers(
            &self.identity,
            &self.host,
            "POST",
            &path_and_query,
            &bytes,
            now_secs(),
        )
        .map_err(|e| BrokerError::Request(e.to_string()))?;
        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .body(bytes);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| BrokerError::Unreachable(e.to_string()))?;
        decode(resp).await
    }
}

impl Broker for BrokerClient {
    async fn providers(&self) -> Result<Vec<Provider>, BrokerError> {
        #[derive(Deserialize)]
        struct Body {
            providers: Vec<Provider>,
        }
        let resp = self
            .http
            .get(self.url("/connect/providers"))
            .send()
            .await
            .map_err(|e| BrokerError::Unreachable(e.to_string()))?;
        let body: Body = decode(resp).await?;
        Ok(body.providers)
    }

    async fn start_flow(
        &self,
        provider: &str,
        req: &StartFlowRequest,
    ) -> Result<String, BrokerError> {
        #[derive(Deserialize)]
        struct Body {
            authorize_url: String,
        }
        let body: Body = self
            .signed_post(&format!("/connect/{provider}/flows"), req)
            .await?;
        Ok(body.authorize_url)
    }

    async fn exchange(
        &self,
        provider: &str,
        req: &ExchangeRequest,
    ) -> Result<TokenResponse, BrokerError> {
        self.signed_post(&format!("/connect/{provider}/exchange"), req)
            .await
    }

    async fn refresh(&self, provider: &str, grant: &str) -> Result<TokenResponse, BrokerError> {
        #[derive(Serialize)]
        struct Body<'a> {
            grant: &'a str,
        }
        self.signed_post(&format!("/connect/{provider}/refresh"), &Body { grant })
            .await
    }

    async fn revoke_at_provider(
        &self,
        revoke_url: &str,
        access_token: &str,
    ) -> Result<(), BrokerError> {
        let resp = self
            .http
            .post(revoke_url)
            .form(&[("token", access_token)])
            .send()
            .await
            .map_err(|e| BrokerError::Unreachable(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        Err(BrokerError::Provider {
            detail: format!(
                "revoke endpoint answered {}: {}",
                status.as_u16(),
                trim(&text)
            ),
        })
    }
}

/// The three signature headers for one request. `path` includes the
/// query string; `body` is exactly what goes on the wire.
pub fn signed_headers(
    identity: &SigningKey,
    host: &str,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp_secs: u64,
) -> Result<[(&'static str, String); 3], p2claw_identity::IdentityError> {
    let digest: [u8; 32] = Sha256::digest(body).into();
    let sig = sign_box_request(identity, host, method, path, timestamp_secs, &digest)?;
    Ok([
        (BOX_REQUEST_PEER_HEADER, identity.peer_id().to_z32()),
        (BOX_REQUEST_TIMESTAMP_HEADER, timestamp_secs.to_string()),
        (BOX_REQUEST_SIGNATURE_HEADER, B64_URL.encode(sig.to_bytes())),
    ])
}

/// `host[:port]` as a `Host` header would carry it.
pub fn signing_host(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    provider_error: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

async fn decode<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T, BrokerError> {
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| BrokerError::Unreachable(e.to_string()))?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|e| BrokerError::BadResponse(e.to_string()));
    }
    let err: ErrorBody = serde_json::from_slice(&bytes).unwrap_or(ErrorBody {
        error: None,
        provider_error: None,
        detail: None,
    });
    let code = err.error.unwrap_or_default();
    if code == "invalid_grant" {
        return Err(BrokerError::InvalidGrant);
    }
    if status.as_u16() == 502 {
        let detail = err
            .provider_error
            .or(err.detail)
            .filter(|s| !s.is_empty())
            .unwrap_or(code);
        return Err(BrokerError::Provider { detail });
    }
    let mut detail = if code.is_empty() {
        trim(&String::from_utf8_lossy(&bytes))
    } else {
        code
    };
    if let Some(d) = err.detail.filter(|d| !d.is_empty()) {
        detail = format!("{detail}: {d}");
    }
    Err(BrokerError::Rejected {
        status: status.as_u16(),
        detail,
    })
}

fn trim(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() > 200 {
        let mut t: String = s.chars().take(199).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
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
    use p2claw_identity::{verify_box_request, Signature};

    #[test]
    fn headers_verify_against_the_exact_bytes() {
        let sk = SigningKey::generate();
        let body = br#"{"grant":"g1.k.abc"}"#;
        let [peer, ts, sig] = signed_headers(
            &sk,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/refresh",
            body,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(peer.0, "x-p2claw-peer");
        assert_eq!(ts.0, "x-p2claw-timestamp");
        assert_eq!(sig.0, "x-p2claw-signature");
        let pid = p2claw_identity::PeerId::from_z32(&peer.1).unwrap();
        let sig_bytes: [u8; 64] = B64_URL
            .decode(&sig.1)
            .unwrap()
            .try_into()
            .expect("64-byte signature");
        let sig = Signature::from_bytes(&sig_bytes);
        let digest: [u8; 32] = Sha256::digest(body).into();
        verify_box_request(
            &pid,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/refresh",
            ts.1.parse().unwrap(),
            &digest,
            &sig,
            1_800_000_010,
        )
        .expect("signature verifies");
        // One byte of body drift breaks it.
        let other: [u8; 32] = Sha256::digest(br#"{"grant":"g1.k.abd"}"#).into();
        assert!(verify_box_request(
            &pid,
            "oauth.p2claw.com",
            "POST",
            "/connect/google/refresh",
            1_800_000_000,
            &other,
            &sig,
            1_800_000_010,
        )
        .is_err());
    }

    #[test]
    fn signing_host_keeps_explicit_ports_only() {
        let u = Url::parse("https://oauth.p2claw.com/").unwrap();
        assert_eq!(signing_host(&u).as_deref(), Some("oauth.p2claw.com"));
        let u = Url::parse("http://127.0.0.1:8099").unwrap();
        assert_eq!(signing_host(&u).as_deref(), Some("127.0.0.1:8099"));
        let u = Url::parse("https://oauth.p2claw.com:443/x").unwrap();
        assert_eq!(signing_host(&u).as_deref(), Some("oauth.p2claw.com"));
    }

    #[test]
    fn client_paths_join_under_the_base() {
        let sk = Arc::new(SigningKey::generate());
        let c = BrokerClient::new("https://oauth.p2claw.com/", sk.clone()).unwrap();
        assert_eq!(
            c.url("/connect/google/flows").as_str(),
            "https://oauth.p2claw.com/connect/google/flows"
        );
        let c = BrokerClient::new("http://127.0.0.1:1/prefix", sk).unwrap();
        assert_eq!(
            c.url("/connect/providers").as_str(),
            "http://127.0.0.1:1/prefix/connect/providers"
        );
        assert_eq!(c.host, "127.0.0.1:1");
    }
}
