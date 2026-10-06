//! JWKS fetch + cache for the OAuth broker.
//!
//! Responsibilities:
//!
//! - Lazy first-fetch on first authenticated request — daemon
//!   startup doesn't block on broker availability.
//! - Periodic refresh tick from
//!   [`super::OAuthValidator::spawn_refresh_task`] (~6h cadence,
//!   pinned at the module level).
//! - On a `kid` miss against the cache, the middleware calls
//!   [`JwksCache::refresh`] once and retries the lookup. This
//!   covers the broker-rotated-keys-mid-flight case:
//!   operators publish a new
//!   `kid` and switch the primary; daemons whose cache TTL hasn't
//!   ticked yet still pick up the new key on the first 401-miss.
//! - Fail-closed when the cache is empty AND the fetch fails:
//!   [`JwksCache::current`] returns `JwksError::Unavailable` so
//!   the middleware can map to `503` rather than silently letting
//!   the request through.

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::OAuthConfig;

/// Default per-fetch HTTP timeout. Long enough for a TLS handshake +
/// the trivial JWKS payload, short enough that a hanging broker
/// doesn't pin the per-request middleware path beyond one
/// `forward_timeout`-grade budget.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum JwksError {
    #[error("jwks fetch http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("jwks fetch http status {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("jwks body did not parse: {0}")]
    Parse(String),
    #[error("jwks empty (no keys) or no valid signing keys; rejecting")]
    NoKeys,
    /// First request hit an empty cache AND the eager refresh
    /// failed. Middleware maps this to `503` — fail-closed.
    #[error("jwks cache unavailable: no cached keys and fetch failed: {0}")]
    Unavailable(String),
}

/// One JWK entry decoded from the broker's response. Holds the
/// fully-decoded `VerifyingKey` so the validator's hot path is
/// cache-lookup + signature-verify, no per-request base64.
#[derive(Debug, Clone)]
pub struct Jwk {
    pub kid: String,
    pub verifying_key: VerifyingKey,
}

/// Wire shape of the broker's JWKS endpoint.
#[derive(Debug, Deserialize)]
struct JwksWire {
    keys: Vec<JwkWire>,
}

#[derive(Debug, Deserialize)]
struct JwkWire {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    x: Option<String>,
}

/// Decoded JWKS — what the cache holds.
#[derive(Debug, Clone)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Parse + filter the wire JWKS into trusted Ed25519 keys.
    /// Rejects anything that isn't `kty=OKP / crv=Ed25519 / use=sig`
    /// per the strict invariants in `oauth::jwt`. Empty result (no
    /// keys passed the filter) returns [`JwksError::NoKeys`].
    fn from_wire(wire: JwksWire) -> Result<Self, JwksError> {
        let mut out = Vec::with_capacity(wire.keys.len());
        for k in wire.keys {
            // Strict: any deviation is rejected (skipped), not
            // best-effort accepted.
            if k.kty != super::jwt::EXPECTED_KTY {
                debug!(?k.kid, kty = %k.kty, "jwks: skip non-OKP key");
                continue;
            }
            if k.crv.as_deref() != Some(super::jwt::EXPECTED_CRV) {
                debug!(?k.kid, crv = ?k.crv, "jwks: skip non-Ed25519 key");
                continue;
            }
            if k.use_.as_deref() != Some(super::jwt::EXPECTED_USE) {
                debug!(?k.kid, use_ = ?k.use_, "jwks: skip non-sig key");
                continue;
            }
            if let Some(alg) = k.alg.as_deref() {
                if alg != super::jwt::EXPECTED_ALG {
                    debug!(?k.kid, alg, "jwks: skip non-EdDSA-tagged key");
                    continue;
                }
            }
            let Some(kid) = k.kid else {
                debug!("jwks: skip key with no kid");
                continue;
            };
            let Some(x_b64) = k.x else {
                debug!(kid, "jwks: skip key with no `x` field");
                continue;
            };
            let bytes = match URL_SAFE_NO_PAD.decode(&x_b64) {
                Ok(b) => b,
                Err(e) => {
                    warn!(kid, error = %e, "jwks: `x` field is not valid base64url");
                    continue;
                }
            };
            if bytes.len() != 32 {
                warn!(
                    kid,
                    len = bytes.len(),
                    "jwks: Ed25519 pubkey must be exactly 32 bytes"
                );
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let vk = match VerifyingKey::from_bytes(&arr) {
                Ok(v) => v,
                Err(e) => {
                    warn!(kid, error = %e, "jwks: Ed25519 pubkey bytes invalid (curve point)");
                    continue;
                }
            };
            out.push(Jwk {
                kid,
                verifying_key: vk,
            });
        }
        if out.is_empty() {
            return Err(JwksError::NoKeys);
        }
        Ok(Self { keys: out })
    }
}

/// Live cache shared by the validator + the background refresh task.
///
/// `None` value means "never fetched successfully". After the first
/// successful fetch the slot stays `Some` forever (even if a later
/// refresh fails — operators get a `warn!` log + the cached keys
/// stay in service). The brief: "On JWKS-fetch-failure WITH no cache,
/// fail closed (503)"; on failure WITH a cache, we serve the
/// cached keys until the next refresh.
pub struct JwksCache {
    inner: RwLock<Option<JwksState>>,
    config: Arc<OAuthConfig>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
struct JwksState {
    jwks: Jwks,
}

impl JwksCache {
    pub fn new(config: Arc<OAuthConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            // Friendly UA so broker access logs can tell daemons
            // apart from random scraping.
            .user_agent(concat!(
                "p2claw-agent/",
                env!("CARGO_PKG_VERSION"),
                " (oauth)"
            ))
            .build()
            .expect("reqwest client build");
        Self {
            inner: RwLock::new(None),
            config,
            client,
        }
    }

    /// Return the current cached JWKS, fetching on demand if the
    /// cache is empty. Fail-closed: an empty cache + failing fetch
    /// produces [`JwksError::Unavailable`] for the middleware to
    /// map to `503`.
    pub async fn current(&self) -> Result<Jwks, JwksError> {
        if let Some(state) = self.inner.read().await.clone() {
            return Ok(state.jwks);
        }
        // Cache miss — try one eager fetch. On failure surface as
        // Unavailable so the middleware fails closed with a 503.
        match self.refresh().await {
            Ok(()) => {}
            Err(e) => {
                // Don't poison the cache with a fail-state; just
                // surface Unavailable. Next request retries.
                return Err(JwksError::Unavailable(e.to_string()));
            }
        }
        let snap = self.inner.read().await.clone();
        snap.map(|s| s.jwks)
            .ok_or_else(|| JwksError::Unavailable("post-refresh cache still empty".into()))
    }

    /// Force a fresh fetch + replace the cache on success. On
    /// failure, the existing cache is preserved. Used by the
    /// periodic refresh task and by the middleware's
    /// `retry-once-on-kid-miss` path.
    pub async fn refresh(&self) -> Result<(), JwksError> {
        let url = self.config.jwks_url();
        debug!(url = %url, "jwks: GET");
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(JwksError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }
        let wire: JwksWire = resp
            .json()
            .await
            .map_err(|e| JwksError::Parse(e.to_string()))?;
        let jwks = Jwks::from_wire(wire)?;
        let kids: Vec<String> = jwks.keys.iter().map(|k| k.kid.clone()).collect();
        let new_state = JwksState { jwks };
        let mut slot = self.inner.write().await;
        *slot = Some(new_state);
        info!(?kids, "jwks: refreshed");
        Ok(())
    }

    /// Look up a key by `kid`, refreshing once on miss to handle
    /// broker key rotation. Returns `None` if even the post-refresh
    /// cache lacks the key — the middleware maps that to
    /// `JwtError::BadSignature` (same shape as "key known but
    /// verify failed"; avoids letting callers enumerate kids by
    /// observing a different error).
    pub async fn lookup_with_retry(&self, kid: &str) -> Option<VerifyingKey> {
        if let Ok(jwks) = self.current().await {
            if let Some(jwk) = jwks.find(kid) {
                return Some(jwk.verifying_key);
            }
        }
        // Miss — single retry through `refresh` to pick up a
        // freshly-published key.
        if let Err(e) = self.refresh().await {
            warn!(kid, error = %e, "jwks: kid-miss retry refresh failed");
            return None;
        }
        let jwks = self.inner.read().await.clone()?.jwks;
        jwks.find(kid).map(|j| j.verifying_key)
    }

    /// Test-only helper to seed the cache without a network fetch.
    /// `pub` (not `cfg(test)`) so external integration tests in
    /// `crates/agent/tests/oauth_middleware_e2e.rs` can seed
    /// against a synthetic broker keypair without spinning up a
    /// real broker. Production callers MUST NOT use this — there's
    /// no input validation, no signature check, just "treat these
    /// keys as trusted." Wire `JwksCache::new` + `refresh` (or
    /// `current`) for the lazy fetch path.
    pub async fn install_for_test(&self, jwks: Jwks) {
        let mut slot = self.inner.write().await;
        *slot = Some(JwksState { jwks });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;

    fn pubkey_b64(sk: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes())
    }

    #[test]
    fn from_wire_accepts_valid_ed25519_sig_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let wire: JwksWire = serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "k1",
                "use": "sig",
                "alg": "EdDSA",
                "x": pubkey_b64(&sk),
            }]
        }))
        .unwrap();
        let jwks = Jwks::from_wire(wire).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, "k1");
    }

    #[test]
    fn from_wire_filters_wrong_kty() {
        let wire: JwksWire = serde_json::from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": "k1",
                "use": "sig",
                "x": "AAAA",
            }]
        }))
        .unwrap();
        let err = Jwks::from_wire(wire).unwrap_err();
        assert!(matches!(err, JwksError::NoKeys), "{err:?}");
    }

    #[test]
    fn from_wire_filters_wrong_use() {
        // `use=enc` (encryption-only) key must not be picked up
        // for signature validation.
        let sk = SigningKey::generate(&mut OsRng);
        let wire: JwksWire = serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "k1",
                "use": "enc",
                "alg": "EdDSA",
                "x": pubkey_b64(&sk),
            }]
        }))
        .unwrap();
        let err = Jwks::from_wire(wire).unwrap_err();
        assert!(matches!(err, JwksError::NoKeys), "{err:?}");
    }

    #[test]
    fn from_wire_filters_wrong_curve() {
        let wire: JwksWire = serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed448",
                "kid": "k1",
                "use": "sig",
                "x": "AAAA",
            }]
        }))
        .unwrap();
        let err = Jwks::from_wire(wire).unwrap_err();
        assert!(matches!(err, JwksError::NoKeys));
    }

    #[test]
    fn from_wire_rejects_wrong_length_x() {
        // 16-byte x — too short for Ed25519 (32 bytes).
        let wire: JwksWire = serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "k1",
                "use": "sig",
                "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode([0u8; 16]),
            }]
        }))
        .unwrap();
        let err = Jwks::from_wire(wire).unwrap_err();
        assert!(matches!(err, JwksError::NoKeys));
    }

    #[test]
    fn find_by_kid_works() {
        let sk = SigningKey::generate(&mut OsRng);
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: "k1".into(),
                verifying_key: sk.verifying_key(),
            }],
        };
        assert!(jwks.find("k1").is_some());
        assert!(jwks.find("k2").is_none());
    }

    #[tokio::test]
    async fn install_for_test_and_lookup() {
        let cfg = Arc::new(OAuthConfig {
            broker_url: "https://example.invalid".into(),
            expected_aud_z32: "test".into(),
        });
        let cache = JwksCache::new(cfg);
        let sk = SigningKey::generate(&mut OsRng);
        cache
            .install_for_test(Jwks {
                keys: vec![Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;
        let vk = cache.lookup_with_retry("k1").await;
        assert!(vk.is_some());
    }

    #[tokio::test]
    async fn current_fails_closed_when_unfetched_and_broker_unreachable() {
        // No install_for_test; broker_url points at an unroutable
        // address so the eager fetch fails fast.
        let cfg = Arc::new(OAuthConfig {
            broker_url: "http://127.0.0.1:1".into(),
            expected_aud_z32: "test".into(),
        });
        let cache = JwksCache::new(cfg);
        let err = cache.current().await.unwrap_err();
        assert!(matches!(err, JwksError::Unavailable(_)), "{err:?}");
    }

    // Silence "unused" — `Signer` import is needed for the
    // ed25519-dalek API but only used in jwt.rs's tests.
    #[allow(dead_code)]
    fn _use_signer(sk: &SigningKey) -> ed25519_dalek::Signature {
        sk.sign(b"x")
    }
}
