//! Daemon-side OAuth middleware.
//!
//! The edge is presence-only on the session cookie; daemons do the
//! cryptographic JWT validation. This module owns that validation
//! end-to-end for the daemon:
//!
//! - [`jwks`] — fetch + cache the broker's published JWKS, with
//!   lazy first-fetch on demand + periodic refresh + retry-once on
//!   `kid` miss (handles broker key rotation mid-flight).
//! - [`jwt`] — hand-rolled, strict EdDSA-only JWT validator.
//!   Pinned to `alg=EdDSA`; explicitly rejects `alg=none` and any
//!   other algorithm; checks `iss`, `aud`, `exp`.
//! - [`middleware`] — per-request glue. Always strips incoming
//!   `X-P2claw-*` headers (defense-in-depth). When the
//!   destination app has `requires_auth=true`, extracts the JWT
//!   from `Cookie: __p2claw_session=…` or `Authorization: Bearer
//!   …`, validates, on success strips the credential and injects
//!   `X-P2claw-User` / `X-P2claw-Email` / `X-P2claw-Name` /
//!   `X-P2claw-Picture` for the upstream to consume; on failure
//!   returns `401` with `P2claw-Auth-Required: true` for the
//!   bootstrap to react to.
//!
//! `OAuthValidator` is the single object the forwarder holds; it
//! bundles the JWKS cache + the static config (broker URL,
//! expected `iss`, our peer_id as the expected `aud`) the
//! validator uses.

use std::sync::Arc;
use std::time::Duration;

pub mod device;
pub mod jwks;
pub mod jwt;
pub mod middleware;

pub use jwks::{Jwk, Jwks, JwksError};
pub use jwt::{Claims, JwtError};
pub use middleware::{AuthOutcome, MiddlewareError};

/// Cookie name carrying the session JWT; the broker sets it under
/// this exact name. The double-underscore prefix matches the
/// `__p2claw_*` route family in `crate::routes`.
pub const SESSION_COOKIE_NAME: &str = "__p2claw_session";

/// Header daemons emit on auth-required 401s so the bootstrap/SW
/// can detect "you need to log in" without parsing the body or
/// matching on the `WWW-Authenticate` realm. Header NAME is the
/// stable wire contract; the value is always the literal string
/// `true` (we keep it a stringly-typed flag for forward compatibility
/// in case auxiliary fields land later).
pub const AUTH_REQUIRED_HEADER: &str = "P2claw-Auth-Required";
pub const AUTH_REQUIRED_VALUE: &str = "true";

/// Header-name prefix the middleware always strips from arriving
/// requests, regardless of `requires_auth`. Belt-and-braces: even
/// public apps must not be able to spoof identity by sending
/// `X-P2claw-User: alice@…` themselves.
pub const IDENTITY_HEADER_PREFIX: &str = "x-p2claw-";

/// Identity headers the middleware INJECTS on a successful JWT
/// validation, populated from the token's claims.
/// Apps read these as the visitor's identity.
pub const HEADER_USER: &str = "X-P2claw-User";
pub const HEADER_EMAIL: &str = "X-P2claw-Email";
pub const HEADER_NAME: &str = "X-P2claw-Name";
pub const HEADER_PICTURE: &str = "X-P2claw-Picture";
pub const HEADER_PROVIDER: &str = "X-P2claw-Provider";

/// Default broker public URL. Used
/// to derive both the JWKS endpoint (`<url>/.well-known/jwks.json`)
/// and the expected `iss` claim (the URL verbatim). Operators
/// running their own broker fork override via the `P2CLAW_AGENT_OAUTH_BROKER_URL`
/// env at agent boot.
pub const DEFAULT_BROKER_URL: &str = "https://oauth.p2claw.com";

/// How often the periodic JWKS refresh task ticks. Brief
/// specifies "every ~6h" — chosen to comfortably outlast the
/// broker's `Cache-Control: max-age=3600` so the refresh acts as a
/// floor independent of the broker's cache hint, but short enough
/// that a planned key rotation (broker advertises the new `kid` an
/// hour before flipping the primary) is picked up by every running
/// daemon within one refresh cycle.
pub const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Compile-time configuration for the OAuth validator. Built once
/// at agent startup from env / static defaults; passed by `Arc` into
/// the validator + the periodic-refresh task. Cheap to clone (just
/// 3 strings).
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Broker public URL — the prefix the JWKS endpoint hangs off
    /// AND the expected `iss` claim value. Set via env
    /// `P2CLAW_AGENT_OAUTH_BROKER_URL`, defaults to
    /// [`DEFAULT_BROKER_URL`].
    pub broker_url: String,
    /// Expected `aud` claim value. Always the running daemon's own
    /// peer_id in z-base-32 (broker mints `aud = peer_id_z32` so
    /// tokens are pinned to a single box). Set once at startup
    /// from `PeerId::to_z32()`.
    pub expected_aud_z32: String,
}

impl OAuthConfig {
    /// JWKS endpoint URL derived from [`Self::broker_url`].
    pub fn jwks_url(&self) -> String {
        // Trim trailing `/` so `https://oauth.p2claw.com/` and
        // `https://oauth.p2claw.com` both produce the canonical
        // `https://oauth.p2claw.com/.well-known/jwks.json`.
        format!(
            "{}/.well-known/jwks.json",
            self.broker_url.trim_end_matches('/')
        )
    }

    /// Expected `iss` claim. Same as `broker_url`, but documented as
    /// a separate accessor so future divergence (e.g. broker
    /// behind a CDN with a different `iss` than its public URL)
    /// has one obvious place to change.
    pub fn expected_iss(&self) -> &str {
        self.broker_url.trim_end_matches('/')
    }
}

/// The single object the forwarder holds. Bundles the static
/// config + the live JWKS cache, exposes a `validate_request`
/// entry point the middleware wraps around the per-request flow.
///
/// Cheaply `Arc`-shared — the forwarder clones one Arc per
/// instance and the periodic-refresh background task holds another.
pub struct OAuthValidator {
    config: Arc<OAuthConfig>,
    jwks: Arc<jwks::JwksCache>,
    /// Nonce replay guard for device-cert proof-of-possession. Shared
    /// across requests (a captured PoP must not be replayable on a
    /// later request within its window).
    replay: Arc<device::ReplayCache>,
}

impl OAuthValidator {
    /// Construct a validator from config. Does NOT fetch JWKS up
    /// front — first authenticated request triggers a lazy fetch
    /// via [`jwks::JwksCache::current`]. This keeps daemon startup
    /// independent of broker availability: a coord-reachable but
    /// broker-unreachable daemon still answers public apps.
    pub fn new(config: OAuthConfig) -> Self {
        let config = Arc::new(config);
        let jwks = Arc::new(jwks::JwksCache::new(config.clone()));
        Self {
            config,
            jwks,
            replay: Arc::new(device::ReplayCache::new()),
        }
    }

    /// Spawn the periodic JWKS-refresh background task. Returns a
    /// [`tokio::task::JoinHandle`] the caller can keep for
    /// shutdown cancellation if needed; the task itself loops
    /// forever (well, until the [`Arc<JwksCache>`] drops, which is
    /// the agent-process lifetime in production).
    pub fn spawn_refresh_task(&self) -> tokio::task::JoinHandle<()> {
        let jwks = self.jwks.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(JWKS_REFRESH_INTERVAL);
            // Skip the first tick — the lazy fetch on first
            // authenticated request covers cold-start. Periodic
            // ticks are pure refresh.
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(e) = jwks.refresh().await {
                    tracing::warn!(error = %e, "oauth: periodic JWKS refresh failed; will retry next interval");
                }
            }
        })
    }

    /// Read-only access to the config (the middleware reads
    /// `expected_aud_z32` + `expected_iss()` per request).
    pub fn config(&self) -> &OAuthConfig {
        &self.config
    }

    /// Read-only access to the JWKS cache (the middleware fetches
    /// keys per request).
    pub fn jwks(&self) -> &Arc<jwks::JwksCache> {
        &self.jwks
    }

    /// The device-cert PoP replay guard.
    pub fn replay(&self) -> &Arc<device::ReplayCache> {
        &self.replay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_url_canonicalises_trailing_slash() {
        let cfg = OAuthConfig {
            broker_url: "https://oauth.p2claw.com/".into(),
            expected_aud_z32: "test".into(),
        };
        assert_eq!(
            cfg.jwks_url(),
            "https://oauth.p2claw.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn jwks_url_without_trailing_slash() {
        let cfg = OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "test".into(),
        };
        assert_eq!(
            cfg.jwks_url(),
            "https://oauth.p2claw.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn expected_iss_strips_trailing_slash() {
        let cfg = OAuthConfig {
            broker_url: "https://oauth.p2claw.com/".into(),
            expected_aud_z32: "test".into(),
        };
        assert_eq!(cfg.expected_iss(), "https://oauth.p2claw.com");
    }
}
